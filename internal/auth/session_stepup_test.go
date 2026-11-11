package auth

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Step-up tests. A step-up is a fresh authentication event: it verifies new
// proofs, issues a SUCCESSOR session with a new secret, revokes its predecessor
// and resets both clocks. It can never lower assurance or phishing resistance.

func (e *sessionEnv) mfaAccount() (string, Enrollment) {
	e.t.Helper()
	id, en := e.enrollTOTP()
	e.retireSeed()
	e.clock.Advance(time.Minute)
	return id, en
}

func (e *sessionEnv) stepUpTOTP(secret []byte, id string, en Enrollment) (IssuedSession, error) {
	e.t.Helper()
	return e.s.StepUpTOTP(e.t.Context(), secret, []byte(sessionTestPassword), id, e.nextCode(en), sessionTestIP)
}

func TestSensitiveOperationPolicyMatrix(t *testing.T) { // REAUTH-STRENGTH, SB-4, A05 boundary
	e := newSessionEnv(t)
	at := e.clock.Now()
	mk := func(assurance Assurance, max int64, age time.Duration) SessionInfo {
		return SessionInfo{ID: "s", UserID: "u", Assurance: assurance, RequiredAssurance: max, UsableAssurance: max, AuthenticatedAt: at.Add(-age), CreatedAt: at.Add(-age), ExpiresAt: at.Add(time.Hour), LastActivityAt: at}
	}
	window := DefaultStepUpWindow
	for _, op := range SensitiveOperations() {
		aal2Only := sensitivePolicies[op].aal2
		t.Run(string(op), func(t *testing.T) {
			// Fresh AAL2: allowed. Boundary: exactly 15m allowed, +1s requires step-up.
			if err := e.s.RequireSensitive(mk(AssuranceAAL2, 2, 0), op); err != nil {
				t.Fatal("fresh AAL2 denied", err)
			}
			if err := e.s.RequireSensitive(mk(AssuranceAAL2, 2, window), op); err != nil {
				t.Fatal("exactly 15m must still be fresh", err)
			}
			if err := e.s.RequireSensitive(mk(AssuranceAAL2, 2, window+time.Second), op); !errors.Is(err, ErrStepUpRequired) {
				t.Fatal(">15m accepted without step-up", err)
			}
			// Password-only evidence on an AAL2-capable account never satisfies it.
			if err := e.s.RequireSensitive(mk(AssurancePasswordOnly, 2, 0), op); !errors.Is(err, ErrStepUpRequired) {
				t.Fatal("password-only session satisfied a sensitive op on an MFA-capable account", err)
			}
			// Preauth/unknown assurance labels never qualify.
			for _, bad := range []Assurance{AssurancePreauth, "", "AAL3", "aal2 "} {
				if err := e.s.RequireSensitive(mk(bad, 2, 0), op); err == nil {
					t.Fatalf("assurance %q accepted", bad)
				}
			}
			if aal2Only {
				if err := e.s.RequireSensitive(mk(AssurancePasswordOnly, 1, 0), op); !errors.Is(err, ErrAssuranceUnavailable) {
					t.Fatal("AAL2-only operation allowed for an account that cannot reach AAL2", err)
				}
			} else {
				if err := e.s.RequireSensitive(mk(AssurancePasswordOnly, 1, 0), op); err != nil {
					t.Fatal("max-available policy must let a genuinely AAL1-only account re-verify its password", err)
				}
				if err := e.s.RequireSensitive(mk(AssurancePasswordOnly, 1, window+time.Second), op); !errors.Is(err, ErrStepUpRequired) {
					t.Fatal("stale AAL1 accepted", err)
				}
			}
			// A session claiming to be authenticated in the future is clock uncertainty.
			if err := e.s.RequireSensitive(mk(AssuranceAAL2, 2, -time.Minute), op); err == nil {
				t.Fatal("future authentication time accepted")
			}
		})
	}
	if err := e.s.RequireSensitive(mk(AssuranceAAL2, 2, 0), SensitiveOperation("undeclared-write")); err != ErrDenied {
		t.Fatal("undeclared operation must default to deny")
	}
	// Every operation class from TD §4.3 is declared.
	for _, want := range []SensitiveOperation{OpPasswordChange, OpAuthenticatorChange, OpNotificationAddress, OpAgentAccessChange, OpBackupExport, OpBackupRestore, OpSecurityPolicy} {
		if _, ok := sensitivePolicies[want]; !ok {
			t.Fatalf("TD §4.3 operation %q is not declared", want)
		}
	}
}

func TestStepUpTOTPRotatesAndResetsBothClocks(t *testing.T) { // REAUTH-STRENGTH, S01, S06
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	old := e.aal2TOTP(id, en)
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	sess, err := e.s.Authenticate(t.Context(), old.Secret(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.s.RequireSensitive(sess.SessionInfo, OpAuthenticatorChange); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("stale session did not require step-up", err)
	}
	// A failed step-up resets nothing.
	if _, err = e.s.StepUpTOTP(t.Context(), old.Secret(), []byte(sessionTestPassword), id, "000000", sessionTestIP); err != ErrDenied {
		t.Fatal("wrong OTP step-up accepted")
	}
	if _, err = e.s.StepUpTOTP(t.Context(), old.Secret(), []byte("wrong password entirely, long enough"), id, e.nextCode(en), sessionTestIP); err != ErrDenied {
		t.Fatal("wrong password step-up accepted")
	}
	if row := e.row(old.Info.ID); row.State != "active" || row.Created != old.Info.CreatedAt.Unix() {
		t.Fatal("failed step-up mutated the session")
	}
	still, err := e.s.Authenticate(t.Context(), old.Secret(), false)
	if err != nil || e.s.RequireSensitive(still.SessionInfo, OpAuthenticatorChange) == nil {
		t.Fatal("failed step-up refreshed authentication time", err)
	}
	// A successful step-up issues a successor and revokes the predecessor.
	next, err := e.stepUpTOTP(old.Secret(), id, en)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(next.Secret(), old.Secret()) || next.Info.ID == old.Info.ID || next.CSRFToken() == old.CSRFToken() {
		t.Fatal("step-up did not rotate secret/ID/CSRF token")
	}
	if _, err = e.s.Authenticate(t.Context(), old.Secret(), true); err != ErrDenied || e.row(old.Info.ID).State != "revoked" {
		t.Fatal("predecessor still valid after step-up")
	}
	fresh, err := e.s.Authenticate(t.Context(), next.Secret(), true)
	if err != nil || e.s.RequireSensitive(fresh.SessionInfo, OpAuthenticatorChange) != nil || e.s.RequireSensitive(fresh.SessionInfo, OpBackupRestore) != nil {
		t.Fatal("stepped-up session not fresh", err)
	}
	// Both timers reset (S06): the successor lives a full new window from now.
	if row := e.row(next.Info.ID); row.Expires-row.Created != int64(DefaultSessionAbsolute/time.Second) || row.Created != e.clock.Now().Unix() || row.Methods != 3 || row.Assurance != 2 {
		t.Fatalf("successor timing/evidence wrong: %+v", row)
	}
	// Steady freshness decays again after the window.
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	later, err := e.s.Authenticate(t.Context(), next.Secret(), true)
	if err != nil || !errors.Is(e.s.RequireSensitive(later.SessionInfo, OpBackupRestore), ErrStepUpRequired) {
		t.Fatal("activity alone refreshed authentication evidence", err)
	}
}

func TestStepUpCannotDowngradeOrCrossAccounts(t *testing.T) { // REAUTH-STRENGTH, RATE-RESET-AAL, SCOPE-TRANSACTION
	e := newSessionEnv(t)
	id, en, key, _ := e.bothFactors()
	e.retireSeed()
	e.clock.Advance(time.Minute)
	phishResistant := e.aal2Key(key)
	// A phishing-resistant session cannot be "refreshed" with weaker TOTP evidence.
	if _, err := e.stepUpTOTP(phishResistant.Secret(), id, en); err != ErrDenied {
		t.Fatal("TOTP step-up downgraded a phishing-resistant session")
	}
	// Password-only never refreshes an MFA-capable account's evidence.
	if _, err := e.s.StepUpPassword(t.Context(), phishResistant.Secret(), []byte(sessionTestPassword), sessionTestIP); err != ErrDenied {
		t.Fatal("password-only step-up accepted for an AAL2-capable account")
	}
	totpSession := e.aal2TOTP(id, en)
	if _, err := e.s.StepUpPassword(t.Context(), totpSession.Secret(), []byte(sessionTestPassword), sessionTestIP); err != ErrDenied {
		t.Fatal("password-only step-up refreshed an AAL2 session")
	}
	// A password-only session MAY step up to AAL2: assurance can only go up.
	weak := e.passwordOnly()
	up, err := e.stepUpTOTP(weak.Secret(), id, en)
	if err != nil || up.Info.Assurance != AssuranceAAL2 || e.row(up.Info.ID).Methods != 3 {
		t.Fatal("password-only session could not be raised to AAL2 by real MFA", err)
	}
	// Unknown / preauth / foreign secrets cannot step up.
	r, _ := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	for name, secret := range map[string][]byte{"preauth": r.Session.Secret(), "unknown": bytes.Repeat([]byte{3}, 32), "short": []byte("x"), "nil": nil} {
		if _, err := e.stepUpTOTP(secret, id, en); err != ErrDenied {
			t.Fatalf("%s secret stepped up", name)
		}
	}
	// A different account's password cannot refresh this session.
	e.exec(`INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES('v','other-user','active','optional',1,1)`)
	hash, err := HashPassword([]byte("another unique synthetic public phrase"))
	if err != nil {
		t.Fatal(err)
	}
	e.exec(`INSERT INTO authenticators(id,user_id,kind,state,bound_at,credential_generation,password_codepoints,password_format,verifier_hash) VALUES('pwd2','v','password','active',1,1,38,'mdt-pwd-u17-nfc-cn-v1',?)`, hash)
	if _, err = e.s.StepUpPassword(t.Context(), e.passwordOnly().Secret(), []byte("another unique synthetic public phrase"), sessionTestIP); err != ErrDenied {
		t.Fatal("another account's password refreshed this session")
	}
}

func TestStepUpPasswordForAAL1OnlyAccount(t *testing.T) { // SB-4: lower assurance still re-verifies
	e := newSessionEnv(t)
	issued := e.passwordOnly()
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	sess, _ := e.s.Authenticate(t.Context(), issued.Secret(), true)
	if err := e.s.RequireSensitive(sess.SessionInfo, OpPasswordChange); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal(err)
	}
	if _, err := e.s.StepUpPassword(t.Context(), issued.Secret(), []byte("incorrect password, but long enough"), sessionTestIP); err != ErrDenied {
		t.Fatal("wrong password step-up accepted")
	}
	up, err := e.s.StepUpPassword(t.Context(), issued.Secret(), []byte(sessionTestPassword), sessionTestIP)
	if err != nil || up.Info.Assurance != AssurancePasswordOnly || e.row(up.Info.ID).Assurance != 1 {
		t.Fatal(err, up.Info)
	}
	fresh, _ := e.s.Authenticate(t.Context(), up.Secret(), true)
	if e.s.RequireSensitive(fresh.SessionInfo, OpPasswordChange) != nil {
		t.Fatal("AAL1 account could not complete its own step-up")
	}
	// ...but it can never satisfy an AAL2-only operation.
	if err = e.s.RequireSensitive(fresh.SessionInfo, OpBackupRestore); !errors.Is(err, ErrAssuranceUnavailable) {
		t.Fatal("password-only satisfied an AAL2 gate", err)
	}
}

func TestStepUpWebAuthnAndWebAuthnOnlyPolicy(t *testing.T) { // A04 / W03: UV required, TOTP cannot step up
	e := newSessionEnv(t)
	id, en, key, _ := e.bothFactors()
	e.exec(`UPDATE users SET mfa_requirement='webauthn'`)
	e.retireSeed()
	e.clock.Advance(time.Minute)
	old := e.aal2Key(key)
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	if _, err := e.stepUpTOTP(old.Secret(), id, en); err != ErrDenied {
		t.Fatal("TOTP step-up satisfied a WebAuthn-only policy")
	}
	c, err := e.s.BeginStepUpWebAuthn(t.Context(), old.Secret())
	if err != nil {
		t.Fatal(err)
	}
	// UV=false is not a valid step-up proof; the failed attempt resets nothing.
	if _, err = e.s.StepUpWebAuthn(t.Context(), old.Secret(), c.ID, key.assert(t, c.Options.Response.Challenge.String(), sessionTestOrigin, 1, e.nextCounter()), sessionTestIP); err != ErrDenied {
		t.Fatal("UV=false step-up accepted")
	}
	c, err = e.s.BeginStepUpWebAuthn(t.Context(), old.Secret())
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.s.StepUpWebAuthn(t.Context(), old.Secret(), c.ID, key.assert(t, c.Options.Response.Challenge.String(), sessionTestOrigin, 5, e.nextCounter()), sessionTestIP)
	if err != nil || next.Info.Assurance != AssuranceAAL2 || !next.Info.PhishingResistant || e.row(next.Info.ID).Methods != 8 {
		t.Fatal("UV step-up failed", err)
	}
	if _, err = e.s.Authenticate(t.Context(), old.Secret(), true); err != ErrDenied {
		t.Fatal("predecessor survived")
	}
	// The assertion is single use and bound to its session: replay on the
	// successor must not mint another session.
	if _, err = e.s.StepUpWebAuthn(t.Context(), next.Secret(), c.ID, key.assert(t, c.Options.Response.Challenge.String(), sessionTestOrigin, 5, e.nextCounter()), sessionTestIP); err != ErrDenied {
		t.Fatal("replayed assertion accepted")
	}
	// A password-only session cannot begin a WebAuthn step-up for another purpose.
	if _, err = e.s.BeginStepUpWebAuthn(t.Context(), bytes.Repeat([]byte{5}, 32)); err != ErrDenied {
		t.Fatal("unknown session began a ceremony")
	}
}

func TestConcurrentStepUpYieldsOneSuccessor(t *testing.T) { // SB concurrency / OTP-REPLAY
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	old := e.aal2TOTP(id, en)
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	code := e.nextCode(en)
	var wg sync.WaitGroup
	var wins atomic.Int32
	issued := make(chan IssuedSession, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, err := e.s.StepUpTOTP(t.Context(), old.Secret(), []byte(sessionTestPassword), id, code, sessionTestIP); err == nil {
				wins.Add(1)
				issued <- s
			}
		}()
	}
	wg.Wait()
	close(issued)
	if wins.Load() != 1 {
		t.Fatalf("%d successors from one OTP", wins.Load())
	}
	live := e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal' AND state='active' AND id!='session' AND last_activity_at>0`)
	if live != 1 {
		t.Fatalf("%d live sessions after concurrent step-up (want only the successor)", live)
	}
}

// Real lifecycle mutations that are session-gated today. Each must reject a
// preauth, a password-only (weaker) session, a stale AAL2 session, a revoked one
// and unknown secrets, and each must succeed after a genuine step-up.
func TestSessionGatedLifecycleMutationsNegativeAndStepUpPositive(t *testing.T) { // E03, E08, E12, N63B4-BINDING-ADDITIONAL, REAUTH-STRENGTH
	type target struct {
		totpID string
		keyID  string
		en     Enrollment
		key    virtualKey
		notice string
	}
	mutations := []struct {
		name string
		call func(e *sessionEnv, secret []byte, x target) error
	}{
		{"BeginTOTP+ConfirmTOTP", func(e *sessionEnv, secret []byte, x target) error {
			n, err := e.l.BeginTOTP(e.t.Context(), secret, "SHA256")
			if err != nil {
				return err
			}
			return e.l.ConfirmTOTP(e.t.Context(), secret, n.ID, enrollmentCode(e.t, n, e.clock.Now()), sessionTestIP)
		}},
		{"RevokeTOTP", func(e *sessionEnv, secret []byte, x target) error {
			return e.l.RevokeTOTP(e.t.Context(), secret, x.totpID)
		}},
		{"IssueRecoveryCodes", func(e *sessionEnv, secret []byte, x target) error {
			_, err := e.l.IssueRecoveryCodes(e.t.Context(), secret)
			return err
		}},
		{"WebAuthn BeginRegistration+FinishRegistration", func(e *sessionEnv, secret []byte, x target) error {
			c, err := e.w.BeginRegistration(e.t.Context(), secret, false)
			if err != nil {
				return err
			}
			return e.w.FinishRegistration(e.t.Context(), secret, c.ID, newVirtualKey(e.t).create(e.t, c.Options.Response.Challenge.String(), sessionTestOrigin, 5))
		}},
		{"WebAuthn Revoke", func(e *sessionEnv, secret []byte, x target) error { return e.w.Revoke(e.t.Context(), secret, x.keyID) }},
		{"RetryNotice", func(e *sessionEnv, secret []byte, x target) error {
			return e.l.RetryNotice(e.t.Context(), secret, x.notice)
		}},
	}
	build := func(t *testing.T) (*sessionEnv, target) {
		e := newSessionEnv(t)
		var x target
		x.totpID, x.en, x.key, x.keyID = e.bothFactors()
		e.retireSeed()
		e.exec(`UPDATE security_notice_outbox SET delivery_state='failed',attempts=8,total_attempts=8,failure_code='temporary' WHERE id=(SELECT id FROM security_notice_outbox ORDER BY id LIMIT 1)`)
		if err := e.db.QueryRow(`SELECT id FROM security_notice_outbox ORDER BY id LIMIT 1`).Scan(&x.notice); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Minute)
		return e, x
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			e, x := build(t)
			// weaker session on an AAL2-capable account
			weak := e.passwordOnly()
			if err := m.call(e, weak.Secret(), x); err != ErrDenied {
				t.Fatal("password-only session performed a sensitive mutation", err)
			}
			// preauth capability
			r, _ := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
			if err := m.call(e, r.Session.Secret(), x); err != ErrDenied {
				t.Fatal("preauth capability performed a sensitive mutation", err)
			}
			// unknown / malformed secrets
			for _, s := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{4}, 32)} {
				if err := m.call(e, s, x); err != ErrDenied {
					t.Fatal("unknown secret performed a sensitive mutation", err)
				}
			}
			// stale AAL2 session
			stale := e.aal2TOTP(x.totpID, x.en)
			e.clock.Advance(DefaultStepUpWindow + time.Second)
			if err := m.call(e, stale.Secret(), x); err != ErrDenied {
				t.Fatal(">15 minute old AAL2 session performed a sensitive mutation", err)
			}
			// logged-out AAL2 session
			out := e.aal2TOTP(x.totpID, x.en)
			if err := e.s.Logout(t.Context(), out.Secret()); err != nil {
				t.Fatal(err)
			}
			if err := m.call(e, out.Secret(), x); err != ErrDenied {
				t.Fatal("logged-out session performed a sensitive mutation", err)
			}
			// step-up positive: the same session, refreshed by real proofs, succeeds.
			up, err := e.stepUpTOTP(stale.Secret(), x.totpID, x.en)
			if err != nil {
				t.Fatal("step-up failed", err)
			}
			if err = m.call(e, up.Secret(), x); err != nil {
				t.Fatal("stepped-up session denied", err)
			}
		})
	}
}

func TestSessionGatedMutationBoundaryExactlyFifteenMinutes(t *testing.T) { // S07 boundary
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	issued := e.aal2TOTP(id, en)
	e.clock.Advance(DefaultStepUpWindow)
	if _, err := e.l.BeginTOTP(t.Context(), issued.Secret(), "SHA256"); err != nil {
		t.Fatal("exactly 15 minutes must still be fresh", err)
	}
	e.clock.Advance(time.Second)
	if _, err := e.l.BeginTOTP(t.Context(), issued.Secret(), "SHA256"); err != ErrDenied {
		t.Fatal("15 minutes + 1s must require step-up")
	}
}

func TestTOTPReplayIsRejectedAcrossLoginAndStepUp(t *testing.T) { // O03 / N63B4-OTP-REPLAY cross-route
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	code := e.nextCode(en)
	issued, err := e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, code, sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	// The identical output cannot be spent again by the step-up route, in the same period.
	if _, err = e.s.StepUpTOTP(t.Context(), issued.Secret(), []byte(sessionTestPassword), id, code, sessionTestIP); err != ErrDenied {
		t.Fatal("OTP accepted twice across login and step-up")
	}
	if _, err = e.s.StepUpTOTP(t.Context(), issued.Secret(), []byte(sessionTestPassword), id, e.nextCode(en), sessionTestIP); err != nil {
		t.Fatal("a fresh OTP must still work", err)
	}
}

func TestLoginAndStepUpShareDurablePasswordThrottle(t *testing.T) { // P08 / N63B4-PWD-ROUTE-PARITY
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	issued := e.aal2TOTP(id, en)
	ips := []string{"192.0.2.21", "192.0.2.22", "192.0.2.23", "192.0.2.24", "192.0.2.25"}
	wrong := []byte("this is definitely not the password")
	// Three failures through the login route, two through step-up: one shared counter.
	for _, ip := range ips[:3] {
		if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", wrong, ip); err != ErrDenied {
			t.Fatal("wrong password logged in")
		}
	}
	for _, ip := range ips[3:] {
		if _, err := e.s.StepUpTOTP(t.Context(), issued.Secret(), wrong, id, "000000", ip); err != ErrDenied {
			t.Fatal("wrong password stepped up")
		}
	}
	var failures int64
	if err := e.db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id='pwd'`).Scan(&failures); err != nil || failures != 5 {
		t.Fatalf("login and step-up do not share the durable counter: %d %v", failures, err)
	}
	// The fifth failure starts the durable wait: even the CORRECT password is
	// refused by BOTH routes from fresh addresses until it elapses.
	if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.31"); err != ErrDenied {
		t.Fatal("login bypassed the shared password wait")
	}
	if _, err := e.s.StepUpTOTP(t.Context(), issued.Secret(), []byte(sessionTestPassword), id, enrollmentCode(t, en, e.clock.Now()), "192.0.2.32"); err != ErrDenied {
		t.Fatal("step-up bypassed the shared password wait")
	}
}
