package auth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

// Assurance-labelled P1.08 tests. Each name cites the nist-authentication-mapping
// row it exercises. They run against the real repository, lifecycle, WebAuthn and
// password services; only the clock/origin/password are synthetic.

func TestSessionSettingsBoundaries(t *testing.T) { // A05 / N63B4-AAL-TIMEOUTS
	l, _, _ := lifecycleFixture(t)
	l.notices.Origin = sessionTestOrigin
	if _, err := NewSessions(l, nil, DefaultSessionSettings()); err != nil {
		t.Fatal("approved 12h/30m/15m defaults rejected", err)
	}
	if d := DefaultSessionSettings(); d.Absolute != 12*time.Hour || d.Idle != 30*time.Minute || d.StepUp != 15*time.Minute {
		t.Fatal("defaults drifted from TD §4.3")
	}
	if _, err := NewSessions(l, nil, SessionSettings{Absolute: time.Hour, Idle: time.Minute, StepUp: time.Minute}); err != nil {
		t.Fatal("stricter settings must be allowed", err)
	}
	for name, bad := range map[string]SessionSettings{
		"zero":          {},
		"zero absolute": {Idle: time.Minute, StepUp: time.Minute},
		"zero idle":     {Absolute: time.Hour, StepUp: time.Minute},
		"zero step-up":  {Absolute: time.Hour, Idle: time.Minute},
		"negative":      {Absolute: -time.Hour, Idle: time.Minute, StepUp: time.Minute},
		"absolute>12h":  {Absolute: 12*time.Hour + time.Second, Idle: time.Minute, StepUp: time.Minute},
		"idle>30m":      {Absolute: time.Hour, Idle: 30*time.Minute + time.Second, StepUp: time.Minute},
		"step-up>15m":   {Absolute: time.Hour, Idle: time.Minute, StepUp: 15*time.Minute + time.Second},
		"idle>absolute": {Absolute: time.Minute, Idle: 2 * time.Minute, StepUp: time.Minute},
		"sub-second":    {Absolute: time.Hour + time.Millisecond, Idle: time.Minute, StepUp: time.Minute},
		"unbounded":     {Absolute: 1<<63 - 1, Idle: time.Minute, StepUp: time.Minute},
	} {
		if _, err := NewSessions(l, nil, bad); err != ErrDenied {
			t.Fatalf("%s settings accepted", name)
		}
	}
	l.notices.Origin = "http://example.invalid"
	if _, err := NewSessions(l, nil, DefaultSessionSettings()); err != ErrDenied {
		t.Fatal("cleartext origin accepted for Secure-cookie sessions")
	}
	if _, err := NewSessions(nil, nil, DefaultSessionSettings()); err != ErrDenied {
		t.Fatal("missing lifecycle accepted")
	}
}

func TestSessionOriginMustMatchWebAuthnOrigin(t *testing.T) { // W02 / S05 name agreement
	e := newSessionEnv(t)
	e.l.notices.Origin = "https://other.example.invalid"
	if _, err := NewSessions(e.l, e.w, DefaultSessionSettings()); err != ErrDenied {
		t.Fatal("cookie origin not covered by the WebAuthn RP origins was accepted")
	}
}

func TestPasswordOnlyIsLowerAssuranceNeverAAL2(t *testing.T) { // SCOPE-PASSWORD / D-01
	e := newSessionEnv(t)
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	info := r.Session.Info
	if info.Assurance != AssurancePasswordOnly || len(r.Next) != 0 || info.UsableAssurance != 1 || info.RequiredAssurance != 1 || info.PhishingResistant || strings.Join(info.Methods, ",") != "password" {
		t.Fatalf("optional-MFA user without MFA must receive a labelled password-only session: %+v", info)
	}
	if row := e.row(info.ID); row.Purpose != "normal" || row.Assurance != 1 || row.Methods != 1 || row.Phishing != 0 || !row.Authenticated.Valid {
		t.Fatalf("persisted evidence not password-only: %+v", row)
	}
	// Enrolling MFA never upgrades the account's password-only login: the user must
	// actually complete the second factor, and skipping it stays AAL1.
	id, en := e.enrollTOTP()
	_ = id
	_ = en
	e.retireSeed()
	e.clock.Advance(time.Minute)
	r, err = e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil || r.Session.Info.Assurance != AssurancePreauth || strings.Join(r.Next, ",") != "totp,no-mfa" {
		t.Fatalf("enrolled optional account must be offered MFA and an explicit skip: %+v %v", r.Next, err)
	}
	if _, err = e.s.Authenticate(t.Context(), r.Session.Secret(), true); err != ErrDenied {
		t.Fatal("preauth capability accepted as a session")
	}
	skipped, err := e.s.LoginWithoutMFA(t.Context(), r.Session.Secret())
	if err != nil || skipped.Info.Assurance != AssurancePasswordOnly || skipped.Info.UsableAssurance != 2 || skipped.Info.RequiredAssurance != 2 || e.row(skipped.Info.ID).Assurance != 1 {
		t.Fatalf("skipping MFA must stay password-only AAL1 even with MFA enrolled: %+v %v", skipped.Info, err)
	}
	if _, err = e.s.LoginWithoutMFA(t.Context(), r.Session.Secret()); err != ErrDenied {
		t.Fatal("consumed preauth capability reused")
	}
}

func TestSecondFactorRequiredAccountsCannotSkipMFA(t *testing.T) { // SCOPE-ADMIN / N63B4-AAL-FACTORS
	for name, mutate := range map[string]string{
		"required":       `UPDATE users SET mfa_requirement='required'`,
		"webauthn":       `UPDATE users SET mfa_requirement='webauthn'`,
		"optional admin": `INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm','u','super_admin','active',1)`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newSessionEnv(t)
			var id string
			var en Enrollment
			var key virtualKey
			if name == "webauthn" {
				id, en, key, _ = e.bothFactors()
			} else {
				id, en = e.enrollTOTP()
			}
			e.exec(mutate)
			e.retireSeed()
			e.clock.Advance(time.Minute)
			baseline := e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal'`)
			r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
			if err != nil || r.Session.Info.Assurance != AssurancePreauth {
				t.Fatalf("required-MFA account received more than a preauth capability: %v %+v", err, r.Session.Info)
			}
			for _, n := range r.Next {
				if n == "no-mfa" {
					t.Fatal("skip offered to a required-MFA account")
				}
			}
			if _, err = e.s.LoginWithoutMFA(t.Context(), r.Session.Secret()); err != ErrDenied {
				t.Fatal("required-MFA account created a password-only session")
			}
			if e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal'`) != baseline {
				t.Fatal("normal session persisted without second factor")
			}
			if name == "webauthn" {
				// WebAuthn-only policy: a valid TOTP cannot complete it (A04).
				if _, err = e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, e.nextCode(en), sessionTestIP); err != ErrDenied {
					t.Fatal("TOTP satisfied a WebAuthn-only account")
				}
				if strings.Join(r.Next, ",") != "webauthn" {
					t.Fatalf("WebAuthn-only account offered %v", r.Next)
				}
				c, err := e.s.BeginLoginWebAuthn(t.Context(), r.Session.Secret())
				if err != nil {
					t.Fatal(err)
				}
				issued, err := e.s.LoginWebAuthn(t.Context(), r.Session.Secret(), c.ID, key.assert(t, c.Options.Response.Challenge.String(), sessionTestOrigin, 5, e.nextCounter()), sessionTestIP)
				if err != nil || issued.Info.Assurance != AssuranceAAL2 || !issued.Info.PhishingResistant || e.row(issued.Info.ID).Methods != 8 {
					t.Fatalf("UV WebAuthn login denied/mislabelled: %v %+v", err, issued.Info)
				}
				return
			}
			issued, err := e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, e.nextCode(en), sessionTestIP)
			if err != nil || issued.Info.Assurance != AssuranceAAL2 || issued.Info.PhishingResistant || strings.Join(issued.Info.Methods, ",") != "password,totp" {
				t.Fatalf("password+TOTP denied/mislabelled: %v %+v", err, issued.Info)
			}
			if row := e.row(issued.Info.ID); row.Assurance != 2 || row.Methods != 3 || row.Phishing != 0 {
				t.Fatalf("persisted evidence wrong: %+v", row)
			}
		})
	}
}

func TestOnlyDefinedAAL2CombinationsAreAccepted(t *testing.T) { // A01 / N63B4-AAL-FACTORS
	e := newSessionEnv(t)
	id, en, key, _ := e.bothFactors()
	e.retireSeed()
	e.clock.Advance(time.Minute)
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	baseline := e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal'`)
	// WebAuthn without user verification (UP only) is single factor: no session.
	c, err := e.s.BeginLoginWebAuthn(t.Context(), r.Session.Secret())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.LoginWebAuthn(t.Context(), r.Session.Secret(), c.ID, key.assert(t, c.Options.Response.Challenge.String(), sessionTestOrigin, 1, e.nextCounter()), sessionTestIP); err != ErrDenied {
		t.Fatal("UV=false assertion created a session")
	}
	// Wrong TOTP, and a TOTP/ID belonging to nobody, create nothing.
	if _, err = e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, "000000", sessionTestIP); err != ErrDenied {
		t.Fatal("wrong TOTP accepted")
	}
	if _, err = e.s.LoginTOTP(t.Context(), r.Session.Secret(), "missing", e.nextCode(en), sessionTestIP); err != ErrDenied {
		t.Fatal("unknown authenticator accepted")
	}
	// TOTP / WebAuthn proofs alone (no password-bound preauth) cannot start a session.
	for _, bogus := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{7}, 32), e.seed} {
		if _, err = e.s.LoginTOTP(t.Context(), bogus, id, e.nextCode(en), sessionTestIP); err != ErrDenied {
			t.Fatalf("TOTP without a password-bound preauth capability accepted (%d bytes)", len(bogus))
		}
	}
	if n := e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal'`); n != baseline {
		t.Fatalf("%d normal sessions persisted by rejected proofs", n)
	}
	// Every persisted AAL2 row is one of the three defined evidence combinations.
	issued, err := e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, e.nextCode(en), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	_ = issued
	if e.scalar(`SELECT count(*) FROM sessions WHERE achieved_assurance=2 AND methods NOT IN (3,5,8)`) != 0 {
		t.Fatal("undefined AAL2 combination persisted")
	}
}

func TestPreauthCapabilityIsNotASession(t *testing.T) { // SESSION-CREATION / E10 shape
	e := newSessionEnv(t)
	id, en := e.enrollTOTP()
	e.retireSeed()
	e.clock.Advance(time.Minute)
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if row := e.row(r.Session.Info.ID); row.Purpose != "preauth" || row.Assurance != 0 || row.Methods != 0 || row.Authenticated.Valid || row.Expires-row.Created != int64(preauthLifetime/time.Second) {
		t.Fatalf("preauth row is not a bounded zero-assurance capability: %+v", row)
	}
	if _, err = e.s.Authenticate(t.Context(), r.Session.Secret(), true); err != ErrDenied {
		t.Fatal("preauth authenticated as a normal session")
	}
	if got, err := e.s.AuthenticatePreauth(t.Context(), r.Session.Secret()); err != nil || got.Assurance != AssurancePreauth {
		t.Fatal("preauth not recognisable as preauth", err)
	}
	// Completion rotates: the preauth secret is consumed and dies with the ceremony.
	issued, err := e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, e.nextCode(en), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(issued.Secret(), r.Session.Secret()) || issued.Info.ID == r.Session.Info.ID {
		t.Fatal("secret/ID not rotated on authentication (session fixation)")
	}
	if e.row(r.Session.Info.ID).State != "revoked" {
		t.Fatal("preauth capability survived completion")
	}
	if _, err = e.s.AuthenticatePreauth(t.Context(), r.Session.Secret()); err != ErrDenied {
		t.Fatal("consumed preauth still authenticates")
	}
	if _, err = e.s.AuthenticatePreauth(t.Context(), issued.Secret()); err != ErrDenied {
		t.Fatal("normal session accepted as preauth capability")
	}
	// Preauth expiry is absolute and short.
	r2, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(preauthLifetime - time.Second)
	if _, err = e.s.AuthenticatePreauth(t.Context(), r2.Session.Secret()); err != nil {
		t.Fatal("preauth expired early", err)
	}
	e.clock.Advance(time.Second)
	if _, err = e.s.AuthenticatePreauth(t.Context(), r2.Session.Secret()); err != ErrDenied {
		t.Fatal("expired preauth accepted")
	}
	if _, err = e.s.LoginTOTP(t.Context(), r2.Session.Secret(), id, e.nextCode(en), sessionTestIP); err != ErrDenied {
		t.Fatal("expired preauth completed a login")
	}
}

type noEntropyReader struct{}

func (noEntropyReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestSessionSecretGenerationAndStorage(t *testing.T) { // SESSION-CREATION, SESSION-STORAGE, G16 / N63B4-RANDOM-EVIDENCE
	e := newSessionEnv(t)
	a := e.passwordOnly()
	e.clock.Advance(time.Second)
	b := e.passwordOnly()
	if len(a.Secret()) != sessionSecretBytes || bytes.Equal(a.Secret(), b.Secret()) || a.Info.ID == b.Info.ID {
		t.Fatal("sessions must have independent 256-bit secrets and IDs")
	}
	var digest []byte
	if err := e.db.QueryRow(`SELECT secret_hash FROM sessions WHERE id=?`, a.Info.ID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(a.Secret())
	if !bytes.Equal(digest, want[:]) {
		t.Fatal("only the SHA-256 digest of the secret may be stored")
	}
	// Neither the secret nor the CSRF token is a stored value.
	var stored int64
	if err := e.db.QueryRow(`SELECT count(*) FROM sessions WHERE secret_hash=? OR id=?`, a.Secret(), string(a.Secret())).Scan(&stored); err != nil || stored != 0 {
		t.Fatal("plaintext session secret persisted", err)
	}
	if a.CSRFToken() == b.CSRFToken() || a.CSRFToken() == "" {
		t.Fatal("CSRF token must be per-session")
	}
	// RNG failure fails closed: no row, no cookie, no deterministic fallback.
	before := e.scalar(`SELECT count(*) FROM sessions`)
	e.s.random = noEntropyReader{}
	if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP); err != ErrDenied {
		t.Fatal("session issued without entropy")
	}
	if e.scalar(`SELECT count(*) FROM sessions`) != before {
		t.Fatal("session row persisted without entropy")
	}
}

func TestAuthenticateReturnsOnlyServerBoundEvidence(t *testing.T) { // SESSION-CREATION altered-AAL / SCOPE-TRANSACTION
	e := newSessionEnv(t)
	issued := e.passwordOnly()
	got, err := e.s.Authenticate(t.Context(), issued.Secret(), false)
	if err != nil || got.Assurance != AssurancePasswordOnly || got.UserID != "u" || got.ID != issued.Info.ID {
		t.Fatal(err, got.SessionInfo)
	}
	if strings.Contains(got.String(), string(got.Secret())) || strings.Contains(got.GoString(), issued.CSRFToken()) {
		t.Fatal("session formatting leaks secrets")
	}
	// Forged persisted evidence without backing authenticator rows is not trusted.
	for name, forge := range map[string]string{
		"AAL2 methods without factor":    `UPDATE sessions SET achieved_assurance=2,methods=3 WHERE id=?`,
		"WebAuthn UV without a key":      `UPDATE sessions SET achieved_assurance=2,methods=8,phishing_resistant=1 WHERE id=?`,
		"password+key without a key row": `UPDATE sessions SET achieved_assurance=2,methods=5 WHERE id=?`,
	} {
		e.exec(`UPDATE sessions SET achieved_assurance=1,methods=1,phishing_resistant=0 WHERE id=?`, issued.Info.ID)
		e.exec(forge, issued.Info.ID)
		if _, err = e.s.Authenticate(t.Context(), issued.Secret(), false); err != ErrDenied {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSessionClocksIdleAndAbsolute(t *testing.T) { // S06, A05 / N63B4-SESSION-CLOCKS, AAL-TIMEOUTS
	e := newSessionEnv(t)
	issued := e.passwordOnly()
	secret := issued.Secret()
	// Idle boundary 30m: valid at 30m-1s, invalid at 30m.
	e.clock.Advance(30*time.Minute - time.Second)
	if _, err := e.s.Authenticate(t.Context(), secret, false); err != nil {
		t.Fatal("idle expiry early", err)
	}
	e.clock.Advance(time.Second)
	if _, err := e.s.Authenticate(t.Context(), secret, false); err != ErrDenied {
		t.Fatal("idle timeout not enforced")
	}
	// Meaningful activity resets idle only; it cannot evade the 12h overall limit.
	issued = e.passwordOnly()
	secret = issued.Secret()
	start := e.clock.Now()
	for e.clock.Now().Sub(start) < 12*time.Hour-20*time.Minute {
		e.clock.Advance(20 * time.Minute)
		if _, err := e.s.Authenticate(t.Context(), secret, true); err != nil {
			t.Fatalf("steady activity denied at %v: %v", e.clock.Now().Sub(start), err)
		}
	}
	e.clock.Advance(12*time.Hour - e.clock.Now().Sub(start) - time.Second)
	if _, err := e.s.Authenticate(t.Context(), secret, true); err != nil {
		t.Fatal("absolute expiry early", err)
	}
	e.clock.Advance(time.Second)
	if _, err := e.s.Authenticate(t.Context(), secret, true); err != ErrDenied {
		t.Fatal("steady activity evaded the 12h overall timeout")
	}
	// Background polling (activity=false) never extends the idle deadline.
	poll := e.passwordOnly()
	for i := 0; i < 5; i++ {
		e.clock.Advance(7 * time.Minute)
		_, err := e.s.Authenticate(t.Context(), poll.Secret(), false)
		if i < 4 && err != nil {
			t.Fatal("poll denied early", i, err)
		}
		if i == 4 && err != ErrDenied {
			t.Fatal("background polling kept an idle session alive")
		}
	}
	// A rollback of the server clock before creation is uncertainty, not validity.
	rolled := e.passwordOnly()
	e.clock.Advance(-time.Minute)
	if _, err := e.s.Authenticate(t.Context(), rolled.Secret(), false); err != ErrDenied {
		t.Fatal("session accepted while clock precedes its creation")
	}
}

func TestSessionLogoutAndInvalidation(t *testing.T) { // SESSION-LOGOUT, AUTHENTICATOR-INVALIDATION, COMPROMISE-REPORT, RESTORE-AUTH-STATE substrate
	cases := map[string]func(t *testing.T, e *sessionEnv, id string){
		"logout": func(t *testing.T, e *sessionEnv, id string) {
			secret := e.lastSecret
			if err := e.s.Logout(t.Context(), secret); err != nil {
				t.Fatal(err)
			}
		},
		"compromise flag": func(t *testing.T, e *sessionEnv, id string) {
			if err := e.l.passwords.MarkCompromised(t.Context(), "u"); err != nil {
				t.Fatal(err)
			}
		},
		"user disabled": func(t *testing.T, e *sessionEnv, id string) { e.exec(`UPDATE users SET state='disabled'`) },
		"session generation": func(t *testing.T, e *sessionEnv, id string) {
			e.exec(`UPDATE installation_control SET session_generation=session_generation+1`)
		},
		"credential generation": func(t *testing.T, e *sessionEnv, id string) {
			e.exec(`UPDATE installation_control SET credential_generation=credential_generation+1`)
		},
		"restore quarantine": func(t *testing.T, e *sessionEnv, id string) {
			e.exec(`UPDATE installation_control SET restore_quarantined=1`)
		},
		"password binding revoked": func(t *testing.T, e *sessionEnv, id string) {
			e.exec(`UPDATE authenticators SET state='disabled' WHERE id='pwd'`)
		},
		"row revoked": func(t *testing.T, e *sessionEnv, id string) {
			e.exec(`UPDATE sessions SET state='revoked',revoked_at=? WHERE id=?`, sessionBaseTime+1, id)
		},
	}
	for name, invalidate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newSessionEnv(t)
			issued := e.passwordOnly()
			e.lastSecret = issued.Secret()
			copied := issued.Secret() // an attacker's copy of the cookie
			if _, err := e.s.Authenticate(t.Context(), copied, true); err != nil {
				t.Fatal(err)
			}
			invalidate(t, e, issued.Info.ID)
			if _, err := e.s.Authenticate(t.Context(), copied, true); err != ErrDenied {
				t.Fatal("copied cookie still valid after invalidation")
			}
		})
	}
	t.Run("bound factor revoked invalidates AAL2 sessions", func(t *testing.T) {
		e := newSessionEnv(t)
		id, en := e.enrollTOTP()
		e.retireSeed()
		issued := e.aal2TOTP(id, en)
		if _, err := e.s.Authenticate(t.Context(), issued.Secret(), false); err != nil {
			t.Fatal(err)
		}
		e.exec(`UPDATE authenticators SET state='revoked',revoked_at=? WHERE id=?`, e.clock.Now().Unix(), id)
		if _, err := e.s.Authenticate(t.Context(), issued.Secret(), false); err != ErrDenied {
			t.Fatal("session survived revocation of the factor that created it")
		}
	})
	t.Run("logout is idempotent and denies unknown secrets", func(t *testing.T) {
		e := newSessionEnv(t)
		if err := e.s.Logout(t.Context(), bytes.Repeat([]byte{9}, 32)); err != ErrDenied {
			t.Fatal("unknown secret logout accepted")
		}
	})
}

func TestStorageFailureNeverAuthenticates(t *testing.T) { // S03 fail-closed boundary
	e := newSessionEnv(t)
	issued := e.passwordOnly()
	e.l.repo.FailClosed()
	if _, err := e.s.Authenticate(t.Context(), issued.Secret(), true); err == nil || err == ErrDenied {
		t.Fatal("storage uncertainty must be distinguishable from a normal denial and never authenticate:", err)
	}
	if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP); err == nil {
		t.Fatal("login accepted through a poisoned repository")
	}
}
