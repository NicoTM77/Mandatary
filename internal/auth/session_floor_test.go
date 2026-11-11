package auth

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"
)

// P1.08 rework: ONE required-assurance floor shared by login issuance, the
// sensitive-write gate, step-up and the lifecycle freshness check. Disabled,
// exhausted, expired, suspended or protectively invalidated bound factors cannot
// lower it, while a genuinely AAL1-only account and a deliberate fresh-AAL2
// removal keep their approved lower-assurance behaviour (NIST E03, E09, E12,
// I08, D-04).

var plantedSecret = bytes.Repeat([]byte{0x5a}, 32)

// plantPasswordOnly inserts a live password-only normal session directly, as a
// forged/legacy row or another issuing path could. It proves the LIFECYCLE gate
// and the session verifier independently refuse it, not only PasswordLogin.
func (e *sessionEnv) plantPasswordOnly() []byte {
	e.t.Helper()
	now := e.clock.Now().Unix()
	digest := sha256.Sum256(plantedSecret)
	e.exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,authenticated_at,created_at,expires_at,last_activity_at,idle_timeout_seconds,credential_generation,session_generation,state) VALUES('planted','u',?,'normal',1,1,?,?,?,?,1800,1,1,'active')`,
		digest[:], now, now, now+3600, now)
	e.exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('planted','pwd','u')`)
	return append([]byte(nil), plantedSecret...)
}

func (e *sessionEnv) retirement(id string) sql.NullString {
	e.t.Helper()
	var r sql.NullString
	if err := e.db.QueryRow(`SELECT retirement_reason FROM authenticators WHERE id=?`, id).Scan(&r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *sessionEnv) factorCount() int64 {
	e.t.Helper()
	return e.scalar(`SELECT count(*) FROM authenticators WHERE kind IN ('totp','webauthn')`)
}

// denyEveryWeakWrite asserts a password-only secret can not change factors or
// issue recovery codes.
func (e *sessionEnv) denyEveryWeakWrite(t *testing.T, secret []byte, label string) {
	t.Helper()
	before := e.factorCount()
	if n, err := e.l.BeginTOTP(t.Context(), secret, "SHA256"); err == nil {
		t.Fatalf("%s: password-only secret began TOTP binding %s", label, n.ID)
	}
	if c, err := e.w.BeginRegistration(t.Context(), secret, false); err == nil {
		t.Fatalf("%s: password-only secret began WebAuthn binding %s", label, c.ID)
	}
	if _, err := e.l.IssueRecoveryCodes(t.Context(), secret); err == nil {
		t.Fatalf("%s: password-only secret issued recovery codes", label)
	}
	if e.factorCount() != before {
		t.Fatalf("%s: factor inventory changed", label)
	}
}

// A password-only session that already exists on a stranded floor-2 account is
// judged like the shared authorizer verifier judges it (C2 parity: both accept it
// as AAL1; new issuance is what is blocked), and it carries no sensitive
// authority: every gate reports assurance-unavailable.
func (e *sessionEnv) requireStrandedSessionHasNoAuthority(t *testing.T, secret []byte) {
	t.Helper()
	info, err := e.s.Authenticate(t.Context(), secret, true)
	if _, theirs := e.verify(secret); (err == nil) != (theirs == nil) {
		t.Fatalf("C2 disagreement: session service err=%v, authorizer verifier err=%v", err, theirs)
	}
	if err != nil {
		t.Fatal("an existing AAL1 session must stay accepted by both layers", err)
	}
	if info.RequiredAssurance != 2 || info.UsableAssurance != 1 || info.Assurance != AssurancePasswordOnly {
		t.Fatalf("stranded session mislabelled: %+v", info.SessionInfo)
	}
	for _, op := range SensitiveOperations() {
		if err := e.s.RequireSensitive(info.SessionInfo, op); err != ErrAssuranceUnavailable {
			t.Fatalf("%s: stranded session must be assurance-unavailable, got %v", op, err)
		}
	}
}

func (e *sessionEnv) normalSessions() int64 {
	return e.scalar(`SELECT count(*) FROM sessions WHERE purpose IN ('normal','preauth')`)
}

// F1 (reviewer probes R1/R1b, permanent): a password-only protective report
// must not make the same password alone enough to log in or to bind a
// replacement factor, recovery codes, or any max-available sensitive write.
func TestSessionFloorReportChainCannotMintReplacementFactor(t *testing.T) { // E12 COMPROMISE-REPORT, I08, E09, D-04
	for _, kind := range []string{"totp", "webauthn"} {
		t.Run(kind, func(t *testing.T) {
			e := newSessionEnv(t)
			var id string
			if kind == "totp" {
				id, _ = e.mfaAccount()
			} else {
				_, id = e.enrollKey()
				e.retireSeed()
				e.clock.Advance(time.Minute)
			}
			// Control: while the factor is live a password-only session is denied.
			weak := e.passwordOnly()
			e.denyEveryWeakWrite(t, weak.Secret(), "before report")
			var err error
			if kind == "totp" {
				err = e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.77")
			} else {
				err = e.w.ReportCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.77")
			}
			if err != nil {
				t.Fatal("protective report denied", err)
			}
			e.clock.Advance(time.Second)
			rows := e.normalSessions()
			if r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.78"); err != ErrDenied {
				t.Fatalf("password-only login after the report issued %s/%v (err %v)", r.Session.Info.Assurance, r.Next, err)
			}
			if e.normalSessions() != rows {
				t.Fatal("denied login persisted a session row")
			}
			planted := e.plantPasswordOnly()
			e.requireStrandedSessionHasNoAuthority(t, planted)
			e.denyEveryWeakWrite(t, planted, "after report")
		})
	}
}

// F2 (reviewer probe R2, permanent): a bound factor that is disabled, exhausted
// or expired still counts toward the account's floor; the login, session
// verifier, sensitive gate and lifecycle write all agree.
func TestSessionFloorUnavailableBoundFactorCannotLowerGate(t *testing.T) { // E03, E09, D-04
	cases := map[string]struct {
		kind, mutate string
	}{
		"totp exhausted":    {"totp", `UPDATE authenticators SET state='disabled',failed_attempts=retry_ceiling WHERE id=?`},
		"totp expired":      {"totp", `UPDATE authenticators SET expires_at=created_at+1 WHERE id=?`},
		"webauthn disabled": {"webauthn", `UPDATE authenticators SET state='disabled',failed_attempts=retry_ceiling WHERE id=?`},
		"webauthn expired":  {"webauthn", `UPDATE authenticators SET expires_at=created_at+1 WHERE id=?`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newSessionEnv(t)
			var id string
			if c.kind == "totp" {
				id, _ = e.mfaAccount()
			} else {
				_, id = e.enrollKey()
				e.retireSeed()
				e.clock.Advance(time.Minute)
			}
			e.exec(c.mutate, id)
			rows := e.normalSessions()
			if r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.80"); err != ErrDenied {
				t.Fatalf("login with only an unavailable bound factor issued %s/%v (err %v)", r.Session.Info.Assurance, r.Next, err)
			}
			if e.normalSessions() != rows {
				t.Fatal("denied login persisted a session row")
			}
			planted := e.plantPasswordOnly()
			e.requireStrandedSessionHasNoAuthority(t, planted)
			e.denyEveryWeakWrite(t, planted, name)
		})
	}
}

// Approved lower-assurance behaviour that must survive the fix: an account that
// never bound a second factor stays AAL1-capable and may bind its first one.
func TestSessionFloorGenuineAAL1OnlyAccountKeepsPasswordOnlyBinding(t *testing.T) { // E03 AAL1-only control
	e := newSessionEnv(t)
	weak := e.passwordOnly()
	if weak.Info.Assurance != AssurancePasswordOnly {
		t.Fatal("AAL1-only login not password-only", weak.Info.Assurance)
	}
	n, err := e.l.BeginTOTP(t.Context(), weak.Secret(), "SHA256")
	if err != nil {
		t.Fatal("AAL1-only account could not begin its first factor", err)
	}
	if err = e.l.ConfirmTOTP(t.Context(), weak.Secret(), n.ID, enrollmentCode(t, n, e.clock.Now()), sessionTestIP); err != nil {
		t.Fatal("AAL1-only account could not bind its first factor", err)
	}
}

// Approved: an optional-MFA account that removes its last factor with FRESH
// maximum-assurance evidence returns to AAL1; that is not a downgrade attack.
func TestSessionFloorDeliberateFreshAAL2RemovalReturnsToAAL1(t *testing.T) { // E09, E12 removal control
	for _, kind := range []string{"totp", "webauthn"} {
		t.Run(kind, func(t *testing.T) {
			e := newSessionEnv(t)
			var aal2 IssuedSession
			var id string
			if kind == "totp" {
				var en Enrollment
				id, en = e.mfaAccount()
				aal2 = e.aal2TOTP(id, en)
				if err := e.l.RevokeTOTP(t.Context(), aal2.Secret(), id); err != nil {
					t.Fatal("fresh AAL2 removal denied", err)
				}
			} else {
				var key virtualKey
				key, id = e.enrollKey()
				e.retireSeed()
				e.clock.Advance(time.Minute)
				aal2 = e.aal2Key(key)
				if err := e.w.Revoke(t.Context(), aal2.Secret(), id); err != nil {
					t.Fatal("fresh AAL2 key removal denied", err)
				}
			}
			e.clock.Advance(time.Second)
			r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.90")
			if err != nil || r.Session.Info.Assurance != AssurancePasswordOnly {
				t.Fatalf("deliberately removed account did not return to AAL1: %v %+v", err, r.Session.Info)
			}
			n, err := e.l.BeginTOTP(t.Context(), r.Session.Secret(), "SHA256")
			if err != nil {
				t.Fatal("AAL1 account could not rebind after deliberate removal", err)
			}
			_ = n
		})
	}
}
