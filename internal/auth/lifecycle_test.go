package auth

import (
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func lifecycleFixture(t *testing.T) (*Lifecycle, *sql.DB, []byte) {
	t.Helper()
	_, r, db := serviceFixture(t)
	now := int64(2000000010)
	secret := []byte("synthetic session only, never a live credential")
	digest := sha256.Sum256(secret)
	queries := []string{
		`INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('addr1','u','first@example.invalid',1,1,1,'active',1),('addr2','u','second@example.invalid',1,1,1,'active',1)`,
		`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,authenticated_at,created_at,expires_at,last_activity_at,credential_generation,session_generation,state) VALUES('session','u',?,'normal',1,1,?, ?, ?, ?,1,1,'active')`,
		`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session','pwd','u')`,
	}
	for i, q := range queries {
		var err error
		if i == 1 {
			_, err = db.Exec(q, digest[:], now, now, now+3600, now)
		} else {
			_, err = db.Exec(q)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	l, err := NewLifecycle(r, NoticeSettings{Origin: "https://synthetic.example.invalid", Contact: "security@example.invalid", Sender: "notices@example.invalid", Relay: "localhost:465", Mode: "implicit"})
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return time.Unix(now, 0) }
	return l, db, secret
}

func TestTOTPConcurrentReplayAndPeriodLimit(t *testing.T) {
	l, _, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	at := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return at }
	code := enrollmentCode(t, e, at)
	results := make(chan bool, 12)
	for i := 0; i < 12; i++ {
		go func() { _, err := l.VerifyTOTP(t.Context(), "u", e.ID, code, "192.0.2.3"); results <- err == nil }()
	}
	count := 0
	for i := 0; i < 12; i++ {
		if <-results {
			count++
		}
	}
	if count != 1 {
		t.Fatal("concurrent OTP accepted count", count)
	}
	// Even a different acceptable future-step OTP cannot be used twice in a
	// single verifier period. Failure flooding cannot slide the wait deadline.
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, at.Add(30*time.Second)), "192.0.2.4"); err != ErrDenied {
		t.Fatal("two OTPs accepted in one period")
	}
}

func TestTOTPLifecycleSessionDenials(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE sessions SET purpose='recovery',achieved_assurance=0,methods=16`,
		`UPDATE sessions SET state='revoked',revoked_at=2000000010`,
		`UPDATE sessions SET authenticated_at=1999999000,created_at=1999999000`,
		`UPDATE installation_control SET restore_quarantined=1`,
		`UPDATE users SET compromised=1`,
		`UPDATE authenticators SET state='disabled' WHERE id='pwd'`,
		`DELETE FROM session_authenticators`,
		`UPDATE notification_addresses SET state='revoked',revoked_at=2000000010`,
	} {
		t.Run(mutation, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := l.BeginTOTP(t.Context(), session, "SHA256"); err != ErrDenied {
				t.Fatal("unsafe enrollment accepted")
			}
		})
	}
}

func TestTOTPRevocationRequiresFreshAssurance(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err = l.RevokeTOTP(t.Context(), session, e.ID); err != ErrDenied {
		t.Fatal("weak session revoked factor")
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	if err = l.RevokeTOTP(t.Context(), session, e.ID); err != nil {
		t.Fatal("fresh reauthenticated revocation denied", err)
	}
	at := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return at }
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, at), "192.0.2.2"); err != ErrDenied {
		t.Fatal("revoked OTP accepted")
	}
	var state string
	if err = db.QueryRow(`SELECT state FROM sessions WHERE id='session'`).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("revocation did not invalidate session")
	}
}

func enrollmentCode(t *testing.T, e Enrollment, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(e.secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA256})
	if err != nil {
		t.Fatal("synthetic code generation failed")
	}
	return code
}

func TestTOTPBindingRequiresProof(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	var state string
	var cipher []byte
	if err = db.QueryRow(`SELECT state,encrypted_secret FROM authenticators WHERE id=?`, e.ID).Scan(&state, &cipher); err != nil || state != "pending" {
		t.Fatal("seed activated without proof")
	}
	if len(cipher) == 0 {
		t.Fatal("seed not encrypted")
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, "000000", "192.0.2.1"); err != ErrDenied {
		t.Fatal("wrong enrollment proof accepted")
	}
	code := enrollmentCode(t, e, l.now())
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, code, "192.0.2.1"); err != nil {
		t.Fatal("correct enrollment proof denied", err)
	}
	if err = db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "active" {
		t.Fatal("proven binding not active")
	}
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, code, "192.0.2.2"); err != ErrDenied {
		t.Fatal("enrollment OTP replay accepted")
	}
	var recipients int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id WHERE e.event_type='authenticator_bound' AND o.dispatch_state='ready'`).Scan(&recipients); err != nil || recipients != 2 {
		t.Fatal("binding notice not durably fanned out")
	}
	if _, err = l.BeginTOTP(t.Context(), session, "SHA256"); err != ErrDenied {
		t.Fatal("weak session added another factor")
	}
}
