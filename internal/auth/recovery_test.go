package auth

import (
	"testing"
)

func TestRecoveryReenrollmentNeverCreatesSession(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	recovery, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	capability, replacement := recovery.ExportOnce()
	if len(replacement) != 1 {
		t.Fatal("used code not replaced")
	}
	if _, err = l.BeginTOTP(t.Context(), capability, "SHA256"); err != ErrDenied {
		t.Fatal("recovery accepted as normal session")
	}
	next, err := l.BeginRecoveredTOTP(t.Context(), capability, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmRecoveredTOTP(t.Context(), capability, next.ID, enrollmentCode(t, next, l.now()), "192.0.2.3"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.BeginRecoveredTOTP(t.Context(), capability, "SHA256"); err != ErrDenied {
		t.Fatal("consumed recovery capability reused")
	}
	var active int
	if err = db.QueryRow(`SELECT count(*) FROM sessions WHERE state='active'`).Scan(&active); err != nil || active != 0 {
		t.Fatal("reenrollment created authority")
	}
	var state string
	if err = db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("old TOTP not revoked")
	}
}

func TestRecoveryCodesAtomicAndRestricted(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.IssueRecoveryCodes(t.Context(), session); err != ErrDenied {
		t.Fatal("password-only issued recovery list")
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	if len(codes) != 10 || len(batch.ExportOnce()) != 0 {
		t.Fatal("codes not ten/show-once")
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("wrong public password"), codes[0], "192.0.2.2"); err != ErrDenied {
		t.Fatal("code alone accepted")
	}
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.3")
			results <- err == nil
		}()
	}
	count := 0
	for i := 0; i < 2; i++ {
		if <-results {
			count++
		}
	}
	if count != 1 {
		t.Fatal("recovery consumption count", count)
	}
	var sessions int
	if err = db.QueryRow(`SELECT count(*) FROM sessions WHERE purpose='normal' AND state='active'`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("recovery left normal authority")
	}
}
