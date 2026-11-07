package auth

import (
	"database/sql"
	"testing"
)

func webRecoveryFixture(t *testing.T) (*WebAuthnService, *sql.DB, []byte, []byte, string) {
	t.Helper()
	w, db, session, _, old := webFixture(t)
	webSession(t, db, old)
	if _, e := db.Exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id='u'`); e != nil {
		t.Fatal(e)
	}
	batch, e := w.lifecycle.IssueRecoveryCodes(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	result, e := w.lifecycle.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), batch.ExportOnce()[0], "192.0.2.20")
	if e != nil {
		t.Fatal(e)
	}
	capability, _ := result.ExportOnce()
	return w, db, session, capability, old
}

func TestWebAuthnRecoveredBindingRestrictedAndSingleUse(t *testing.T) {
	w, db, session, capability, old := webRecoveryFixture(t)
	if _, e := w.lifecycle.BeginRecoveredTOTP(t.Context(), capability, "SHA256"); e != ErrDenied {
		t.Fatal("TOTP bypassed WebAuthn-only recovery")
	}
	if _, e := w.BeginRegistration(t.Context(), capability, false); e != ErrDenied {
		t.Fatal("recovery became normal binding authority")
	}
	if _, e := w.BeginAssertion(t.Context(), capability); e != ErrDenied {
		t.Fatal("recovery became login authority")
	}
	if _, e := w.BeginRecoveredRegistration(t.Context(), session, false); e != ErrDenied {
		t.Fatal("ordinary session became recovery")
	}
	c, e := w.BeginRecoveredRegistration(t.Context(), capability, true)
	if e != nil {
		t.Fatal(e)
	}
	key := newVirtualKey(t)
	response := key.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5)
	if e := w.FinishRegistration(t.Context(), capability, c.ID, response); e != ErrDenied {
		t.Fatal("mixed ceremony accepted")
	}
	if e := w.FinishRecoveredRegistration(t.Context(), capability, c.ID, response); e != nil {
		t.Fatal(e)
	}
	if e := w.FinishRecoveredRegistration(t.Context(), capability, c.ID, response); e != ErrDenied {
		t.Fatal("recovered proof replay accepted")
	}
	if _, e := w.BeginRecoveredRegistration(t.Context(), capability, false); e != ErrDenied {
		t.Fatal("bound recovery reused")
	}
	var active int
	if e := db.QueryRow(`SELECT count(*) FROM sessions WHERE state='active'`).Scan(&active); e != nil || active != 0 {
		t.Fatal("recovery minted session", e)
	}
	var state string
	if e := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, old).Scan(&state); e != nil || state != "revoked" {
		t.Fatal("old key survived replacement", e)
	}
	if e := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type IN ('authenticator_replaced','recovery_completed')`).Scan(&active); e != nil || active != 2 {
		t.Fatal("recovery notices missing", e)
	}
	// Enrollment alone grants nothing. A fresh P1.08-issued preauth fixture must
	// prove the replacement key; the capability and former normal session cannot.
	if _, e := w.BeginAssertion(t.Context(), session); e != ErrDenied {
		t.Fatal("old session survived recovery")
	}
}
