package auth

import (
	"database/sql"
	"testing"
)

// P1.08 owns session creation. Test-only persisted achieved evidence refers to
// the actual enrolled key, never a production session-issuing bypass.
func webSession(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	if _, e := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=8,phishing_resistant=1 WHERE id='session'`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`DELETE FROM session_authenticators WHERE session_id='session'`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, id); e != nil {
		t.Fatal(e)
	}
}
func TestWebAuthnMultiKeyAndPolicyRemovalSafeguard(t *testing.T) {
	w, db, session, first, id := webFixture(t)
	if e := w.Revoke(t.Context(), session, id); e != ErrDenied {
		t.Fatal("weak session removed key")
	}
	webSession(t, db, id)
	second, e := w.BeginRegistration(t.Context(), session, true)
	if e != nil {
		t.Fatal(e)
	}
	key := newVirtualKey(t)
	if e = w.FinishRegistration(t.Context(), session, second.ID, key.create(t, second.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id='u'`); e != nil {
		t.Fatal(e)
	}
	if e = w.Revoke(t.Context(), session, second.ID); e != nil {
		t.Fatal("backup key removal denied", e)
	}
	// Removal revokes every old session, and cannot remove the last policy factor.
	if _, e = w.BeginAssertion(t.Context(), session); e != ErrDenied {
		t.Fatal("revoked session accepted")
	}
	if _, e = db.Exec(`UPDATE sessions SET state='active',revoked_at=NULL`); e != nil {
		t.Fatal(e)
	}
	if e = w.Revoke(t.Context(), session, id); e != ErrDenied {
		t.Fatal("last required WebAuthn key removed")
	}
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, first.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.4"); e != nil {
		t.Fatal("independent remaining key unavailable", e)
	}
}
