package auth

import "testing"

func TestWebAuthnCompromiseReportIsProtectiveNotReplacement(t *testing.T) {
	w, db, session, _, id := webFixture(t)
	if _, e := db.Exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id='u'`); e != nil {
		t.Fatal(e)
	}
	if e := w.ReportCompromise(t.Context(), "synthetic-user", []byte("incorrect synthetic public phrase"), id, "192.0.2.10"); e != ErrDenied || w.lifecycle.repo.FailedClosed() {
		t.Fatal("invalid report poisoned acceptance")
	}
	if e := w.ReportCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), id, "192.0.2.11"); e != nil {
		t.Fatal("legitimate lost-key report denied", e)
	}
	if _, e := w.BeginRegistration(t.Context(), session, false); e != ErrDenied {
		t.Fatal("report granted replacement authority")
	}
	var state string
	if e := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, id).Scan(&state); e != nil || state != "revoked" {
		t.Fatal("reported key still live")
	}
	var n int
	if e := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type='authenticator_suspended'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("independent report intent missing")
	}
}
