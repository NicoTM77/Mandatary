package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestWebAuthnNewKeyCannotEnterPendingAllowlist(t *testing.T) {
	w, db, session, _, id := webFixture(t)
	webSession(t, db, id)
	pending, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	reg, e := w.BeginRegistration(t.Context(), session, false)
	if e != nil {
		t.Fatal(e)
	}
	key := newVirtualKey(t)
	if e = w.FinishRegistration(t.Context(), session, reg.ID, key.create(t, reg.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
		t.Fatal(e)
	}
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id=?`, reg.ID)
	proof, e := w.FinishAssertion(t.Context(), session, pending.ID, key.assert(t, pending.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.236")
	var state string
	var failed int
	if err := db.QueryRow(`SELECT state,failed_attempts FROM authenticators WHERE id=?`, reg.ID).Scan(&state, &failed); err != nil {
		t.Fatal(err)
	}
	if e != ErrDenied || proof.UserID != "" || state != "active" || failed != 99 || w.lifecycle.repo.FailedClosed() {
		t.Fatalf("out-of-allowlist proof charged or admitted: err=%v state=%s failures=%d", e, state, failed)
	}
}

func TestWebAuthnPendingBackupSurvivesOtherKeyInvalidation(t *testing.T) {
	for _, change := range []string{"disabled", "expired", "revoked"} {
		for _, before := range []int{0, 99} {
			t.Run(fmt.Sprintf("%s/backup%d", change, before), func(t *testing.T) {
				w, db, session, keyA, idA := webFixture(t)
				webSession(t, db, idA)
				reg, e := w.BeginRegistration(t.Context(), session, false)
				if e != nil {
					t.Fatal(e)
				}
				keyB := newVirtualKey(t)
				if e = w.FinishRegistration(t.Context(), session, reg.ID, keyB.create(t, reg.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
					t.Fatal(e)
				}
				execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id=?`, idA)
				execFixture(t, db, `UPDATE authenticators SET failed_attempts=? WHERE id=?`, before, reg.ID)
				pending, e := w.BeginAssertion(t.Context(), session)
				if e != nil {
					t.Fatal(e)
				}
				attack, e := w.BeginAssertion(t.Context(), session)
				if e != nil {
					t.Fatal(e)
				}
				switch change {
				case "disabled":
					bad := newVirtualKey(t)
					bad.id = keyA.id
					if _, e = w.FinishAssertion(t.Context(), session, attack.ID, bad.assert(t, attack.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.231"); e != ErrDenied {
						t.Fatal("bad signature allowed", e)
					}
				case "expired":
					at := w.lifecycle.now().Add(time.Second)
					execFixture(t, db, `UPDATE authenticators SET expires_at=? WHERE id=?`, at.Unix(), idA)
					w.lifecycle.now = func() time.Time { return at }
				case "revoked":
					execFixture(t, db, `UPDATE authenticators SET state='revoked',revoked_at=? WHERE id=?`, w.lifecycle.now().Unix(), idA)
				}
				// A is still owned but cannot be selected, even in the original allowlist.
				if _, e = w.FinishAssertion(t.Context(), session, attack.ID, keyA.assert(t, attack.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.234"); e != ErrDenied {
					t.Fatal("ineligible primary accepted", e)
				}
				proof, finish := w.FinishAssertion(t.Context(), session, pending.ID, keyB.assert(t, pending.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.232")
				var state string
				var failed int
				if e = db.QueryRow(`SELECT state,failed_attempts FROM authenticators WHERE id=?`, reg.ID).Scan(&state, &failed); e != nil {
					t.Fatal(e)
				}
				t.Logf("pending backup result=%v before=%d after=%d state=%s", finish, before, failed, state)
				if finish != nil || proof.AuthenticatorID != reg.ID || failed != before || state != "active" {
					t.Fatal("valid pending independent backup charged or disabled")
				}
				if _, e = w.FinishAssertion(t.Context(), session, pending.ID, keyB.assert(t, pending.Options.Response.Challenge.String(), "https://example.invalid", 5, 2), "192.0.2.235"); e != ErrDenied {
					t.Fatal("pending backup replay admitted")
				}
				fresh, e := w.BeginAssertion(t.Context(), session)
				if e != nil {
					t.Fatal(e)
				}
				if len(fresh.Options.Response.AllowedCredentials) != 1 {
					t.Fatal("new ceremony offered ineligible primary")
				}
				if _, e = w.FinishAssertion(t.Context(), session, fresh.ID, keyB.assert(t, fresh.Options.Response.Challenge.String(), "https://example.invalid", 5, 2), "192.0.2.233"); e != nil {
					t.Fatal("fresh independent backup denied", e)
				}
			})
		}
	}
}
