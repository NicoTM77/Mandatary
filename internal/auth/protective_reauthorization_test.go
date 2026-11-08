package auth

import (
	"sync"
	"testing"
	"time"
)

func TestProtectiveRemovalFreshnessExpiryPreservesHealthyRepository(t *testing.T) {
	for _, kind := range []string{"webauthn", "totp"} {
		t.Run(kind, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			var revoke func() error
			var id string
			if kind == "webauthn" {
				w, err := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
				if err != nil {
					t.Fatal(err)
				}
				reg, err := w.BeginRegistration(t.Context(), session, false)
				if err != nil {
					t.Fatal(err)
				}
				if err = w.FinishRegistration(t.Context(), session, reg.ID, newVirtualKey(t).create(t, reg.Options.Response.Challenge.String(), "https://example.invalid", 5)); err != nil {
					t.Fatal(err)
				}
				id = reg.ID
				webSession(t, db, id)
				revoke = func() error { return w.Revoke(t.Context(), session, id) }
			} else {
				reg := queueBindingNotice(t, l, session)
				id = reg.ID
				execFixture(t, db, `UPDATE sessions SET achieved_assurance=2,methods=3`)
				execFixture(t, db, `INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, id)
				revoke = func() error { return l.RevokeTOTP(t.Context(), session, id) }
			}
			at := l.now()
			l.now = func() time.Time { return at.Add(901 * time.Second) }
			if _, e := l.passwords.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.240"); e != nil {
				t.Fatal("positive password control", e)
			}
			calls := 0
			l.now = func() time.Time {
				calls++
				if calls == 1 {
					return at.Add(899 * time.Second)
				}
				return at.Add(901 * time.Second)
			}
			e := revoke()
			var state string
			if err := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, id).Scan(&state); err != nil {
				t.Fatal(err)
			}
			poisoned := l.repo.FailedClosed()
			l.now = func() time.Time { return at.Add(902 * time.Second) }
			_, independent := l.passwords.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.241")
			t.Logf("remove=%v state=%s fail_closed=%v independent_password=%v", e, state, poisoned, independent)
			if e != ErrDenied || state != "active" {
				t.Fatal("expiry did not safely deny removal")
			}
			if poisoned || independent != nil {
				t.Fatal("logical expiry poisoned unrelated authentication")
			}
		})
	}
}

func TestProtectiveConcurrentRemovalPreservesHealthyRepository(t *testing.T) {
	w, db, session, _, id := webFixture(t)
	webSession(t, db, id)
	start := make(chan struct{})
	results := make(chan error, 8)
	var ready sync.WaitGroup
	ready.Add(8)
	for i := 0; i < 8; i++ {
		go func() { ready.Done(); <-start; results <- w.Revoke(t.Context(), session, id) }()
	}
	ready.Wait()
	close(start)
	successes := 0
	for i := 0; i < 8; i++ {
		e := <-results
		if e == nil {
			successes++
		} else if e != ErrDenied {
			t.Fatal(e)
		}
	}
	if successes != 1 || w.lifecycle.repo.FailedClosed() {
		t.Fatalf("concurrent invalidation poisoned healthy repository: successes=%d poison=%v", successes, w.lifecycle.repo.FailedClosed())
	}
	if _, e := w.lifecycle.passwords.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.245"); e != nil {
		t.Fatal("independent password denied after concurrent removal", e)
	}
}

func TestProtectiveReportPasswordExpiryPreservesIndependentKey(t *testing.T) {
	w, db, session, key, id := webFixture(t)
	pending, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	at := w.lifecycle.now()
	execFixture(t, db, `UPDATE authenticators SET expires_at=? WHERE id='pwd'`, at.Unix()+1)
	w.lifecycle.passwords.now = func() time.Time { return at }
	calls := 0
	w.lifecycle.now = func() time.Time {
		calls++
		if calls < 3 {
			return at
		}
		return at.Add(2 * time.Second)
	}
	e = w.ReportCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), id, "192.0.2.242")
	if e != ErrDenied {
		t.Fatal("expired report authority acknowledged", e)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	w.lifecycle.now = func() time.Time { return at.Add(3 * time.Second) }
	proof, independent := w.FinishAssertion(t.Context(), session, pending.ID, key.assert(t, pending.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.243")
	if state != "active" || w.lifecycle.repo.FailedClosed() || independent != nil || proof.AuthenticatorID != id {
		t.Fatalf("normal report-authority expiry poisoned independent key: state=%s calls=%d poison=%v proof=%v", state, calls, w.lifecycle.repo.FailedClosed(), independent)
	}
}
