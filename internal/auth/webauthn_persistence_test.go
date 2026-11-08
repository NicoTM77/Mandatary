package auth

import (
	"testing"
	"time"
)

func TestWebAuthnConcurrentReplayAndRestart(t *testing.T) {
	w, db, session, key, _ := webFixture(t)
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	response := key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
	results := make(chan bool, 12)
	for i := 0; i < 12; i++ {
		go func() {
			_, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.24")
			results <- e == nil
		}()
	}
	accepted := 0
	for i := 0; i < 12; i++ {
		if <-results {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("concurrent challenge acceptances", accepted)
	}
	w.lifecycle = reopenLifecycle(t, w.lifecycle, db)
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.25"); e != ErrDenied {
		t.Fatal("restart revived challenge")
	}
	c, e = w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.26"); e != ErrDenied {
		t.Fatal("restart forgot monotonic counter")
	}
}

func TestWebAuthnFailureCeilingBackoffAndIndependentKey(t *testing.T) {
	w, db, session, key, id := webFixture(t)
	webSession(t, db, id)
	backup, e := w.BeginRegistration(t.Context(), session, true)
	if e != nil {
		t.Fatal(e)
	}
	second := newVirtualKey(t)
	if e = w.FinishRegistration(t.Context(), session, backup.ID, second.create(t, backup.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
		t.Fatal(e)
	}
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=98 WHERE kind='webauthn' AND id<>?`, backup.ID)
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 1, 1), "192.0.2.27"); e != ErrDenied {
		t.Fatal("UV downgrade accepted")
	}
	var before int64
	if e = db.QueryRow(`SELECT next_attempt_at FROM authenticators WHERE id=?`, id).Scan(&before); e != nil {
		t.Fatal(e)
	}
	c, e = w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if _, e = w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.28"); e != ErrDenied {
			t.Fatal("backoff bypassed")
		}
	}
	var after int64
	var failures int
	if e = db.QueryRow(`SELECT next_attempt_at,failed_attempts FROM authenticators WHERE id=?`, id).Scan(&after, &failures); e != nil || after != before || failures != 99 {
		t.Fatal("rejected traffic slid or charged backoff", e)
	}
	at := time.Unix(before, 0)
	w.lifecycle.now = func() time.Time { return at }
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 1, 1), "192.0.2.29"); e != ErrDenied {
		t.Fatal("bad proof accepted")
	}
	var state string
	if e = db.QueryRow(`SELECT state,failed_attempts FROM authenticators WHERE id=?`, id).Scan(&state, &failures); e != nil || state != "disabled" || failures != 100 {
		t.Fatal("ceiling not durable", state, failures, e)
	}
	w.lifecycle = reopenLifecycle(t, w.lifecycle, db)
	c, e = w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, second.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.30"); e != nil {
		t.Fatal("independent key disabled", e)
	}
}

func TestWebAuthnSQLiteSyncFailureNeverAcknowledges(t *testing.T) {
	for _, op := range []string{"begin", "bind", "verify", "wrong-proof", "report", "remove"} {
		t.Run(op, func(t *testing.T) {
			probe := installAuthSyncProbe(t)
			w, db, session, key, id := webFixture(t)
			webSession(t, db, id)
			execFixture(t, db, `UPDATE users SET mfa_requirement='webauthn' WHERE id='u'`)
			var c AssertionOptions
			var registration RegistrationOptions
			var e error
			if op == "bind" {
				registration, e = w.BeginRegistration(t.Context(), session, false)
			}
			if op == "verify" || op == "wrong-proof" {
				c, e = w.BeginAssertion(t.Context(), session)
			}
			if op == "remove" {
				execFixture(t, db, `UPDATE users SET mfa_requirement='optional' WHERE id='u'`)
			}
			if e != nil {
				t.Fatal(e)
			}
			probe.mu.Lock()
			probe.fail = true
			probe.mu.Unlock()
			switch op {
			case "begin":
				_, e = w.BeginAssertion(t.Context(), session)
			case "bind":
				e = w.FinishRegistration(t.Context(), session, registration.ID, newVirtualKey(t).create(t, registration.Options.Response.Challenge.String(), "https://example.invalid", 5))
			case "verify":
				_, e = w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.31")
			case "wrong-proof":
				_, e = w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 1, 1), "192.0.2.31")
			case "report":
				e = w.ReportCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), id, "192.0.2.31")
			case "remove":
				e = w.Revoke(t.Context(), session, id)
			}
			probe.mu.Lock()
			failed := probe.failed
			probe.fail = false
			probe.mu.Unlock()
			if e != ErrDenied || failed == 0 || !w.lifecycle.repo.FailedClosed() {
				t.Fatal("actual WAL xSync failure not fail closed", op, failed, e)
			}
			t.Logf("operation=%s actual_failed_wal_syncs=%d", op, failed)
		})
	}
}
