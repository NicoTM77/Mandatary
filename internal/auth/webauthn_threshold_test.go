package auth

import (
	"testing"
)

func TestWebAuthnThresholdNoticeFailureAndRepair(t *testing.T) {
	for _, fault := range []string{"none", "marker", "outbox", "sync-disable", "sync-expand"} {
		t.Run(fault, func(t *testing.T) {
			var probe *authSyncProbe
			if fault == "sync-disable" || fault == "sync-expand" {
				probe = installAuthSyncProbe(t)
			}
			w, db, session, key, id := webFixture(t)
			l := w.lifecycle
			relay := receiver(t, "implicit", "", false, false)
			l.notices.Relay, l.notices.RootCAs = relay.relay, relay.roots
			if n, e := l.DispatchNotices(t.Context(), 8); e != nil || n != 2 {
				t.Fatal("initial fanout", n, e)
			}
			execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id=?`, id)
			c, e := w.BeginAssertion(t.Context(), session)
			if e != nil {
				t.Fatal(e)
			}
			response := key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 1, 1)
			if fault == "marker" {
				execFixture(t, db, `CREATE TRIGGER reject_key_marker BEFORE INSERT ON protective_notice_intents BEGIN SELECT RAISE(ABORT,'synthetic'); END`)
			}
			if fault == "outbox" {
				execFixture(t, db, `CREATE TRIGGER reject_key_outbox BEFORE INSERT ON security_notice_outbox BEGIN SELECT RAISE(ABORT,'synthetic'); END`)
			}
			if fault == "sync-disable" {
				probe.mu.Lock()
				probe.fail = true
				probe.mu.Unlock()
			}
			// Competing completions at one credential's terminal failure budget must
			// charge exactly one evaluated proof and create exactly one invalidation.
			results := make(chan error, 2)
			for range 2 {
				go func() { _, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.42"); results <- e }()
			}
			for range 2 {
				if e := <-results; e != ErrDenied {
					t.Fatal("bad proof accepted", e)
				}
			}
			if fault == "sync-disable" {
				probe.mu.Lock()
				failed := probe.failed
				probe.fail = false
				probe.mu.Unlock()
				if failed == 0 || !l.repo.FailedClosed() {
					t.Fatal("disable sync fault not fail closed")
				}
				return
			}
			var state string
			var failures int
			if e := db.QueryRow(`SELECT state,failed_attempts FROM authenticators WHERE id=?`, id).Scan(&state, &failures); e != nil || state != "disabled" || failures != 100 {
				t.Fatal("notice failure reversed disablement", state, failures, e)
			}
			if fault == "sync-expand" {
				probe.mu.Lock()
				probe.fail = true
				probe.mu.Unlock()
			}
			n, dispatchErr := l.DispatchNotices(t.Context(), 8)
			switch fault {
			case "sync-expand":
				probe.mu.Lock()
				failed := probe.failed
				probe.fail = false
				probe.mu.Unlock()
				if dispatchErr != ErrDenied || failed == 0 || !l.repo.FailedClosed() {
					t.Fatal("expansion sync fault not fail closed")
				}
			case "outbox":
				if dispatchErr != ErrDenied {
					t.Fatal("outbox fault not exercised")
				}
			case "none":
				if dispatchErr != nil || n != 2 {
					t.Fatal("suspension fanout", n, dispatchErr)
				}
			}
			if fault == "marker" {
				execFixture(t, db, `DROP TRIGGER reject_key_marker`)
			}
			if fault == "outbox" {
				execFixture(t, db, `DROP TRIGGER reject_key_outbox`)
			}
			w.lifecycle = reopenLifecycle(t, l, db)
			l = w.lifecycle
			if _, e := w.BeginAssertion(t.Context(), session); e != ErrDenied {
				t.Fatal("disabled key available after restart")
			}
			n, e = l.DispatchNotices(t.Context(), 8)
			if e != nil {
				t.Fatal(e)
			}
			expected := 2
			if fault == "none" || fault == "marker" {
				expected = 0
			}
			if n != expected {
				t.Fatal("incorrect repair fanout", n, expected)
			}
			var events int
			if e := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type='authenticator_suspended'`).Scan(&events); e != nil || events != 1 {
				t.Fatal("missing/duplicate suspension", events, e)
			}
			if fault == "marker" {
				health, e := l.NoticeHealth(t.Context())
				if e != nil || !health.Degraded {
					t.Fatal("unmatched incident hidden")
				}
			}
		})
	}
}
