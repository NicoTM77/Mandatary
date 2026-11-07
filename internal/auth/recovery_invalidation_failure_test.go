package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRecoveryThresholdNoticeFailureCannotUndoDisablement(t *testing.T) {
	for _, fault := range []string{"marker", "outbox"} {
		t.Run(fault, func(t *testing.T) {
			l, db, _, saved := issuedRecoveryFixture(t)
			relay := receiver(t, "implicit", "", false, false)
			l.notices.Relay, l.notices.RootCAs = relay.relay, relay.roots
			if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 4 {
				t.Fatal("initial notice delivery", n, err)
			}
			execFixture(t, db, `UPDATE recovery_batches SET failures=99 WHERE state='active'`)
			table := "protective_notice_intents"
			if fault == "outbox" {
				table = "security_notice_outbox"
			}
			execFixture(t, db, `CREATE TRIGGER reject_recovery_notice BEFORE INSERT ON `+table+` BEGIN SELECT RAISE(ABORT,'synthetic notice failure'); END`)
			if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "incorrect-synthetic-saved-code", "192.0.2.2"); err != ErrDenied {
				t.Fatal("invalid code accepted", err)
			}
			if fault == "outbox" {
				if _, err := l.DispatchNotices(t.Context(), 8); err != ErrDenied {
					t.Fatal("outbox failure not exercised", err)
				}
			} else if !l.repo.FailedClosed() {
				t.Fatal("marker failure not fail closed")
			}
			var state string
			var failures int
			if err := db.QueryRow(`SELECT state,failures FROM recovery_batches`).Scan(&state, &failures); err != nil || state != "disabled" || failures != 100 {
				t.Fatal("notice failure undid disablement", state, failures, err)
			}
			execFixture(t, db, `DROP TRIGGER reject_recovery_notice`)
			l = reopenLifecycle(t, l, db)
			health, err := l.NoticeHealth(t.Context())
			if err != nil || !health.Degraded || health.Protective != 1 {
				t.Fatal("restart lost protective incident", health, err)
			}
			if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), saved, "192.0.2.3"); err != ErrDenied {
				t.Fatal("notice failure revived saved codes", err)
			}
			n, err := l.DispatchNotices(t.Context(), 8)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "outbox" {
				if n != 2 || len(relay.received()) != 6 {
					t.Fatal("repair lost all-address delivery", n)
				}
			} else {
				if n != 0 || len(relay.received()) != 4 {
					t.Fatal("unmatched incident silently retargeted", n)
				}
				health, err = l.NoticeHealth(t.Context())
				if err != nil || !health.Degraded || health.Protective != 1 {
					t.Fatal("manual incident hidden after dispatch", health, err)
				}
			}
		})
	}
}

func TestRecoveryThresholdSQLiteSyncFailureIsFailClosed(t *testing.T) {
	for _, boundary := range []string{"disable", "expand"} {
		t.Run(boundary, func(t *testing.T) {
			probe := installAuthSyncProbe(t)
			l, db, _, saved := issuedRecoveryFixture(t)
			relay := receiver(t, "implicit", "", false, false)
			l.notices.Relay, l.notices.RootCAs = relay.relay, relay.roots
			if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 4 {
				t.Fatal("initial notice delivery", n, err)
			}
			// Compulsory MFA prevents the preliminary password observation
			// from writing a success reset: the fault hits recovery's own commit.
			execFixture(t, db, `UPDATE users SET mfa_requirement='required' WHERE id='u'`)
			execFixture(t, db, `UPDATE recovery_batches SET failures=99 WHERE state='active'`)
			if boundary == "expand" {
				if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "incorrect-synthetic-saved-code", "192.0.2.2"); err != ErrDenied {
					t.Fatal("invalid code accepted", err)
				}
			}
			probe.mu.Lock()
			probe.fail = true
			probe.mu.Unlock()
			var err error
			if boundary == "disable" {
				_, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "incorrect-synthetic-saved-code", "192.0.2.2")
			} else {
				_, err = l.DispatchNotices(t.Context(), 8)
			}
			probe.mu.Lock()
			failed := probe.failed
			probe.fail = false
			probe.mu.Unlock()
			if err != ErrDenied || failed == 0 || !l.repo.FailedClosed() {
				t.Fatal("actual SQLite xSync failure not fail closed", boundary, failed, err)
			}
			t.Logf("boundary=%s actual_failed_wal_syncs=%d poisoned=%t", boundary, failed, l.repo.FailedClosed())
			if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), saved, "192.0.2.3"); err != ErrDenied {
				t.Fatal("uncertain handle accepted saved code", err)
			}
			if boundary == "expand" {
				l = reopenLifecycle(t, l, db)
				var state string
				if err := db.QueryRow(`SELECT state FROM recovery_batches`).Scan(&state); err != nil || state != "disabled" {
					t.Fatal("expansion sync failure revived batch", state, err)
				}
				if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 2 {
					t.Fatal("restart failed to repair expansion", n, err)
				}
			}
		})
	}
}

func TestRecoveryOnlyEvaluatedCeilingCrossingNotifies(t *testing.T) {
	l, db, _, _ := issuedRecoveryFixture(t)
	execFixture(t, db, `UPDATE recovery_batches SET failures=98 WHERE state='active'`)
	if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "incorrect-synthetic-saved-code", "192.0.2.2"); err != ErrDenied {
		t.Fatal("invalid code accepted", err)
	}
	var deadline int64
	if err := db.QueryRow(`SELECT next_attempt_at FROM recovery_batches`).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, attempt := range []struct {
		ctx            context.Context
		password, code string
	}{
		{t.Context(), "a unique synthetic public phrase", "incorrect-synthetic-saved-code"}, // durable backoff
		{t.Context(), "a unique synthetic public phrase", strings.Repeat("x", 129)},
		{t.Context(), "wrong synthetic phrase", "incorrect-synthetic-saved-code"},
		{cancelled, "a unique synthetic public phrase", "incorrect-synthetic-saved-code"},
	} {
		if _, err := l.Recover(attempt.ctx, "synthetic-user", []byte(attempt.password), attempt.code, "192.0.2.3"); err != ErrDenied {
			t.Fatal("rejected proof accepted", err)
		}
	}
	var failures, intents int
	var after int64
	if err := db.QueryRow(`SELECT failures,next_attempt_at FROM recovery_batches`).Scan(&failures, &after); err != nil || failures != 99 || after != deadline {
		t.Fatal("pre-evaluation rejection charged/slid batch", failures, after, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM protective_notice_intents`).Scan(&intents); err != nil || intents != 0 {
		t.Fatal("notice before actual invalidation", intents, err)
	}
	at := time.Unix(deadline, 0)
	l.now = func() time.Time { return at }
	if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "incorrect-synthetic-saved-code", "192.0.2.4"); err != ErrDenied {
		t.Fatal("invalid code accepted", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM protective_notice_intents`).Scan(&intents); err != nil || intents != 1 {
		t.Fatal("actual invalidation notice missing", intents, err)
	}
}
