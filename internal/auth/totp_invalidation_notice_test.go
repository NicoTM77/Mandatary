package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestTOTPThresholdInvalidationNoticeConcurrentRestart(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE authenticators SET failed_attempts=99 WHERE id=?`, e.ID); err != nil {
		t.Fatal(err)
	}
	at := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return at }
	var path string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	key, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := store.Open(t.Context(), store.Options{DataDir: filepath.Dir(path), MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	other, err := NewLifecycle(peer, l.notices)
	if err != nil {
		t.Fatal(err)
	}
	other.now = l.now
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			s := l
			if i%2 == 1 {
				s = other
			}
			_, err := s.VerifyTOTP(t.Context(), "u", e.ID, "abcdef", "192.0.2.3")
			results <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-results; err != ErrDenied {
			t.Fatal("invalid proof accepted", err)
		}
	}
	var count, failed int
	var state string
	if err := db.QueryRow(`SELECT state,failed_attempts FROM authenticators WHERE id=?`, e.ID).Scan(&state, &failed); err != nil {
		t.Fatal(err)
	}
	if state != "disabled" || failed != 100 {
		t.Fatal("threshold not atomic", state, failed)
	}
	if err := db.QueryRow(`SELECT count(*) FROM protective_notice_intents WHERE event_type='authenticator_suspended'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("invalidation lacks exactly one protective intent", count, err)
	}
	l = reopenLifecycle(t, l, db)
	f := receiver(t, "implicit", "", false, false)
	l.notices.Relay, l.notices.RootCAs = f.relay, f.roots
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 4 {
		t.Fatal("binding/invalidation fanout failed", n, err)
	}
	messages := f.received()
	suspended := 0
	for _, m := range messages {
		if strings.Contains(m, "Security event: authenticator_suspended") {
			suspended++
		}
	}
	if suspended != 2 {
		t.Fatal("invalidation not sent to all independent addresses", suspended)
	}
	if _, err := l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, at), "192.0.2.4"); err != ErrDenied {
		t.Fatal("disabled factor revived")
	}
}

func TestTOTPThresholdNoticeFailureCannotUndoDisablement(t *testing.T) {
	for _, fault := range []string{"outbox", "marker"} {
		t.Run(fault, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e := queueBindingNotice(t, l, session)
			if _, err := db.Exec(`UPDATE authenticators SET failed_attempts=99 WHERE id=?`, e.ID); err != nil {
				t.Fatal(err)
			}
			table := "security_notice_outbox"
			if fault == "marker" {
				table = "protective_notice_intents"
			}
			if _, err := db.Exec(`CREATE TRIGGER reject_invalidation BEFORE INSERT ON ` + table + ` BEGIN SELECT RAISE(ABORT,'synthetic notice failure'); END`); err != nil {
				t.Fatal(err)
			}
			if _, err := l.VerifyTOTP(t.Context(), "u", e.ID, "abcdef", "192.0.2.3"); err != ErrDenied {
				t.Fatal("invalid proof accepted")
			}
			// Dispatch expansion exercises ordinary outbox failure AFTER disablement.
			if fault == "outbox" {
				if _, err := l.DispatchNotices(t.Context(), 8); err != ErrDenied {
					t.Fatal("outbox fault not exercised")
				}
			}
			var state string
			if err := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "disabled" {
				t.Fatal("notice failure undid invalidation", state, err)
			}
			if _, err := db.Exec(`DROP TRIGGER reject_invalidation`); err != nil {
				t.Fatal(err)
			}
			l = reopenLifecycle(t, l, db)
			status, err := l.NoticeHealth(t.Context())
			if err != nil || !status.Degraded || status.Protective != 1 {
				t.Fatal("restart lost protective incident", status, err)
			}
		})
	}
}

func TestUnboundTOTPExhaustionIsNotInvalidationNotice(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE authenticators SET failed_attempts=99 WHERE id=?`, e.ID); err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, "abcdef", "192.0.2.3"); err != ErrDenied {
		t.Fatal("invalid proof accepted")
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM protective_notice_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unbound factor produced invalidation notice", count, err)
	}
}
