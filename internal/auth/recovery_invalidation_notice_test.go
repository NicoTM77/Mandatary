package auth

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func issuedRecoveryFixture(t *testing.T) (*Lifecycle, *sql.DB, Enrollment, string) {
	t.Helper()
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	execFixture(t, db, `UPDATE sessions SET achieved_assurance=2,methods=3`)
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	codes, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	return l, db, e, codes.ExportOnce()[0]
}

func TestRecoveryThresholdInvalidationNoticeConcurrentRestart(t *testing.T) {
	l, db, enrollment, saved := issuedRecoveryFixture(t)
	relay := receiver(t, "implicit", "", false, false)
	l.notices.Relay, l.notices.RootCAs = relay.relay, relay.roots
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 4 {
		t.Fatal("initial binding/issuance delivery", n, err)
	}
	execFixture(t, db, `UPDATE recovery_batches SET failures=99 WHERE state='active'`)
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
	start := make(chan struct{})
	results := make(chan error, 2)
	// Two real repository handles contend at the same durable batch ceiling.
	for _, service := range []*Lifecycle{l, other} {
		go func(s *Lifecycle) {
			<-start
			_, err := s.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "incorrect-synthetic-saved-code", "192.0.2.2")
			results <- err
		}(service)
	}
	close(start)
	for range 2 {
		if err := <-results; err != ErrDenied {
			t.Fatal("invalid recovery accepted", err)
		}
	}
	var state string
	var failures, intents int
	if err := db.QueryRow(`SELECT state,failures FROM recovery_batches`).Scan(&state, &failures); err != nil || state != "disabled" || failures != 100 {
		t.Fatal("threshold not serialized", state, failures, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM protective_notice_intents WHERE event_type='authenticator_suspended'`).Scan(&intents); err != nil || intents != 1 {
		t.Fatal("issued recovery batch invalidation lacks exactly one protective notice", intents, err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	// A later address edit cannot redirect the threshold's immutable snapshot.
	execFixture(t, db, `UPDATE notification_addresses SET state='revoked',revoked_at=2000000010 WHERE id='addr1'`)
	execFixture(t, db, `INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('addr3','u','changed@example.invalid',1,2000000010,2000000010,'active',1)`)
	l = reopenLifecycle(t, l, db)
	health, err := l.NoticeHealth(t.Context())
	if err != nil || !health.Degraded || health.Protective != 1 {
		t.Fatal("restart lost pending protective notice", health, err)
	}
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 2 {
		t.Fatal("invalidation fanout", n, err)
	}
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 0 {
		t.Fatal("invalidation redelivered", n, err)
	}
	recipients := map[string]int{}
	for _, message := range relay.received() {
		if strings.Contains(message, "Security event: authenticator_suspended") {
			for _, address := range []string{"first@example.invalid", "second@example.invalid", "changed@example.invalid"} {
				if strings.Contains(message, "To: "+address+"\r\n") {
					recipients[address]++
				}
			}
		}
	}
	if len(relay.received()) != 6 || recipients["first@example.invalid"] != 1 || recipients["second@example.invalid"] != 1 || recipients["changed@example.invalid"] != 0 {
		t.Fatal("invalidation not delivered to exact original destinations", recipients)
	}
	var events, capabilities int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type='authenticator_suspended'`).Scan(&events); err != nil || events != 1 {
		t.Fatal("missing/duplicate invalidation event", events, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM recovery_capabilities`).Scan(&capabilities); err != nil || capabilities != 0 {
		t.Fatal("failed recovery created authority", capabilities, err)
	}
	at := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return at }
	if _, err := l.VerifyTOTP(t.Context(), "u", enrollment.ID, enrollmentCode(t, enrollment, at), "192.0.2.3"); err != nil {
		t.Fatal("independent factor disabled", err)
	}
	if _, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), saved, "192.0.2.4"); err != ErrDenied {
		t.Fatal("disabled batch revived", err)
	}
}
