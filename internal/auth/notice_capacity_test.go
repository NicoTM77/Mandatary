package auth

import (
	"net"
	"testing"
	"time"
)

func TestNoticeSharedLeaseCeilingDoesNotBlockRevocation(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.IssueRecoveryCodes(t.Context(), session); err != nil {
		t.Fatal(err)
	} // four recipient records
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err = listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	l.notices.Relay = listener.Addr().String()
	results := make(chan error, 4)
	// Distinct service handles share durable worker capacity; no network lock.
	for range 4 {
		next, err := NewLifecycle(l.repo, l.notices)
		if err != nil {
			t.Fatal(err)
		}
		next.now = l.now
		go func() { _, err := next.DispatchNotices(t.Context(), 1); results <- err }()
	}
	conns := []net.Conn{}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for range 4 {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal("four workers failed to reach bounded fixture")
		}
		conns = append(conns, conn)
	}
	var leases int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE worker_token IS NOT NULL AND lease_until>2000000010`).Scan(&leases); err != nil || leases != 4 {
		t.Fatal("shared lease accounting wrong")
	}
	if n, err := l.DispatchNotices(t.Context(), 1); err != nil || n != 0 {
		t.Fatal("fifth worker exceeded shared capacity")
	}
	if err = l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.2"); err != nil {
		t.Fatal("network workers blocked protective revocation")
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal("lease outcome failed to persist")
		}
	}
}

func TestNoticeMaximumAgeAndRepairCycleBounds(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	at := l.now().Add(72 * time.Hour)
	l.now = func() time.Time { return at }
	for range 2 {
		if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 0 {
			t.Fatal("expired notice was sent")
		}
	}
	var failed int
	if err := db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='failed' AND attempts=0`).Scan(&failed); err != nil || failed != 2 {
		t.Fatal("age exhaustion not visible")
	}
	if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3,created_at=2000259210,authenticated_at=2000259210,reauthenticated_at=2000259210,last_activity_at=2000259210,expires_at=2000260010`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	var id, snapshot string
	var version int64
	if err := db.QueryRow(`SELECT id,recipient_snapshot,address_version FROM security_notice_outbox ORDER BY id LIMIT 1`).Scan(&id, &snapshot, &version); err != nil {
		t.Fatal(err)
	}
	for cycle := 1; cycle <= 3; cycle++ {
		if err := l.RetryNotice(t.Context(), session, id); err != nil {
			t.Fatal("permitted explicit repair denied")
		}
		if _, err := db.Exec(`UPDATE security_notice_outbox SET delivery_state='failed',attempts=8 WHERE id=?`, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.RetryNotice(t.Context(), session, id); err != ErrDenied {
		t.Fatal("unbounded repair cycles accepted")
	}
	var actual string
	var actualVersion int64
	if err := db.QueryRow(`SELECT recipient_snapshot,address_version FROM security_notice_outbox WHERE id=?`, id).Scan(&actual, &actualVersion); err != nil || actual != snapshot || actualVersion != version {
		t.Fatal("repair retargeted old notice")
	}
}
