package auth

import (
	"bufio"
	"database/sql"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNoticesMissingTLSNeverSubmitOrAuthenticate(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var forbidden atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer func() { _ = conn.Close() }()
				_, _ = conn.Write([]byte("220 synthetic relay\r\n"))
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(line, "EHLO") {
						_, _ = conn.Write([]byte("250 no TLS here\r\n"))
					} else {
						forbidden.Add(1)
						_, _ = conn.Write([]byte("500 forbidden\r\n"))
					}
				}
			}()
		}
	}()
	l.notices.Relay = listener.Addr().String()
	l.notices.Mode = "starttls"
	l.notices.Username = "synthetic-user"
	l.notices.CredentialID = "synthetic-smtp"
	if err = l.repo.PutSMTPSecret(t.Context(), "synthetic-smtp", []byte("synthetic credential canary, never a real password")); err != nil {
		t.Fatal(err)
	}
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	n, err := l.DispatchNotices(t.Context(), 8)
	if err != nil || n != 0 {
		t.Fatal("missing TLS did not fail closed")
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='pending' AND failure_code='tls' AND attempts=1`).Scan(&count); err != nil || count != 2 {
		t.Fatal("TLS failure not durably classified")
	}
	if forbidden.Load() != 0 {
		t.Fatal("auth or submission attempted without TLS")
	}
	_ = listener.Close()
	<-done
}

func TestNoticeRetryExhaustionIsDurableAndVisible(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.notices.Relay = listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	now := l.now()
	l.now = func() time.Time { return now }
	for attempt := int64(1); attempt <= 8; attempt++ {
		if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 0 {
			t.Fatal("relay outage was accepted", err)
		}
		var failures, attempts int64
		var state string
		var next sql.NullInt64
		if err = db.QueryRow(`SELECT attempts,delivery_state,next_attempt_at FROM security_notice_outbox ORDER BY id LIMIT 1`).Scan(&attempts, &state, &next); err != nil || attempts != attempt {
			t.Fatal("wrong persistent retry count")
		}
		if attempt == 8 {
			if state != "failed" {
				t.Fatal("exhaustion silently dropped")
			}
			break
		}
		wait := int64(60) << uint(attempt-1)
		if wait > 3600 {
			wait = 3600
		}
		if state != "pending" || !next.Valid || next.Int64 != now.Unix()+wait {
			t.Fatal("retry schedule mismatch")
		}
		if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 0 {
			t.Fatal("early retry accepted")
		}
		if err = db.QueryRow(`SELECT attempts FROM security_notice_outbox ORDER BY id LIMIT 1`).Scan(&failures); err != nil || failures != attempt {
			t.Fatal("rejected traffic slid retry")
		}
		// A new service handle consumes persisted retry state, not an in-memory queue.
		l2, err := NewLifecycle(l.repo, l.notices)
		if err != nil {
			t.Fatal(err)
		}
		l2.now = func() time.Time { return now }
		l = l2
		now = now.Add(time.Duration(wait) * time.Second)
	}
}

func TestNoticeExplicitRepairRequiresFreshAuthority(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	f := receiver(t, "implicit", "", false, false)
	l.notices.Relay = f.relay
	l.notices.RootCAs = f.roots
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE security_notice_outbox SET delivery_state='failed',attempts=8,total_attempts=8,failure_code='temporary'`); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.QueryRow(`SELECT id FROM security_notice_outbox ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := l.RetryNotice(t.Context(), []byte("invalid or recovery-only authority"), id); err != ErrDenied {
		t.Fatal("weak retry authority accepted")
	}
	if err := l.RetryNotice(t.Context(), session, id); err != nil {
		t.Fatal(err)
	}
	n, err := l.DispatchNotices(t.Context(), 8)
	if err != nil || n != 1 {
		t.Fatal("explicit repair did not resubmit")
	}
	var repair, total int
	if err = db.QueryRow(`SELECT repair_count,total_attempts FROM security_notice_outbox WHERE id=?`, id).Scan(&repair, &total); err != nil || repair != 1 || total != 9 {
		t.Fatal("repair erased attempt history")
	}
	health, err := l.NoticeHealth(t.Context())
	if err != nil || !health.Degraded || health.Failed != 1 {
		t.Fatal("undelivered notice not operator-visible")
	}
}

func TestNoticeCapacityRollsBackOrdinaryActivation(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	for _, q := range []string{
		`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1024) INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) SELECT 'fill-'||x,'u','authenticator_bound',2000000010,2002592010,'fill-'||x FROM n`,
		`INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until,dispatch_state,authority_generation) SELECT id,id,'u','addr1',1,'first@example.invalid',2002592010,'ready',1 FROM security_events`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != ErrDenied {
		t.Fatal("activation exceeded outbox capacity")
	}
	var state string
	if err = db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "pending" {
		t.Fatal("failed notice still activated authority")
	}
}
