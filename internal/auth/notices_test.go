package auth

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type smtpFixture struct {
	relay     string
	roots     *x509.CertPool
	mu        sync.Mutex
	messages  []string
	afterData func()
}

func (f *smtpFixture) onData(fn func()) { f.mu.Lock(); defer f.mu.Unlock(); f.afterData = fn }
func (f *smtpFixture) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.messages...)
}

// All data remains inside an actual loopback receiver. No real mail or live
// credentials, certificate-verification bypass, Docker, external relay or logs.
func receiver(t *testing.T, mode, auth string, ambiguous, partial bool) *smtpFixture {
	t.Helper()
	https := httptest.NewTLSServer(nil)
	certificate := https.TLS.Certificates[0]
	https.Close()
	parsed, e := x509.ParseCertificate(certificate.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	var listener net.Listener
	if mode == "implicit" {
		listener, e = tls.Listen("tcp", "127.0.0.1:0", config)
	} else {
		listener, e = net.Listen("tcp", "127.0.0.1:0")
	}
	if e != nil {
		t.Fatal(e)
	}
	f := &smtpFixture{relay: listener.Addr().String(), roots: roots}
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				reader := bufio.NewReader(conn)
				_, _ = conn.Write([]byte("220 synthetic ESMTP\r\n"))
				secure := mode == "implicit"
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if !secure {
							_, _ = conn.Write([]byte("250-fixture\r\n250 STARTTLS\r\n"))
						} else if auth != "" {
							_, _ = conn.Write([]byte("250-fixture\r\n250 AUTH PLAIN\r\n"))
						} else {
							_, _ = conn.Write([]byte("250 fixture\r\n"))
						}
					case strings.HasPrefix(line, "STARTTLS"):
						if secure {
							return
						}
						_, _ = conn.Write([]byte("220 upgrade\r\n"))
						upgraded := tls.Server(conn, config)
						if e = upgraded.Handshake(); e != nil {
							return
						}
						conn = upgraded
						reader = bufio.NewReader(conn)
						secure = true
					case strings.HasPrefix(line, "AUTH"):
						if !secure {
							return
						}
						if auth == "deny" {
							_, _ = conn.Write([]byte("535 authentication denied\r\n"))
						} else {
							_, _ = conn.Write([]byte("235 authenticated\r\n"))
						}
					case strings.HasPrefix(line, "MAIL FROM:"):
						if !secure {
							return
						}
						_, _ = conn.Write([]byte("250 accepted\r\n"))
					case strings.HasPrefix(line, "RCPT TO:"):
						if partial && strings.Contains(line, "first@example.invalid") {
							_, _ = conn.Write([]byte("550 rejected\r\n"))
						} else {
							_, _ = conn.Write([]byte("250 accepted\r\n"))
						}
					case strings.HasPrefix(line, "DATA"):
						_, _ = conn.Write([]byte("354 send\r\n"))
						var body strings.Builder
						for {
							line, e = reader.ReadString('\n')
							if e != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						f.mu.Lock()
						f.messages = append(f.messages, body.String())
						after := f.afterData
						f.mu.Unlock()
						if after != nil {
							after()
						}
						if ambiguous {
							return
						}
						_, _ = conn.Write([]byte("250 relay accepted\r\n"))
					case strings.HasPrefix(line, "QUIT"):
						_, _ = conn.Write([]byte("221 bye\r\n"))
						return
					default:
						_, _ = conn.Write([]byte("500 refused\r\n"))
					}
				}
			}()
		}
	}()
	return f
}
func queueBindingNotice(t *testing.T, l *Lifecycle, session []byte) Enrollment {
	t.Helper()
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	return e
}
func TestSecurityNoticesTLSAndFanout(t *testing.T) {
	for _, mode := range []string{"implicit", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			f := receiver(t, mode, "", false, false)
			l.notices.Relay = f.relay
			l.notices.Mode = mode
			l.notices.RootCAs = f.roots
			e := queueBindingNotice(t, l, session)
			n, err := l.DispatchNotices(t.Context(), 8)
			if err != nil || n != 2 {
				t.Fatal("fanout not submitted", n, err)
			}
			var accepted int
			if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='relay-accepted'`).Scan(&accepted); err != nil || accepted != 2 {
				t.Fatal("relay result not persisted")
			}
			messages := f.received()
			if len(messages) != 2 {
				t.Fatal("wrong receiver count")
			}
			for _, m := range messages {
				if !strings.Contains(m, "security@example.invalid") || !strings.Contains(m, "not proof of inbox delivery") || strings.Contains(m, e.secret) {
					t.Fatal("notice content/secret boundary failed")
				}
			}
		})
	}
}
func TestNoticesCertificateAndAuthenticationFailures(t *testing.T) {
	for _, kind := range []string{"tls", "auth"} {
		t.Run(kind, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			f := receiver(t, "implicit", "deny", false, false)
			l.notices.Relay = f.relay
			if kind == "auth" {
				l.notices.RootCAs = f.roots
				l.notices.Username = "synthetic"
				l.notices.CredentialID = "smtp"
				if err := l.repo.PutSMTPSecret(t.Context(), "smtp", []byte("synthetic auth canary, not a live credential")); err != nil {
					t.Fatal(err)
				}
			}
			queueBindingNotice(t, l, session)
			n, err := l.DispatchNotices(t.Context(), 8)
			if err != nil || n != 0 {
				t.Fatal("failed protected delivery accepted")
			}
			var failed int
			if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='pending' AND failure_code=?`, kind).Scan(&failed); err != nil || failed != 2 {
				t.Fatal("failure not safely persisted")
			}
			if len(f.received()) != 0 {
				t.Fatal("DATA sent through failed TLS/auth")
			}
		})
	}
}
func TestNoticesPartialFailureKeepsRecipientSnapshots(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	f := receiver(t, "implicit", "", false, true)
	l.notices.Relay = f.relay
	l.notices.RootCAs = f.roots
	queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE notification_addresses SET state='revoked',revoked_at=2000000010 WHERE id='addr1'`); err != nil {
		t.Fatal(err)
	}
	n, err := l.DispatchNotices(t.Context(), 8)
	if err != nil || n != 1 {
		t.Fatal("partial relay outcome wrong")
	}
	var failed, accepted int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='failed' AND recipient_snapshot='first@example.invalid' AND failure_code='recipient'`).Scan(&failed); err != nil || failed != 1 {
		t.Fatal("old snapshot silently retargeted or lost")
	}
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='relay-accepted'`).Scan(&accepted); err != nil || accepted != 1 {
		t.Fatal("one recipient failure erased another outcome")
	}
}
func TestNoticeRestoreRaceDoesNotAcknowledgeStaleGeneration(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	f := receiver(t, "implicit", "", false, false)
	l.notices.Relay = f.relay
	l.notices.RootCAs = f.roots
	queueBindingNotice(t, l, session)
	changed := make(chan error, 2)
	f.onData(func() {
		_, err := db.Exec(`UPDATE installation_control SET restore_quarantined=1,credential_generation=2,session_generation=2,restore_generation=2`)
		changed <- err
	})
	n, err := l.DispatchNotices(t.Context(), 8)
	if n != 0 || err != ErrDenied {
		t.Fatal("stale-generation send acknowledged")
	}
	if err = <-changed; err != nil {
		t.Fatal(err)
	}
	if len(f.received()) != 1 {
		t.Fatal("quarantine did not stop further submissions")
	}
	var accepted int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='relay-accepted'`).Scan(&accepted); err != nil || accepted != 0 {
		t.Fatal("stale result persisted as current")
	}
}

func TestNoticesAmbiguousACKRetriesStableIdentity(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	f := receiver(t, "implicit", "", true, false)
	l.notices.Relay = f.relay
	l.notices.RootCAs = f.roots
	queueBindingNotice(t, l, session)
	now := l.now()
	l.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		n, err := l.DispatchNotices(t.Context(), 8)
		if err != nil || n != 0 {
			t.Fatal("ambiguous ACK recorded as relay success")
		}
		now = now.Add(61 * time.Second)
	}
	messages := f.received()
	if len(messages) != 4 {
		t.Fatal("ambiguous send not retried")
	}
	ids := map[string]int{}
	for _, message := range messages {
		for _, line := range strings.Split(message, "\r\n") {
			if strings.HasPrefix(line, "Message-ID:") {
				ids[line]++
			}
		}
	}
	if len(ids) != 2 {
		t.Fatal("retry changed stable event identity")
	}
	for _, count := range ids {
		if count != 2 {
			t.Fatal("wrong at-least-once count")
		}
	}
	var pending int
	if err := db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='pending' AND failure_code='ambiguous' AND attempts=2`).Scan(&pending); err != nil || pending != 2 {
		t.Fatal("ambiguous state not durable")
	}
}
