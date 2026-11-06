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
)

func TestSecurityNoticesTLSAndFanout(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	https := httptest.NewTLSServer(nil)
	cert := https.TLS.Certificates[0]
	https.Close()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var mu sync.Mutex
	messages := []string{}
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
				reader := bufio.NewReader(conn)
				_, _ = conn.Write([]byte("220 fixture ESMTP\r\n"))
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						_, _ = conn.Write([]byte("250 fixture\r\n"))
					case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
						_, _ = conn.Write([]byte("250 accepted\r\n"))
					case strings.HasPrefix(line, "DATA"):
						_, _ = conn.Write([]byte("354 send\r\n"))
						var body strings.Builder
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						mu.Lock()
						messages = append(messages, body.String())
						mu.Unlock()
						_, _ = conn.Write([]byte("250 relay accepted\r\n"))
					case strings.HasPrefix(line, "QUIT"):
						_, _ = conn.Write([]byte("221 bye\r\n"))
						return
					default:
						_, _ = conn.Write([]byte("500 invalid\r\n"))
					}
				}
			}()
		}
	}()
	l.notices.Relay = listener.Addr().String()
	l.notices.RootCAs = roots
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	n, err := l.DispatchNotices(t.Context(), 8)
	if err != nil || n != 2 {
		t.Fatal("fanout not submitted", n, err)
	}
	var accepted int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE delivery_state='relay-accepted'`).Scan(&accepted); err != nil || accepted != 2 {
		t.Fatal("relay result not persisted")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 2 {
		t.Fatal("wrong receiver count")
	}
	for _, m := range messages {
		if !strings.Contains(m, "security@example.invalid") || !strings.Contains(m, "not proof of inbox delivery") || strings.Contains(m, e.secret) {
			t.Fatal("notice content/secret boundary failed")
		}
	}
	_ = listener.Close()
	<-done
	_ = net.IPv4len
}
