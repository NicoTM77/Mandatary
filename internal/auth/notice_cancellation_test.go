package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Exercise cancellation precisely at the real TLS handshake completion boundary.
// The network cancellation callback must not race the TLS-wrapped conn selection.
func TestNoticeCancellationAtTLSHandshakeBoundary(t *testing.T) {
	l, _, _ := lifecycleFixture(t)
	source := httptest.NewTLSServer(nil)
	certificate := source.TLS.Certificates[0]
	source.Close()
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	l.notices.RootCAs = roots
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	l.notices.Relay = listener.Addr().String()
	cancellations := make(chan context.CancelFunc)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for cancel := range cancellations {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			secure, ok := conn.(*tls.Conn)
			if !ok {
				_ = conn.Close()
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if secure.Handshake() == nil {
				cancel()
			}
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
	}()
	defer func() { close(cancellations); _ = listener.Close(); <-done }()
	for range 512 {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		cancellations <- cancel
		failure := l.sendNotice(ctx, store.NextNoticeRow{RecipientSnapshot: "first@example.invalid"})
		cancel()
		if failure == "" {
			t.Fatal("cancelled pre-submission work reported success")
		}
	}
}
