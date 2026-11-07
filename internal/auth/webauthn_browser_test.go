//go:build webauthnbrowser

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Deliberately test-only adapter; never linked into cmd/mandatary. The synthetic
// server stays loopback and knows one synthetic session. Product routes/cookies/
// CSRF/setup/normal-session creation remain P1.08/09/16 and cannot use this adapter.
func TestWebAuthnBrowserVirtualAuthenticator(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	origin := "https://example.invalid:" + fmt.Sprint(port)
	w, e := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{origin}})
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		rw.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(rw, "<!doctype html><title>Synthetic WebAuthn fixture</title>")
	})
	mux.HandleFunc("POST /begin-registration", func(rw http.ResponseWriter, r *http.Request) {
		c, e := w.BeginRegistration(r.Context(), session, r.URL.Query().Get("resident") == "true")
		if e != nil {
			rw.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(rw).Encode(c)
	})
	mux.HandleFunc("POST /finish-registration", func(rw http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(http.MaxBytesReader(rw, r.Body, 32768))
		if e != nil || w.FinishRegistration(r.Context(), session, r.URL.Query().Get("id"), b) != nil {
			rw.WriteHeader(403)
		}
	})
	mux.HandleFunc("POST /begin-assertion", func(rw http.ResponseWriter, r *http.Request) {
		c, e := w.BeginAssertion(r.Context(), session)
		if e != nil {
			rw.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(rw).Encode(c)
	})
	mux.HandleFunc("POST /finish-assertion", func(rw http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(http.MaxBytesReader(rw, r.Body, 32768))
		if e != nil {
			rw.WriteHeader(403)
			return
		}
		proof, e := w.FinishAssertion(r.Context(), session, r.URL.Query().Get("id"), b, "192.0.2.9")
		if e != nil {
			rw.WriteHeader(403)
			return
		}
		webSession(t, db, proof.AuthenticatorID)
	})
	server := httptest.NewUnstartedServer(mux)
	_ = server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	script := filepath.Join("..", "..", "web", "tests", "webauthn-browser.mjs")
	cmd := exec.CommandContext(t.Context(), "node", script, origin)
	cmd.Env = os.Environ()
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("browser fixture failed: %v\n%s", e, output)
	}
	t.Logf("%s", output)
}
