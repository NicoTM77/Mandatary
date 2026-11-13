//go:build webauthnbrowser

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/web"
)

// P1.16.4 browser tests: the REAL admin bundle (web/dist), the REAL static handler, the REAL account,
// account-security, recovery and administrative routes, WebAuthn bound to the fixture origin, and the real
// services over a real SQLite installation with a real loopback TLS SMTP receiver. Only the clock, the
// origin and the synthetic password are synthetic. The control server (plain loopback HTTP, never part of
// the product) stands in for the host operator (time, mailbox, mail dispatch) and for an agent that uses
// a token it was given; it is not linked into cmd/mandatary.

func startSecurityUIFixture(t *testing.T) uiFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://example.invalid:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	logs := &syncBuffer{}
	logger, err := logging.New(logs, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}

	// The account "synthetic-user" is a super administrator with one TOTP factor (newAdminEnv's own set-up),
	// built on a server clock that starts at the real present: pages show time left against the browser's clock.
	e := newSessionEnv(t)
	e.clock.now = time.Now().Truncate(time.Second)
	at := e.clock.now.Unix()
	e.exec(`UPDATE sessions SET created_at=?, authenticated_at=?, last_activity_at=?, expires_at=? WHERE id='session'`, at, at, at, at+3600)
	e.exec(`UPDATE notification_addresses SET created_at=?, verified_at=?`, at, at)
	id, en := e.mfaAccount()
	e.exec(`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm','u','super_admin','active',1)`)
	ae := &adminEnv{sessionEnv: e, totpID: id, totp: en}
	admin, err := NewAdmin(e.l, DefaultAdminSettings(), ae.notify)
	if err != nil {
		t.Fatal(err)
	}
	ae.a = admin
	ae.secret, ae.sessID = ae.aal2Session(id)
	ae.agentOwnedBy("synthetic-agent", "u")
	smtp := receiver(t, "implicit", "", false, false)
	e.l.notices.Origin = origin
	e.l.notices.Relay, e.l.notices.RootCAs = smtp.relay, smtp.roots

	keys, err := NewWebAuthn(e.l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{origin}})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := NewSessions(e.l, keys, DefaultSessionSettings())
	if err != nil {
		t.Fatal(err)
	}
	browser := NewBrowser(sessions)
	if err := RegisterAccountRoutes(browser, sessions); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSecurityRoutes(browser, sessions); err != nil {
		t.Fatal(err)
	}
	adminHTTP, err := NewAdminHTTP(ae.a)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminHTTP.Register(browser); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", web.Handler())
	for _, path := range append(AccountPaths(), SecurityPaths()...) {
		mux.Handle(path, browser)
	}
	mux.Handle(AdminPathPrefix, browser)

	control := http.NewServeMux()
	control.HandleFunc("GET /seed", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]string{"seed": ae.totp.secret})
	})
	control.HandleFunc("POST /policy", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ MFA string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.MFA != "required" && in.MFA != "optional") {
			http.Error(w, "bad policy", http.StatusBadRequest)
			return
		}
		e.exec(`UPDATE users SET mfa_requirement=?`, in.MFA)
		writeJSONBody(w, map[string]string{"mfa": in.MFA})
	})
	// The administrator role is switched off: the account becomes an ordinary person.
	control.HandleFunc("POST /demote", func(w http.ResponseWriter, r *http.Request) {
		e.exec(`UPDATE administrative_roles SET state='disabled' WHERE id='adm'`)
		writeJSONBody(w, map[string]bool{"ok": true})
	})
	control.HandleFunc("GET /now", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]int64{"unix": e.clock.Now().Unix()})
	})
	control.HandleFunc("POST /advance", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Seconds int }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Seconds < 1 || in.Seconds > 7200 {
			http.Error(w, "bad advance", http.StatusBadRequest)
			return
		}
		e.clock.Advance(time.Duration(in.Seconds) * time.Second)
		writeJSONBody(w, map[string]int{"seconds": in.Seconds})
	})
	// The newest address proof mailed to one recipient.
	control.HandleFunc("POST /proof", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ To string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.To == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		messages := smtp.received()
		for i := len(messages) - 1; i >= 0; i-- {
			if strings.Contains(messages[i], "To: "+in.To+"\r\n") {
				if m := proofLine.FindStringSubmatch(messages[i]); m != nil {
					writeJSONBody(w, map[string]string{"proof": m[1]})
					return
				}
			}
		}
		http.Error(w, "no proof delivered", http.StatusNotFound)
	})
	// How many messages the receiver holds, and to whom the newest went.
	control.HandleFunc("GET /mailbox", func(w http.ResponseWriter, r *http.Request) {
		messages := smtp.received()
		recipients := []string{}
		for _, m := range messages {
			for _, line := range strings.Split(m, "\r\n") {
				if rest, ok := strings.CutPrefix(line, "To: "); ok {
					recipients = append(recipients, rest)
					break
				}
			}
		}
		writeJSONBody(w, map[string]any{"count": len(messages), "to": recipients})
	})
	control.HandleFunc("POST /dispatch", func(w http.ResponseWriter, r *http.Request) {
		n, err := e.l.DispatchNotices(r.Context(), 32)
		if err != nil {
			http.Error(w, "dispatch failed", http.StatusInternalServerError)
			return
		}
		writeJSONBody(w, map[string]int{"dispatched": n})
	})
	// The relay goes away: later notices cannot be delivered (they stay in the durable outbox).
	control.HandleFunc("POST /break-mail", func(w http.ResponseWriter, r *http.Request) {
		e.l.notices.Relay = "127.0.0.1:1"
		writeJSONBody(w, map[string]bool{"ok": true})
	})
	// An agent that presents a token it was given: does the shared verifier accept it now?
	control.HandleFunc("POST /agent-accepts", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Token string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Token == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeJSONBody(w, map[string]bool{"accepted": ae.accepted([]byte(in.Token))})
	})
	control.HandleFunc("POST /check-logs", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Canaries []string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		leaked := false
		for _, canary := range in.Canaries {
			if len(canary) >= 8 && strings.Contains(logs.String(), canary) {
				leaked = true
			}
		}
		if logs.String() == "" {
			http.Error(w, "the log recorded nothing, so this check proves nothing", http.StatusInternalServerError)
			return
		}
		writeJSONBody(w, map[string]bool{"leaked": leaked})
	})
	// Raw store scan: a revealed secret must not rest in the database in the clear.
	control.HandleFunc("POST /check-store", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Canaries []string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		raw := ae.rawStore()
		leaked := false
		for _, canary := range in.Canaries {
			if len(canary) >= 8 && strings.Contains(string(raw), canary) {
				leaked = true
			}
		}
		writeJSONBody(w, map[string]bool{"leaked": leaked})
	})

	app := httptest.NewUnstartedServer(logging.HTTP(logger, mux))
	_ = app.Listener.Close()
	app.Listener = listener
	app.StartTLS()
	t.Cleanup(app.Close)
	ctl := httptest.NewServer(control)
	t.Cleanup(ctl.Close)
	return uiFixture{origin: origin, control: ctl.URL}
}

func TestSecurityUIBrowser(t *testing.T) {
	scenarios := []string{"a11y-selfcheck", "security-flows", "recovery-flow", "key-flows", "denial-matrix"}
	for _, scheme := range []string{"light", "dark"} {
		for _, scenario := range scenarios {
			t.Run(scenario+"/"+scheme, func(t *testing.T) {
				fixture := startSecurityUIFixture(t)
				ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
				defer cancel()
				script := filepath.Join("..", "..", "web", "tests", "security-ui-browser.mjs")
				cmd := exec.CommandContext(ctx, "node", script, scenario, scheme, fixture.origin, fixture.control)
				cmd.Env = os.Environ()
				output, err := cmd.CombinedOutput()
				if err != nil {
					if secretLookingOutput.Match(output) {
						t.Fatalf("browser scenario failed and its output looked secret-bearing, so it is not shown: %v", err)
					}
					t.Fatalf("browser scenario failed: %v\n%s", err, output)
				}
				t.Logf("%s", output)
			})
		}
	}
}
