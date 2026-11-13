//go:build webauthnbrowser

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/NicoTM77/Mandatary/web"
)

// P1.16.3 browser tests: the REAL admin application bundle (web/dist), the REAL static handler, the REAL
// setup adapter, account routes and services over a real SQLite installation, a real loopback TLS SMTP
// receiver and synthetic loopback HTTPS. Only the clock, the origin and synthetic passwords are
// synthetic. The control server (plain loopback HTTP, never part of the product) stands in for the host
// operator (reveal a token), the mailbox (read a proof), time (advance the server clock) and the server
// log (check for canaries). Nothing here is linked into cmd/mandatary.

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type uiFixture struct {
	origin, control string
	// caPEM is the fixture server's own (public) certificate. The scripts' raw HTTPS client trusts exactly
	// this certificate instead of switching certificate validation off.
	caPEM string
}

// fixtureCA returns the public certificate of the started fixture server, PEM encoded.
func fixtureCA(app *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: app.Certificate().Raw}))
}

// browserEnv is the environment of one browser script: the engine and the certificate to trust.
func browserEnv(engine string, fixture uiFixture) []string {
	return append(os.Environ(), "MANDATARY_BROWSER_ENGINE="+engine, "MANDATARY_FIXTURE_CA_PEM="+fixture.caPEM)
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// startUIFixture serves the composition cmd/mandatary uses (setup adapter + account routes + static
// shell) for either a fresh installation ("setup") or an installation with one optional-MFA account that
// holds a TOTP factor ("login").
func startUIFixture(t *testing.T, kind string) uiFixture {
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

	mux := http.NewServeMux()
	mux.Handle("/", web.Handler())
	control := http.NewServeMux()
	var advance func(time.Duration)
	var now func() time.Time

	switch kind {
	case "setup":
		clock := &testClock{now: time.Now().Truncate(time.Second)}
		advance, now = clock.Advance, clock.Now
		smtp := receiver(t, "implicit", "", false, false)
		key, err := store.LoadMasterKey(strings.Repeat("22", 32), "")
		if err != nil {
			t.Fatal(err)
		}
		repo, err := store.Open(t.Context(), store.Options{DataDir: filepath.Join(t.TempDir(), "data"), MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = repo.Close() })
		l, err := NewLifecycle(repo, NoticeSettings{Origin: origin, Contact: "security@example.invalid", Sender: "notices@example.invalid", Relay: smtp.relay, Mode: "implicit", RootCAs: smtp.roots})
		if err != nil {
			t.Fatal(err)
		}
		l.now = clock.Now
		s, err := NewSetup(repo, l, SetupSettings{Origin: origin, Build: "test-build"})
		if err != nil {
			t.Fatal(err)
		}
		s.now = clock.Now
		if r, err := s.EnsureInitial(t.Context()); err != nil || r.Outcome != "issued" {
			t.Fatal("no initial generation", err)
		}
		adapter, err := NewSetupHTTP(s)
		if err != nil {
			t.Fatal(err)
		}
		mux.Handle(SetupPathPrefix, adapter.Handler())
		mountAccount(t, mux, l)
		control.HandleFunc("POST /reveal", func(w http.ResponseWriter, r *http.Request) {
			term := &fakeTerminal{}
			if _, err := s.Reveal(r.Context(), PurposeInitialSetup, "", term); err != nil || term.token() == "" {
				http.Error(w, "reveal failed", http.StatusInternalServerError)
				return
			}
			writeJSONBody(w, map[string]string{"token": term.token()})
		})
		control.HandleFunc("POST /maintain", func(w http.ResponseWriter, r *http.Request) {
			if _, err := s.Reconcile(r.Context()); err != nil {
				http.Error(w, "reconcile failed", http.StatusInternalServerError)
				return
			}
			writeJSONBody(w, map[string]bool{"ok": true})
		})
		control.HandleFunc("GET /proof", func(w http.ResponseWriter, r *http.Request) {
			messages := smtp.received()
			for i := len(messages) - 1; i >= 0; i-- {
				if m := proofLine.FindStringSubmatch(messages[i]); m != nil {
					writeJSONBody(w, map[string]string{"proof": m[1]})
					return
				}
			}
			http.Error(w, "no proof delivered", http.StatusNotFound)
		})
	case "login":
		e := newSessionEnv(t)
		_, enrollment := e.mfaAccount()
		e.l.notices.Origin = origin
		advance, now = e.clock.Advance, e.clock.Now
		mountAccount(t, mux, e.l)
		control.HandleFunc("GET /seed", func(w http.ResponseWriter, r *http.Request) {
			writeJSONBody(w, map[string]string{"seed": enrollment.secret})
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
	default:
		t.Fatal("unknown fixture", kind)
	}
	control.HandleFunc("POST /advance", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Seconds int }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Seconds < 1 || in.Seconds > 7200 {
			http.Error(w, "bad advance", http.StatusBadRequest)
			return
		}
		advance(time.Duration(in.Seconds) * time.Second)
		writeJSONBody(w, map[string]int{"seconds": in.Seconds})
	})
	control.HandleFunc("GET /now", func(w http.ResponseWriter, r *http.Request) { writeJSONBody(w, map[string]int64{"unix": now().Unix()}) })
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

	app := httptest.NewUnstartedServer(logging.HTTP(logger, mux))
	_ = app.Listener.Close()
	app.Listener = listener
	app.StartTLS()
	t.Cleanup(app.Close)
	ctl := httptest.NewServer(control)
	t.Cleanup(ctl.Close)
	return uiFixture{origin: origin, control: ctl.URL, caPEM: fixtureCA(app)}
}

// mountAccount mounts the account routes exactly as cmd/mandatary does.
func mountAccount(t *testing.T, mux *http.ServeMux, l *Lifecycle) {
	t.Helper()
	sessions, err := NewSessions(l, nil, DefaultSessionSettings())
	if err != nil {
		t.Fatal(err)
	}
	browser := NewBrowser(sessions)
	if err := RegisterAccountRoutes(browser, sessions); err != nil {
		t.Fatal(err)
	}
	for _, path := range AccountPaths() {
		mux.Handle(path, browser)
	}
}

var secretLookingOutput = regexp.MustCompile(`[A-Z2-7]{26,}|synthetic setup passphrase|a unique synthetic public phrase`)

func TestAdminUIBrowser(t *testing.T) {
	scenarios := []struct{ name, kind string }{
		{"setup-login", "setup"},
		{"setup-replay-expiry", "setup"},
		{"login-flows", "login"},
	}
	for _, engine := range browserEngines(t) {
		for _, scheme := range []string{"light", "dark"} {
			for _, scenario := range scenarios {
				t.Run(engine+"/"+scenario.name+"/"+scheme, func(t *testing.T) {
					fixture := startUIFixture(t, scenario.kind)
					ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
					defer cancel()
					script := filepath.Join("..", "..", "web", "tests", "admin-ui-browser.mjs")
					cmd := exec.CommandContext(ctx, "node", script, scenario.name, scheme, fixture.origin, fixture.control)
					cmd.Env = browserEnv(engine, fixture)
					output, err := cmd.CombinedOutput()
					if err != nil {
						// The script never prints a secret; guard anyway before echoing anything.
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
}

// browserEngines lists the Playwright engines to drive: MANDATARY_BROWSER_ENGINES (comma separated, from
// chromium, firefox, webkit), default chromium. An unknown name fails the test rather than being skipped.
func browserEngines(t *testing.T) []string {
	t.Helper()
	list := os.Getenv("MANDATARY_BROWSER_ENGINES")
	if list == "" {
		return []string{"chromium"}
	}
	var engines []string
	for _, engine := range strings.Split(list, ",") {
		engine = strings.TrimSpace(engine)
		if engine != "chromium" && engine != "firefox" && engine != "webkit" {
			t.Fatalf("unknown browser engine %q in MANDATARY_BROWSER_ENGINES", engine)
		}
		engines = append(engines, engine)
	}
	return engines
}
