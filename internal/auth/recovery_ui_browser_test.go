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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/web"
)

// P1.18.3 browser tests: the REAL admin bundle (web/dist), the REAL static handler, the REAL account, step-up and administrative
// routes including the four P1.18 routes, and the real services (Admin, backup service, sessions, lifecycle) over a real SQLite
// installation. Only the clock, the origin and the synthetic password are synthetic. The control server (plain loopback HTTP, never
// part of the product) stands in for the host operator: it seeds a world, changes records after a backup, RUNS the real host
// recovery ceremony that ends restore quarantine (RESTORE-08, no web route can do it: a new administrator with a fresh password
// and authenticator is enrolled, nothing the backup carried is revived), reports the installation's state,
// and plants a real database fault. It is not linked into cmd/mandatary.

func startRecoveryUIFixture(t *testing.T) uiFixture {
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

	e := newSessionEnv(t)
	// The server clock starts at the real present: pages show time left against the browser's own clock.
	e.clock.now = time.Now().Truncate(time.Second)
	at := e.clock.now.Unix()
	e.exec(`UPDATE sessions SET created_at=?, authenticated_at=?, last_activity_at=?, expires_at=? WHERE id='session'`, at, at, at, at+3600)
	e.exec(`UPDATE notification_addresses SET created_at=?, verified_at=?`, at, at)
	id, en := e.mfaAccount()
	e.exec(`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm','u','super_admin','active',1)`)
	e.exec(`UPDATE endpoints SET state='active', authority_generation=1 WHERE slug='local'`)
	ae := &adminEnv{sessionEnv: e, totpID: id, totp: en}
	admin, err := NewAdmin(e.l, DefaultAdminSettings(), ae.notify)
	if err != nil {
		t.Fatal(err)
	}
	ae.a = admin
	ae.secret, ae.sessID = ae.aal2Session(id)
	svc, err := backup.New(e.l.repo, "browser-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.SetBackup(svc); err != nil {
		t.Fatal(err)
	}
	e.l.notices.Origin = origin

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
	adminHTTP, err := NewAdminHTTP(admin)
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
	reply := func(w http.ResponseWriter, v any) { writeJSONBody(w, v) }
	fail := func(w http.ResponseWriter, msg string) { http.Error(w, msg, http.StatusInternalServerError) }

	control.HandleFunc("GET /seed", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]string{"seed": ae.totp.secret}) })
	control.HandleFunc("GET /now", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]int64{"unix": e.clock.Now().Unix()}) })
	control.HandleFunc("POST /advance", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Seconds int }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Seconds < 1 || in.Seconds > 7200 {
			http.Error(w, "bad advance", http.StatusBadRequest)
			return
		}
		e.clock.Advance(time.Duration(in.Seconds) * time.Second)
		reply(w, map[string]int{"seconds": in.Seconds})
	})

	// A small world the restore has something to say about: a person, a group, an agent they own, and an ALLOW rule for the group.
	control.HandleFunc("POST /world", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		alice, err := admin.CreateUser(ctx, ae.secret, "browser-alice")
		if err != nil {
			fail(w, "user")
			return
		}
		group, err := admin.CreateGroup(ctx, ae.secret, "browser-ops")
		if err != nil {
			fail(w, "group")
			return
		}
		agent, err := admin.CreateAgent(ctx, ae.secret, AgentRequest{Name: "browser-bot", OwnerUserID: alice.ID})
		if err != nil {
			fail(w, "agent")
			return
		}
		limit := 25
		if _, err := admin.CreateRules(ctx, ae.secret, RuleRequest{Subject: RuleSubject{Kind: "group", ID: group.ID}, Effect: "ALLOW", Operations: []string{"container:logs"},
			Selector: SelectorSpec{ContainerName: "browser-proxy"}, LogTailMax: &limit}); err != nil {
			fail(w, "rule")
			return
		}
		if _, err := admin.IssueCredential(ctx, ae.secret, agent.ID, CredentialRequest{}); err != nil {
			fail(w, "credential")
			return
		}
		reply(w, map[string]string{"user": alice.ID, "group": group.ID, "agent": agent.ID})
	})
	// After the backup: one new person, and a DENY on the same subject the file's ALLOW names (the file cannot know either).
	control.HandleFunc("POST /local-change", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		zed, err := admin.CreateUser(ctx, ae.secret, "browser-zed")
		if err != nil {
			fail(w, "user")
			return
		}
		var groupID string
		if err := e.db.QueryRow(`SELECT id FROM groups WHERE name='browser-ops'`).Scan(&groupID); err != nil {
			fail(w, "group lookup")
			return
		}
		if _, err := admin.CreateRules(ctx, ae.secret, RuleRequest{Subject: RuleSubject{Kind: "group", ID: groupID}, Effect: "DENY", Operations: []string{"container:logs"},
			Selector: SelectorSpec{ContainerName: "browser-proxy"}}); err != nil {
			fail(w, "rule")
			return
		}
		reply(w, map[string]string{"user": zed.ID})
	})
	control.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		count := func(q string) int64 { return e.scalar(q) }
		reply(w, map[string]int64{
			"quarantined":       count(`SELECT restore_quarantined FROM installation_control`),
			"restoreGeneration": count(`SELECT restore_generation FROM installation_control`),
			"sessions":          count(`SELECT count(*) FROM sessions WHERE state='active'`),
			"reports":           count(`SELECT count(*) FROM restore_reports`),
			"activeUsers":       count(`SELECT count(*) FROM users WHERE state='active'`),
			"activeGroups":      count(`SELECT count(*) FROM groups WHERE state='active'`),
			"activeAgents":      count(`SELECT count(*) FROM agents WHERE state='active'`),
			"activePolicies":    count(`SELECT count(*) FROM policies WHERE state='active'`),
			"activeCredentials": count(`SELECT count(*) FROM agent_credentials WHERE state='active'`),
			"users":             count(`SELECT count(*) FROM users`),
			"policies":          count(`SELECT count(*) FROM policies`),
		})
	})
	// The REAL host recovery (setup service, purpose restore_recovery): a NEW administrator with a fresh password and TOTP, who
	// signs in through the ordinary login. The backup administrator and everything it held stay inactive; nothing else is approved.
	// The new credentials are returned so the browser can sign in with them (they are synthetic).
	control.HandleFunc("POST /ceremony", func(w http.ResponseWriter, r *http.Request) {
		r2 := ae.hostRecoveryCeremony()
		reply(w, map[string]string{"username": r2.Username, "password": r2.Password, "seed": r2.Seed})
	})
	// A REAL database fault in the middle of the import: SQLite itself raises it, exactly as a constraint failure would.
	control.HandleFunc("POST /fault", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ On bool }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		for _, ev := range []string{"insert", "update"} {
			if in.On {
				e.exec(`CREATE TRIGGER IF NOT EXISTS fail_group_` + ev + ` BEFORE ` + strings.ToUpper(ev) + ` ON groups BEGIN SELECT RAISE(ABORT,'synthetic constraint failure'); END`)
			} else {
				e.exec(`DROP TRIGGER IF EXISTS fail_group_` + ev)
			}
		}
		reply(w, map[string]bool{"on": in.On})
	})
	// An ordinary signed-in person (not the administrator) with a genuine fresh AAL2 session row: the cookie value only.
	control.HandleFunc("POST /ordinary", func(w http.ResponseWriter, r *http.Request) {
		p := &PolicyE2E{T: t, env: ae, Repo: e.l.repo, Clock: e.clock}
		cookie, _ := p.OrdinaryUser("browser-ordinary")
		reply(w, map[string]string{"cookie": cookie})
	})
	// An agent that presents a token it was given: does the shared verifier accept it now?
	control.HandleFunc("POST /agent-accepts", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Token string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Token == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply(w, map[string]bool{"accepted": ae.accepted([]byte(in.Token))})
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
			fail(w, "the log recorded nothing, so this check proves nothing")
			return
		}
		reply(w, map[string]bool{"leaked": leaked})
	})
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
		reply(w, map[string]bool{"leaked": leaked})
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

func TestRecoveryUIBrowser(t *testing.T) {
	scenarios := []string{"export-flows", "restore-flows", "restore-failure", "parallel-restore", "denial"}
	for _, engine := range browserEngines(t) {
		for _, scheme := range []string{"light", "dark"} {
			for _, scenario := range scenarios {
				t.Run(engine+"/"+scenario+"/"+scheme, func(t *testing.T) {
					fixture := startRecoveryUIFixture(t)
					ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
					defer cancel()
					script := filepath.Join("..", "..", "web", "tests", "recovery-ui-browser.mjs")
					cmd := exec.CommandContext(ctx, "node", script, scenario, scheme, fixture.origin, fixture.control)
					cmd.Env = browserEnv(engine, fixture)
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
}
