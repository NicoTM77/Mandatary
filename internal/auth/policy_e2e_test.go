package auth_test

// P1.17.2 acceptance: administrator -> user/group/agent -> grant on A, with B, ungranted functions,
// ordinary users, directly crafted requests and the administrator role all refused. The whole stack is real
// except the Docker daemon: the SQLite store, the single policy administrator's session through the real
// Browser boundary (cookie, Origin, CSRF, step-up), the real Admin service and routes, the shared
// authz.Authorizer, ops.Service, the REST adapter and the official MCP server, driven over loopback HTTP by
// net/http and by the official go-sdk MCP client. The backend is the in-memory MockBackend behind a spy that
// counts every operational call BEFORE delegating, so "must not reach Docker" is measured. No Docker
// socket, container build, real mail or secret is involved. This is component/integration evidence over a
// mock backend: not real Docker, not a browser, and not a NIST/FIPS claim.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	apimcp "github.com/NicoTM77/Mandatary/internal/mcp"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

const (
	edgeID    = docker.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	billingID = docker.ContainerID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	admin     = "/api/v1/admin"
	pol       = admin + "/policy"
)

// spy counts every operational backend call before delegating.
type spy struct {
	*docker.MockBackend
	mu  sync.Mutex
	ops []string
}

func (s *spy) rec(m string) { s.mu.Lock(); s.ops = append(s.ops, m); s.mu.Unlock() }
func (s *spy) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ops...)
}
func (s *spy) InspectStatus(ctx context.Context, t docker.TargetIdentity) (docker.InspectStatus, error) {
	s.rec("InspectStatus")
	return s.MockBackend.InspectStatus(ctx, t)
}
func (s *spy) InspectConfig(ctx context.Context, t docker.TargetIdentity) (docker.InspectConfig, error) {
	s.rec("InspectConfig")
	return s.MockBackend.InspectConfig(ctx, t)
}
func (s *spy) Logs(ctx context.Context, t docker.TargetIdentity, o docker.LogOptions) (docker.LogStream, error) {
	s.rec("Logs")
	return s.MockBackend.Logs(ctx, t, o)
}
func (s *spy) Start(ctx context.Context, t docker.TargetIdentity) error {
	s.rec("Start")
	return s.MockBackend.Start(ctx, t)
}
func (s *spy) Stop(ctx context.Context, t docker.TargetIdentity, o docker.StopOptions) error {
	s.rec("Stop")
	return s.MockBackend.Stop(ctx, t, o)
}
func (s *spy) Restart(ctx context.Context, t docker.TargetIdentity, o docker.RestartOptions) error {
	s.rec("Restart")
	return s.MockBackend.Restart(ctx, t, o)
}

type world struct {
	t      *testing.T
	p      *auth.PolicyE2E
	mock   *docker.MockBackend
	spy    *spy
	az     *authz.Authorizer
	srv    *httptest.Server
	cookie string
	csrf   string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	p := auth.NewPolicyE2E(t)
	idCfg, containers := docker.DefaultMockFixtures(p.EndpointID)
	containers = append(containers, docker.MockContainerFixture{ // an innocuously named labelled peer (SELF-08)
		ID: docker.ContainerID(strings.Repeat("9", 64)), Name: "reverse-proxy", Image: "nginx:1.27-alpine", State: "running", Status: "Up",
		Labels: map[string]string{docker.SelfLabelKey: docker.SelfLabelValue},
	})
	mock, err := docker.NewMockBackend(docker.MockOptions{EndpointID: p.EndpointID, Identity: idCfg, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if err = mock.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	sp := &spy{MockBackend: mock}
	az, err := authz.NewAuthorizer(authz.Config{Repository: p.Repo, Clock: p.Now, Backends: map[domain.EndpointID]docker.DockerBackend{p.EndpointID: sp}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = az.Close() })
	svc, err := ops.New(ops.Config{Authorizer: az, RevalidateInterval: ops.MaxRevalidateInterval}) // 30 s: only the PUSH path can cut a stream inside the 15 s guard below
	if err != nil {
		t.Fatal(err)
	}
	p.SetNotify(svc.NotifyAuthorityChange)
	p.Admin.WithTargetSource(auth.AuthorizerTargets{A: az})
	gw, err := api.NewGateway(api.GatewayConfig{Executor: svc, Authenticator: az, Endpoints: map[string]domain.EndpointID{"local": p.EndpointID}})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.NewHandler(api.Config{Gateway: gw, Ready: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	mcpH, err := apimcp.NewHandler(apimcp.Config{Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Compose(rest, mcpH, http.NotFoundHandler()))
	t.Cleanup(srv.Close)
	cookie, csrf := p.AdminSession()
	return &world{t: t, p: p, mock: mock, spy: sp, az: az, srv: srv, cookie: cookie, csrf: csrf}
}

// adm is one request by the administrator through the real Browser boundary.
func (w *world) adm(method, path, body string) (int, map[string]any) {
	w.t.Helper()
	return decode(w.p.Do(method, path, body, w.cookie, w.csrf))
}

func (w *world) must(method, path, body string, want int) map[string]any {
	w.t.Helper()
	code, out := w.adm(method, path, body)
	if code != want {
		w.t.Fatalf("%s %s %s: %d %v", method, path, body, code, out)
	}
	return out
}

func decode(code int, body string) (int, map[string]any) {
	var out map[string]any
	if body != "" {
		_ = json.Unmarshal([]byte(body), &out)
	}
	return code, out
}

// outcome is a transport-neutral machine-surface result.
type outcome struct {
	status int
	code   string
	reason string
}

func (o outcome) String() string { return fmt.Sprintf("%d/%s/%s", o.status, o.code, o.reason) }

var okOutcome = outcome{status: 200}

func errOutcome(status int, raw []byte) outcome {
	var b struct {
		Error struct {
			Code   string `json:"code"`
			Status int    `json:"status"`
			Reason string `json:"reason"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &b)
	if b.Error.Status != 0 {
		status = b.Error.Status
	}
	return outcome{status: status, code: b.Error.Code, reason: b.Error.Reason}
}

// restOp performs one operation over REST: op is one of status|config|logs|start|stop|restart.
func (w *world) restOp(token, op, container, query string) outcome {
	w.t.Helper()
	method := http.MethodGet
	if op == "start" || op == "stop" || op == "restart" {
		method = http.MethodPost
	}
	path := "/api/v1/endpoints/local/containers/" + container + "/" + op
	if query != "" {
		path += "?" + query
	}
	return w.restRaw(token, method, path)
}

func (w *world) restRaw(token, method, path string) outcome {
	w.t.Helper()
	req, err := http.NewRequest(method, w.srv.URL+path, nil)
	if err != nil {
		w.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return okOutcome
	}
	return errOutcome(resp.StatusCode, raw)
}

// headerTransport adds the bearer token and records the first non-2xx response, so a refusal that happens
// before the JSON-RPC layer (a 401) is still observed as the HTTP status it is.
type headerTransport struct {
	token string
	mu    *sync.Mutex
	first *outcome
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.token != "" {
		r.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err == nil && resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		h.mu.Lock()
		if h.first.status == 0 {
			*h.first = errOutcome(resp.StatusCode, raw)
		}
		h.mu.Unlock()
		resp.Body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return resp, err
}

var mcpTools = map[string]string{"status": "container_status", "config": "container_config", "logs": "container_logs", "start": "container_start", "stop": "container_stop", "restart": "container_restart"}

// mcpOp performs one operation through a REAL MCP client session (initialize + tools/call).
func (w *world) mcpOp(token, op, container string, extra map[string]any) outcome {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	first, mu := &outcome{}, &sync.Mutex{}
	client := mcp.NewClient(&mcp.Implementation{Name: "p117-e2e", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: w.srv.URL + "/mcp", HTTPClient: &http.Client{Transport: headerTransport{token: token, mu: mu, first: first}}, DisableStandaloneSSE: true, MaxRetries: -1,
	}, nil)
	if err != nil {
		mu.Lock()
		defer mu.Unlock()
		if first.status != 0 {
			return *first
		}
		w.t.Fatalf("MCP connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	args := map[string]any{"endpoint": "local", "container": container}
	for k, v := range extra {
		args[k] = v
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: mcpTools[op], Arguments: args})
	if err != nil {
		mu.Lock()
		defer mu.Unlock()
		if first.status != 0 {
			return *first
		}
		w.t.Fatalf("MCP CallTool %s: %v", op, err)
	}
	if res.IsError {
		raw, _ := json.Marshal(res.StructuredContent)
		return errOutcome(0, raw)
	}
	return okOutcome
}

// both runs one operation over REST and MCP and requires the same outcome.
func (w *world) both(token, op, container string, want outcome, restQuery string, mcpArgs map[string]any) {
	w.t.Helper()
	if got := w.restOp(token, op, container, restQuery); got != want {
		w.t.Errorf("REST %s %s: %s, want %s", op, container, got, want)
	}
	if got := w.mcpOp(token, op, container, mcpArgs); got != want {
		w.t.Errorf("MCP %s %s: %s, want %s", op, container, got, want)
	}
}

var (
	denied      = outcome{status: 403, code: "forbidden", reason: "default_deny"}
	capExceeded = outcome{status: 403, code: "forbidden", reason: "parameter_cap_exceeded"}
	unauth      = outcome{status: 401, code: "unauthenticated"}
)

type follower struct {
	t     *testing.T
	resp  *http.Response
	lines chan string
	stop  context.CancelFunc
}

func (w *world) follow(token, container string) *follower {
	w.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.srv.URL+"/api/v1/endpoints/local/containers/"+container+"/logs?follow=true&tail=1", nil)
	if err != nil {
		cancel()
		w.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		w.t.Fatal(err)
	}
	f := &follower{t: w.t, resp: resp, lines: make(chan string, 64), stop: cancel}
	w.t.Cleanup(func() { cancel(); _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		w.t.Fatalf("follow: %d", resp.StatusCode)
	}
	go func() {
		defer close(f.lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			f.lines <- sc.Text()
		}
	}()
	return f
}

// ended waits for the stream's terminal object and returns its error reason.
func (f *follower) ended() string {
	f.t.Helper()
	deadline := time.After(15 * time.Second) // shorter than the 30 s pull interval, so only the push path can pass
	for {
		select {
		case line, ok := <-f.lines:
			if !ok {
				f.t.Fatal("stream closed without a terminal error object")
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				f.t.Fatalf("not NDJSON: %q", line)
			}
			if e, ok := m["error"].(map[string]any); ok {
				reason, _ := e["reason"].(string)
				return reason
			}
		case <-deadline:
			f.t.Fatal("the stream was not ended by the policy change")
		}
	}
}

func (w *world) newAgent(user, group, agent string) (userID, groupID, agentID, token string) {
	w.t.Helper()
	userID = w.must(http.MethodPost, admin+"/users", `{"username":"`+user+`"}`, http.StatusCreated)["user"].(map[string]any)["id"].(string)
	groupID = w.must(http.MethodPost, admin+"/groups", `{"name":"`+group+`"}`, http.StatusCreated)["group"].(map[string]any)["id"].(string)
	agentID = w.must(http.MethodPost, admin+"/agents", `{"name":"`+agent+`","owner_user_id":"`+userID+`"}`, http.StatusCreated)["agent"].(map[string]any)["id"].(string)
	w.must(http.MethodPut, admin+"/groups/"+groupID+"/members/agent/"+agentID, "", http.StatusNoContent)
	token = w.issue(agentID)
	return
}

func (w *world) issue(agentID string) string {
	w.t.Helper()
	out := w.must(http.MethodPost, admin+"/agents/"+agentID+"/credentials", `{}`, http.StatusCreated)
	return out["token"].(string)
}

func (w *world) ruleIDs(out map[string]any) []string {
	var ids []string
	for _, r := range out["rules"].([]any) {
		ids = append(ids, r.(map[string]any)["id"].(string))
	}
	return ids
}

func (w *world) rulesPage() map[string]any {
	return w.must(http.MethodGet, pol+"/rules", "", http.StatusOK)
}

func TestPolicyAdministrationAB(t *testing.T) {
	t.Parallel() // the world owns its repository, clock, authorizer and loopback server
	w := newWorld(t)
	_, groupID, agentID, token := w.newAgent("alice", "ops", "ci-runner")
	A, B := "edge-proxy", "billing-worker"

	t.Run("default is refusal: an agent with no rule reaches nothing", func(t *testing.T) {
		for _, op := range []string{"status", "config", "logs", "start", "stop", "restart"} {
			w.both(token, op, A, denied, "", nil)
			w.both(token, op, B, denied, "", nil)
		}
		if got := w.spy.calls(); len(got) != 0 {
			t.Fatalf("a request with no rule reached Docker: %v", got)
		}
	})

	t.Run("the administrator role alone grants no container operation", func(t *testing.T) {
		id, secret := w.p.AdminCredentials()
		for _, op := range authz.AllOperations() {
			_, err := w.az.Authorize(context.Background(), authz.AuthorizeRequest{Principal: authz.PrincipalCredentials{SessionID: authz.SessionID(id), SessionSecret: secret}, EndpointID: w.p.EndpointID, TargetRef: A, Operation: op})
			if err == nil {
				t.Fatalf("the administrator session was authorized for %s with no rule", op)
			}
		}
		// A session cookie is not a machine credential, and an agent the administrator owns inherits nothing.
		if got := w.restOp(w.cookie, "status", A, ""); got != unauth {
			t.Fatalf("a session cookie value as a bearer: %s", got)
		}
		adminBot := w.must(http.MethodPost, admin+"/agents", `{"name":"admin-bot","owner_user_id":"u"}`, http.StatusCreated)["agent"].(map[string]any)["id"].(string)
		botToken := w.issue(adminBot)
		w.both(botToken, "status", A, denied, "", nil)
		w.both(botToken, "logs", A, denied, "", nil)
		if len(w.spy.calls()) != 0 {
			t.Fatalf("calls %v", w.spy.calls())
		}
	})

	var ruleIDsA []string
	t.Run("grant on A works over REST and a real MCP client", func(t *testing.T) {
		out := w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:logs","container:inspect_status"],"selector":{"container_name":"edge-proxy","compose_project":"platform","compose_service":"edge-proxy"},"log_tail_max":50}`, http.StatusCreated)
		ruleIDsA = w.ruleIDs(out)
		if len(ruleIDsA) != 2 {
			t.Fatalf("rules %v", out)
		}
		w.both(token, "status", A, okOutcome, "", nil)
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
		if got := w.spy.calls(); len(got) != 4 {
			t.Fatalf("exactly the four allowed calls must reach Docker, got %v", got)
		}
	})

	t.Run("B, ungranted functions, caps, raw proxy and exec stay refused with zero Docker calls", func(t *testing.T) {
		w.spy.mu.Lock()
		w.spy.ops = nil
		w.spy.mu.Unlock()
		for _, op := range []string{"status", "config", "logs", "start", "stop", "restart"} {
			w.both(token, op, B, denied, "", nil) // B: no rule
		}
		for _, op := range []string{"config", "start", "stop", "restart"} {
			w.both(token, op, A, denied, "", nil) // A, ungranted function
		}
		w.both(token, "logs", A, capExceeded, "tail=51", map[string]any{"tail": 51})
		for _, p := range []string{"/v1.43/containers/edge-proxy/json", "/api/v1/endpoints/local/containers/edge-proxy/exec", "/api/v1/endpoints/local/containers", "/api/v1/admin/policy/rules"} {
			if got := w.restRaw(token, http.MethodGet, p); got.status != 404 && got.status != 401 {
				t.Errorf("GET %s with an agent token: %s", p, got)
			}
		}
		if got := w.spy.calls(); len(got) != 0 {
			t.Fatalf("refused requests reached Docker: %v", got)
		}
	})

	t.Run("the page shows rules with present targets and never lists Mandatary or its peers", func(t *testing.T) {
		page := w.rulesPage()
		if page["endpoint"].(map[string]any)["safety"] != "verified" {
			t.Fatalf("endpoint %v", page["endpoint"])
		}
		for _, r := range page["rules"].([]any) {
			tg := r.(map[string]any)["target"].(map[string]any)
			if tg["status"] != "present" || tg["matches"] != float64(1) {
				t.Fatalf("rule target %v", tg)
			}
		}
		raw, _ := json.Marshal(page["inventory"])
		for _, forbidden := range []string{"mandatary-self", "mandatary-peer-stopped", "reverse-proxy"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("inventory names %q: %s", forbidden, raw)
			}
		}
		if !strings.Contains(string(raw), "edge-proxy") {
			t.Fatalf("inventory %s", raw)
		}
	})

	t.Run("a broken selector guard grants nothing and is shown as a missing target", func(t *testing.T) {
		out := w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:start"],"selector":{"container_name":"billing-worker","compose_project":"not-platform"}}`, http.StatusCreated)
		id := w.ruleIDs(out)[0]
		found := false
		for _, r := range w.rulesPage()["rules"].([]any) {
			m := r.(map[string]any)
			if m["id"] == id {
				found = true
				if m["target"].(map[string]any)["status"] != "missing" {
					t.Fatalf("a guard that matches nothing must be flagged missing: %v", m["target"])
				}
			}
		}
		if !found {
			t.Fatal("rule not listed")
		}
		w.both(token, "start", B, denied, "", nil)
		w.must(http.MethodDelete, pol+"/rules/"+id, "", http.StatusNoContent)
		if len(w.spy.calls()) != 0 {
			t.Fatalf("calls %v", w.spy.calls())
		}
	})

	t.Run("a Deny created by the administrator cuts an open stream before the call returns", func(t *testing.T) {
		f := w.follow(token, A)
		out := w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"agent","id":"`+agentID+`"},"effect":"DENY","operations":["container:logs"],"selector":{"container_name":"edge-proxy"}}`, http.StatusCreated)
		if reason := f.ended(); reason != "authorization_ended" {
			t.Fatalf("stream ended with %q", reason)
		}
		w.both(token, "logs", A, denied, "tail=5", map[string]any{"tail": 5}) // deny overrides the group's allow
		w.must(http.MethodDelete, pol+"/rules/"+w.ruleIDs(out)[0], "", http.StatusNoContent)
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
	})

	t.Run("tightening, disabling and deleting a rule take effect at once", func(t *testing.T) {
		logsRule := ""
		for _, r := range w.rulesPage()["rules"].([]any) {
			if m := r.(map[string]any); m["operation"] == "container:logs" {
				logsRule = m["id"].(string)
			}
		}
		w.must(http.MethodPut, pol+"/rules/"+logsRule, `{"effect":"ALLOW","selector":{"container_name":"edge-proxy","compose_project":"platform","compose_service":"edge-proxy"},"log_tail_max":10}`, http.StatusOK)
		w.both(token, "logs", A, capExceeded, "tail=11", map[string]any{"tail": 11})
		w.both(token, "logs", A, okOutcome, "tail=10", map[string]any{"tail": 10})
		f := w.follow(token, A)
		w.must(http.MethodPost, pol+"/rules/"+logsRule+"/disable", "", http.StatusNoContent)
		if reason := f.ended(); reason != "authorization_ended" {
			t.Fatalf("stream ended with %q", reason)
		}
		w.both(token, "logs", A, denied, "tail=5", map[string]any{"tail": 5})
		w.must(http.MethodPost, pol+"/rules/"+logsRule+"/enable", "", http.StatusNoContent)
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
		w.must(http.MethodDelete, pol+"/rules/"+logsRule, "", http.StatusNoContent)
		w.both(token, "logs", A, denied, "tail=5", map[string]any{"tail": 5})
	})

	// Re-grant logs so the remaining cases can hold a follow stream.
	regrant := func() []string {
		return w.ruleIDs(w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:logs"],"selector":{"container_name":"edge-proxy","compose_project":"platform"}}`, http.StatusCreated))
	}

	t.Run("membership is the only way a group's rules reach an agent", func(t *testing.T) {
		regrant()
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
		f := w.follow(token, A)
		w.must(http.MethodDelete, admin+"/groups/"+groupID+"/members/agent/"+agentID, "", http.StatusNoContent)
		if reason := f.ended(); reason != "authorization_ended" {
			t.Fatalf("stream ended with %q", reason)
		}
		w.both(token, "logs", A, denied, "tail=5", map[string]any{"tail": 5})
		w.must(http.MethodPut, admin+"/groups/"+groupID+"/members/agent/"+agentID, "", http.StatusNoContent)
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
	})

	t.Run("disabling the owner revokes the agent, and enabling it back revives nothing", func(t *testing.T) {
		userID := w.userID("alice")
		f := w.follow(token, A)
		w.must(http.MethodPost, admin+"/users/"+userID+"/disable", "", http.StatusNoContent)
		if reason := f.ended(); reason != "authorization_ended" {
			t.Fatalf("stream ended with %q", reason)
		}
		w.both(token, "logs", A, unauth, "tail=5", map[string]any{"tail": 5})
		w.must(http.MethodPost, admin+"/users/"+userID+"/enable", "", http.StatusNoContent)
		w.both(token, "logs", A, unauth, "tail=5", map[string]any{"tail": 5}) // the agent is still disabled
		w.must(http.MethodPost, admin+"/agents/"+agentID+"/enable", "", http.StatusNoContent)
		w.both(token, "logs", A, unauth, "tail=5", map[string]any{"tail": 5}) // and its old token stays revoked
		fresh := w.issue(agentID)
		w.both(token, "logs", A, unauth, "tail=5", map[string]any{"tail": 5})
		w.both(fresh, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5}) // the rules and membership were kept
		token = fresh
	})

	t.Run("transferring ownership changes accountability only", func(t *testing.T) {
		bob := w.must(http.MethodPost, admin+"/users", `{"username":"bobby"}`, http.StatusCreated)["user"].(map[string]any)["id"].(string)
		w.must(http.MethodPut, admin+"/agents/"+agentID+"/owner", `{"owner_user_id":"`+bob+`"}`, http.StatusNoContent)
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
		w.both(token, "start", A, denied, "", nil)
		w.must(http.MethodPut, admin+"/agents/"+agentID+"/owner", `{"owner_group_id":"`+groupID+`"}`, http.StatusNoContent)
		w.both(token, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
	})

	t.Run("a rule is the only grant: it gives the administrator's own account access, and its removal takes it away", func(t *testing.T) {
		id, secret := w.p.AdminCredentials()
		req := authz.AuthorizeRequest{Principal: authz.PrincipalCredentials{SessionID: authz.SessionID(id), SessionSecret: secret}, EndpointID: w.p.EndpointID, TargetRef: A, Operation: authz.OpContainerInspectStatus}
		if _, err := w.az.Authorize(context.Background(), req); err == nil {
			t.Fatal("authorized with no rule")
		}
		out := w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"user","id":"u"},"effect":"ALLOW","operations":["container:inspect_status"],"selector":{"container_name":"edge-proxy"}}`, http.StatusCreated)
		if _, err := w.az.Authorize(context.Background(), req); err != nil {
			t.Fatalf("a rule naming the administrator's account must grant exactly that: %v", err)
		}
		req.Operation = authz.OpContainerRestart
		if _, err := w.az.Authorize(context.Background(), req); err == nil {
			t.Fatal("a status rule granted restart")
		}
		w.must(http.MethodDelete, pol+"/rules/"+w.ruleIDs(out)[0], "", http.StatusNoContent)
		req.Operation = authz.OpContainerInspectStatus
		if _, err := w.az.Authorize(context.Background(), req); err == nil {
			t.Fatal("still authorized after the rule was deleted")
		}
	})

	t.Run("ordinary-user and agent-token policy mutations fail with directly crafted requests", func(t *testing.T) {
		bobCookie, bobCSRF := w.p.OrdinaryUser("mallory")
		before := w.p.CountPolicyState()
		var liveRule string // a rule that exists right now
		for _, r := range w.rulesPage()["rules"].([]any) {
			liveRule = r.(map[string]any)["id"].(string)
		}
		if liveRule == "" {
			t.Fatal("no live rule to attack")
		}
		crafted := []struct{ method, path, body string }{
			{http.MethodPost, pol + "/rules", `{"subject":{"kind":"agent","id":"` + agentID + `"},"effect":"ALLOW","operations":["container:start","container:stop","container:restart","container:inspect_config"],"selector":{"container_name":"*","name_is_glob":true}}`},
			{http.MethodPost, pol + "/rules", `{"subject":{"kind":"user","id":"ord-mallory"},"effect":"ALLOW","operations":["container:logs"],"selector":{"container_name":"billing-worker"}}`},
			{http.MethodPut, pol + "/rules/" + liveRule, `{"effect":"DENY","selector":{"container_name":"edge-proxy"}}`},
			{http.MethodDelete, pol + "/rules/" + liveRule, ``},
			{http.MethodPost, pol + "/rules/" + liveRule + "/disable", ``},
			{http.MethodPost, admin + "/groups/" + groupID + "/disable", ``},
			{http.MethodPost, admin + "/users/u/disable", ``},
			{http.MethodPut, admin + "/groups/" + groupID + "/members/user/ord-mallory", ``},
			{http.MethodPost, admin + "/agents", `{"name":"mallory-bot","owner_user_id":"ord-mallory"}`},
			{http.MethodPost, admin + "/agents/" + agentID + "/credentials", `{}`},
			{http.MethodPost, admin + "/agents/" + agentID + "/disable", ``},
			{http.MethodPut, admin + "/agents/" + agentID + "/owner", `{"owner_user_id":"ord-mallory"}`},
			{http.MethodPost, pol + "/rules/preview", `{"selector":{"container_name":"billing-worker"}}`},
		}
		for _, c := range crafted {
			code, body := w.p.Do(c.method, c.path, c.body, bobCookie, bobCSRF)
			if code != http.StatusForbidden || !strings.Contains(body, "forbidden") {
				t.Errorf("ordinary user %s %s: %d %s", c.method, c.path, code, body)
			}
			// The same crafted requests with an agent bearer token are not even sessions.
			if code, _ = w.p.DoBearer(c.method, c.path, c.body, token); code != http.StatusUnauthorized && code != http.StatusForbidden && code != http.StatusNotFound {
				t.Errorf("agent token %s %s: %d", c.method, c.path, code)
			}
		}
		for _, p := range []string{pol + "/users", pol + "/groups", pol + "/agents", pol + "/rules"} {
			if code, body := w.p.Do(http.MethodGet, p, "", bobCookie, bobCSRF); code != http.StatusForbidden || strings.Contains(body, "ci-runner") {
				t.Errorf("ordinary user GET %s: %d %s", p, code, body)
			}
		}
		if after := w.p.CountPolicyState(); after != before {
			t.Fatalf("refused requests changed policy state:\n%s\n--\n%s", before, after)
		}
		// Nothing was granted: the ordinary user's own account has no rule and the agent kept exactly what it had.
		w.both(token, "start", A, denied, "", nil)
		w.both(token, "config", B, denied, "", nil)
	})

	t.Run("a container removed or recreated under another identity stops matching", func(t *testing.T) {
		w.mock.RemoveContainer(edgeID)
		w.both(token, "status", A, denied, "", nil) // target missing is indistinguishable from ungranted
		for _, r := range w.rulesPage()["rules"].([]any) {
			m := r.(map[string]any)
			if m["selector"].(map[string]any)["container_name"] == "edge-proxy" && m["target"].(map[string]any)["status"] != "missing" {
				t.Fatalf("a deleted target must be listed as missing, not dropped or present: %v", m["target"])
			}
		}
		// Recreated under the same name but another Compose project: the guard refuses it.
		if err := w.mock.UpsertContainer(docker.MockContainerFixture{
			ID: docker.ContainerID(strings.Repeat("e", 64)), Name: "edge-proxy", Image: "nginx:1.27-alpine", State: "running",
			Labels: map[string]string{"com.docker.compose.project": "intruder", "com.docker.compose.service": "edge-proxy"},
		}); err != nil {
			t.Fatal(err)
		}
		w.both(token, "status", A, denied, "", nil)
		// Back under the guarded identity the grant applies again.
		w.mock.RemoveContainer(docker.ContainerID(strings.Repeat("e", 64)))
		if err := w.mock.UpsertContainer(docker.MockContainerFixture{
			ID: edgeID, Name: "edge-proxy", Image: "nginx:1.27-alpine", State: "running",
			Labels: map[string]string{"com.docker.compose.project": "platform", "com.docker.compose.service": "edge-proxy"},
		}); err != nil {
			t.Fatal(err)
		}
		w.both(token, "status", A, okOutcome, "", nil)
	})
}

func (w *world) userID(name string) string {
	w.t.Helper()
	for _, u := range w.must(http.MethodGet, pol+"/users", "", http.StatusOK)["users"].([]any) {
		if m := u.(map[string]any); m["username"] == name {
			return m["id"].(string)
		}
	}
	w.t.Fatalf("no user %s", name)
	return ""
}
