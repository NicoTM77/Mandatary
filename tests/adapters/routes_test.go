package adapters_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/docker"
	apimcp "github.com/NicoTM77/Mandatary/internal/mcp"
)

// rawDo sends an exact, unnormalized request line to the real server.
func rawDo(t *testing.T, e *env, method, target string, hdr http.Header, body []byte) (int, http.Header, []byte) {
	t.Helper()
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, e.srv.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the target verbatim (no cleaning, no encoding normalization).
	req.URL = &url.URL{Scheme: u.Scheme, Host: u.Host, Opaque: "//" + u.Host + target}
	req.Header = hdr.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data
}

func bearer(tok string) http.Header { return http.Header{"Authorization": {"Bearer " + tok}} }

// Raw Docker paths and alternate spellings never reach Docker, with or without a valid
// token, under any method (plan row P1.14: "unrecognized route/method/query must not
// reach Docker").
func TestRawDockerPathsQueryPassthroughAndAlternateRoutesNeverReachDocker(t *testing.T) {
	e := newEnv(t)
	tok := e.token("wildcard")
	paths := []string{
		// Docker Engine API shapes, versioned and unversioned.
		"/containers/json", "/containers/json?all=1", "/v1.44/containers/json", "/v1.44/containers/edge-proxy/json", "/v1.44/containers/edge-proxy/exec",
		"/containers/edge-proxy/start", "/containers/edge-proxy/logs?follow=1", "/containers/mandatary-self/stop", "/exec/abc/start",
		"/images/json", "/volumes", "/networks", "/info", "/version", "/_ping", "/events", "/system/df", "/swarm", "/build", "/commit",
		// Adapter namespace, wrong shapes.
		"/api/v1/containers", "/api/v1/containers/json", "/api/v1/containers/edge-proxy/status", "/api/v1/endpoints", "/api/v1/endpoints/local",
		"/api/v1/endpoints/local/containers", "/api/v1/endpoints/local/containers/edge-proxy",
		"/api/v1/endpoints/local/containers/edge-proxy/exec", "/api/v1/endpoints/local/containers/edge-proxy/top",
		"/api/v1/endpoints/local/containers/edge-proxy/json", "/api/v1/endpoints/local/containers/edge-proxy/kill",
		"/api/v1/endpoints/local/exec", "/api/v1/endpoints/local/images/json", "/api/v1/endpoints/local/containers/json",
		"/api/v1/discovery", "/api/v1/access-requests", "/api/v1/usage", "/api/v1/stats",
		"/api/v2/endpoints/local/containers/edge-proxy/status", "/API/V1/endpoints/local/containers/edge-proxy/status",
		"/api/v1/endpoints/local/containers/edge-proxy/status/", "/api/v1/endpoints/local/containers/edge-proxy/status/exec",
		// Path-cleaning, dot-segment, double-slash and encoding tricks.
		"//api/v1/endpoints/local/containers/edge-proxy/status", "/api//v1/endpoints/local/containers/edge-proxy/status",
		"/api/v1//endpoints/local/containers/edge-proxy/status", "/api/v1/endpoints/local/containers/edge-proxy//status",
		"/api/v1/endpoints/local/containers/edge-proxy/./status", "/api/v1/endpoints/local/containers/edge-proxy/../edge-proxy/status",
		"/api/v1/endpoints/local/containers/../../../../v1.44/containers/json", "/api/v1/endpoints/local/containers/%2e%2e/%2e%2e/containers/json",
		"/api/v1/endpoints/local/containers/edge-proxy/status%2Fexec", "/api/v1/endpoints/local/containers/edge-proxy%2Fexec/status",
		"/api/v1/endpoints/local/containers/edge-proxy/%73tatus/", "/api/v1/endpoints/local/containers/edge-proxy/status;exec",
		"/api%2Fv1/endpoints/local/containers/edge-proxy/status", "/%61pi/v1/endpoints/local/containers/edge-proxy/status",
		"/api/v1/endpoints/local/containers/edge-proxy/status#/exec",
		// MCP namespace, wrong shapes.
		"/mcp/", "/mcp/tools", "/mcp/exec", "/mcp//", "/MCP", "/mcp%2f", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
		"/oauth/token", "/authorize", "/sse", "/messages",
	}
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	for _, p := range paths {
		for _, m := range methods {
			for _, hdr := range []http.Header{nil, bearer(tok)} {
				status, _, _ := rawDo(t, e, m, p, hdr, nil)
				// Nothing may succeed; every answer is a refusal or a redirect to nothing.
				if status < 300 || status == 500 {
					t.Errorf("%s %s (auth=%v): status %d", m, p, hdr != nil, status)
				}
			}
		}
	}
	if calls := e.spy.snapshot(); len(calls) != 0 {
		t.Fatalf("unrecognized routes reached the Docker backend: %v", calls)
	}
	if calls := e.other.snapshot(); len(calls) != 0 {
		t.Fatalf("unrecognized routes reached the second backend: %v", calls)
	}
}

func TestUnknownMethodsAndQueriesOnKnownRoutesNeverReachDockerAndDefinedParametersStillWork(t *testing.T) {
	e := newEnv(t)
	tok := e.token("wildcard")
	for _, s := range api.Specs() {
		path := "/api/v1/endpoints/local/containers/edge-proxy/" + s.Segment
		for _, m := range []string{"PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", map[string]string{"GET": "POST", "POST": "GET"}[s.Method]} {
			status, hdr, body := rawDo(t, e, m, path, bearer(tok), nil)
			if status != http.StatusMethodNotAllowed || hdr.Get("Allow") != s.Method {
				t.Errorf("%s %s: %d allow=%q", m, path, status, hdr.Get("Allow"))
			}
			if m != "HEAD" && !strings.Contains(string(body), api.CodeMethodNotAllowed) {
				t.Errorf("%s %s: body %s", m, path, body)
			}
		}
		for _, q := range []string{"?all=1", "?force=true", "?v=1", "?path=/containers/json", "?x=1&y=2", "?access_token=" + tok, "?tail=5;all=1", "?%00=1"} {
			status, _, _ := rawDo(t, e, s.Method, path+q, bearer(tok), nil)
			if status != http.StatusBadRequest {
				t.Errorf("%s %s%s: %d, want 400", s.Method, path, q, status)
			}
		}
	}
	if calls := e.spy.snapshot(); len(calls) != 0 {
		t.Fatalf("unknown methods/queries reached the Docker backend: %v", calls)
	}
	// Control: the defined parameters of the same routes do work.
	if status, _, body := rawDo(t, e, "GET", "/api/v1/endpoints/local/containers/edge-proxy/logs?tail=1&stdout=true&stderr=true", bearer(tok), nil); status != 200 {
		t.Fatalf("control: %d %s", status, body)
	}
}

// N63B4 S05 / SB-10 and S08: agent bearer tokens never become cookies or assurance, no
// state-changing GET exists, cross-site browser requests are refused and no CORS is offered.
func TestBrowserBoundaryNoCookiesNoCORSNoStateChangingGETAndBearerNeverMintsASession(t *testing.T) {
	e := newEnv(t)
	tok := e.token("wildcard")
	for _, s := range api.Specs() {
		if s.Method == "GET" && !s.ReadOnly {
			t.Errorf("%s is a state-changing GET", s.Tool)
		}
	}
	e.spy.reset()
	for _, s := range api.Specs() {
		if s.Method != "GET" {
			continue
		}
		status, hdr, _ := rawDo(t, e, "GET", "/api/v1/endpoints/local/containers/edge-proxy/"+s.Segment+"?tail=1", bearer(tok), nil)
		if s.Segment != "logs" {
			status, hdr, _ = rawDo(t, e, "GET", "/api/v1/endpoints/local/containers/edge-proxy/"+s.Segment, bearer(tok), nil)
		}
		if status != 200 {
			t.Fatalf("GET %s: %d", s.Segment, status)
		}
		if len(hdr.Values("Set-Cookie")) != 0 {
			t.Errorf("GET %s set a cookie", s.Segment)
		}
	}
	for _, c := range e.spy.operationalCalls() {
		if c == "Start" || c == "Stop" || c == "Restart" {
			t.Fatalf("a GET performed %s", c)
		}
	}
	// Cross-site and cross-origin requests, with and without a valid token, simple or preflighted.
	for _, origin := range []string{"https://evil.example", "null", "http://127.0.0.1:1"} {
		for _, h := range []http.Header{bearer(tok), {}} {
			hdr := h.Clone()
			hdr.Set("Origin", origin)
			for _, req := range []struct{ m, p string }{
				{"GET", "/api/v1/endpoints/local/containers/edge-proxy/status"}, {"POST", "/api/v1/endpoints/local/containers/edge-proxy/stop"},
				{"OPTIONS", "/api/v1/endpoints/local/containers/edge-proxy/status"}, {"POST", "/mcp"}, {"GET", "/mcp"}, {"OPTIONS", "/mcp"}, {"GET", "/api/v1/readyz"},
			} {
				status, rh, _ := rawDo(t, e, req.m, req.p, hdr, nil)
				if status != http.StatusForbidden {
					t.Errorf("%s %s Origin=%s: %d", req.m, req.p, origin, status)
				}
				for k := range rh {
					if strings.HasPrefix(strings.ToLower(k), "access-control-") || strings.EqualFold(k, "Set-Cookie") {
						t.Errorf("%s %s answered with %s", req.m, req.p, k)
					}
				}
			}
		}
	}
	if n := len(e.spy.operationalCalls()); n != 3 { // only the three control GETs above
		t.Fatalf("operational calls %d", n)
	}
}

// ---- MCP-specific protocol behavior ----------------------------------------------------------

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`
const mcpAccept = "application/json, text/event-stream"

func mcpHeaders(tok string, extra ...string) http.Header {
	h := http.Header{"Content-Type": {"application/json"}, "Accept": {mcpAccept}}
	if tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		h.Set(extra[i], extra[i+1])
	}
	return h
}

func TestMCPEveryHTTPRequestIsAuthenticatedBeforeItsBodyIsParsed(t *testing.T) {
	e := newEnv(t)
	bodies := map[string]string{
		"initialize": initBody,
		"tools/list": `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		"tools/call": `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"container_status","arguments":{"endpoint":"local","container":"mandatary-self"}}}`,
		"ping":       `{"jsonrpc":"2.0","id":4,"method":"ping"}`,
		"batch":      `[{"jsonrpc":"2.0","id":5,"method":"tools/list"},{"jsonrpc":"2.0","id":6,"method":"ping"}]`,
		"garbage":    `{{{{`,
		"empty":      ``,
		"huge":       `{"x":"` + strings.Repeat("a", api.MaxMCPBodyBytes) + `"}`,
	}
	for name, body := range bodies {
		for _, tok := range []string{"", canonToken("nobody-has-this"), e.token("revoked"), e.token("importedquarantined"), e.token("disabledagent")} {
			status, hdr, data := rawDo(t, e, "POST", "/mcp", mcpHeaders(tok), []byte(body))
			if status != 401 || hdr.Get("WWW-Authenticate") == "" || !strings.Contains(string(data), api.CodeUnauthenticated) {
				t.Errorf("%s token=%q: %d %s", name, truncate(tok, 8), status, truncate(string(data), 100))
			}
		}
	}
	if n := e.spy.total(); n != 0 {
		t.Fatalf("unauthenticated MCP traffic reached the backend %d times", n)
	}
}

func TestMCPRouteMethodQueryOriginAndBodyBoundaries(t *testing.T) {
	e := newEnv(t)
	tok := e.token("granted")
	type tc struct {
		name           string
		method, target string
		hdr            http.Header
		body           string
		status         int
	}
	for _, c := range []tc{
		{"GET is unsupported (stateless server)", "GET", "/mcp", mcpHeaders(tok, "Accept", "text/event-stream"), "", 405},
		{"DELETE is unsupported", "DELETE", "/mcp", mcpHeaders(tok), "", 405},
		{"PUT", "PUT", "/mcp", mcpHeaders(tok), initBody, 405},
		{"OPTIONS preflight", "OPTIONS", "/mcp", mcpHeaders(tok), "", 405},
		{"trailing slash is another path", "POST", "/mcp/", mcpHeaders(tok), initBody, 404},
		{"subpath", "POST", "/mcp/tools", mcpHeaders(tok), initBody, 404},
		{"query on the route", "POST", "/mcp?session=1", mcpHeaders(tok), initBody, 400},
		{"empty query marker", "POST", "/mcp?", mcpHeaders(tok), initBody, 400},
		{"token in the query only", "POST", "/mcp?access_token=" + tok, mcpHeaders(""), initBody, 401},
		{"foreign origin", "POST", "/mcp", mcpHeaders(tok, "Origin", "https://evil.example"), initBody, 403},
		{"null origin", "POST", "/mcp", mcpHeaders(tok, "Origin", "null"), initBody, 403},
		{"oversized body", "POST", "/mcp", mcpHeaders(tok), `{"x":"` + strings.Repeat("a", api.MaxMCPBodyBytes) + `"}`, 413},
		{"not json", "POST", "/mcp", mcpHeaders(tok), `{{{{`, 400},
		{"wrong content type", "POST", "/mcp", mcpHeaders(tok, "Content-Type", "text/plain"), initBody, 415},
		{"accept without event-stream", "POST", "/mcp", mcpHeaders(tok, "Accept", "application/json"), initBody, 400},
		{"unsupported protocol version header", "POST", "/mcp", mcpHeaders(tok, "MCP-Protocol-Version", "1999-01-01"), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, 400},
		{"no session id is ever issued or required", "POST", "/mcp", mcpHeaders(tok), initBody, 200},
	} {
		status, hdr, data := rawDo(t, e, c.method, c.target, c.hdr, []byte(c.body))
		if status != c.status {
			t.Errorf("%s: %d %s, want %d", c.name, status, truncate(string(data), 120), c.status)
		}
		if hdr.Get("Mcp-Session-Id") != "" {
			t.Errorf("%s: the stateless server issued a session id", c.name)
		}
		for k := range hdr {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s: CORS header %s", c.name, k)
			}
		}
	}
	if n := len(e.spy.operationalCalls()); n != 0 {
		t.Fatalf("%d operational calls", n)
	}
}

func listTools(t *testing.T, e *env, tok string) []*mcp.Tool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _, err := connectMCP(ctx, e, func(h http.Header) { h.Set("Authorization", "Bearer "+tok) })
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Tools
}

func TestMCPToolCatalogIsExactlyTheSixStrictToolsAndListingIsNotAuthorization(t *testing.T) {
	e := newEnv(t)
	want := map[string]api.Spec{}
	for _, s := range api.Specs() {
		want[s.Tool] = s
	}
	// The catalog is identical for an agent with every grant and one with none.
	var catalogs []string
	for _, key := range []string{"granted", "nogrant", "adminowned", "wildcard"} {
		tools := listTools(t, e, e.token(key))
		if len(tools) != len(want) || len(tools) != 6 {
			t.Fatalf("%s lists %d tools", key, len(tools))
		}
		for _, tool := range tools {
			spec, ok := want[tool.Name]
			if !ok {
				t.Fatalf("%s lists unapproved tool %q", key, tool.Name)
			}
			schema, _ := json.Marshal(tool.InputSchema)
			golden, _ := json.Marshal(apimcp.InputSchema(spec.Operation))
			if !jsonEqual(schema, golden) {
				t.Fatalf("%s schema differs from the contract:\n%s\n%s", tool.Name, schema, golden)
			}
			var m map[string]any
			_ = json.Unmarshal(schema, &m)
			if m["additionalProperties"] != false || m["type"] != "object" {
				t.Fatalf("%s schema is not closed: %s", tool.Name, schema)
			}
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != spec.ReadOnly || (tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint) {
				t.Fatalf("%s annotations %+v", tool.Name, tool.Annotations)
			}
		}
		b, _ := json.Marshal(tools)
		catalogs = append(catalogs, string(b))
	}
	for _, c := range catalogs[1:] {
		if c != catalogs[0] {
			t.Fatal("the tool catalog differs by principal: listing must reveal nothing about authorization")
		}
	}
	// ...and calling any listed tool as the agent with no grant is denied with zero operational calls.
	e.spy.reset()
	for _, tool := range sixTools {
		o := mcpTransport{}.do(t, e, req(e.token("nogrant"), tool, "edge-proxy"))
		if !o.sameClass(denied(api.ReasonDefaultDeny).outcome()) {
			t.Fatalf("%s: %s", tool, o)
		}
	}
	if n := len(e.spy.operationalCalls()); n != 0 {
		t.Fatalf("%d operational calls for an agent with no grant", n)
	}
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && fmt.Sprint(x) == fmt.Sprint(y)
}

func TestMCPServerAdvertisesOnlyToolsAndNoHiddenFeatures(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, _, err := connectMCP(ctx, e, func(h http.Header) { h.Set("Authorization", "Bearer "+e.token("wildcard")) })
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	init := cs.InitializeResult()
	if init.ServerInfo.Name != "mandatary" || init.ServerInfo.Version != api.ContractVersion {
		t.Fatalf("server info %+v", init.ServerInfo)
	}
	caps := init.Capabilities
	if caps.Tools == nil || caps.Prompts != nil || caps.Resources != nil || caps.Logging != nil || caps.Completions != nil || caps.Experimental != nil {
		t.Fatalf("capabilities %+v: only tools may be advertised", caps)
	}
	// The SDK answers these with empty lists even when the capability is not advertised;
	// what matters is that nothing is served.
	if r, err := cs.ListPrompts(ctx, nil); err == nil && len(r.Prompts) != 0 {
		t.Errorf("prompts are served: %d", len(r.Prompts))
	}
	if r, err := cs.ListResources(ctx, nil); err == nil && len(r.Resources) != 0 {
		t.Errorf("resources are served: %d", len(r.Resources))
	}
	if r, err := cs.ListResourceTemplates(ctx, nil); err == nil && len(r.ResourceTemplates) != 0 {
		t.Errorf("resource templates are served: %d", len(r.ResourceTemplates))
	}
	if n := e.spy.total(); n != 0 {
		t.Fatalf("protocol-level traffic reached the backend %d times", n)
	}
}

// Authority is per HTTP request: there is no MCP session that can carry one request's
// identity into the next, outlive a revocation, or be replayed under another token.
func TestMCPAuthorityIsEvaluatedPerRequestAndNeverCarriedByASession(t *testing.T) {
	e := newEnv(t)
	var current atomic.Value
	current.Store(e.token("granted"))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, rec, err := connectMCP(ctx, e, func(h http.Header) { h.Set("Authorization", "Bearer "+current.Load().(string)) })
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	callStatus := func(container string) (*mcp.CallToolResult, error) {
		return cs.CallTool(ctx, &mcp.CallToolParams{Name: "container_status", Arguments: map[string]any{"endpoint": "local", "container": container}})
	}
	res, err := callStatus("edge-proxy")
	if err != nil || res.IsError {
		t.Fatalf("granted: %v %+v", err, res)
	}
	current.Store(e.token("nogrant")) // the very same MCP client session now carries another token
	res, err = callStatus("edge-proxy")
	if err != nil || !res.IsError || mcpResult(t, res).Reason != api.ReasonDefaultDeny {
		t.Fatalf("a session must not carry the first request's authority: %v %+v", err, res)
	}
	current.Store(e.token("granted"))
	e.exec(`UPDATE agent_credentials SET state='revoked', revoked_at=? WHERE id=?`, e.clock.Now().Unix(), e.agents["granted"].credID)
	if _, err = callStatus("edge-proxy"); err == nil {
		t.Fatal("a revoked token was accepted on an established MCP session")
	}
	if f, ok := rec.firstFailure(); !ok || f.status != 401 {
		t.Fatalf("revoked token: %+v", f)
	}
	if n := len(e.spy.operationalCalls()); n != 1 { // only the first, granted call
		t.Fatalf("operational calls %d", n)
	}
}

// Concurrent traffic over both transports, with revocation racing it, under -race.
func TestConcurrentRequestsOverBothTransportsAndRevocationAreRaceFree(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	var okCount, deniedCount atomic.Int64
	run := func(tr transport, key string) {
		defer wg.Done()
		for i := 0; i < 15; i++ {
			o := tr.do(t, e, req(e.token(key), "container_status", "edge-proxy"))
			switch o.Status {
			case 200:
				okCount.Add(1)
			case 401, 403:
				deniedCount.Add(1)
			default:
				t.Errorf("%s: %s", tr.name(), o)
			}
		}
	}
	for _, tr := range transports {
		wg.Add(2)
		go run(tr, "granted")
		go run(tr, "nogrant")
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.exec(`UPDATE agent_credentials SET state='revoked', revoked_at=? WHERE id=?`, e.clock.Now().Unix(), e.agents["granted"].credID)
		_ = e.svc.NotifyAuthorityChange(context.Background())
	}()
	wg.Wait()
	if okCount.Load()+deniedCount.Load() != 4*15 {
		t.Fatalf("ok=%d denied=%d", okCount.Load(), deniedCount.Load())
	}
	// After the revocation every request with that token is refused on both transports.
	for _, tr := range transports {
		if o := tr.do(t, e, req(e.token("granted"), "container_status", "edge-proxy")); o.Status != 401 {
			t.Fatalf("%s after revocation: %s", tr.name(), o)
		}
	}
}

func TestNoSecretOrTokenIsEverEchoedByAnyAdapterResponse(t *testing.T) {
	e := newEnv(t)
	tok := e.token("granted")
	for _, tr := range transports {
		for _, c := range []call{
			req(tok, "container_config", "edge-proxy"),
			req(tok, "container_status", "edge-proxy"),
			req(tok, "container_status", "mandatary-self"),
			req(canonToken("nobody-has-this"), "container_status", "edge-proxy"),
			req(tok, "container_status", "x y z"),
			req(tok, "container_status", "edge-proxy", a(tok, 1)), // the token used as an unknown field name
			req(tok, "container_logs", "edge-proxy", a("since", tok)),
		} {
			o := tr.do(t, e, c)
			assertNoSecrets(t, tr.name(), o.String())
			if strings.Contains(o.String(), tok) || strings.Contains(o.String(), tok[4:]) {
				t.Errorf("%s echoed the token: %s", tr.name(), o)
			}
		}
	}
	_ = docker.OpLogs
}
