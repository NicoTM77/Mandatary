package adapters_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
)

// call is one transport-neutral request of the matrix. op is an MCP tool name (the six
// are mapped to their REST route; anything else is an unsupported operation).
type call struct {
	token     string
	headers   http.Header // extra/raw header overrides: Authorization key replaces the token
	noAuth    bool
	op        string
	endpoint  string
	container string
	args      map[string]any
}

// outcome is what a caller observes, identical for both transports.
type outcome struct {
	Status  int            `json:"status"`
	Code    string         `json:"code,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}

func (o outcome) String() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func (o outcome) sameClass(p outcome) bool {
	return o.Status == p.Status && o.Code == p.Code && o.Reason == p.Reason
}

func (o outcome) samePayload(p outcome) bool {
	return reflect.DeepEqual(norm(o.Payload), norm(p.Payload))
}

func norm(v map[string]any) map[string]any {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func errOutcome(status int, body []byte) outcome {
	var eb api.ErrorBody
	if err := json.Unmarshal(body, &eb); err != nil || eb.Error.Code == "" {
		return outcome{Status: status, Code: "UNPARSEABLE:" + truncate(string(body), 80)}
	}
	return outcome{Status: eb.Error.Status, Code: eb.Error.Code, Reason: eb.Error.Reason}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// transport executes one call and returns the outcome.
type transport interface {
	name() string
	do(t *testing.T, e *env, c call) outcome
}

// ---- REST over real HTTP ---------------------------------------------------------------

type restTransport struct{}

func (restTransport) name() string { return "REST" }

func restRoute(op string) (method, segment string, ok bool) {
	for _, s := range api.Specs() {
		if s.Tool == op {
			return s.Method, s.Segment, true
		}
	}
	return "", "", false
}

func (restTransport) do(t *testing.T, e *env, c call) outcome {
	t.Helper()
	method, segment, known := restRoute(c.op)
	if !known { // an unsupported operation is a route that does not exist
		method, segment = "POST", strings.TrimPrefix(c.op, "container_")
	}
	u := e.srv.URL + "/api/v1/endpoints/" + url.PathEscape(c.endpoint) + "/containers/" + url.PathEscape(c.container) + "/" + segment
	var body io.Reader
	if known && len(c.args) > 0 {
		if method == "GET" {
			q := url.Values{}
			for k, v := range c.args {
				q.Set(k, fmt.Sprint(v))
			}
			u += "?" + q.Encode()
		} else {
			b, _ := json.Marshal(c.args)
			body = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	applyHeaders(req.Header, c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("REST %s %s: %v", method, u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatalf("REST success body is not an object: %q", data)
		}
		return outcome{Status: 200, Payload: payload}
	}
	return errOutcome(resp.StatusCode, data)
}

func applyHeaders(h http.Header, c call) {
	if !c.noAuth && c.token != "" {
		h.Set("Authorization", "Bearer "+c.token)
	}
	for k, vs := range c.headers {
		h.Del(k)
		for _, v := range vs {
			h.Add(k, v)
		}
	}
}

// ---- MCP over real Streamable HTTP with the official go-sdk client ----------------------

type mcpTransport struct{}

func (mcpTransport) name() string { return "MCP" }

// recorder is the HTTP round tripper of the MCP client: it injects the case's headers and
// records every non-2xx response so a rejection at the HTTP layer (401, 403) is observable
// whichever way the client surfaces it.
type recorder struct {
	mu      sync.Mutex
	headers func(h http.Header)
	failed  []recorded
	last    int
}

type recorded struct {
	status int
	body   []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if r.headers != nil {
		r.headers(req.Header)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.last = resp.StatusCode
	r.mu.Unlock()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		r.mu.Lock()
		r.failed = append(r.failed, recorded{resp.StatusCode, data})
		r.mu.Unlock()
	}
	return resp, nil
}

func (r *recorder) firstFailure() (recorded, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.failed) == 0 {
		return recorded{}, false
	}
	return r.failed[0], true
}

// connect opens a real MCP client session (initialize + initialized) over HTTP.
func connectMCP(ctx context.Context, e *env, headers func(http.Header)) (*mcp.ClientSession, *recorder, error) {
	rec := &recorder{headers: headers}
	client := mcp.NewClient(&mcp.Implementation{Name: "adapters-matrix-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             e.srv.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: rec},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	return cs, rec, err
}

func (mcpTransport) do(t *testing.T, e *env, c call) outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // hang guard only
	defer cancel()
	cs, rec, err := connectMCP(ctx, e, func(h http.Header) { applyHeaders(h, c) })
	if err != nil {
		if f, ok := rec.firstFailure(); ok {
			return errOutcome(f.status, f.body)
		}
		t.Fatalf("MCP connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	args := map[string]any{"endpoint": c.endpoint, "container": c.container}
	for k, v := range c.args {
		args[k] = v
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: c.op, Arguments: args})
	if err != nil {
		var je *jsonrpc.Error
		if errors.As(err, &je) && je.Code == jsonrpc.CodeInvalidParams && strings.Contains(je.Message, "unknown tool") {
			return outcome{Status: 404, Code: api.CodeNotFound} // a protocol error that reached nothing
		}
		if f, ok := rec.firstFailure(); ok {
			return errOutcome(f.status, f.body)
		}
		t.Fatalf("MCP CallTool %s: %v", c.op, err)
	}
	return mcpResult(t, res)
}

func mcpResult(t *testing.T, res *mcp.CallToolResult) outcome {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		return errOutcome(0, b)
	}
	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("MCP success structured content is not an object: %s", b)
	}
	return outcome{Status: 200, Payload: payload}
}

var transports = []transport{restTransport{}, mcpTransport{}}

// ---- expectations ------------------------------------------------------------------------

// reach states how far a request may go. The spy measures it.
type reach int

const (
	reachNothing     reach = iota // zero backend calls of ANY kind (not even a target lookup)
	reachLookupOnly               // authorization may resolve a target; zero operational calls
	reachExactlyOnce              // exactly one operational call, of the requested operation
)

type want struct {
	status int
	code   string
	reason string
	reach  reach
}

func ok() want { return want{status: 200, reach: reachExactlyOnce} }
func denied(reason string) want {
	return want{status: 403, code: api.CodeForbidden, reason: reason, reach: reachLookupOnly}
}
func unauth() want { return want{status: 401, code: api.CodeUnauthenticated, reach: reachNothing} }
func invalid() want {
	return want{status: 400, code: api.CodeInvalidRequest, reach: reachNothing}
}
func notFound() want { return want{status: 404, code: api.CodeNotFound, reach: reachNothing} }

func (w want) outcome() outcome { return outcome{Status: w.status, Code: w.code, Reason: w.reason} }

// matrixCase is one row of the identical positive/negative matrix.
type matrixCase struct {
	id string
	c  call
	w  want
}

// runMatrix runs every case through BOTH transports against the same environment and
// proves, per case: the outcome class equals the expectation, the spy measured the
// promised reach, and the two transports agree exactly (class and success payload).
func runMatrix(t *testing.T, e *env, cases []matrixCase) {
	t.Helper()
	seen := map[string]bool{}
	for _, mc := range cases {
		if seen[mc.id] {
			t.Fatalf("duplicate case id %s", mc.id)
		}
		seen[mc.id] = true
		t.Run(mc.id, func(t *testing.T) {
			got := map[string]outcome{}
			for _, tr := range transports {
				e.spy.reset()
				e.other.reset()
				o := tr.do(t, e, mc.c)
				got[tr.name()] = o
				if !o.sameClass(mc.w.outcome()) {
					t.Errorf("%s: got %s, want %s", tr.name(), o, mc.w.outcome())
				}
				checkReach(t, tr.name(), e, mc)
				if o.Status == 200 {
					if len(o.Payload) == 0 {
						t.Errorf("%s: empty success payload", tr.name())
					}
					assertNoSecrets(t, tr.name(), o.String())
				}
			}
			if a, b := got["REST"], got["MCP"]; !a.sameClass(b) || !a.samePayload(b) {
				t.Errorf("transport parity broken:\n  REST %s\n  MCP  %s", a, b)
			}
		})
	}
}

func checkReach(t *testing.T, name string, e *env, mc matrixCase) {
	t.Helper()
	calls := append(e.spy.snapshot(), e.other.snapshot()...)
	opCalls := append(e.spy.operationalCalls(), e.other.operationalCalls()...)
	switch mc.w.reach {
	case reachNothing:
		if len(calls) != 0 {
			t.Errorf("%s: reached the Docker backend %v, want nothing (not even a lookup)", name, calls)
		}
	case reachLookupOnly:
		if len(opCalls) != 0 {
			t.Errorf("%s: operational Docker calls %v on a denied request", name, opCalls)
		}
	case reachExactlyOnce:
		wantCall := map[string]string{
			"container_status": "InspectStatus", "container_config": "InspectConfig", "container_logs": "Logs",
			"container_start": "Start", "container_stop": "Stop", "container_restart": "Restart",
		}[mc.c.op]
		if len(opCalls) != 1 || opCalls[0] != wantCall {
			t.Errorf("%s: operational calls %v, want exactly [%s]", name, opCalls, wantCall)
		}
	}
}

var secretPatterns = []string{canaryEnv, "DATABASE_PASSWORD=" + canaryEnv, "mdt_"}

func assertNoSecrets(t *testing.T, name, text string) {
	t.Helper()
	for _, s := range secretPatterns {
		if strings.Contains(text, s) {
			t.Errorf("%s: response contains secret material %q", name, s)
		}
	}
}
