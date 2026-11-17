package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/logging"
	apimcp "github.com/NicoTM77/Mandatary/internal/mcp"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// P1.20 review 519 F2: the product server's WriteTimeout is 10 s, a stop or restart is allowed
// timeout_seconds + StopGrace (25 s by default). These tests run the REAL serverFor, the REAL REST and MCP
// handlers and a real MCP client over a real listener, with an executor that behaves like the shared
// service (it announces the dispatch bound only for an admitted stop/restart; the real service's
// announcements are pinned in internal/ops/dispatch_observer_test.go) and takes longer than the server's
// bound to answer, like a daemon stopping a container that ignores SIGTERM.

const (
	slowStopToken = "mdt_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	// slowStopDelay is longer than the server's 10 s write bound (main.go serverFor).
	slowStopDelay = 10500 * time.Millisecond
	slowStopBound = 10*time.Second + ops.DefaultStopGrace // the default stop dispatch bound
)

type slowStopExecutor struct {
	announce bool          // behave like an admitted request: tell the transport the bound
	delay    time.Duration // how long the "daemon" takes
	calls    atomic.Int64
}

func (s *slowStopExecutor) Execute(ctx context.Context, req ops.Request) (ops.Result, error) {
	s.calls.Add(1)
	if s.announce {
		if observe := ops.DispatchObserverFrom(ctx); observe != nil {
			observe(slowStopBound)
		}
	}
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return ops.Result{}, ctx.Err()
	}
	target := docker.TargetIdentity{EndpointID: req.EndpointID, ContainerID: docker.ContainerID(strings.Repeat("a", 64))}
	return ops.Result{Target: target, ContainerName: req.Target, Operation: req.Operation}, nil
}

type slowStopAuth struct{}

func (slowStopAuth) Authenticate(_ context.Context, creds authz.PrincipalCredentials) error {
	if creds.AgentToken != slowStopToken {
		return authz.ErrUnauthenticated
	}
	return nil
}

// startSlowStopServer serves the composed REST+MCP surface through the real serverFor.
func startSlowStopServer(t *testing.T, exec *slowStopExecutor) string {
	t.Helper()
	ep := domain.EndpointID("00000000-0000-4000-8000-000000000001")
	gw, err := api.NewGateway(api.GatewayConfig{Executor: exec, Authenticator: slowStopAuth{}, Endpoints: map[string]domain.EndpointID{"local": ep}})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.NewHandler(api.Config{Gateway: gw, Ready: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	mcpHandler, err := apimcp.NewHandler(apimcp.Config{Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}
	logger, err := logging.New(io.Discard, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}
	srv := serverFor("127.0.0.1:0", logger, api.Compose(rest, mcpHandler, http.NotFoundHandler()))
	if srv.WriteTimeout != 10*time.Second {
		t.Fatalf("this regression is about the 10 s server write bound, serverFor has %v", srv.WriteTimeout)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

type slowStopOutcome struct {
	status  int
	outcome string // the "outcome" field of a completed action
	err     error  // a transport failure: the server cut the response off
	took    time.Duration
}

func slowStopREST(base, op, token string) slowStopOutcome {
	start := time.Now()
	req, _ := http.NewRequest(http.MethodPost, base+api.BasePath+"/endpoints/local/containers/edge-proxy/"+op, bytes.NewReader(nil))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return slowStopOutcome{err: err, took: time.Since(start)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	out := slowStopOutcome{status: resp.StatusCode, err: err, took: time.Since(start)}
	var v struct {
		Outcome string `json:"outcome"`
	}
	if json.Unmarshal(body, &v) == nil {
		out.outcome = v.Outcome
	}
	return out
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return (&http.Transport{DisableKeepAlives: true}).RoundTrip(r)
}

func slowStopMCP(t *testing.T, base, tool string) slowStopOutcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // hang guard only
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "write-deadline-test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             base + api.MCPPath,
		HTTPClient:           &http.Client{Transport: bearerTransport{token: slowStopToken}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	start := time.Now()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{"endpoint": "local", "container": "edge-proxy"}})
	out := slowStopOutcome{err: err, took: time.Since(start)}
	if err == nil {
		out.status = http.StatusOK
		if res.IsError {
			out.status = http.StatusBadGateway
		}
		raw, _ := json.Marshal(res.StructuredContent)
		var v struct {
			Outcome string `json:"outcome"`
		}
		_ = json.Unmarshal(raw, &v)
		out.outcome = v.Outcome
	}
	return out
}

// P120-F2-01: an admitted stop or restart that outlives the server's 10 s write bound still delivers its
// result, on REST and on MCP. Before the fix the client got an EOF (a 502 with an empty body behind the
// shipped proxy) for an operation the daemon had executed and the service had counted as allowed.
func TestAdmittedStopAndRestartDeliverTheirResultPastTheServerWriteBound(t *testing.T) {
	for _, op := range []string{"stop", "restart"} {
		t.Run("rest/"+op, func(t *testing.T) {
			t.Parallel()
			exec := &slowStopExecutor{announce: true, delay: slowStopDelay}
			base := startSlowStopServer(t, exec)
			got := slowStopREST(base, op, slowStopToken)
			if got.err != nil || got.status != http.StatusOK || got.outcome != "completed" {
				t.Fatalf("REST %s took %v: status %d outcome %q err %v; want 200 completed", op, got.took, got.status, got.outcome, got.err)
			}
			if got.took < 10*time.Second {
				t.Fatalf("the executor answered in %v: this test no longer outlives the 10 s write bound", got.took)
			}
		})
		t.Run("mcp/"+op, func(t *testing.T) {
			t.Parallel()
			exec := &slowStopExecutor{announce: true, delay: slowStopDelay}
			base := startSlowStopServer(t, exec)
			got := slowStopMCP(t, base, "container_"+op)
			if got.err != nil || got.status != http.StatusOK || got.outcome != "completed" {
				t.Fatalf("MCP %s took %v: status %d outcome %q err %v; want a completed result", op, got.took, got.status, got.outcome, got.err)
			}
			if got.took < 10*time.Second {
				t.Fatalf("the executor answered in %v: this test no longer outlives the 10 s write bound", got.took)
			}
		})
	}
}

// P120-F2-02 (negative controls): nothing gives a request more time on its own. A request the service
// did not admit (it never announced a bound: denied, refused, unverified) that runs past the server's
// bound is cut off exactly as before, and an unauthenticated request never reaches the executor at all.
func TestUnadmittedRequestsKeepTheServerWriteBound(t *testing.T) {
	for _, op := range []string{"stop", "restart"} {
		t.Run("rest/"+op+"/never-announced", func(t *testing.T) {
			t.Parallel()
			exec := &slowStopExecutor{announce: false, delay: slowStopDelay}
			got := slowStopREST(startSlowStopServer(t, exec), op, slowStopToken)
			if got.err == nil {
				t.Fatalf("a request that was never admitted got an answer (%d) after %v: it must keep the 10 s bound", got.status, got.took)
			}
			if got.took > 12*time.Second {
				t.Fatalf("cut off after %v, want about 10 s", got.took)
			}
		})
		t.Run("mcp/"+op+"/never-announced", func(t *testing.T) {
			t.Parallel()
			exec := &slowStopExecutor{announce: false, delay: slowStopDelay}
			got := slowStopMCP(t, startSlowStopServer(t, exec), "container_"+op)
			if got.err == nil && got.outcome == "completed" {
				t.Fatalf("a request that was never admitted completed after %v: it must keep the 10 s bound", got.took)
			}
		})
		t.Run("rest/"+op+"/unauthenticated", func(t *testing.T) {
			t.Parallel()
			exec := &slowStopExecutor{announce: true, delay: slowStopDelay}
			base := startSlowStopServer(t, exec)
			for name, token := range map[string]string{"no-token": "", "unknown-token": "mdt_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"} {
				got := slowStopREST(base, op, token)
				if got.err != nil || got.status != http.StatusUnauthorized {
					t.Fatalf("%s: status %d err %v, want a prompt 401", name, got.status, got.err)
				}
				if got.took > 2*time.Second {
					t.Fatalf("the 401 took %v", got.took)
				}
			}
			if n := exec.calls.Load(); n != 0 {
				t.Fatalf("an unauthenticated request reached the executor %d times", n)
			}
		})
	}
}
