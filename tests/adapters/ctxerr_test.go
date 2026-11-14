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
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// rawResponse performs one call and returns the status and the COMPLETE wire body, so a
// leak anywhere in the response (message, structured content, text content) is visible.
func rawResponse(t *testing.T, tr transport, e *env, c call) (int, string) {
	t.Helper()
	switch tr.(type) {
	case restTransport:
		method, segment, _ := restRoute(c.op)
		u := e.srv.URL + "/api/v1/endpoints/" + url.PathEscape(c.endpoint) + "/containers/" + url.PathEscape(c.container) + "/" + segment
		var body io.Reader
		if len(c.args) > 0 {
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
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	default:
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cs, _, err := connectMCP(ctx, e, func(h http.Header) { applyHeaders(h, c) })
		if err != nil {
			t.Fatalf("MCP connect: %v", err)
		}
		defer func() { _ = cs.Close() }()
		args := map[string]any{"endpoint": c.endpoint, "container": c.container}
		for k, v := range c.args {
			args[k] = v
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: c.op, Arguments: args})
		if err != nil {
			t.Fatalf("MCP CallTool %s: %v", c.op, err)
		}
		wire, _ := json.Marshal(res)
		o := mcpResult(t, res)
		if !res.IsError {
			return o.Status, string(wire)
		}
		return o.Status, string(wire)
	}
}

// P1.18.4 P113-L2: the actual Classify contract over the real REST and structured-MCP
// adapters for every one of the six keys: a backend error that is (or wraps) a context
// cancellation is canceled/499, one that is (or wraps) a deadline is timeout/504, each
// with the SAME code and fixed message on both transports; never forbidden/denied; the
// cause text never reaches the wire; exactly one accounted outcome (error) per call, so
// no double accounting. Joined cancel+deadline is sanitized by the shared service with
// Canceled first (docker.SanitizeError), which the adapters then map to canceled/499.
func TestContextErrorsMapToCanceled499AndTimeout504OnBothTransportsAndNeverToForbidden(t *testing.T) {
	const canary = "CANARY_CAUSE_P1184_SECRET_0123456789"
	causes := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"canceled", fmt.Errorf("%s: %w", canary, context.Canceled), 499, api.CodeCanceled},
		{"deadline", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), 504, api.CodeTimeout},
		{"joined-cancel-deadline", errors.Join(errors.New(canary), context.DeadlineExceeded, context.Canceled), 499, api.CodeCanceled},
	}
	for _, tr := range transports {
		for _, cause := range causes {
			for _, tool := range sixTools {
				// A fresh world per call: the mock (like the SDK adapter) reads a context error
				// from an operational call as a fault of the whole endpoint and drops the safety
				// proof, so a second call in the same world would be refused for that reason.
				t.Run(tr.name()+"/"+cause.name+"/"+tool, func(t *testing.T) {
					e := newEnv(t, func(o *envOptions) { o.usage = true })
					for _, op := range []docker.Operation{docker.OpInspectStatus, docker.OpInspectConfig, docker.OpLogs, docker.OpStart, docker.OpStop, docker.OpRestart} {
						e.mock.SetOperationFailure(op, cause.err)
					}
					status, wire := rawResponse(t, tr, e, req(e.token("granted"), tool, "edge-proxy"))
					if strings.Contains(wire, canary) || strings.Contains(wire, e.token("granted")) {
						t.Fatalf("cause or credential leaked: %s", wire)
					}
					if tr.name() == "REST" {
						if status != cause.status {
							t.Fatalf("REST status %d, want %d (%s)", status, cause.status, wire)
						}
						o := errOutcome(status, []byte(wire))
						if o.Code != cause.code || o.Reason != "" {
							t.Fatalf("outcome %v, want code %s and no reason", o, cause.code)
						}
					} else {
						// Structured MCP tool error: the same code, status and fixed message.
						var res struct {
							IsError           bool `json:"isError"`
							StructuredContent struct {
								Error struct {
									Status int    `json:"status"`
									Code   string `json:"code"`
									Reason string `json:"reason"`
								} `json:"error"`
							} `json:"structuredContent"`
						}
						if err := json.Unmarshal([]byte(wire), &res); err != nil || !res.IsError {
							t.Fatalf("MCP result is not a structured tool error: %v %s", err, wire)
						}
						if got := res.StructuredContent.Error; got.Status != cause.status || got.Code != cause.code || got.Reason != "" {
							t.Fatalf("MCP error %+v, want %d %s", got, cause.status, cause.code)
						}
					}
					if strings.Contains(wire, `"`+api.CodeForbidden+`"`) || strings.Contains(wire, "default_deny") {
						t.Fatalf("a context error was reported as forbidden/denied: %s", wire)
					}
					rows, err := e.ledger.Rollups(t.Context(), store.UsageHourly)
					if err != nil {
						t.Fatal(err)
					}
					var allowed, denied, errCount int64
					for _, r := range rows {
						allowed, denied, errCount = allowed+r.Allowed, denied+r.Denied, errCount+r.Error
					}
					if allowed != 0 || denied != 0 || errCount != 1 {
						t.Fatalf("accounting allowed=%d denied=%d error=%d, want exactly one error and nothing else", allowed, denied, errCount)
					}
				})
			}
		}
	}
}
