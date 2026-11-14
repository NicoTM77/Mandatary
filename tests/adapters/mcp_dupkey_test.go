package adapters_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// mcpWire is a minimal raw Streamable-HTTP MCP client. It sends the EXACT bytes given,
// so a request with a duplicated JSON object key reaches the real HTTP adapter, the
// official go-sdk decoder and the tool handler unchanged (a typed client cannot spell it).
type mcpWire struct {
	t       *testing.T
	url     string
	token   string
	session string
}

func newMCPWire(t *testing.T, e *env, token string) *mcpWire {
	t.Helper()
	w := &mcpWire{t: t, url: e.srv.URL + "/mcp", token: token}
	status, _, hdr := w.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"dupkey","version":"1"}}}`)
	if status != http.StatusOK {
		t.Fatalf("initialize: HTTP %d", status)
	}
	w.session = hdr.Get("Mcp-Session-Id")
	if status, _, _ := w.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); status != http.StatusAccepted && status != http.StatusOK {
		t.Fatalf("initialized: HTTP %d", status)
	}
	return w
}

func (w *mcpWire) post(body string) (int, string, http.Header) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader([]byte(body)))
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+w.token)
	if w.session != "" {
		req.Header.Set("Mcp-Session-Id", w.session)
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header
}

// toolError extracts the structured tool error (or the JSON-RPC error) of a tools/call
// answer, which may arrive as plain JSON or as one SSE event.
func toolError(t *testing.T, raw string) (code string, status int, isToolError bool, rpcCode int) {
	t.Helper()
	payload := raw
	if i := strings.Index(raw, "data:"); i >= 0 {
		payload = strings.TrimSpace(raw[i+len("data:"):])
		if j := strings.IndexByte(payload, '\n'); j >= 0 {
			payload = payload[:j]
		}
	}
	var msg struct {
		Error  *struct{ Code int } `json:"error"`
		Result *struct {
			IsError           bool `json:"isError"`
			StructuredContent struct {
				Error struct {
					Code   string `json:"code"`
					Status int    `json:"status"`
				} `json:"error"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		t.Fatalf("unparseable MCP answer %q: %v", raw, err)
	}
	if msg.Error != nil {
		return "", 0, false, msg.Error.Code
	}
	if msg.Result == nil {
		t.Fatalf("MCP answer has neither result nor error: %q", raw)
	}
	return msg.Result.StructuredContent.Error.Code, msg.Result.StructuredContent.Error.Status, msg.Result.IsError, 0
}

// P1.18.4 P114-I3: duplicate JSON object keys are rejected by the SHARED strict decoder on
// the MCP transport too, proven on the wire through the real HTTP adapter and the official
// SDK (not by calling the helper): a duplicate top-level key, a duplicate identifier that
// would retarget the call, and a nested object with duplicate keys all produce the same
// sanitized invalid_request (400) tool error as REST, no backend call of any kind and no
// usage event. The non-duplicate control reaches exactly one stop.
func TestMCPDuplicateObjectKeysAreRejectedOnTheWireWithZeroBackendAndUsageEffect(t *testing.T) {
	call := func(args string) string {
		return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"container_stop","arguments":` + args + `}}`
	}
	cases := []struct {
		name string
		args string
	}{
		{"duplicate-parameter", `{"endpoint":"local","container":"edge-proxy","timeout_seconds":5,"timeout_seconds":6}`},
		{"duplicate-container-identifier-retargets", `{"endpoint":"local","container":"edge-proxy","container":"billing-worker","timeout_seconds":5}`},
		{"duplicate-endpoint-identifier", `{"endpoint":"local","endpoint":"remote-2","container":"edge-proxy"}`},
		{"nested-object-with-duplicate-keys", `{"endpoint":"local","container":"edge-proxy","timeout_seconds":{"v":5,"v":6}}`},
		{"nested-duplicate-inside-array", `{"endpoint":"local","container":"edge-proxy","timeout_seconds":[{"v":1,"v":2}]}`},
		{"duplicate-key-with-same-value", `{"endpoint":"local","container":"edge-proxy","timeout_seconds":5,"timeout_seconds":5}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(o *envOptions) { o.usage = true })
			w := newMCPWire(t, e, e.token("granted"))
			e.spy.reset()
			status, raw, _ := w.post(call(tc.args))
			if status != http.StatusOK {
				t.Fatalf("HTTP %d %q", status, raw)
			}
			code, st, isToolErr, rpcCode := toolError(t, raw)
			// The adapter reports it as the common invalid_request tool error; a JSON-RPC
			// invalid params error is the other sanitized rejection and is equally accepted
			// as long as nothing was dispatched.
			if !((isToolErr && code == api.CodeInvalidRequest && st == 400) || rpcCode == -32602 || rpcCode == -32600) {
				t.Fatalf("want sanitized invalid_request/invalid_params, got tool=%v code=%q status=%d rpc=%d: %q", isToolErr, code, st, rpcCode, raw)
			}
			if n := e.spy.total(); n != 0 {
				t.Fatalf("%d backend calls %v for a malformed request", n, e.spy.snapshot())
			}
			if rows, err := e.ledger.Rollups(t.Context(), store.UsageHourly); err != nil || len(rows) != 0 {
				t.Fatalf("malformed request produced usage rows %v (%v)", rows, err)
			}
			if strings.Contains(raw, "billing-worker") || strings.Contains(raw, e.token("granted")) {
				t.Fatalf("response echoes request material: %q", raw)
			}
		})
	}

	t.Run("control-without-duplicates-reaches-exactly-one-stop", func(t *testing.T) {
		e := newEnv(t, func(o *envOptions) { o.usage = true })
		w := newMCPWire(t, e, e.token("granted"))
		e.spy.reset()
		status, raw, _ := w.post(call(`{"endpoint":"local","container":"edge-proxy","timeout_seconds":5}`))
		if status != http.StatusOK {
			t.Fatalf("HTTP %d %q", status, raw)
		}
		if _, _, isToolErr, rpcCode := toolError(t, raw); isToolErr || rpcCode != 0 {
			t.Fatalf("the control was refused: %q", raw)
		}
		if got := e.spy.operationalCalls(); len(got) != 1 || got[0] != "Stop" {
			t.Fatalf("operational calls = %v, want exactly [Stop]", got)
		}
	})
}
