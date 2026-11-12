package adapters_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

// follower is an open REST follow stream (NDJSON).
type follower struct {
	t      *testing.T
	resp   *http.Response
	lines  chan string
	cancel context.CancelFunc
}

const followPath = "/api/v1/endpoints/local/containers/edge-proxy/logs?follow=true&tail=1"

func openFollow(t *testing.T, e *env, token, path string) *follower {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &follower{t: t, resp: resp, lines: make(chan string, 64), cancel: cancel}
	t.Cleanup(f.close)
	if resp.StatusCode != http.StatusOK {
		return f
	}
	go func() {
		defer close(f.lines)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			f.lines <- sc.Text()
		}
	}()
	return f
}

func (f *follower) close() { f.cancel(); _ = f.resp.Body.Close() }

// next returns the next NDJSON object; the bound is only a hang guard for the test run.
func (f *follower) next() (map[string]any, bool) {
	f.t.Helper()
	select {
	case line, ok := <-f.lines:
		if !ok {
			return nil, false
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			f.t.Fatalf("not an NDJSON object: %q", line)
		}
		return m, true
	case <-time.After(60 * time.Second):
		f.t.Fatal("stream produced neither a frame nor an end")
		return nil, false
	}
}

// terminal reads until the stream ends and returns its single terminal object and whether
// the body then closed (EOF).
func (f *follower) terminal() (map[string]any, bool) {
	f.t.Helper()
	for {
		m, ok := f.next()
		if !ok {
			return nil, false
		}
		if _, isFrame := m["stream"]; isFrame {
			continue
		}
		if _, isMeta := m["container_id"]; isMeta {
			continue
		}
		_, more := f.next()
		return m, !more
	}
}

func (f *follower) wantTerminalError(code, reason string) {
	f.t.Helper()
	m, closed := f.terminal()
	eb, _ := m["error"].(map[string]any)
	if eb == nil || eb["code"] != code || (reason != "" && eb["reason"] != reason) || !closed {
		f.t.Fatalf("terminal = %v (body closed after: %v), want error %s/%s", m, closed, code, reason)
	}
}

// eventually bounds a wait for an asynchronous server-side effect (a lease release after a
// client disconnect). It yields instead of sleeping on a timer; the deadline is a hang guard.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not observed", what)
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
}

func appendLog(e *env, text string) {
	e.mock.AppendLog(edgeID, docker.MockLogLine{Timestamp: e.clock.Now(), Stream: docker.LogStreamStdout, Line: text})
}

func TestFollowStreamDeliversFramesAndEndsWhenTheClientLeaves(t *testing.T) {
	e := newEnv(t)
	f := openFollow(t, e, e.token("granted"), followPath)
	if f.resp.StatusCode != 200 || f.resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("%d %s", f.resp.StatusCode, f.resp.Header.Get("Content-Type"))
	}
	meta, _ := f.next()
	if meta["container_id"] != string(edgeID) || meta["endpoint_id"] != string(localEP) || meta["name"] != "edge-proxy" {
		t.Fatalf("meta %v", meta)
	}
	if first, _ := f.next(); first["stream"] == nil || first["text"] == nil {
		t.Fatalf("backlog frame %v", first)
	}
	appendLog(e, "live-line-1")
	live, _ := f.next()
	if live["stream"] != "stdout" || !strings.Contains(live["text"].(string), "live-line-1") {
		t.Fatalf("live frame %v", live)
	}
	if n := e.az.ActiveLeaseCount(); n != 1 {
		t.Fatalf("%d active leases while streaming", n)
	}
	f.close() // client leaves: the lease must be released and the stream must end
	eventually(t, "lease release after client disconnect", func() bool { return e.az.ActiveLeaseCount() == 0 })
}

func TestFollowStreamEndsOnEveryRevocationOrExpiryCauseOverREST(t *testing.T) {
	type cause struct {
		name   string
		agent  string
		apply  func(*env)
		notify bool // push (NotifyAuthorityChange) vs pull (revalidation tick)
		code   string
		reason string
	}
	revoke := func(key string) func(*env) {
		return func(e *env) {
			e.exec(`UPDATE agent_credentials SET state='revoked', revoked_at=? WHERE id=?`, e.clock.Now().Unix(), e.agents[key].credID)
		}
	}
	causes := []cause{
		{"token-revoked", "granted", revoke("granted"), true, api.CodeForbidden, ""},
		{"token-expired", "short", func(e *env) { e.clock.Advance(2 * time.Minute) }, true, api.CodeForbidden, ""},
		{"agent-disabled", "granted", func(e *env) { e.exec(`UPDATE agents SET state='disabled' WHERE id=?`, e.agents["granted"].agentID) }, true, api.CodeForbidden, ""},
		{"logs-allow-removed", "granted", func(e *env) {
			e.exec(`UPDATE policies SET state='disabled' WHERE agent_id=? AND operation='container:logs'`, e.agents["granted"].agentID)
		}, true, api.CodeForbidden, ""},
		{"explicit-deny-added", "granted", func(e *env) {
			e.policy("agent_id", e.agents["granted"].agentID, selEdge, "DENY", docker.OpLogs, nil, nil)
		}, true, api.CodeForbidden, ""},
		{"restore-quarantine", "granted", func(e *env) { e.exec(`UPDATE installation_control SET restore_quarantined=1 WHERE singleton=1`) }, true, api.CodeForbidden, ""},
		{"credential-generation-bumped-by-restore", "granted", func(e *env) {
			e.exec(`UPDATE installation_control SET credential_generation=2 WHERE singleton=1`)
		}, true, api.CodeForbidden, ""},
		{"safety-proof-lost", "wildcard", func(e *env) { e.mock.SimulateEventDiscontinuity() }, false, api.CodeForbidden, ""},
		// The same revocations detected by the stream's own revalidation tick (no push at all).
		{"pull/token-revoked", "granted", revoke("granted"), false, api.CodeForbidden, ""},
		{"pull/token-expired", "short", func(e *env) { e.clock.Advance(2 * time.Minute) }, false, api.CodeForbidden, ""},
	}
	for _, c := range causes {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, func(o *envOptions) { o.interval = 10 * time.Millisecond })
			f := openFollow(t, e, e.token(c.agent), followPath)
			if f.resp.StatusCode != 200 {
				t.Fatalf("open: %d", f.resp.StatusCode)
			}
			f.next() // meta: the lease is held and the backend stream is open
			c.apply(e)
			if c.notify {
				if err := e.svc.NotifyAuthorityChange(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			f.wantTerminalError(c.code, c.reason)
			eventually(t, "lease release after the stream ended", func() bool { return e.az.ActiveLeaseCount() == 0 })
			// No frame was delivered after the authorization ended.
			appendLog(e, "after-revocation")
			select {
			case l, ok := <-f.lines:
				if ok {
					t.Fatalf("a frame followed the end of the stream: %s", l)
				}
			default:
			}
		})
	}
}

func TestFollowRequestsAreAuthorizedAndBoundedLikeEveryOtherRequest(t *testing.T) {
	e := newEnv(t, func(o *envOptions) { o.perStream = 2; o.streams = 3 })
	deny := func(token, path string, status int, code, reason string) {
		t.Helper()
		e.spy.reset()
		f := openFollow(t, e, token, path)
		defer f.close()
		body, _ := io.ReadAll(f.resp.Body)
		if f.resp.StatusCode != status {
			t.Fatalf("%s: %d %s, want %d", path, f.resp.StatusCode, body, status)
		}
		var eb api.ErrorBody
		if json.Unmarshal(body, &eb) != nil || eb.Error.Code != code || eb.Error.Reason != reason {
			t.Fatalf("%s: %s, want %s/%s", path, body, code, reason)
		}
	}
	deny("", followPath, 401, api.CodeUnauthenticated, "")
	if n := e.spy.total(); n != 0 {
		t.Fatalf("an unauthenticated follow reached the backend %d times", n)
	}
	deny(e.token("nogrant"), followPath, 403, api.CodeForbidden, api.ReasonDefaultDeny)
	deny(e.token("granted"), "/api/v1/endpoints/local/containers/mandatary-self/logs?follow=true", 403, api.CodeForbidden, api.ReasonDefaultDeny)
	deny(e.token("granted"), "/api/v1/endpoints/local/containers/billing-worker/logs?follow=true", 403, api.CodeForbidden, api.ReasonDefaultDeny)
	deny(e.token("granted"), "/api/v1/endpoints/local/containers/edge-proxy/logs?follow=maybe", 400, api.CodeInvalidRequest, "")
	deny(e.token("granted"), "/api/v1/endpoints/local/containers/edge-proxy/status?follow=true", 400, api.CodeInvalidRequest, "")
	deny(e.token("capped"), "/api/v1/endpoints/local/containers/edge-proxy/logs?follow=true&tail=6", 403, api.CodeForbidden, api.ReasonCapExceeded)
	if n := len(e.spy.operationalCalls()); n != 0 {
		t.Fatalf("a refused follow made %d operational calls", n)
	}

	// Concurrent streams are capped per credential and overall; slots return on close.
	a1 := openFollow(t, e, e.token("granted"), followPath)
	a2 := openFollow(t, e, e.token("granted"), followPath)
	a1.next()
	a2.next()
	deny(e.token("granted"), followPath, 429, api.CodeTooManyStreams, "")
	b1 := openFollow(t, e, e.token("wildcard"), followPath) // another credential still has room...
	b1.next()
	deny(e.token("wildcard"), followPath, 429, api.CodeTooManyStreams, "") // ...until the overall cap (3) is reached
	a1.close()
	eventually(t, "a released stream slot", func() bool {
		f := openFollow(t, e, e.token("granted"), followPath)
		defer f.close()
		return f.resp.StatusCode == 200
	})
}

func TestMCPHasNoFollowStreamingAndRESTFollowIsLogsOnly(t *testing.T) {
	e := newEnv(t)
	for _, tr := range []transport{mcpTransport{}} {
		o := tr.do(t, e, req(e.token("granted"), "container_logs", "edge-proxy", a("follow", true)))
		if !o.sameClass(invalid().outcome()) {
			t.Fatalf("%s follow=true: %s", tr.name(), o)
		}
	}
	if n := len(e.spy.operationalCalls()); n != 0 {
		t.Fatalf("%d operational calls", n)
	}
}
