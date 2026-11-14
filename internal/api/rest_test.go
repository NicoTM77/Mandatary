package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

const (
	localEP   = domain.EndpointID("00000000-0000-4000-8000-000000000001")
	goodToken = "mdt_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	badToken  = "mdt_1123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
)

// fakeExec records every Execute and returns a configurable outcome. It lets these
// tests prove, without a store or a backend, which requests reach the shared service.
type fakeExec struct {
	mu    sync.Mutex
	calls []ops.Request
	err   error
}

func (f *fakeExec) Execute(_ context.Context, r ops.Request) (ops.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return ops.Result{}, err
	}
	id := docker.ContainerID(strings.Repeat("a", 64))
	res := ops.Result{Target: docker.TargetIdentity{EndpointID: r.EndpointID, ContainerID: id}, ContainerName: "edge-proxy", Operation: r.Operation}
	switch r.Operation {
	case docker.OpInspectStatus:
		res.Status = &docker.InspectStatus{EndpointID: r.EndpointID, ContainerID: id, Name: "edge-proxy", State: "running", Running: true}
	case docker.OpInspectConfig:
		res.Config = &docker.InspectConfig{EndpointID: r.EndpointID, ContainerID: id, Name: "edge-proxy"}
	}
	return res, nil
}

func (f *fakeExec) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }
func (f *fakeExec) last() ops.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// fakeAuth accepts exactly goodToken and counts calls.
type fakeAuth struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeAuth) Authenticate(_ context.Context, c authz.PrincipalCredentials) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if c.AgentToken != goodToken || c.SessionID != "" || len(c.SessionSecret) != 0 || c.UserID != "" || c.AgentID != "" || c.AgentCredentialID != "" || c.UntrustedCallerAdmin || c.UntrustedCallerAssurance != 0 {
		return authz.ErrUnauthenticated
	}
	return nil
}
func (f *fakeAuth) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type rig struct {
	t    *testing.T
	exec *fakeExec
	auth *fakeAuth
	h    *api.Handler
}

func newRig(t *testing.T, mutate ...func(*api.Config)) *rig {
	t.Helper()
	r := &rig{t: t, exec: &fakeExec{}, auth: &fakeAuth{}}
	gw, err := api.NewGateway(api.GatewayConfig{Executor: r.exec, Authenticator: r.auth, Endpoints: map[string]domain.EndpointID{"local": localEP}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.Config{Gateway: gw, Ready: func() bool { return true }}
	for _, m := range mutate {
		m(&cfg)
	}
	if r.h, err = api.NewHandler(cfg); err != nil {
		t.Fatal(err)
	}
	return r
}

type req struct {
	method, path, body string
	header             http.Header
	token              string // "" = none; "-" = explicitly no header
}

func (r *rig) do(q req) *httptest.ResponseRecorder {
	r.t.Helper()
	var body *strings.Reader
	if q.body != "" {
		body = strings.NewReader(q.body)
	} else {
		body = strings.NewReader("")
	}
	hr := httptest.NewRequest(q.method, q.path, body)
	if q.body == "" {
		hr.Body = http.NoBody
		hr.ContentLength = 0
	}
	for k, vs := range q.header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	switch q.token {
	case "":
		hr.Header.Set("Authorization", "Bearer "+goodToken)
	case "-":
	default:
		hr.Header.Set("Authorization", "Bearer "+q.token)
	}
	if q.body != "" && hr.Header.Get("Content-Type") == "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, hr)
	return w
}

func errBody(t *testing.T, w *httptest.ResponseRecorder) api.ErrorDetail {
	t.Helper()
	var b api.ErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Error.Code == "" {
		t.Fatalf("not a common error body (%d): %q (%v)", w.Code, w.Body.String(), err)
	}
	if b.Error.Status != w.Code {
		t.Fatalf("body status %d != HTTP status %d", b.Error.Status, w.Code)
	}
	return b.Error
}

const base = "/api/v1/endpoints/local/containers/edge-proxy/"

func TestRouteInventoryIsExactAndRefusesEverythingElseBeforeAnyBackendOrAuthStateIsTouched(t *testing.T) {
	r := newRig(t)
	unknown := []string{
		"/", "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2/readyz", "/API/V1/readyz", "/api/v1//readyz", "/api/v1/readyz/",
		"/api/v1/containers", "/api/v1/containers/json", "/api/v1/containers/edge-proxy/status",
		"/api/v1/endpoints", "/api/v1/endpoints/", "/api/v1/endpoints/local", "/api/v1/endpoints/local/containers",
		"/api/v1/endpoints/local/containers/", "/api/v1/endpoints/local/containers/edge-proxy",
		base + "exec", base + "top", base + "kill", base + "pause", base + "remove", base + "rename", base + "update",
		base + "attach", base + "archive", base + "export", base + "stats", base + "changes", base + "json", base + "wait",
		base + "status/", base + "status/extra", base + "logs/stream", base + "STATUS", base + "Status",
		"/api/v1/endpoints/local/containers/edge-proxy/exec/start", "/api/v1/endpoints/local/exec", "/api/v1/endpoints/local/images/json",
		"/api/v1/endpoints/local/volumes", "/api/v1/endpoints/local/networks", "/api/v1/endpoints/local/info",
		"/api/v1/access-requests", "/api/v1/discovery", "/api/v1/discovery/containers", "/api/v1/stats", "/api/v1/usage",
		"/api/v1/session", "/api/v1/login", "/api/v1/setup", "/api/v1/recovery", "/api/v1/tokens", "/api/v1/agents",
		"/api/v1/endpoints/local/containers/%2e%2e/status/..",
		"/api/v1/endpoints/local/containers/edge-proxy/status/%2e%2e/exec", "/api/v1/endpoints/local/containers/edge-proxy/status%2Fexec",
		"/v1.44/containers/json", "/containers/json", "/v1.44/containers/edge-proxy/exec", "/_ping", "/version", "/info",
		"/mcp", "/.well-known/oauth-protected-resource", "/oauth/token", "/api/v1/readyz%00",
	}
	for _, path := range unknown {
		for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
			if w := r.do(req{method: m, path: path}); w.Code != http.StatusNotFound || errBody(t, w).Code != api.CodeNotFound {
				t.Errorf("%s %s = %d, want 404 not_found", m, path, w.Code)
			}
		}
	}
	// A known route with any method other than its own is 405 with an Allow header.
	for _, s := range api.Specs() {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"} {
			if m == s.Method {
				continue
			}
			w := r.do(req{method: m, path: base + s.Segment})
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != s.Method || errBody(t, w).Code != api.CodeMethodNotAllowed {
				t.Errorf("%s %s = %d allow=%q, want 405 allow=%s", m, s.Segment, w.Code, w.Header().Get("Allow"), s.Method)
			}
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "HEAD", "OPTIONS"} {
		if w := r.do(req{method: m, path: "/api/v1/readyz"}); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s readyz = %d", m, w.Code)
		}
	}
	if r.exec.count() != 0 || r.auth.count() != 0 {
		t.Fatalf("unrecognized routes/methods reached authentication (%d) or the shared service (%d)", r.auth.count(), r.exec.count())
	}
}

func TestEncodedSeparatorsInIdentifiersAreInvalidRequestsNotRoutes(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{
		"/api/v1/endpoints/local/containers/a%2Fb/status", "/api/v1/endpoints/local/containers/a%2fb/status",
		"/api/v1/endpoints/local/containers/a%5Cb/status", "/api/v1/endpoints/local/containers/a%00b/status",
		"/api/v1/endpoints/local/containers/a%0Ab/status", "/api/v1/endpoints/a%2Fb/containers/x/status",
		"/api/v1/endpoints/local%2Fcontainers%2Fx/containers/y/status",
	} {
		if w := r.do(req{method: "GET", path: path}); w.Code != http.StatusBadRequest || errBody(t, w).Code != api.CodeInvalidRequest {
			t.Errorf("%s = %d", path, w.Code)
		}
		if w := r.do(req{method: "GET", path: path, token: "-"}); w.Code != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated = %d (authentication comes first)", path, w.Code)
		}
	}
	if r.exec.count() != 0 {
		t.Fatal("an unsafe identifier reached the shared service")
	}
}

func TestSixOperationsReachTheSharedServiceOnceWithExactlyTheirTypedRequest(t *testing.T) {
	r := newRig(t)
	cases := []struct {
		spec   api.Spec
		body   string
		query  string
		verify func(*testing.T, ops.Request)
	}{
		{spec: mustSpec(docker.OpInspectStatus)},
		{spec: mustSpec(docker.OpInspectConfig)},
		{spec: mustSpec(docker.OpStart)},
		{spec: mustSpec(docker.OpStop), body: `{"timeout_seconds":7}`, verify: func(t *testing.T, q ops.Request) {
			if q.Stop == nil || q.Stop.TimeoutSeconds == nil || *q.Stop.TimeoutSeconds != 7 || q.Restart != nil || q.Logs != nil {
				t.Errorf("stop request %+v", q)
			}
		}},
		{spec: mustSpec(docker.OpRestart), verify: func(t *testing.T, q ops.Request) {
			if q.Restart == nil || q.Restart.TimeoutSeconds != nil || q.Stop != nil {
				t.Errorf("restart request %+v", q)
			}
		}},
		{spec: mustSpec(docker.OpLogs), query: "?tail=5&stdout=true&stderr=false&timestamps=true&since=2026-11-08T09:00:00%2B01:00", verify: func(t *testing.T, q ops.Request) {
			o := q.Logs
			if o == nil || o.Tail != 5 || !o.Stdout || o.Stderr || !o.Timestamps || o.Follow || o.TailAll || o.Since.IsZero() || o.Since.Location().String() != "UTC" || o.Since.Hour() != 8 {
				t.Errorf("logs options %+v", o)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.spec.Tool, func(t *testing.T) {
			before := r.exec.count()
			w := r.do(req{method: c.spec.Method, path: base + c.spec.Segment + c.query, body: c.body})
			// The fake service cannot open a log stream (the real one is exercised in
			// tests/adapters), so a logs request ends 500 here AFTER reaching it.
			if want := http.StatusOK; w.Code != want && c.spec.Operation != docker.OpLogs {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if r.exec.count() != before+1 {
				t.Fatalf("Execute called %d times", r.exec.count()-before)
			}
			q := r.exec.last()
			if q.Operation != c.spec.Operation || q.EndpointID != localEP || q.Target != "edge-proxy" {
				t.Fatalf("request %+v", q)
			}
			if q.Credentials.AgentToken != goodToken || q.Credentials.SessionID != "" || q.Credentials.UserID != "" || q.Credentials.AgentID != "" || len(q.Credentials.SessionSecret) != 0 || q.Credentials.UntrustedCallerAdmin || q.Credentials.UntrustedCallerAssurance != 0 {
				t.Fatal("only the opaque agent token may come from the caller")
			}
			if c.verify != nil {
				c.verify(t, q)
			}
			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("content type %q", got)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("missing hardening headers")
			}
		})
	}
	// Endpoint by UUID is equivalent to the configured slug.
	if w := r.do(req{method: "GET", path: "/api/v1/endpoints/" + string(localEP) + "/containers/edge-proxy/status"}); w.Code != 200 || r.exec.last().EndpointID != localEP {
		t.Fatalf("uuid endpoint: %d", w.Code)
	}
}

func mustSpec(op docker.Operation) api.Spec {
	s, ok := api.SpecFor(op)
	if !ok {
		panic("no spec")
	}
	return s
}

func TestAuthenticationIsEvaluatedFirstAndOnlyAcceptsOneCanonicalBearerToken(t *testing.T) {
	r := newRig(t)
	protected := []string{"mandatary-self", strings.Repeat("1", 64), "mandatary-peer-stopped", "edge-proxy", "nonexistent"}
	bad := map[string]http.Header{
		"no header":               {},
		"empty bearer":            {"Authorization": {"Bearer "}},
		"bearer only":             {"Authorization": {"Bearer"}},
		"basic":                   {"Authorization": {"Basic " + goodToken}},
		"token scheme":            {"Authorization": {"Token " + goodToken}},
		"raw token":               {"Authorization": {goodToken}},
		"seven-char other scheme": {"Authorization": {"Basic  " + goodToken}},
		"tab after bearer":        {"Authorization": {"Bearer\t" + goodToken}},
		"bearer-like prefix":      {"Authorization": {"Bearers " + goodToken}},
		"double space":            {"Authorization": {"Bearer  " + goodToken}},
		"trailing space":          {"Authorization": {"Bearer " + goodToken + " "}},
		"two headers":             {"Authorization": {"Bearer " + goodToken, "Bearer " + goodToken}},
		"wrong prefix":            {"Authorization": {"Bearer mdx_" + goodToken[4:]}},
		"short token":             {"Authorization": {"Bearer mdt_short"}},
		"long token":              {"Authorization": {"Bearer " + goodToken + "A"}},
		"non-base62":              {"Authorization": {"Bearer mdt_0123456789abcdefghijklmnopqrstuvwxyzABCDE-_"}},
		"jwt":                     {"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"}},
		"session secret":          {"Authorization": {"Bearer session-secret-0123456789abcdef0123456789abcdef"}},
		"setup capability":        {"Authorization": {"Bearer " + strings.Repeat("s", 43)}},
		"cookie only":             {"Cookie": {"mandatary_session=" + goodToken}},
		"x-forwarded-user":        {"X-Forwarded-User": {"admin"}, "X-User": {"root"}, "X-Mandatary-Admin": {"true"}},
		"caller-asserted aal2":    {"X-Assurance": {"2"}, "Authorization": {"Bearer " + badToken}},
	}
	for name, hdr := range bad {
		for _, target := range protected {
			w := r.do(req{method: "GET", path: "/api/v1/endpoints/local/containers/" + target + "/status", header: hdr, token: "-"})
			if w.Code != http.StatusUnauthorized || errBody(t, w).Code != api.CodeUnauthenticated || w.Header().Get("WWW-Authenticate") == "" {
				t.Errorf("%s target %s: %d %s", name, target, w.Code, w.Body.String())
			}
		}
	}
	// Tokens in the URL are never credentials (and are not even looked at when no header exists).
	if w := r.do(req{method: "GET", path: base + "status?access_token=" + goodToken, token: "-"}); w.Code != http.StatusUnauthorized {
		t.Errorf("query token: %d", w.Code)
	}
	// An unknown but well-formed token is rejected by the authenticator, still before any target logic.
	if w := r.do(req{method: "GET", path: "/api/v1/endpoints/local/containers/mandatary-self/status", token: badToken}); w.Code != http.StatusUnauthorized {
		t.Errorf("unknown token on a protected name: %d (must not become a 403 name oracle)", w.Code)
	}
	if r.exec.count() != 0 {
		t.Fatalf("unauthenticated requests reached the shared service %d times", r.exec.count())
	}
	// Scheme matching is case-insensitive (RFC 6750); the token never is.
	if w := r.do(req{method: "GET", path: base + "status", header: http.Header{"Authorization": {"bEaReR " + goodToken}}, token: "-"}); w.Code != http.StatusOK {
		t.Errorf("lower-case scheme: %d", w.Code)
	}
	// Authentication precedes validation: a bad query is 401 without a token, 400 with one.
	if w := r.do(req{method: "GET", path: base + "status?all=1", token: "-"}); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated invalid query: %d", w.Code)
	}
	if w := r.do(req{method: "GET", path: base + "status?all=1"}); w.Code != http.StatusBadRequest {
		t.Errorf("authenticated invalid query: %d", w.Code)
	}
}

func TestAuthenticatorFailuresAreMappedAndNeverReachTheSharedService(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		status int
		reason string
	}{
		{"expired/revoked/unknown", authz.ErrUnauthenticated, 401, ""},
		{"restored installation", fmt.Errorf("x: %w", &authz.DenialError{Base: authz.ErrForbidden, Reason: authz.ReasonRestoreQuarantined}), 403, api.ReasonRestoreQuarantined},
		{"storage failure fails closed", &authz.DenialError{Base: authz.ErrForbidden, Reason: authz.ReasonDefaultDeny}, 403, api.ReasonDefaultDeny},
	} {
		r := newRig(t)
		r.auth.err = c.err
		w := r.do(req{method: "GET", path: base + "status"})
		e := errBody(t, w)
		if w.Code != c.status || e.Reason != c.reason {
			t.Errorf("%s: %d %+v", c.name, w.Code, e)
		}
		if r.exec.count() != 0 {
			t.Errorf("%s reached the shared service", c.name)
		}
	}
}

func TestStrictSchemaRefusesEveryUnknownOrMalformedQueryAndBodyBeforeTheSharedService(t *testing.T) {
	r := newRig(t)
	longBody := `{"timeout_seconds":5,"x":"` + strings.Repeat("a", api.MaxBodyBytes) + `"}`
	cases := []struct {
		name   string
		q      req
		status int
	}{
		// Passthrough attempts: any Docker-style option, on every route.
		{"status all", req{method: "GET", path: base + "status?all=1"}, 400},
		{"status v", req{method: "GET", path: base + "status?v=1"}, 400},
		{"config force", req{method: "GET", path: base + "config?force=true"}, 400},
		{"config size", req{method: "GET", path: base + "config?size=true"}, 400},
		{"start t", req{method: "POST", path: base + "start?t=5"}, 400},
		{"stop query timeout", req{method: "POST", path: base + "stop?timeout_seconds=5"}, 400},
		{"restart signal", req{method: "POST", path: base + "restart?signal=SIGKILL"}, 400},
		{"logs details", req{method: "GET", path: base + "logs?details=true"}, 400},
		{"logs path", req{method: "GET", path: base + "logs?path=/containers/json"}, 400},
		{"logs raw", req{method: "GET", path: base + "logs?raw=/v1.44/containers/edge-proxy/logs"}, 400},
		{"logs host", req{method: "GET", path: base + "logs?host=unix:///var/run/docker.sock"}, 400},
		{"logs filters", req{method: "GET", path: base + "logs?filters=%7B%7D"}, 400},
		{"logs empty key", req{method: "GET", path: base + "logs?=1"}, 400},
		{"logs encoded key", req{method: "GET", path: base + "logs?t%61il=5"}, 500}, // decodes to tail: reaches the (stream-less) fake service
		{"logs case", req{method: "GET", path: base + "logs?TAIL=5"}, 400},
		// Value forms.
		{"tail all", req{method: "GET", path: base + "logs?tail=all"}, 400},
		{"tail zero", req{method: "GET", path: base + "logs?tail=0"}, 400},
		{"tail negative", req{method: "GET", path: base + "logs?tail=-1"}, 400},
		{"tail float", req{method: "GET", path: base + "logs?tail=1.5"}, 400},
		{"tail exp", req{method: "GET", path: base + "logs?tail=1e3"}, 400},
		{"tail hex", req{method: "GET", path: base + "logs?tail=0x10"}, 400},
		{"tail leading zero", req{method: "GET", path: base + "logs?tail=007"}, 400},
		{"tail huge", req{method: "GET", path: base + "logs?tail=99999999999"}, 400},
		{"tail empty", req{method: "GET", path: base + "logs?tail="}, 400},
		{"tail repeated", req{method: "GET", path: base + "logs?tail=1&tail=2"}, 400},
		{"stdout numeric", req{method: "GET", path: base + "logs?stdout=1"}, 400},
		{"stdout capital", req{method: "GET", path: base + "logs?stdout=True"}, 400},
		{"follow maybe", req{method: "GET", path: base + "logs?follow=maybe"}, 400},
		{"since word", req{method: "GET", path: base + "logs?since=yesterday"}, 400},
		{"since unix", req{method: "GET", path: base + "logs?since=1700000000"}, 400},
		{"since no zone", req{method: "GET", path: base + "logs?since=2026-11-08T09:00:00"}, 400},
		{"malformed escape", req{method: "GET", path: base + "logs?tail=%zz"}, 400},
		{"semicolon pair", req{method: "GET", path: base + "logs?tail=5;stdout=true"}, 400},
		// Bodies.
		{"GET with body", req{method: "GET", path: base + "status", body: `{}`}, 400},
		{"start with body", req{method: "POST", path: base + "start", body: `{}`}, 400},
		{"logs with body", req{method: "GET", path: base + "logs", body: `{"tail":5}`}, 400},
		{"stop unknown field", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5,"force":true}`}, 400},
		{"stop signal", req{method: "POST", path: base + "stop", body: `{"signal":"SIGKILL"}`}, 400},
		{"stop container override", req{method: "POST", path: base + "stop", body: `{"container":"mandatary-self"}`}, 400},
		{"stop endpoint override", req{method: "POST", path: base + "stop", body: `{"endpoint":"` + string(localEP) + `"}`}, 400},
		{"stop duplicate key", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5,"timeout_seconds":6}`}, 400},
		{"stop string timeout", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":"5"}`}, 400},
		{"stop float timeout", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5.5}`}, 400},
		{"stop null timeout", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":null}`}, 400},
		{"stop array", req{method: "POST", path: base + "stop", body: `[5]`}, 400},
		{"stop scalar", req{method: "POST", path: base + "stop", body: `5`}, 400},
		{"stop trailing data", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5} {}`}, 400},
		{"stop truncated", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5`}, 400},
		{"stop not json", req{method: "POST", path: base + "stop", body: `timeout_seconds=5`}, 400},
		{"stop form content type", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5}`, header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}}, 415},
		{"stop text content type", req{method: "POST", path: base + "stop", body: `{"timeout_seconds":5}`, header: http.Header{"Content-Type": {"text/plain"}}}, 415},
		{"stop oversized", req{method: "POST", path: base + "stop", body: longBody}, 413},
		// Identifiers.
		{"unknown endpoint slug", req{method: "GET", path: "/api/v1/endpoints/remote/containers/edge-proxy/status"}, 400},
		{"endpoint with dots", req{method: "GET", path: "/api/v1/endpoints/..%2f/containers/edge-proxy/status"}, 400},
		{"overlong container", req{method: "GET", path: "/api/v1/endpoints/local/containers/" + strings.Repeat("a", api.MaxTargetBytes+1) + "/status"}, 400},
		{"overlong endpoint", req{method: "GET", path: "/api/v1/endpoints/" + strings.Repeat("a", api.MaxEndpointBytes+1) + "/containers/x/status"}, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := r.exec.count()
			w := r.do(c.q)
			if w.Code != c.status {
				t.Fatalf("%s %s: %d %s, want %d", c.q.method, c.q.path, w.Code, w.Body.String(), c.status)
			}
			if c.status >= 400 && c.status < 500 {
				if got := errBody(t, w); got.Code == "" {
					t.Fatal("no common error")
				}
				if r.exec.count() != before {
					t.Fatalf("refused request reached the shared service")
				}
			}
		})
	}
}

func TestSharedServiceErrorsMapToTheCommonErrorsAndNeverLeakTheirText(t *testing.T) {
	const canary = "CANARY-secret-token-env-dsn"
	forbiddenWith := func(r authz.DenialReason) error {
		return fmt.Errorf("%s: %w", canary, &authz.DenialError{Base: authz.ErrForbidden, Reason: r})
	}
	for _, c := range []struct {
		name   string
		err    error
		status int
		code   string
		reason string
	}{
		{"unauthenticated", fmt.Errorf("%s: %w", canary, authz.ErrUnauthenticated), 401, api.CodeUnauthenticated, ""},
		{"self protected hides as default deny", forbiddenWith(authz.ReasonSelfProtected), 403, api.CodeForbidden, api.ReasonDefaultDeny},
		{"target missing hides as default deny", forbiddenWith(authz.ReasonTargetMissing), 403, api.CodeForbidden, api.ReasonDefaultDeny},
		{"explicit deny hides as default deny", forbiddenWith(authz.ReasonExplicitDeny), 403, api.CodeForbidden, api.ReasonDefaultDeny},
		{"default deny", forbiddenWith(authz.ReasonDefaultDeny), 403, api.CodeForbidden, api.ReasonDefaultDeny},
		{"decision stale hides", forbiddenWith(authz.ReasonDecisionStale), 403, api.CodeForbidden, api.ReasonDefaultDeny},
		{"quarantine is global state", forbiddenWith(authz.ReasonRestoreQuarantined), 403, api.CodeForbidden, api.ReasonRestoreQuarantined},
		{"unverified is global state", forbiddenWith(authz.ReasonSafetyUnverified), 403, api.CodeForbidden, api.ReasonSafetyUnverified},
		{"endpoint inactive", forbiddenWith(authz.ReasonEndpointInactive), 403, api.CodeForbidden, api.ReasonEndpointInactive},
		{"cap exceeded", forbiddenWith(authz.ReasonParameterCapExceeded), 403, api.CodeForbidden, api.ReasonCapExceeded},
		{"authorization ended", fmt.Errorf("%s: %w", canary, ops.ErrStreamRevoked), 403, api.CodeForbidden, api.ReasonAuthorizationEnded},
		{"invalid request", ops.ErrInvalidRequest, 400, api.CodeInvalidRequest, ""},
		{"docker protected", fmt.Errorf("%s: %w", canary, docker.ErrProtectedTarget), 403, api.CodeForbidden, api.ReasonDefaultDeny},
		{"docker unverified", fmt.Errorf("%s: %w", canary, docker.ErrUnverified), 403, api.CodeForbidden, api.ReasonSafetyUnverified},
		{"docker not found", fmt.Errorf("%s: %w", canary, docker.ErrTargetNotFound), 404, api.CodeNotFound, ""},
		{"docker unavailable", fmt.Errorf("%s: %w", canary, docker.ErrBackendUnavailable), 503, api.CodeBackendUnavailable, ""},
		{"docker failed", fmt.Errorf("%s: %w", canary, docker.ErrBackendFailed), 502, api.CodeBackendFailed, ""},
		{"deadline", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), 504, api.CodeTimeout, ""},
		{"unknown error", errors.New(canary), 500, api.CodeInternal, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.exec.err = c.err
			w := r.do(req{method: "GET", path: base + "status"})
			if w.Code != c.status {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			e := errBody(t, w)
			if e.Code != c.code || e.Reason != c.reason {
				t.Fatalf("%+v", e)
			}
			if strings.Contains(w.Body.String(), canary) || strings.Contains(w.Body.String(), goodToken) {
				t.Fatalf("error text leaked: %s", w.Body.String())
			}
		})
	}
	if p := api.Classify(context.Canceled); p.Status != 499 || p.Code != api.CodeCanceled {
		t.Fatalf("canceled: %+v", p)
	}
}

func TestBrowserBoundaryOriginIsRefusedAndNoCORSIsEverOffered(t *testing.T) {
	r := newRig(t)
	for _, origin := range []string{"https://evil.example", "null", "http://localhost:8080", ""} {
		hdr := http.Header{"Origin": {origin}}
		for _, q := range []req{
			{method: "GET", path: base + "status", header: hdr},
			{method: "POST", path: base + "stop", header: hdr, body: `{}`},
			{method: "OPTIONS", path: base + "status", header: http.Header{"Origin": {origin}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"authorization"}}},
			{method: "GET", path: "/api/v1/readyz", header: hdr},
			{method: "GET", path: "/api/v1/nothing", header: hdr},
		} {
			w := r.do(q)
			if w.Code != http.StatusForbidden || errBody(t, w).Reason != api.ReasonForbiddenOrigin {
				t.Errorf("origin %q %s %s: %d", origin, q.method, q.path, w.Code)
			}
			for k := range w.Header() {
				if strings.HasPrefix(strings.ToLower(k), "access-control-") {
					t.Errorf("CORS header %s offered", k)
				}
			}
		}
	}
	if r.auth.count() != 0 || r.exec.count() != 0 {
		t.Fatal("cross-origin requests reached authentication or the shared service")
	}
	// A configured origin passes; two Origin headers never do.
	ok := newRig(t, func(c *api.Config) { c.AllowedOrigins = []string{"https://ops.example"} })
	if w := ok.do(req{method: "GET", path: base + "status", header: http.Header{"Origin": {"https://ops.example"}}}); w.Code != http.StatusOK {
		t.Errorf("allowed origin: %d", w.Code)
	}
	if w := ok.do(req{method: "GET", path: base + "status", header: http.Header{"Origin": {"https://ops.example", "https://ops.example"}}}); w.Code != http.StatusForbidden {
		t.Errorf("duplicate origin: %d", w.Code)
	}
	for _, bad := range []string{"*", "null", ""} {
		if _, err := api.NewHandler(api.Config{Gateway: ok.h2gw(), Ready: func() bool { return true }, AllowedOrigins: []string{bad}}); err == nil {
			t.Errorf("origin %q accepted in configuration", bad)
		}
	}
}

func (r *rig) h2gw() *api.Gateway {
	gw, _ := api.NewGateway(api.GatewayConfig{Executor: r.exec, Authenticator: r.auth})
	return gw
}

func TestReadinessReportsUnverifiedBackendsWithoutAuthentication(t *testing.T) {
	ready := false
	r := newRig(t, func(c *api.Config) { c.Ready = func() bool { return ready } })
	w := r.do(req{method: "GET", path: "/api/v1/readyz", token: "-"})
	var body api.ReadyResult
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusServiceUnavailable || body.Ready || body.Version != api.ContractVersion {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	ready = true
	if w := r.do(req{method: "GET", path: "/api/v1/readyz", token: "-"}); w.Code != 200 {
		t.Fatalf("ready: %d", w.Code)
	}
	if w := r.do(req{method: "GET", path: "/api/v1/readyz?x=1", token: "-"}); w.Code != 400 {
		t.Fatalf("query: %d", w.Code)
	}
	if r.auth.count() != 0 || r.exec.count() != 0 {
		t.Fatal("readiness touched authentication or the shared service")
	}
}

func TestTokenAndRequestsNeverFormatTheirSecrets(t *testing.T) {
	tok, prob := api.BearerToken(http.Header{"Authorization": {"Bearer " + goodToken}})
	if prob != nil {
		t.Fatal(prob)
	}
	var out strings.Builder
	for _, v := range []any{tok, &tok, []any{tok}, map[string]any{"t": tok}} {
		fmt.Fprintf(&out, "%v|%+v|%#v|%s|%q|%x|", v, v, v, v, v, v)
		b, _ := json.Marshal(v)
		out.Write(b)
	}
	if strings.Contains(out.String(), goodToken) || strings.Contains(out.String(), goodToken[4:]) {
		t.Fatalf("token leaked: %s", out.String())
	}
}

func TestOperationCatalogIsExactlyTheSixApprovedKeysAndUnsupportedOnesAreAbsent(t *testing.T) {
	want := map[docker.Operation]bool{}
	for _, op := range ops.Operations() {
		want[op] = true
	}
	specs := api.Specs()
	if len(specs) != len(want) || len(specs) != 6 {
		t.Fatalf("%d specs for %d approved keys", len(specs), len(want))
	}
	seenTool, seenSeg := map[string]bool{}, map[string]bool{}
	for _, s := range specs {
		if !want[s.Operation] || seenTool[s.Tool] || seenSeg[s.Segment] {
			t.Fatalf("spec %+v is unapproved or duplicated", s)
		}
		seenTool[s.Tool], seenSeg[s.Segment] = true, true
		if s.Method != "GET" && s.Method != "POST" {
			t.Fatalf("method %s", s.Method)
		}
		if (s.Method == "GET") != s.ReadOnly {
			t.Fatalf("%s: read-only operations must be GET and mutating ones POST", s.Tool)
		}
	}
	for _, bad := range []string{"exec", "container_exec", "list_containers", "discover", "request_container_access", "docker", "docker_api", "container_list", "container_remove"} {
		if _, ok := api.SpecForTool(bad); ok {
			t.Errorf("unsupported tool %s present", bad)
		}
	}
}

// P1.18.4 P113-L2: the exact Classify contract for context errors. context.Canceled is
// canceled/499 and context.DeadlineExceeded is timeout/504 with their fixed messages,
// whatever wraps them, and neither can ever be classified as a 403 denial. On an
// UNSANITIZED joined cancellation+deadline the deadline is checked first (504); the
// shared service sanitizes before the adapters see an error, so the observable service
// precedence is documented in docs/operations.md and tested in internal/ops.
func TestClassifyContextErrorContractIsCanceled499AndTimeout504NeverForbidden(t *testing.T) {
	const canary = "CANARY_CAUSE_P1184_0123456789"
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"canceled", context.Canceled, 499, api.CodeCanceled},
		{"wrapped canceled", fmt.Errorf("%s: %w", canary, context.Canceled), 499, api.CodeCanceled},
		{"deadline", context.DeadlineExceeded, 504, api.CodeTimeout},
		{"wrapped deadline", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), 504, api.CodeTimeout},
		{"joined cancel+deadline", errors.Join(context.Canceled, context.DeadlineExceeded), 504, api.CodeTimeout},
		{"joined deadline+cancel", errors.Join(context.DeadlineExceeded, context.Canceled), 504, api.CodeTimeout},
		{"joined cause+cancel", errors.Join(errors.New(canary), context.Canceled), 499, api.CodeCanceled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := api.Classify(c.err)
			if p.Status != c.status || p.Code != c.code {
				t.Fatalf("Classify = %d %s, want %d %s", p.Status, p.Code, c.status, c.code)
			}
			if p.Code == api.CodeForbidden || p.Status == http.StatusForbidden || p.Reason != "" {
				t.Fatalf("a context error classified as a denial: %+v", p)
			}
			if strings.Contains(p.Message, canary) {
				t.Fatalf("cause text leaked into the fixed message: %q", p.Message)
			}
			// The same table backs the structured MCP tool error.
			q := api.ProblemOf(c.code, "")
			if q.Status != c.status || q.Message != p.Message {
				t.Fatalf("ProblemOf(%s) = %d %q, want %d %q", c.code, q.Status, q.Message, c.status, p.Message)
			}
		})
	}
}
