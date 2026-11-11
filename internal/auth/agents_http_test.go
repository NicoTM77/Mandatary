package auth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
)

// HTTP adapter tests over the real Browser boundary (cookie, Origin, CSRF, step-up)
// and the real administrative service. Routes are mounted only here and in later
// owners' composition; the product binary still mounts no administrative route.

type adminHTTP struct {
	*adminEnv
	b      *Browser
	cookie string
	csrf   string
}

func newAdminHTTP(t *testing.T) *adminHTTP {
	t.Helper()
	e := newAdminEnv(t)
	b := NewBrowser(e.s)
	adapter, err := NewAdminHTTP(e.a)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Register(b); err != nil {
		t.Fatal(err)
	}
	return &adminHTTP{adminEnv: e, b: b, cookie: encodeSessionCookie(e.secret), csrf: csrfToken(e.secret, e.sessID)}
}

type adminReq struct {
	method, path, body string
	cookie, csrf       *string
	origin             string
	contentType        string
	headers            map[string][]string
}

func (h *adminHTTP) do(q adminReq) *httptest.ResponseRecorder {
	h.t.Helper()
	cookie, csrf := h.cookie, h.csrf
	if q.cookie != nil {
		cookie = *q.cookie
	}
	if q.csrf != nil {
		csrf = *q.csrf
	}
	var body io.Reader
	if q.body != "" {
		body = strings.NewReader(q.body)
	}
	r := httptest.NewRequest(q.method, "https://example.invalid"+q.path, body)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	unsafe := q.method != http.MethodGet
	if unsafe {
		if csrf != "" {
			r.Header.Set(CSRFHeader, csrf)
		}
		origin := q.origin
		if origin == "" {
			origin = sessionTestOrigin
		}
		r.Header.Set("Origin", origin)
		ct := q.contentType
		if ct == "" {
			ct = "application/json"
		}
		r.Header.Set("Content-Type", ct)
	}
	for k, vs := range q.headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	h.b.ServeHTTP(w, r)
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("response %d %q: %v", w.Code, w.Body.String(), err)
	}
}

func (h *adminHTTP) post(path, body string) *httptest.ResponseRecorder {
	return h.do(adminReq{method: http.MethodPost, path: path, body: body})
}

func (h *adminHTTP) mustCreate(path, body string, status int) map[string]any {
	h.t.Helper()
	w := h.post(path, body)
	if w.Code != status {
		h.t.Fatalf("POST %s %s: %d %s", path, body, w.Code, w.Body.String())
	}
	var out map[string]any
	if w.Body.Len() > 0 {
		decodeJSON(h.t, w, &out)
	}
	return out
}

const adminBase = "/api/v1/admin"

func TestAdministrativeRouteInventoryIsExactAndExplicit(t *testing.T) { // default deny, no role route
	h := newAdminHTTP(t)
	want := map[string]RoutePolicy{
		"GET " + adminBase + "/users":                                           {Require: RequireSession},
		"GET " + adminBase + "/groups":                                          {Require: RequireSession},
		"GET " + adminBase + "/agents":                                          {Require: RequireSession},
		"POST " + adminBase + "/users":                                          {Require: RequireSession, Sensitive: OpSecurityPolicy},
		"POST " + adminBase + "/groups":                                         {Require: RequireSession, Sensitive: OpSecurityPolicy},
		"POST " + adminBase + "/agents":                                         {Require: RequireSession, Sensitive: OpSecurityPolicy},
		"PUT " + adminBase + "/groups/{group}/members/{kind}/{member}":          {Require: RequireSession, Sensitive: OpSecurityPolicy},
		"DELETE " + adminBase + "/groups/{group}/members/{kind}/{member}":       {Require: RequireSession, Sensitive: OpSecurityPolicy},
		"POST " + adminBase + "/agents/{agent}/disable":                         {Require: RequireSession, Sensitive: OpAgentAccessChange},
		"POST " + adminBase + "/agents/{agent}/credentials":                     {Require: RequireSession, Sensitive: OpAgentAccessChange},
		"POST " + adminBase + "/agents/{agent}/credentials/rotate":              {Require: RequireSession, Sensitive: OpAgentAccessChange},
		"POST " + adminBase + "/agents/{agent}/credentials/{credential}/revoke": {Require: RequireSession, Sensitive: OpAgentAccessChange},
	}
	got := map[string]RoutePolicy{}
	for _, r := range h.b.Routes() {
		got[r.Pattern] = r.Policy
		lower := strings.ToLower(r.Pattern)
		if strings.Contains(lower, "role") || strings.Contains(lower, "admin/admin") || strings.Contains(lower, "token_hash") {
			t.Errorf("route %q exposes a role/administrator path", r.Pattern)
		}
	}
	if len(got) != len(want) {
		var names []string
		for p := range got {
			names = append(names, p)
		}
		sort.Strings(names)
		t.Fatalf("route inventory %v", names)
	}
	for pattern, policy := range want {
		if got[pattern] != policy {
			t.Errorf("%s: policy %+v, want %+v", pattern, got[pattern], policy)
		}
	}
	// Anything else, including other methods on registered paths, is not a route.
	for _, q := range []adminReq{
		{method: http.MethodGet, path: adminBase + "/roles"}, {method: http.MethodPost, path: adminBase + "/roles", body: `{}`},
		{method: http.MethodDelete, path: adminBase + "/agents"}, {method: http.MethodPut, path: adminBase + "/agents", body: `{}`},
		{method: http.MethodGet, path: adminBase + "/agents/x/credentials"}, {method: http.MethodPatch, path: adminBase + "/agents/x", body: `{}`},
		{method: http.MethodDelete, path: adminBase + "/agents/x/credentials/y"}, {method: http.MethodGet, path: adminBase},
		{method: http.MethodGet, path: adminBase + "/agents/"}, {method: http.MethodPost, path: adminBase + "/agents/x/credentials/"},
		{method: http.MethodPost, path: adminBase + "//agents", body: `{}`}, {method: http.MethodPost, path: strings.ToUpper(adminBase) + "/AGENTS", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/%2e%2e/credentials", body: `{}`},
	} {
		if w := h.do(q); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusMovedPermanently && w.Code != http.StatusTemporaryRedirect && w.Code != http.StatusPermanentRedirect {
			t.Errorf("%s %s reached a handler: %d", q.method, q.path, w.Code)
		}
	}
	if len(h.b.Routes()) != 12 {
		t.Fatalf("expected 12 routes, got %d", len(h.b.Routes()))
	}
}

func TestAdministrationOverHTTPEndToEndRevealsTheTokenOnce(t *testing.T) {
	h := newAdminHTTP(t)
	user := h.mustCreate(adminBase+"/users", `{"username":"owner.user"}`, http.StatusCreated)["user"].(map[string]any)
	group := h.mustCreate(adminBase+"/groups", `{"name":"team"}`, http.StatusCreated)["group"].(map[string]any)
	agent := h.mustCreate(adminBase+"/agents", `{"name":"bot","owner_user_id":"`+user["id"].(string)+`"}`, http.StatusCreated)["agent"].(map[string]any)
	if agent["owner_user_id"] != user["id"] || agent["state"] != "active" {
		t.Fatalf("agent %+v", agent)
	}
	member := adminBase + "/groups/" + group["id"].(string) + "/members/agent/" + agent["id"].(string)
	for range 2 {
		if w := h.do(adminReq{method: http.MethodPut, path: member}); w.Code != http.StatusNoContent {
			t.Fatalf("PUT member: %d %s", w.Code, w.Body.String())
		}
	}
	w := h.post(adminBase+"/agents/"+agent["id"].(string)+"/credentials", `{"ttl_seconds":3600}`)
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("issue: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	var issued struct {
		Credential CredentialView `json:"credential"`
		Token      string         `json:"token"`
	}
	decodeJSON(t, w, &issued)
	if !ValidAgentTokenFormat(issued.Token) || issued.Credential.Status != CredentialActive || issued.Credential.ExpiresAt == nil || !h.accepted([]byte(issued.Token)) {
		t.Fatalf("issued %+v", issued)
	}
	// Reveal once: no listing, repeat or error response ever shows it again.
	for _, p := range []string{"/agents", "/groups", "/users"} {
		w := h.do(adminReq{method: http.MethodGet, path: adminBase + p})
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), issued.Token) || strings.Contains(w.Body.String(), hex.EncodeToString(sha([]byte(issued.Token)))) || strings.Contains(w.Body.String(), "token_hash") {
			t.Fatalf("GET %s: %d leaked or failed: %s", p, w.Code, w.Body.String())
		}
	}
	// Rotation reveals the new token and labels the old one.
	w = h.post(adminBase+"/agents/"+agent["id"].(string)+"/credentials/rotate", `{"overlap_seconds":600}`)
	var rotated struct {
		Credential CredentialView   `json:"credential"`
		Token      string           `json:"token"`
		RotatedOut []CredentialView `json:"rotated_out"`
	}
	decodeJSON(t, w, &rotated)
	if w.Code != http.StatusCreated || rotated.Token == issued.Token || len(rotated.RotatedOut) != 1 || rotated.RotatedOut[0].Status != CredentialOverlapping || rotated.RotatedOut[0].ID != issued.Credential.ID {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if !h.accepted([]byte(issued.Token)) || !h.accepted([]byte(rotated.Token)) {
		t.Fatal("both tokens must be accepted during the overlap")
	}
	h.clock.Advance(10 * time.Minute)
	h.refresh()
	if h.accepted([]byte(issued.Token)) {
		t.Fatal("rotated-out token accepted at the boundary")
	}
	// Revoke the survivor over HTTP.
	if w := h.post(adminBase+"/agents/"+agent["id"].(string)+"/credentials/"+rotated.Credential.ID+"/revoke", ``); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if h.accepted([]byte(rotated.Token)) {
		t.Fatal("revoked token accepted")
	}
	// Disable the agent and remove the member.
	if w := h.do(adminReq{method: http.MethodDelete, path: member}); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE member: %d", w.Code)
	}
	if w := h.post(adminBase+"/agents/"+agent["id"].(string)+"/disable", ``); w.Code != http.StatusNoContent {
		t.Fatalf("disable: %d", w.Code)
	}
}

func TestAdministrativeRoutesNeedTheBrowserBoundary(t *testing.T) { // CSRF, Origin, cookie, content type, step-up
	h := newAdminHTTP(t)
	agent := h.agentOwnedBy("bot", h.person("owner"))
	mutations := []adminReq{
		{method: http.MethodPost, path: adminBase + "/users", body: `{"username":"probe"}`},
		{method: http.MethodPost, path: adminBase + "/groups", body: `{"name":"probe"}`},
		{method: http.MethodPost, path: adminBase + "/agents", body: `{"name":"probe","owner_user_id":"u"}`},
		{method: http.MethodPut, path: adminBase + "/groups/g/members/user/u"},
		{method: http.MethodDelete, path: adminBase + "/groups/g/members/user/u"},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/disable"},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials/rotate", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials/c/revoke"},
	}
	reads := []string{adminBase + "/users", adminBase + "/groups", adminBase + "/agents"}
	empty, wrong := "", "A"+h.csrf[1:]
	before := h.snapshot()
	for _, m := range mutations {
		label := m.method + " " + m.path
		for name, variant := range map[string]adminReq{
			"no cookie":      {cookie: &empty},
			"no csrf":        {csrf: &empty},
			"wrong csrf":     {csrf: &wrong},
			"foreign origin": {origin: "https://evil.example"},
			"null origin":    {origin: "null"},
			"form body":      {contentType: "application/x-www-form-urlencoded"},
			"text body":      {contentType: "text/plain"},
			"bearer instead": {cookie: &empty, headers: map[string][]string{"Authorization": {"Bearer mdt_" + strings.Repeat("a", 43)}}},
			"garbage cookie": {cookie: func() *string { s := "not-a-session"; return &s }()},
		} {
			q := m
			q.cookie, q.csrf, q.origin, q.contentType, q.headers = variant.cookie, variant.csrf, variant.origin, variant.contentType, variant.headers
			if w := h.do(q); w.Code < 400 || w.Code >= 500 {
				t.Errorf("%s with %s: %d", label, name, w.Code)
			}
		}
	}
	for _, p := range reads {
		for name, q := range map[string]adminReq{"no cookie": {cookie: &empty}, "garbage cookie": {cookie: func() *string { s := "x"; return &s }()}, "bearer": {cookie: &empty, headers: map[string][]string{"Authorization": {"Bearer " + h.cookie}}}} {
			q.method, q.path = http.MethodGet, p
			if w := h.do(q); w.Code != http.StatusUnauthorized {
				t.Errorf("GET %s with %s: %d", p, name, w.Code)
			}
		}
	}
	h.mustNoChange("rejected requests", before)
	if h.notifications() != 0 {
		t.Fatal("rejected request notified")
	}
}

func TestAdministrativeMutationsOverHTTPRequireFreshAAL2(t *testing.T) { // every sensitive mutation: negative + step-up positive
	h := newAdminHTTP(t)
	agent := h.agentOwnedBy("bot", h.person("owner"))
	group := h.group("grp")
	mutations := []adminReq{
		{method: http.MethodPost, path: adminBase + "/users", body: `{"username":"late"}`},
		{method: http.MethodPost, path: adminBase + "/groups", body: `{"name":"late"}`},
		{method: http.MethodPost, path: adminBase + "/agents", body: `{"name":"late","owner_user_id":"u"}`},
		{method: http.MethodPut, path: adminBase + "/groups/" + group + "/members/agent/" + agent},
		{method: http.MethodDelete, path: adminBase + "/groups/" + group + "/members/agent/" + agent},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials/rotate", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials/c/revoke"},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/disable"},
	}
	h.clock.Advance(DefaultStepUpWindow + time.Second) // evidence older than 15 minutes
	before := h.snapshot()
	for _, m := range mutations {
		w := h.do(m)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "step_up_required") {
			t.Errorf("%s %s with stale evidence: %d %s", m.method, m.path, w.Code, w.Body.String())
		}
	}
	h.mustNoChange("stale evidence", before)
	for _, p := range []string{"/users", "/groups", "/agents"} {
		if w := h.do(adminReq{method: http.MethodGet, path: adminBase + p}); w.Code != http.StatusOK {
			t.Errorf("reads must not need step-up: GET %s %d", p, w.Code)
		}
	}
	// A real step-up (password + fresh TOTP) yields a successor session that may mutate.
	stepped, err := h.stepUpTOTP(h.secret, h.totpID, h.totp)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := encodeSessionCookie(stepped.Secret()), stepped.CSRFToken()
	q := mutations[1]
	q.cookie, q.csrf = &cookie, &csrf
	if w := h.do(q); w.Code != http.StatusCreated {
		t.Fatalf("mutation after step-up: %d %s", w.Code, w.Body.String())
	}
	// The pre-step-up cookie is dead.
	if w := h.do(adminReq{method: http.MethodGet, path: adminBase + "/users"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("superseded cookie still accepted: %d", w.Code)
	}
}

func TestOrdinaryUsersAndOwnersCannotAdministerOverHTTP(t *testing.T) { // privilege escalation
	h := newAdminHTTP(t)
	agent := h.agentOwnedBy("bot", "u")                                       // the signed-in human OWNS the agent
	h.exec(`UPDATE administrative_roles SET state='disabled' WHERE id='adm'`) // ...but is not the administrator
	before := h.snapshot()
	for _, q := range []adminReq{
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials/rotate", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/disable"},
		{method: http.MethodPost, path: adminBase + "/users", body: `{"username":"x"}`},
		{method: http.MethodPost, path: adminBase + "/groups", body: `{"name":"x"}`},
		{method: http.MethodPost, path: adminBase + "/agents", body: `{"name":"y","owner_user_id":"u"}`},
		{method: http.MethodGet, path: adminBase + "/agents"}, {method: http.MethodGet, path: adminBase + "/users"}, {method: http.MethodGet, path: adminBase + "/groups"},
	} {
		w := h.do(q)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "forbidden") {
			t.Errorf("%s %s by a non-administrator: %d %s", q.method, q.path, w.Code, w.Body.String())
		}
	}
	h.mustNoChange("non-administrator over HTTP", before)
}

func TestAdministrativeBodiesAreStrictAndMassAssignmentIsRejected(t *testing.T) {
	h := newAdminHTTP(t)
	owner := h.person("owner")
	agent := h.agentOwnedBy("bot", owner)
	routes := map[string]string{
		adminBase + "/users":                                   `{"username":"probe"}`,
		adminBase + "/groups":                                  `{"name":"probe"}`,
		adminBase + "/agents":                                  `{"name":"probe","owner_user_id":"` + owner + `"}`,
		adminBase + "/agents/" + agent + "/credentials":        `{}`,
		adminBase + "/agents/" + agent + "/credentials/rotate": `{}`,
	}
	h.issue(agent, CredentialRequest{})
	before := h.snapshot()
	for path, valid := range routes {
		inject := func(extra string) string {
			return strings.TrimSuffix(valid, "}") + map[bool]string{true: "", false: ","}[valid == `{}`] + extra + "}"
		}
		for name, body := range map[string]string{
			"state escalation":     inject(`"state":"active"`),
			"role escalation":      inject(`"role":"super_admin"`),
			"administrator flag":   inject(`"is_admin":true`),
			"generation":           inject(`"credential_generation":99`),
			"authority generation": inject(`"authority_generation":99`),
			"verifier":             inject(`"token_hash":"00"`),
			"explicit token":       inject(`"token":"mdt_` + strings.Repeat("a", 43) + `"`),
			"second owner":         inject(`"owner_group_id":"g"`),
			"trailing data":        valid + ` {}`,
			"trailing garbage":     valid + `x`,
			"array":                `[]`,
			"null":                 `null`,
			"string":               `"x"`,
			"number":               `1`,
			"truncated":            valid[:len(valid)-1],
			"wrong content":        `username=a&name=a`,
			"nested":               `{"a":{"b":{"c":1}}}`,
			"oversized":            `{"name":"` + strings.Repeat("a", 70000) + `"}`,
		} {
			if w := h.post(path, body); w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("POST %s %s: %d %s", path, name, w.Code, w.Body.String())
			}
		}
	}
	h.mustNoChange("malformed or mass-assignment bodies", before)
	if h.notifications() != 0 {
		t.Fatal("rejected bodies notified")
	}
	// Typed-field abuse on the optional numeric fields.
	for name, body := range map[string]string{
		"string ttl": `{"ttl_seconds":"3600"}`, "float ttl": `{"ttl_seconds":1.5}`, "negative ttl": `{"ttl_seconds":-1}`, "zero ttl": `{"ttl_seconds":0}`,
		"huge ttl": `{"ttl_seconds":9223372036854775807}`, "above max": `{"ttl_seconds":7776001}`, "ttl and non-expiring": `{"ttl_seconds":60,"non_expiring":true}`,
		"non-expiring unapproved": `{"non_expiring":true}`, "bool ttl": `{"ttl_seconds":true}`,
	} {
		if w := h.post(adminBase+"/agents/"+agent+"/credentials/rotate", body); w.Code != http.StatusBadRequest {
			t.Errorf("rotate %s: %d", name, w.Code)
		}
	}
	for name, body := range map[string]string{"negative overlap": `{"overlap_seconds":-1}`, "float overlap": `{"overlap_seconds":2.5}`, "huge overlap": `{"overlap_seconds":9223372036854775807}`, "above max": `{"overlap_seconds":86401}`, "both": `{"overlap_seconds":60,"immediate":true}`, "string": `{"overlap_seconds":"60"}`} {
		if w := h.post(adminBase+"/agents/"+agent+"/credentials/rotate", body); w.Code != http.StatusBadRequest {
			t.Errorf("rotate %s: %d %s", name, w.Code, w.Body.String())
		}
	}
	h.mustNoChange("typed-field abuse", before)
}

func TestRotationOverlapFieldSemanticsOverHTTP(t *testing.T) {
	h := newAdminHTTP(t)
	agent := h.agentOwnedBy("bot", h.person("owner"))
	_, first := h.issue(agent, CredentialRequest{})
	rotate := func(body string) (token string, out []CredentialView) {
		w := h.post(adminBase+"/agents/"+agent+"/credentials/rotate", body)
		if w.Code != http.StatusCreated {
			t.Fatalf("rotate %s: %d %s", body, w.Code, w.Body.String())
		}
		var res struct {
			Token      string           `json:"token"`
			RotatedOut []CredentialView `json:"rotated_out"`
		}
		decodeJSON(t, w, &res)
		return res.Token, res.RotatedOut
	}
	now := h.clock.Now().Unix()
	_, out := rotate(`{}`) // omitted: the configured default (one hour)
	if len(out) != 1 || *out[0].OverlapUntil != now+3600 {
		t.Fatalf("default overlap %+v", out)
	}
	_, out = rotate(`{"overlap_seconds":0}`) // explicit zero: no overlap
	if len(out) != 2 || out[0].Status != CredentialRevoked || out[1].Status != CredentialRevoked {
		t.Fatalf("explicit zero must revoke at once: %+v", out)
	}
	if h.accepted(first) {
		t.Fatal("first token survived an immediate rotation")
	}
	_, out = rotate(`{"immediate":true}`)
	if len(out) != 1 || out[0].Status != CredentialRevoked {
		t.Fatalf("immediate %+v", out)
	}
}

func TestAdministrativeErrorsAreFixedCodesThatNeverEchoInput(t *testing.T) {
	h := newAdminHTTP(t)
	canary := "CANARY!4711-mdt_" + strings.Repeat("Q", 43)
	owner := h.person("owner")
	cases := []struct {
		name string
		q    adminReq
		code int
		body string
	}{
		{"invalid name echo", adminReq{method: http.MethodPost, path: adminBase + "/users", body: `{"username":"` + canary + `"}`}, 400, "invalid_request"},
		{"unknown owner echo", adminReq{method: http.MethodPost, path: adminBase + "/agents", body: `{"name":"a","owner_user_id":"` + strings.ReplaceAll(canary, "mdt_", "x") + `"}`}, 400, "invalid_request"},
		{"unknown agent", adminReq{method: http.MethodPost, path: adminBase + "/agents/unknown-agent/credentials", body: `{}`}, 404, "not_found"},
		{"unknown agent revoke", adminReq{method: http.MethodPost, path: adminBase + "/agents/unknown-agent/credentials/c/revoke"}, 404, "not_found"},
		{"bad id echo", adminReq{method: http.MethodPost, path: adminBase + "/agents/" + "a%20b%0Ac" + "/credentials", body: `{}`}, 400, "invalid_request"},
		{"duplicate", adminReq{method: http.MethodPost, path: adminBase + "/users", body: `{"username":"owner"}`}, 409, "conflict"},
		{"bad member kind", adminReq{method: http.MethodPut, path: adminBase + "/groups/g/members/admin/" + owner}, 400, "invalid_request"},
	}
	for _, c := range cases {
		w := h.do(c.q)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != `{"error":"`+c.body+`"}` {
			t.Errorf("%s: %d %q", c.name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "CANARY") {
			t.Errorf("%s echoed input", c.name)
		}
	}
	// Storage uncertainty is 503, never a granted result.
	h.l.repo.FailClosed()
	if w := h.post(adminBase+"/users", `{"username":"after-poison"}`); w.Code != http.StatusUnauthorized && w.Code != http.StatusServiceUnavailable {
		t.Fatalf("poisoned store: %d", w.Code)
	}
}

func TestIssuedTokenNeverReachesLogsOrErrorBodies(t *testing.T) { // P1.04 canary extension, every level and format
	for _, format := range []string{"json", "text"} {
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
			t.Run(format+"/"+level.String(), func(t *testing.T) {
				h := newAdminHTTP(t)
				var logs bytes.Buffer
				opts := &slog.HandlerOptions{Level: level}
				var handler slog.Handler = slog.NewJSONHandler(&logs, opts)
				if format == "text" {
					handler = slog.NewTextHandler(&logs, opts)
				}
				logged := logging.HTTP(slog.New(handler), h.b)
				agent := h.agentOwnedBy("bot", h.person("owner"))
				do := func(method, path, body string) *httptest.ResponseRecorder {
					r := httptest.NewRequest(method, "https://example.invalid"+path, strings.NewReader(body))
					r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: h.cookie})
					r.Header.Set("Origin", sessionTestOrigin)
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set(CSRFHeader, h.csrf)
					w := httptest.NewRecorder()
					logged.ServeHTTP(w, r)
					return w
				}
				w := do(http.MethodPost, adminBase+"/agents/"+agent+"/credentials", `{}`)
				var res struct{ Token string }
				decodeJSON(t, w, &res)
				if !ValidAgentTokenFormat(res.Token) {
					t.Fatalf("no token issued: %s", w.Body.String())
				}
				// An error path carrying the token back as input.
				do(http.MethodPost, adminBase+"/agents/"+agent+"/credentials/"+res.Token+"/revoke", ``)
				do(http.MethodPost, adminBase+"/users", `{"username":"`+res.Token+`"}`)
				for _, secret := range []string{res.Token, res.Token[4:], h.cookie, h.csrf} {
					if strings.Contains(logs.String(), secret) {
						t.Fatalf("log output contains a secret: %s", logs.String())
					}
				}
			})
		}
	}
}

func TestAgentCredentialRoutesNeverAcceptAgentTokens(t *testing.T) { // N63B4-SCOPE-MACHINE, TOKEN-NOT-PRESENCE
	h := newAdminHTTP(t)
	agent := h.agentOwnedBy("bot", "u")
	_, token := h.issue(agent, CredentialRequest{})
	bearer := map[string][]string{"Authorization": {"Bearer " + string(token)}}
	none := ""
	before := h.snapshot()
	for _, q := range []adminReq{
		{method: http.MethodGet, path: adminBase + "/agents"},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/credentials/rotate", body: `{}`},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/disable"},
		{method: http.MethodPost, path: adminBase + "/users", body: `{"username":"viaagent"}`},
	} {
		q.cookie, q.csrf, q.headers = &none, &none, bearer
		if w := h.do(q); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("%s %s with an agent bearer token: %d", q.method, q.path, w.Code)
		}
		// Placing the token in the session cookie is no better.
		cookie := string(token)
		q.cookie, q.headers = &cookie, nil
		if w := h.do(q); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Errorf("%s %s with an agent token as cookie: %d", q.method, q.path, w.Code)
		}
	}
	h.mustNoChange("agent token administration over HTTP", before)
	if !h.accepted(token) {
		t.Fatal("attempted misuse damaged the credential")
	}
}
