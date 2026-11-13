package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// P1.17 routes over the real Browser boundary and the real administrative service. The unit contract of
// the service is policy_admin_test.go and identity_admin_test.go; here the adapter is pinned: what it
// accepts, how it maps outcomes, and that nothing a caller asserts about itself is ever an input.

const polBase = adminBase + "/policy"

func (h *adminHTTP) req(method, path, body string) (int, string) {
	h.t.Helper()
	w := h.do(adminReq{method: method, path: path, body: body})
	return w.Code, w.Body.String()
}

func (h *adminHTTP) must(method, path, body string, want int) map[string]any {
	h.t.Helper()
	code, raw := h.req(method, path, body)
	if code != want {
		h.t.Fatalf("%s %s %s: %d %s", method, path, body, code, raw)
	}
	var out map[string]any
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

const logsRule = `{"subject":{"kind":"agent","id":"%s"},"effect":"ALLOW","operations":["container:logs","container:inspect_status"],"selector":{"container_name":"edge-proxy","compose_project":"platform"},"log_tail_max":200}`

func ruleFor(subjectKind, id string) string {
	return `{"subject":{"kind":"` + subjectKind + `","id":"` + id + `"},"effect":"ALLOW","operations":["container:logs"],"selector":{"container_name":"web"}}`
}

func TestPolicyRoutesEndToEnd(t *testing.T) {
	t.Parallel()
	h := newAdminHTTP(t)
	user := h.person("owner")
	agent := h.agentOwnedBy("bot", user)
	group := h.group("ops")

	// Create two rules in one call; the page lists them with their subject, selector and ceilings.
	out := h.must(http.MethodPost, polBase+"/rules", strings.Replace(logsRule, "%s", agent, 1), http.StatusCreated)
	rules, _ := out["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("created %v", out)
	}
	first := rules[0].(map[string]any)
	if first["effect"] != "ALLOW" || first["state"] != "active" || first["operation"] != "container:logs" || first["log_tail_max"] != float64(200) {
		t.Fatalf("created view %v", first)
	}
	page := h.must(http.MethodGet, polBase+"/rules", "", http.StatusOK)
	if got := len(page["rules"].([]any)); got != 2 {
		t.Fatalf("page rules %d", got)
	}
	if page["endpoint"].(map[string]any)["safety"] != "unverified" || page["inventory"] != nil {
		t.Fatalf("with no container source the endpoint is unverified and has no inventory: %v", page["endpoint"])
	}
	for _, r := range page["rules"].([]any) {
		if r.(map[string]any)["target"].(map[string]any)["status"] != "unknown" {
			t.Fatalf("an uninspectable endpoint must report unknown targets: %v", r)
		}
	}
	id := first["id"].(string)

	// Preview needs the session and CSRF, writes nothing and reports that the endpoint is unavailable.
	pv := h.must(http.MethodPost, polBase+"/rules/preview", `{"selector":{"container_name":"web*","name_is_glob":true}}`, http.StatusOK)
	if pv["available"] != false || len(pv["matches"].([]any)) != 0 {
		t.Fatalf("preview %v", pv)
	}
	if code, _ := h.req(http.MethodPost, polBase+"/rules/preview", `{"selector":{"container_name":"web["}}`); code != http.StatusBadRequest {
		t.Fatalf("invalid preview selector: %d", code)
	}

	// Edit, disable, enable, delete.
	edited := h.must(http.MethodPut, polBase+"/rules/"+id, `{"effect":"DENY","selector":{"container_name":"edge-proxy"}}`, http.StatusOK)
	if r := edited["rule"].(map[string]any); r["effect"] != "DENY" || r["log_tail_max"] != nil {
		t.Fatalf("edited %v", r)
	}
	h.must(http.MethodPost, polBase+"/rules/"+id+"/disable", "", http.StatusNoContent)
	h.must(http.MethodPost, polBase+"/rules/"+id+"/enable", "", http.StatusNoContent)
	if code, _ := h.req(http.MethodPost, polBase+"/rules/"+id+"/enable", ""); code != http.StatusConflict {
		t.Fatalf("enabling an active rule: %d", code)
	}
	h.must(http.MethodDelete, polBase+"/rules/"+id, "", http.StatusNoContent)
	if code, _ := h.req(http.MethodDelete, polBase+"/rules/"+id, ""); code != http.StatusNotFound {
		t.Fatalf("second delete: %d", code)
	}

	// Identity lifecycle, owner transfer and the page-shaped reads.
	h.must(http.MethodPost, adminBase+"/users/"+user+"/disable", "", http.StatusNoContent)
	if h.agentState(agent) != "disabled" {
		t.Fatal("disabling the owner did not cascade over HTTP")
	}
	h.must(http.MethodPost, adminBase+"/users/"+user+"/enable", "", http.StatusNoContent)
	h.must(http.MethodPost, adminBase+"/agents/"+agent+"/enable", "", http.StatusNoContent)
	h.must(http.MethodPut, adminBase+"/agents/"+agent+"/owner", `{"owner_group_id":"`+group+`"}`, http.StatusNoContent)
	h.must(http.MethodPost, adminBase+"/groups/"+group+"/disable", "", http.StatusNoContent)
	h.must(http.MethodPost, adminBase+"/groups/"+group+"/enable", "", http.StatusNoContent)
	if code, _ := h.req(http.MethodDelete, adminBase+"/groups/"+group, ""); code != http.StatusConflict {
		t.Fatalf("deleting a group that owns an agent: %d", code)
	}
	h.must(http.MethodPut, adminBase+"/agents/"+agent+"/owner", `{"owner_user_id":"`+user+`"}`, http.StatusNoContent)
	h.must(http.MethodDelete, adminBase+"/groups/"+group, "", http.StatusNoContent)
	users := h.must(http.MethodGet, polBase+"/users", "", http.StatusOK)["users"].([]any)
	if len(users) < 2 {
		t.Fatalf("users page %v", users)
	}
	h.must(http.MethodGet, polBase+"/groups", "", http.StatusOK)
	ag := h.must(http.MethodGet, polBase+"/agents", "", http.StatusOK)
	if len(ag["agents"].([]any)) != 1 {
		t.Fatalf("agents page %v", ag)
	}
}

func (h *adminHTTP) agentState(id string) string {
	h.t.Helper()
	var s string
	if err := h.db.QueryRow(`SELECT state FROM agents WHERE id=?`, id).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

// policyMutations is every new mutating route with a body that is valid for it, so one matrix drives the
// Browser-boundary, step-up, non-administrator and strict-body checks.
func (h *adminHTTP) policyMutations() []adminReq {
	user := h.person("subject")
	agent := h.agentOwnedBy("subject-bot", user)
	group := h.group("subject-group")
	rule := h.mustCreate(polBase+"/rules", ruleFor("user", user), http.StatusCreated)["rules"].([]any)[0].(map[string]any)["id"].(string)
	return []adminReq{
		{method: http.MethodPost, path: polBase + "/rules", body: ruleFor("group", group)},
		{method: http.MethodPut, path: polBase + "/rules/" + rule, body: `{"effect":"DENY","selector":{"container_name":"other"}}`},
		{method: http.MethodPost, path: polBase + "/rules/" + rule + "/disable"},
		{method: http.MethodPost, path: polBase + "/rules/" + rule + "/enable"},
		{method: http.MethodDelete, path: polBase + "/rules/" + rule},
		{method: http.MethodPost, path: adminBase + "/users/" + user + "/disable"},
		{method: http.MethodPost, path: adminBase + "/users/" + user + "/enable"},
		{method: http.MethodPost, path: adminBase + "/groups/" + group + "/disable"},
		{method: http.MethodPost, path: adminBase + "/groups/" + group + "/enable"},
		{method: http.MethodDelete, path: adminBase + "/groups/" + group},
		{method: http.MethodPost, path: adminBase + "/agents/" + agent + "/enable"},
		{method: http.MethodPut, path: adminBase + "/agents/" + agent + "/owner", body: `{"owner_group_id":"` + group + `"}`},
	}
}

var policyReads = []string{polBase + "/users", polBase + "/groups", polBase + "/agents", polBase + "/rules"}

func TestPolicyRoutesNeedTheBrowserBoundary(t *testing.T) { // CSRF, Origin, cookie, content type
	t.Parallel()
	h := newAdminHTTP(t)
	mutations := append(h.policyMutations(), adminReq{method: http.MethodPost, path: polBase + "/rules/preview", body: `{"selector":{"container_name":"web"}}`})
	empty, wrong := "", wrongCSRF(h.csrf)
	before, setup := h.snapshot(), h.notifications()
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
	for _, p := range policyReads {
		for name, q := range map[string]adminReq{"no cookie": {cookie: &empty}, "garbage cookie": {cookie: func() *string { s := "x"; return &s }()}, "bearer": {cookie: &empty, headers: map[string][]string{"Authorization": {"Bearer " + h.cookie}}}} {
			q.method, q.path = http.MethodGet, p
			if w := h.do(q); w.Code != http.StatusUnauthorized {
				t.Errorf("GET %s with %s: %d", p, name, w.Code)
			}
		}
	}
	h.mustNoChange("rejected requests", before)
	if h.notifications() != setup {
		t.Fatal("a rejected request notified")
	}
}

func TestPolicyMutationsRequireFreshAAL2ButReadsDoNot(t *testing.T) {
	t.Parallel()
	h := newAdminHTTP(t)
	mutations := h.policyMutations()
	n := h.notifications()
	h.clock.Advance(DefaultStepUpWindow + time.Second) // evidence older than 15 minutes
	before := h.snapshot()
	for _, m := range mutations {
		w := h.do(m)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "step_up_required") {
			t.Errorf("%s %s with stale evidence: %d %s", m.method, m.path, w.Code, w.Body.String())
		}
	}
	h.mustNoChange("stale evidence", before)
	if h.notifications() != n {
		t.Fatal("a refused mutation notified")
	}
	for _, p := range policyReads {
		if w := h.do(adminReq{method: http.MethodGet, path: p}); w.Code != http.StatusOK {
			t.Errorf("reads must not need step-up: GET %s %d", p, w.Code)
		}
	}
}

func TestOrdinaryUsersCannotManagePolicyOverDirectlyCraftedRequests(t *testing.T) { // acceptance: ordinary-user policy mutations fail
	t.Parallel()
	h := newAdminHTTP(t)
	mutations := append(h.policyMutations(), adminReq{method: http.MethodPost, path: polBase + "/rules/preview", body: `{"selector":{"container_name":"web"}}`})
	// The signed-in human, with a genuine fresh AAL2 session and a valid CSRF token, is NOT the administrator.
	h.exec(`UPDATE administrative_roles SET state='disabled' WHERE id='adm'`)
	before := h.snapshot()
	n := h.notifications()
	for _, q := range mutations {
		if w := h.do(q); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "forbidden") {
			t.Errorf("%s %s by a non-administrator: %d %s", q.method, q.path, w.Code, w.Body.String())
		}
	}
	for _, p := range policyReads {
		w := h.do(adminReq{method: http.MethodGet, path: p})
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s by a non-administrator: %d", p, w.Code)
		}
		if strings.Contains(w.Body.String(), "subject") {
			t.Errorf("GET %s leaked data to a non-administrator", p)
		}
	}
	h.mustNoChange("non-administrator over HTTP", before)
	if h.notifications() != n {
		t.Fatal("a denied request notified")
	}
}

func TestPolicyBodiesAreStrictAndNoCallerAssertionIsAnInput(t *testing.T) {
	t.Parallel()
	h := newAdminHTTP(t)
	user := h.person("subject")
	agent := h.agentOwnedBy("bot", user)
	valid := ruleFor("agent", agent)
	rule := h.mustCreate(polBase+"/rules", valid, http.StatusCreated)["rules"].([]any)[0].(map[string]any)["id"].(string)
	routes := map[string]struct{ method, valid string }{
		polBase + "/rules":                        {http.MethodPost, strings.Replace(valid, `"web"`, `"fresh"`, 1)},
		polBase + "/rules/" + rule:                {http.MethodPut, `{"effect":"DENY","selector":{"container_name":"fresh"}}`},
		polBase + "/rules/preview":                {http.MethodPost, `{"selector":{"container_name":"web"}}`},
		adminBase + "/agents/" + agent + "/owner": {http.MethodPut, `{"owner_user_id":"` + user + `"}`},
	}
	inject := func(body, extra string) string { return strings.TrimSuffix(body, "}") + "," + extra + "}" }
	before, setup := h.snapshot(), h.notifications()
	for path, r := range routes {
		for name, body := range map[string]string{
			"state":              inject(r.valid, `"state":"active"`),
			"role":               inject(r.valid, `"role":"super_admin"`),
			"administrator flag": inject(r.valid, `"is_admin":true`),
			"generation":         inject(r.valid, `"authority_generation":99`),
			"id":                 inject(r.valid, `"id":"forced"`),
			"endpoint":           inject(r.valid, `"endpoint_id":"00000000-0000-4000-8000-000000000002"`),
			"acknowledged broad": inject(r.valid, `"acknowledged_broad":true`),
			"trailing data":      r.valid + ` {}`,
			"trailing garbage":   r.valid + `x`,
			"array":              `[]`,
			"null":               `null`,
			"string":             `"x"`,
			"truncated":          r.valid[:len(r.valid)-1],
			"wrong content":      `name=a`,
			"empty body":         ``,
			"oversized":          `{"name":"` + strings.Repeat("a", 70000) + `"}`,
		} {
			w := h.do(adminReq{method: r.method, path: path, body: body})
			if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("%s %s %s: %d %s", r.method, path, name, w.Code, w.Body.String())
			}
		}
	}
	// The creation body in particular: nothing but the documented fields, with strictly typed values.
	for name, body := range map[string]string{
		"effect lower case":      strings.Replace(valid, `"ALLOW"`, `"allow"`, 1),
		"effect number":          strings.Replace(valid, `"ALLOW"`, `1`, 1),
		"operations a string":    strings.Replace(valid, `["container:logs"]`, `"container:logs"`, 1),
		"operation wildcard":     strings.Replace(valid, `container:logs`, `container:*`, 1),
		"operation exec":         strings.Replace(valid, `container:logs`, `container:exec`, 1),
		"operation raw":          strings.Replace(valid, `container:logs`, `docker:raw`, 1),
		"cap as float":           inject(valid, `"log_tail_max":1.5`),
		"cap as string":          inject(valid, `"log_tail_max":"10"`),
		"cap negative":           inject(valid, `"log_tail_max":-1`),
		"cap on a deny":          strings.Replace(inject(valid, `"log_tail_max":10`), `"ALLOW"`, `"DENY"`, 1),
		"subject kind role":      strings.Replace(valid, `"kind":"agent"`, `"kind":"role"`, 1),
		"subject is the role id": `{"subject":{"kind":"user","id":"super_admin"},"effect":"ALLOW","operations":["container:logs"],"selector":{"container_name":"web"}}`,
		"selector name missing":  strings.Replace(valid, `"container_name":"web"`, `"name_is_glob":true`, 1),
		"glob flag as string":    strings.Replace(valid, `"container_name":"web"`, `"container_name":"web","name_is_glob":"yes"`, 1),
	} {
		w := h.do(adminReq{method: http.MethodPost, path: polBase + "/rules", body: body})
		if w.Code != http.StatusBadRequest {
			t.Errorf("create %s: %d %s", name, w.Code, w.Body.String())
		}
	}
	h.mustNoChange("malformed or mass-assignment bodies", before)
	if h.notifications() != setup {
		t.Fatal("a rejected body notified")
	}
}

func TestPolicyErrorsAreFixedCodesThatNeverEchoInput(t *testing.T) {
	t.Parallel()
	h := newAdminHTTP(t)
	secretish := "ECHO-CANARY-9f3a"
	for _, q := range []adminReq{
		{method: http.MethodPost, path: polBase + "/rules", body: `{"subject":{"kind":"user","id":"` + secretish + `"},"effect":"ALLOW","operations":["container:logs"],"selector":{"container_name":"web"}}`},
		{method: http.MethodPost, path: polBase + "/rules", body: `{"subject":{"kind":"user","id":"u"},"effect":"ALLOW","operations":["container:logs"],"selector":{"container_name":"` + secretish + `["}}`},
		{method: http.MethodPut, path: polBase + "/rules/" + secretish, body: `{"effect":"DENY","selector":{"container_name":"x"}}`},
		{method: http.MethodDelete, path: polBase + "/rules/" + secretish},
		{method: http.MethodPost, path: adminBase + "/users/" + secretish + "/disable"},
		{method: http.MethodPut, path: adminBase + "/agents/" + secretish + "/owner", body: `{"owner_user_id":"` + secretish + `"}`},
		{method: http.MethodPost, path: polBase + "/rules/preview", body: `{"selector":{"container_name":"` + secretish + `["}}`},
	} {
		w := h.do(q)
		if w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s %s: %d", q.method, q.path, w.Code)
		}
		if strings.Contains(w.Body.String(), secretish) {
			t.Errorf("%s %s echoed its input: %s", q.method, q.path, w.Body.String())
		}
		var body map[string]string
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 1 || body["error"] == "" {
			t.Errorf("%s %s: not a fixed error object: %s", q.method, q.path, w.Body.String())
		}
	}
}

// The web client decodes these pages strictly (a list that is not an array is a failed load), so an empty
// list must be [] on the wire and never null. Only `inventory` is allowed to be null, and it means
// "the endpoint cannot be listed".
func TestEmptyPagesUseEmptyArrays(t *testing.T) {
	t.Parallel()
	h := newAdminHTTP(t)
	for _, p := range []string{"/users", "/groups", "/agents", "/rules"} {
		_, raw := h.req(http.MethodGet, polBase+p, "")
		var page map[string]any
		if err := json.Unmarshal([]byte(raw), &page); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		var walk func(path string, v any)
		walk = func(path string, v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					if e == nil && k != "inventory" && k != "log_tail_max" && k != "stop_timeout_max" {
						t.Errorf("%s: %s.%s is null", p, path, k)
					}
					walk(path+"."+k, e)
				}
			case []any:
				for i, e := range x {
					walk(fmt.Sprintf("%s[%d]", path, i), e)
				}
			}
		}
		walk("", page)
	}
	// Groups and agents with nothing in them exercise the nested lists.
	g := h.group("empty")
	_ = g
	_, raw := h.req(http.MethodGet, polBase+"/groups", "")
	if strings.Contains(raw, "null") {
		t.Fatalf("groups page contains null: %s", raw)
	}
	_ = h.agentOwnedBy("lone", h.person("someone"))
	_, raw = h.req(http.MethodGet, polBase+"/agents", "")
	if strings.Contains(raw, "null") {
		t.Fatalf("agents page contains null: %s", raw)
	}
	_, raw = h.req(http.MethodGet, polBase+"/users", "")
	if strings.Contains(raw, "null") {
		t.Fatalf("users page contains null: %s", raw)
	}
}
