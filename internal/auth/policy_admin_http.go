package auth

import (
	"net/http"
)

// P1.17 routes of the administrative adapter (agents_http.go owns the Browser boundary, the strict body
// decoder and the fixed error codes; this file only adds handlers). Every route is registered on an
// auth.Browser, so the cookie, exact Origin, per-session CSRF, JSON-only body, 64 KiB bound and (for a
// mutation) the step-up gate run BEFORE any handler, and the service independently re-checks the single
// administrator, AAL2 freshness and the live generations in its own durable transaction. No handler
// consults a role, an effect-less default or anything the caller says about itself.
//
// Reads are page-shaped (`/policy/...`) and mutations reuse the P1.10 routes where one exists. Bodies are
// single JSON objects with unknown fields refused, so a request cannot assign state, generation, an
// administrative role or a subject's authority. There is no route that creates, grants or moves an
// administrative role and none that names an operation outside the six approved keys.

const policyBase = adminAPIBase + "/policy"

type policyRoute struct {
	pattern string
	policy  RoutePolicy
	handler http.HandlerFunc
}

func (h *AdminHTTP) policyRoutes(read, mutate RoutePolicy) []policyRoute {
	return []policyRoute{
		{"GET " + policyBase + "/users", read, h.policyUsers},
		{"GET " + policyBase + "/groups", read, h.policyGroups},
		{"GET " + policyBase + "/agents", read, h.policyAgents},
		{"GET " + policyBase + "/rules", read, h.policyRules},
		// A preview is a read that carries a body: it needs the session and CSRF but no step-up, writes nothing.
		{"POST " + policyBase + "/rules/preview", read, h.previewRule},
		{"POST " + policyBase + "/rules", mutate, h.createRules},
		{"PUT " + policyBase + "/rules/{rule}", mutate, h.updateRule},
		{"POST " + policyBase + "/rules/{rule}/enable", mutate, h.enableRule},
		{"POST " + policyBase + "/rules/{rule}/disable", mutate, h.disableRule},
		{"DELETE " + policyBase + "/rules/{rule}", mutate, h.deleteRule},
		{"POST " + adminAPIBase + "/users/{user}/disable", mutate, h.userLifecycle(false)},
		{"POST " + adminAPIBase + "/users/{user}/enable", mutate, h.userLifecycle(true)},
		{"POST " + adminAPIBase + "/groups/{group}/disable", mutate, h.groupLifecycle(false)},
		{"POST " + adminAPIBase + "/groups/{group}/enable", mutate, h.groupLifecycle(true)},
		{"DELETE " + adminAPIBase + "/groups/{group}", mutate, h.deleteGroup},
		{"POST " + adminAPIBase + "/agents/{agent}/enable", mutate, h.enableAgent},
		{"PUT " + adminAPIBase + "/agents/{agent}/owner", mutate, h.transferAgent},
	}
}

// emptyBody accepts an absent body or an empty object, nothing else.
func emptyBody(r *http.Request) bool { return decodeStrict(r, &struct{}{}, true) }

func (h *AdminHTTP) policyUsers(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.UsersPage(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (h *AdminHTTP) policyGroups(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.GroupsPage(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, out)
}

func (h *AdminHTTP) policyAgents(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.AgentsPage(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, out)
}

func (h *AdminHTTP) policyRules(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.RulesPage(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, out)
}

func (h *AdminHTTP) previewRule(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Selector SelectorSpec `json:"selector"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	out, err := h.a.PreviewSelector(r.Context(), secret, body.Selector)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, out)
}

// ruleBody is the creation schema. caps are absent (null) unless the rule is an ALLOW that takes them.
type ruleBody struct {
	Subject        RuleSubject  `json:"subject"`
	Effect         string       `json:"effect"`
	Operations     []string     `json:"operations"`
	Selector       SelectorSpec `json:"selector"`
	LogTailMax     *int         `json:"log_tail_max"`
	StopTimeoutMax *int         `json:"stop_timeout_max"`
}

func (h *AdminHTTP) createRules(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body ruleBody
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	out, err := h.a.CreateRules(r.Context(), secret, RuleRequest(body))
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusCreated, map[string]any{"rules": out})
}

func (h *AdminHTTP) updateRule(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Effect         string       `json:"effect"`
		Selector       SelectorSpec `json:"selector"`
		LogTailMax     *int         `json:"log_tail_max"`
		StopTimeoutMax *int         `json:"stop_timeout_max"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	out, err := h.a.UpdateRule(r.Context(), secret, r.PathValue("rule"), RuleEdit{Effect: body.Effect, Selector: body.Selector, LogTailMax: body.LogTailMax, StopTimeoutMax: body.StopTimeoutMax})
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"rule": out})
}

func (h *AdminHTTP) ruleState(call func(*Admin, *http.Request, []byte) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, ok := adminSecret(r)
		if !ok || !emptyBody(r) {
			writeJSONError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if err := call(h.a, r, secret); err != nil {
			adminFailure(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *AdminHTTP) enableRule(w http.ResponseWriter, r *http.Request) {
	h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		return a.EnableRule(r.Context(), s, r.PathValue("rule"))
	})(w, r)
}

func (h *AdminHTTP) disableRule(w http.ResponseWriter, r *http.Request) {
	h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		return a.DisableRule(r.Context(), s, r.PathValue("rule"))
	})(w, r)
}

func (h *AdminHTTP) deleteRule(w http.ResponseWriter, r *http.Request) {
	h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		return a.DeleteRule(r.Context(), s, r.PathValue("rule"))
	})(w, r)
}

func (h *AdminHTTP) userLifecycle(enable bool) http.HandlerFunc {
	return h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		if enable {
			return a.EnableUser(r.Context(), s, r.PathValue("user"))
		}
		return a.DisableUser(r.Context(), s, r.PathValue("user"))
	})
}

func (h *AdminHTTP) groupLifecycle(enable bool) http.HandlerFunc {
	return h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		if enable {
			return a.EnableGroup(r.Context(), s, r.PathValue("group"))
		}
		return a.DisableGroup(r.Context(), s, r.PathValue("group"))
	})
}

func (h *AdminHTTP) deleteGroup(w http.ResponseWriter, r *http.Request) {
	h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		return a.DeleteGroup(r.Context(), s, r.PathValue("group"))
	})(w, r)
}

func (h *AdminHTTP) enableAgent(w http.ResponseWriter, r *http.Request) {
	h.ruleState(func(a *Admin, r *http.Request, s []byte) error {
		return a.EnableAgent(r.Context(), s, r.PathValue("agent"))
	})(w, r)
}

func (h *AdminHTTP) transferAgent(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		OwnerUserID  string `json:"owner_user_id"`
		OwnerGroupID string `json:"owner_group_id"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.a.TransferAgent(r.Context(), secret, r.PathValue("agent"), AgentOwner{UserID: body.OwnerUserID, GroupID: body.OwnerGroupID}); err != nil {
		adminFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
