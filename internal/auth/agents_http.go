package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"time"
)

// AdminHTTP is the administrative route adapter (P1.10). It translates strictly
// decoded JSON into Admin calls and Admin results into fixed responses. It adds
// no authority of its own: every route is registered on an auth.Browser, so
// the cookie, exact Origin, per-session CSRF token, JSON-only body and step-up
// gates run BEFORE any handler, and the service independently re-checks the single
// administrator, AAL2 freshness and the live control generations inside its own
// durable transaction. Agent bearer tokens never reach this surface: the Browser
// reads only the session cookie (N63B4-SCOPE-MACHINE).
//
// There is deliberately no role, administrator, policy-effect, generation,
// verifier or token-input field anywhere in the request schemas: unknown fields are
// rejected, so a mass-assignment attempt fails before any state is read.
//
// Only registration is provided. The static server mounts no route until its
// owning task composes login/step-up adapters (P1.16) and the API surface (P1.14).
type AdminHTTP struct{ a *Admin }

// NewAdminHTTP wraps an administrative service.
func NewAdminHTTP(a *Admin) (*AdminHTTP, error) {
	if a == nil {
		return nil, ErrDenied
	}
	return &AdminHTTP{a: a}, nil
}

const adminAPIBase = "/api/v1/admin"

// AdminPathPrefix is the subtree a server mounts to this boundary for the
// administrative API; the Browser answers 404 for any path it did not register.
const AdminPathPrefix = adminAPIBase + "/"

// Register mounts the fixed route set. Each pattern carries an explicit policy:
// reads need a normal session (the service requires the administrator);
// identity/group/membership changes are class security-policy-change and
// credential changes are class agent-credential-change, both AAL2 within 15 minutes.
func (h *AdminHTTP) Register(b *Browser) error {
	if b == nil {
		return ErrDenied
	}
	read := RoutePolicy{Require: RequireSession}
	policy := RoutePolicy{Require: RequireSession, Sensitive: OpSecurityPolicy}
	credential := RoutePolicy{Require: RequireSession, Sensitive: OpAgentAccessChange}
	routes := []struct {
		pattern string
		policy  RoutePolicy
		handler http.HandlerFunc
	}{
		{"GET " + adminAPIBase + "/users", read, h.listUsers},
		{"GET " + adminAPIBase + "/groups", read, h.listGroups},
		{"GET " + adminAPIBase + "/agents", read, h.listAgents},
		{"POST " + adminAPIBase + "/users", policy, h.createUser},
		{"POST " + adminAPIBase + "/groups", policy, h.createGroup},
		{"POST " + adminAPIBase + "/agents", policy, h.createAgent},
		{"PUT " + adminAPIBase + "/groups/{group}/members/{kind}/{member}", policy, h.addMember},
		{"DELETE " + adminAPIBase + "/groups/{group}/members/{kind}/{member}", policy, h.removeMember},
		{"POST " + adminAPIBase + "/agents/{agent}/disable", credential, h.disableAgent},
		{"POST " + adminAPIBase + "/agents/{agent}/credentials", credential, h.issueCredential},
		{"POST " + adminAPIBase + "/agents/{agent}/credentials/rotate", credential, h.rotateCredential},
		{"POST " + adminAPIBase + "/agents/{agent}/credentials/{credential}/revoke", credential, h.revokeCredential},
	}
	for _, r := range routes {
		if err := b.Handle(r.pattern, r.policy, r.handler); err != nil {
			return err
		}
	}
	return nil
}

func writeAdminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// adminFailure maps service errors to fixed, input-free responses. Storage detail,
// the failing check and request values are never reflected.
func adminFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAdminInvalid):
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, ErrAdminNotFound):
		writeJSONError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrAdminConflict):
		writeJSONError(w, http.StatusConflict, "conflict")
	case errors.Is(err, ErrDenied):
		writeJSONError(w, http.StatusForbidden, "forbidden")
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
	}
}

// decodeStrict reads exactly one JSON OBJECT into dst: unknown fields, trailing
// data and any non-object value (including null, which encoding/json would
// silently accept as an empty struct) are refused. optional accepts an absent body.
func decodeStrict(r *http.Request, dst any, optional bool) bool {
	raw, err := io.ReadAll(r.Body) // already bounded by the Browser's MaxBytesReader
	if err != nil {
		return false
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return optional
	}
	if raw[0] != '{' {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return false
	}
	var extra json.RawMessage
	return errors.Is(dec.Decode(&extra), io.EOF)
}

// seconds converts an explicit seconds field. Zero is meaningful only where the
// caller allows it; overflow and negative values are always refused.
func seconds(v *int64, zeroOK bool) (time.Duration, bool, bool) {
	if v == nil {
		return 0, false, true
	}
	if *v < 0 || (*v == 0 && !zeroOK) || *v > math.MaxInt64/int64(time.Second) {
		return 0, true, false
	}
	return time.Duration(*v) * time.Second, true, true
}

func adminSecret(r *http.Request) ([]byte, bool) {
	s, ok := SessionFrom(r)
	if !ok {
		return nil, false
	}
	return s.secret, true
}

func (h *AdminHTTP) listUsers(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.ListUsers(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (h *AdminHTTP) listGroups(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.ListGroups(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (h *AdminHTTP) listAgents(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	out, err := h.a.ListAgents(r.Context(), secret)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"agents": out})
}

func (h *AdminHTTP) createUser(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Username string `json:"username"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	out, err := h.a.CreateUser(r.Context(), secret, body.Username)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusCreated, map[string]any{"user": out})
}

func (h *AdminHTTP) createGroup(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Name string `json:"name"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	out, err := h.a.CreateGroup(r.Context(), secret, body.Name)
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusCreated, map[string]any{"group": out})
}

func (h *AdminHTTP) createAgent(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Name         string `json:"name"`
		OwnerUserID  string `json:"owner_user_id"`
		OwnerGroupID string `json:"owner_group_id"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	out, err := h.a.CreateAgent(r.Context(), secret, AgentRequest{Name: body.Name, OwnerUserID: body.OwnerUserID, OwnerGroupID: body.OwnerGroupID})
	if err != nil {
		adminFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusCreated, map[string]any{"agent": out})
}

func (h *AdminHTTP) addMember(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok || !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.a.AddMember(r.Context(), secret, r.PathValue("group"), MemberKind(r.PathValue("kind")), r.PathValue("member")); err != nil {
		adminFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHTTP) removeMember(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok || !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.a.RemoveMember(r.Context(), secret, r.PathValue("group"), MemberKind(r.PathValue("kind")), r.PathValue("member")); err != nil {
		adminFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHTTP) disableAgent(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok || !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.a.DisableAgent(r.Context(), secret, r.PathValue("agent")); err != nil {
		adminFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHTTP) revokeCredential(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok || !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.a.RevokeCredential(r.Context(), secret, r.PathValue("agent"), r.PathValue("credential")); err != nil {
		adminFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// credentialBody is the lifetime schema shared by issue and rotate. An absent
// ttl_seconds means the configured default; a present value must be >= 1.
type credentialBody struct {
	TTLSeconds  *int64 `json:"ttl_seconds"`
	NonExpiring bool   `json:"non_expiring"`
}

func (b credentialBody) request() (CredentialRequest, bool) {
	ttl, _, ok := seconds(b.TTLSeconds, false)
	return CredentialRequest{TTL: ttl, NonExpiring: b.NonExpiring}, ok
}

func (h *AdminHTTP) issueCredential(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body credentialBody
	if !ok || !decodeStrict(r, &body, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	req, valid := body.request()
	if !valid {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	issued, err := h.a.IssueCredential(r.Context(), secret, r.PathValue("agent"), req)
	if err != nil {
		adminFailure(w, err)
		return
	}
	token := issued.ExportOnce()
	defer clear(token)
	writeAdminJSON(w, http.StatusCreated, map[string]any{"credential": issued.Credential, "token": string(token)})
}

func (h *AdminHTTP) rotateCredential(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		credentialBody
		OverlapSeconds *int64 `json:"overlap_seconds"`
		Immediate      bool   `json:"immediate"`
	}
	if !ok || !decodeStrict(r, &body, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	req, valid := body.request()
	// overlap_seconds: absent = configured default; 0 = no overlap (revoke at once).
	overlap, present, overlapOK := seconds(body.OverlapSeconds, true)
	if !valid || !overlapOK || (present && body.Immediate) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	immediate := body.Immediate || (present && overlap == 0)
	res, err := h.a.RotateCredential(r.Context(), secret, r.PathValue("agent"), RotateRequest{CredentialRequest: req, Overlap: overlap, Immediate: immediate})
	if err != nil {
		adminFailure(w, err)
		return
	}
	token := res.New.ExportOnce()
	defer clear(token)
	writeAdminJSON(w, http.StatusCreated, map[string]any{"credential": res.New.Credential, "token": string(token), "rotated_out": res.RotatedOut})
}
