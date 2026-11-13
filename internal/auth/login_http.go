package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Browser account routes (P1.16.3, slice 1): the password step of login, its two
// completion steps, session info and logout. This file adds NO authority: every
// proof is verified by Sessions, every route sits behind the Browser boundary
// (exact Host/Origin, JSON-only, bounded body, server-derived CSRF) with an
// explicit RoutePolicy, and no request field can set an assurance, method, role
// or time. WebAuthn login, step-up and the factor/recovery lifecycle are slice 2
// and are deliberately NOT registered here.
//
// Public outcomes (the SPA interprets only these):
//
//	401 unauthenticated  no/ended/unknown credential or capability (cookie cleared
//	                     by the boundary), or a failed PASSWORD step (generic: unknown
//	                     user, wrong password, exhausted factor and an account wait
//	                     are one outcome, password contract parity)
//	403 denied           a refused second-factor or password-only completion
//	                     (wrong, replayed, throttled and exhausted codes are one outcome)
//	403 forbidden        Origin/CSRF refusal (from the boundary)
//	503 unavailable      storage uncertainty; never access
const (
	LoginPath      = "/api/v1/login"
	LoginTOTPPath  = "/api/v1/login/totp"
	LoginNoMFAPath = "/api/v1/login/no-mfa"
	SessionPath    = "/api/v1/session"
	LogoutPath     = "/api/v1/logout"
)

// AccountPaths lists the exact paths RegisterAccountRoutes serves, for mounting.
func AccountPaths() []string {
	return []string{LoginPath, LoginTOTPPath, LoginNoMFAPath, SessionPath, LogoutPath}
}

// accountHTTP carries the services shared by the handlers.
type accountHTTP struct {
	b *Browser
	s *Sessions
}

// RegisterAccountRoutes mounts the slice-1 account routes on b. It refuses a nil
// boundary or service, and any weaker re-registration of an existing pattern.
func RegisterAccountRoutes(b *Browser, s *Sessions) error {
	if b == nil || s == nil || b.sessions != s {
		return ErrDenied
	}
	h := &accountHTTP{b: b, s: s}
	routes := []struct {
		pattern string
		policy  RoutePolicy
		handler http.Handler
	}{
		{"POST " + LoginPath, RoutePolicy{Require: RequireNone}, http.HandlerFunc(h.login)},
		{"POST " + LoginTOTPPath, RoutePolicy{Require: RequirePreauth}, http.HandlerFunc(h.loginTOTP)},
		{"POST " + LoginNoMFAPath, RoutePolicy{Require: RequirePreauth}, http.HandlerFunc(h.loginNoMFA)},
		{"GET " + SessionPath, RoutePolicy{Require: RequireSession}, http.HandlerFunc(h.info)},
		{"POST " + LogoutPath, RoutePolicy{Require: RequireSession}, noQuery(b.LogoutHandler())},
	}
	for _, r := range routes {
		if err := b.Handle(r.pattern, r.policy, r.handler); err != nil {
			return err
		}
	}
	return nil
}

// noQuery refuses any query string: nothing on these routes reads one, and a
// credential-looking query must never be treated as merely ignored.
func noQuery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			writeJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *accountHTTP) fault(w http.ResponseWriter, err error, denied func()) {
	if errors.Is(err, ErrDenied) {
		denied()
		return
	}
	writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
}

func (h *accountHTTP) login(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	result, err := h.s.PasswordLogin(r.Context(), body.Username, password, peerIP(r))
	clear(password)
	if err != nil {
		h.fault(w, err, func() { writeJSONError(w, http.StatusUnauthorized, "unauthenticated") })
		return
	}
	h.b.SetSessionCookie(w, result.Session)
	if result.Session.Info.Assurance == AssurancePreauth {
		// The account's usable TOTP factors (non-secret identifiers) let the page offer
		// a choice when there are several; with one, the server picks it anyway.
		factors := []totpRow{}
		if _, acct, e := h.s.preauthOwner(r.Context(), result.Session.Secret()); e == nil {
			factors = totpFactorRows(acct)
		}
		writeJSON(w, http.StatusOK, map[string]any{"step": "factor", "next": result.Next, "csrf_token": result.Session.CSRFToken(), "totp_factors": factors})
		return
	}
	// An optional-MFA account with no second factor and a long password: a
	// labelled lower-assurance session. The SPA reads the label from GET session.
	writeJSON(w, http.StatusOK, map[string]any{"step": "session"})
}

// loginTOTP completes a login with a verified TOTP. The authenticator is chosen
// by the SERVER: the SPA has no authenticator identifier, and an account with
// several live TOTP factors is refused here rather than guessed at (selection is
// slice 2). No factor attempt is spent on a refusal made before verification.
func (h *accountHTTP) loginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	var body struct {
		Code            string `json:"code"`
		AuthenticatorID string `json:"authenticator_id"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	pre, ok := SessionFrom(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	secret := pre.Secret()
	_, acct, err := h.s.preauthOwner(r.Context(), secret)
	if err != nil {
		h.fault(w, err, func() { h.b.ClearSessionCookie(w); writeJSONError(w, http.StatusUnauthorized, "unauthenticated") })
		return
	}
	id, chosen := chooseTOTP(acct, body.AuthenticatorID)
	if !chosen {
		writeJSONError(w, http.StatusForbidden, "denied")
		return
	}
	issued, err := h.s.LoginTOTP(r.Context(), secret, id, body.Code, peerIP(r))
	body.Code = ""
	if err != nil {
		h.fault(w, err, func() { writeJSONError(w, http.StatusForbidden, "denied") })
		return
	}
	h.b.SetSessionCookie(w, issued)
	writeJSON(w, http.StatusOK, map[string]any{"step": "session"})
}

// loginNoMFA completes the explicitly offered password-only login. The service
// re-checks policy: administrators, required-MFA accounts and stranded floors
// are refused no matter what the page offered.
func (h *accountHTTP) loginNoMFA(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	if !decodeEmptyObject(r) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	pre, ok := SessionFrom(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	issued, err := h.s.LoginWithoutMFA(r.Context(), pre.Secret())
	if err != nil {
		h.fault(w, err, func() { writeJSONError(w, http.StatusForbidden, "denied") })
		return
	}
	h.b.SetSessionCookie(w, issued)
	writeJSON(w, http.StatusOK, map[string]any{"step": "session"})
}

// info returns the server-derived session view for the SPA shell: the labels of
// SessionInfoHandler plus the non-secret username. Every field comes from the
// persisted session and the live account; the client asserts nothing.
func (h *accountHTTP) info(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	session, ok := SessionFrom(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var acct accountView
	err := h.s.read(r.Context(), func(q *store.Queries) error {
		c, e := q.GetInstallationControl(r.Context())
		if e != nil {
			return e
		}
		acct, e = loadAccount(r.Context(), q, c, session.UserID, h.s.l.now().Unix())
		return e
	})
	if err != nil {
		h.fault(w, err, func() { h.b.ClearSessionCookie(w); writeJSONError(w, http.StatusUnauthorized, "unauthenticated") })
		return
	}
	stale := h.s.l.now().Sub(session.AuthenticatedAt) > h.s.settings.StepUp
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":           acct.user.Username,
		"administrator":      acct.admin,
		"step_up_methods":    acct.stepUpMethods(session, h.s.webauthnReady()),
		"totp_factors":       totpFactorRows(acct),
		"assurance":          session.Assurance,
		"methods":            session.Methods,
		"phishing_resistant": session.PhishingResistant,
		"required_assurance": session.RequiredAssurance,
		"usable_assurance":   session.UsableAssurance,
		"authenticated_at":   session.AuthenticatedAt.Unix(),
		"expires_at":         session.ExpiresAt.Unix(),
		"csrf_token":         session.CSRFToken(),
		"step_up_required":   stale,
	})
}
