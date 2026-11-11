package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// SetupCookieName is deliberately NOT the normal session cookie: the normal
// verifier ignores it, and the setup verifier ignores the normal cookie. It uses
// the same __Host- scoping (Secure, Path=/, no Domain) and is never persistent.
const SetupCookieName = "__Host-mandatary_setup"

// SetupPathPrefix is the entire setup HTTP surface. There is no GET that mutates
// anything, no redirect, no query/path/fragment secret and no SPA fallback.
const SetupPathPrefix = "/api/v1/setup/"

// SetupHTTP is the browser-facing adapter of Setup (SETUP-02/05/06). It applies
// the same Host, exact-Origin, JSON-only, bounded-body and server-derived CSRF
// discipline as the normal browser layer, additionally answers 404 for EVERY path
// when no setup/recovery generation or session is live, and trusts no forwarded
// header: the peer IP is the connection's RemoteAddr.
type SetupHTTP struct {
	s      *Setup
	origin string
	host   string
}

// NewSetupHTTP binds the adapter to the configured HTTPS origin.
func NewSetupHTTP(s *Setup) (*SetupHTTP, error) {
	if s == nil {
		return nil, ErrSetupDenied
	}
	u, err := url.Parse(s.settings.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, ErrSetupDenied
	}
	return &SetupHTTP{s: s, origin: canonicalOrigin(u.Scheme, u.Host), host: canonicalHost(u.Host)}, nil
}

type setupRoute struct {
	method  string
	path    string
	session bool // requires a live setup session (cookie + CSRF for unsafe methods)
	handle  func(h *SetupHTTP, w http.ResponseWriter, r *http.Request, session SetupSession)
}

func (h *SetupHTTP) routes() []setupRoute {
	return []setupRoute{
		{http.MethodPost, "exchange", false, (*SetupHTTP).exchange},
		{http.MethodGet, "session", true, (*SetupHTTP).sessionInfo},
		{http.MethodPost, "account", true, (*SetupHTTP).account},
		{http.MethodPost, "addresses/proof", true, (*SetupHTTP).addressProof},
		{http.MethodPost, "addresses/confirm", true, (*SetupHTTP).addressConfirm},
		{http.MethodPost, "totp", true, (*SetupHTTP).totpBegin},
		{http.MethodPost, "totp/confirm", true, (*SetupHTTP).totpConfirm},
		{http.MethodPost, "complete", true, (*SetupHTTP).complete},
	}
}

// Handler serves only SetupPathPrefix. Mount it beside (never inside) the static
// handler; any other path must not be routed here.
func (h *SetupHTTP) Handler() http.Handler {
	routes := h.routes()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		if r.Host == "" || canonicalHost(r.Host) != h.host {
			writeJSONError(w, http.StatusMisdirectedRequest, "misdirected_request")
			return
		}
		name, ok := strings.CutPrefix(r.URL.Path, SetupPathPrefix)
		if !ok || r.URL.RawQuery != "" {
			writeJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		var route *setupRoute
		pathKnown := false
		for i := range routes {
			if routes[i].path == name {
				pathKnown = true
				if routes[i].method == r.Method {
					route = &routes[i]
				}
			}
		}
		// Closed unless a generation/session is live: the surface itself does not
		// exist after setup, and probing reveals nothing else.
		open, err := h.s.surfaceOpen(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		if !pathKnown || !open {
			writeJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		if route == nil {
			w.Header().Set("Allow", allowedMethods(routes, name))
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		unsafe := route.method != http.MethodGet
		if unsafe {
			if !h.sameOrigin(r) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			if !jsonBody(r) {
				writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		var session SetupSession
		if route.session {
			secret, present, valid := setupSecretFrom(r)
			if !valid {
				if present {
					clearSetupCookie(w)
				}
				writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			info, err := h.s.Authenticate(r.Context(), secret)
			if err != nil {
				if errors.Is(err, ErrSetupDenied) {
					clearSetupCookie(w)
					writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
					return
				}
				writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
				return
			}
			session = SetupSession{SetupSessionInfo: info, secret: secret}
			if unsafe {
				want := session.CSRFToken()
				tokens := r.Header.Values(CSRFHeader)
				if len(tokens) != 1 || len(tokens[0]) != len(want) || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(want)) != 1 {
					writeJSONError(w, http.StatusForbidden, "forbidden")
					return
				}
			}
		}
		route.handle(h, w, r, session)
	})
}

func allowedMethods(routes []setupRoute, name string) string {
	var methods []string
	for _, r := range routes {
		if r.path == name {
			methods = append(methods, r.method)
		}
	}
	return strings.Join(methods, ", ")
}

// surfaceOpen reports whether any consumable generation or live session exists.
func (s *Setup) surfaceOpen(ctx context.Context) (bool, error) {
	status, err := s.Status(ctx)
	if err != nil {
		return false, err
	}
	if status.LiveSessions > 0 {
		return true, nil
	}
	for _, t := range status.Tokens {
		if t.State == "retrieved" && !t.Expired {
			return true, nil
		}
	}
	return false, nil
}

func (h *SetupHTTP) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != h.origin {
		return false
	}
	site := r.Header.Values("Sec-Fetch-Site")
	return len(site) == 0 || (len(site) == 1 && site[0] == "same-origin")
}

func setSetupCookie(w http.ResponseWriter, secret []byte) {
	http.SetCookie(w, &http.Cookie{Name: SetupCookieName, Value: base64.RawURLEncoding.EncodeToString(secret), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func clearSetupCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SetupCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// setupSecretFrom parses EXACTLY one setup cookie from the raw header (quoting,
// duplicates and look-alikes are rejected) and ignores every other cookie.
func setupSecretFrom(r *http.Request) (secret []byte, present, ok bool) {
	var values []string
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			name, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && name == SetupCookieName {
				values = append(values, value)
			}
		}
	}
	if len(values) == 0 {
		return nil, false, false
	}
	if len(values) != 1 || len(values[0]) != base64.RawURLEncoding.EncodedLen(sessionSecretBytes) {
		return nil, true, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	if err != nil || len(decoded) != sessionSecretBytes {
		return nil, true, false
	}
	return decoded, true, true
}

// peerIP is the connection's own address. Forwarded headers are never consulted.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func decodeBody(r *http.Request, v any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return false
	}
	// Exactly one JSON value: trailing data is rejected.
	var extra json.RawMessage
	return decoder.Decode(&extra) == io.EOF
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeSetupError maps fixed outcomes only. No token, digest, password, proof,
// storage or policy detail beyond the static guidance strings is ever echoed.
func writeSetupError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPassword) || errors.Is(err, ErrBlocked):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "password_rejected", "guidance": err.Error()})
	case errors.Is(err, ErrSetupBusy):
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, ErrSetupDenied):
		writeJSONError(w, http.StatusForbidden, "denied")
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
	}
}

func (h *SetupHTTP) exchange(w http.ResponseWriter, r *http.Request, _ SetupSession) {
	var body struct {
		Token string `json:"token"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	session, err := h.s.Exchange(r.Context(), body.Token, peerIP(r))
	body.Token = ""
	if err != nil {
		if errors.Is(err, ErrSetupDenied) {
			writeJSONError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		writeSetupError(w, err)
		return
	}
	setSetupCookie(w, session.secret)
	writeJSON(w, http.StatusOK, h.view(session))
}

func (h *SetupHTTP) view(s SetupSession) map[string]any {
	return map[string]any{
		"purpose":          s.Purpose,
		"expires_at":       s.ExpiresAt.Unix(),
		"csrf_token":       s.CSRFToken(),
		"replace_password": s.ReplacePassword,
		"target_user":      s.TargetUser,
		"account_staged":   s.AccountStaged,
		"totp_begun":       s.TOTPBegun,
		"totp_proven":      s.TOTPProven,
		"addresses":        s.Addresses,
		"mail_configured":  s.MailConfigured,
	}
}

func (h *SetupHTTP) sessionInfo(w http.ResponseWriter, _ *http.Request, session SetupSession) {
	writeJSON(w, http.StatusOK, h.view(session))
}

func (h *SetupHTTP) account(w http.ResponseWriter, r *http.Request, session SetupSession) {
	var body struct {
		Username  string   `json:"username"`
		Password  string   `json:"password"`
		Addresses []string `json:"addresses"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	staged, err := h.s.StageAccount(r.Context(), session.secret, AccountRequest{Username: body.Username, Password: password, Addresses: body.Addresses})
	if err != nil {
		writeSetupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"addresses": staged})
}

func (h *SetupHTTP) addressProof(w http.ResponseWriter, r *http.Request, session SetupSession) {
	var body struct {
		AddressID string `json:"address_id"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.s.SendAddressProof(r.Context(), session.secret, body.AddressID); err != nil {
		writeSetupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SetupHTTP) addressConfirm(w http.ResponseWriter, r *http.Request, session SetupSession) {
	var body struct {
		AddressID string `json:"address_id"`
		Proof     string `json:"proof"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.s.ConfirmAddress(r.Context(), session.secret, body.AddressID, body.Proof, peerIP(r)); err != nil {
		writeSetupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SetupHTTP) totpBegin(w http.ResponseWriter, r *http.Request, session SetupSession) {
	var body struct {
		Algorithm string `json:"algorithm"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	enrollment, err := h.s.BeginTOTP(r.Context(), session.secret, body.Algorithm)
	if err != nil {
		writeSetupError(w, err)
		return
	}
	seed := enrollment.ExportOnce()
	defer clear(seed)
	// The seed is shown exactly once, over the protected channel, never logged.
	writeJSON(w, http.StatusOK, map[string]any{"authenticator_id": enrollment.ID, "secret": string(seed), "algorithm": body.Algorithm, "digits": 6, "period": 30})
}

func (h *SetupHTTP) totpConfirm(w http.ResponseWriter, r *http.Request, session SetupSession) {
	var body struct {
		Code string `json:"code"`
	}
	if !decodeBody(r, &body) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.s.ConfirmTOTP(r.Context(), session.secret, body.Code, peerIP(r)); err != nil {
		writeSetupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SetupHTTP) complete(w http.ResponseWriter, r *http.Request, session SetupSession) {
	if !decodeEmptyObject(r) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.s.Complete(r.Context(), session.secret)
	if err != nil {
		writeSetupError(w, err)
		return
	}
	// No cookie, session or token is issued: the administrator must now log in
	// through the ordinary password + MFA path. The setup cookie is cleared.
	clearSetupCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"purpose": result.Purpose, "username": result.Username, "login_required": true})
}

func decodeEmptyObject(r *http.Request) bool {
	data, err := io.ReadAll(r.Body)
	return err == nil && bytes.Equal(bytes.TrimSpace(data), []byte("{}"))
}
