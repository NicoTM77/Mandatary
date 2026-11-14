package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Restricted-recovery routes (P1.16.4). Recovery is the saved-code path: a still
// valid password plus ONE unused saved code yields a ten-minute RE-ENROLMENT
// capability and one replacement code (Lifecycle.Recover). It is never a session,
// never ordinary login evidence and cannot reach any session route; its cookie is
// distinct from the session cookie and the Browser boundary never reads it.
//
// The capability is presented only to the routes below. Each unsafe route is behind
// the same Origin/JSON/body bounds as every other (the Browser guard) and ALSO
// needs a CSRF token derived from the capability secret, so a cross-site request
// cannot spend or advance a victim's capability.
const (
	RecoveryPath            = "/api/v1/recovery"
	RecoveryStatePath       = "/api/v1/recovery/state"
	RecoveryTOTPPath        = "/api/v1/recovery/totp"
	RecoveryTOTPConfirmPath = "/api/v1/recovery/totp/confirm"
	RecoveryKeyBeginPath    = "/api/v1/recovery/webauthn/begin"
	RecoveryKeyFinishPath   = "/api/v1/recovery/webauthn/finish"

	// RecoveryCookieName uses the __Host- prefix like the session cookie.
	RecoveryCookieName = "__Host-mandatary_recovery"
	recoveryCookieTTL  = 600 // seconds; the capability itself also expires server-side
)

type recoveryHTTP struct {
	b *Browser
	s *Sessions
}

type recoveryHandler func(http.ResponseWriter, *http.Request, []byte, recoveryView)

func registerRecoveryRoutes(b *Browser, s *Sessions) error {
	h := &recoveryHTTP{b: b, s: s}
	anonymous := RoutePolicy{Require: RequireNone}
	type route struct {
		pattern string
		handler http.HandlerFunc
	}
	routes := []route{
		{"POST " + RecoveryPath, h.recover},
		{"GET " + RecoveryStatePath, h.capability(false, h.state)},
		{"POST " + RecoveryTOTPPath, h.capability(true, h.totpBegin)},
		{"POST " + RecoveryTOTPConfirmPath, h.capability(true, h.totpConfirm)},
	}
	if s.webauthnReady() {
		routes = append(routes,
			route{"POST " + RecoveryKeyBeginPath, h.capability(true, h.keyBegin)},
			route{"POST " + RecoveryKeyFinishPath, h.capability(true, h.keyFinish)},
		)
	}
	for _, rt := range routes {
		if err := b.Handle(rt.pattern, anonymous, noQuery(rt.handler)); err != nil {
			return err
		}
	}
	return nil
}

func recoveryCSRF(secret []byte, capabilityID string) string {
	return csrfToken(secret, "recovery:"+capabilityID)
}

// recoverySecretFrom extracts the secret from EXACTLY one recovery cookie, with the
// same raw-header parsing as the session cookie so duplicates/quoting cannot smuggle
// a different value.
func recoverySecretFrom(r *http.Request) (secret []byte, present, ok bool) {
	var values []string
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			name, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && name == RecoveryCookieName {
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

func (h *recoveryHTTP) setCookie(w http.ResponseWriter, secret []byte) {
	http.SetCookie(w, &http.Cookie{Name: RecoveryCookieName, Value: encodeSessionCookie(secret), Path: "/", MaxAge: recoveryCookieTTL, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (h *recoveryHTTP) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: RecoveryCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// recoveryView is what a live capability lets the page know.
type recoveryView struct {
	id        string
	expiresAt int64
	methods   []string
	selected  bool
}

// view resolves the live capability or denies. TOTP policy is tried first; a
// WebAuthn-only account resolves only for the WebAuthn method.
func (h *recoveryHTTP) view(r *http.Request, secret []byte) (recoveryView, error) {
	var out recoveryView
	// Sessions.read keeps a logical denial (an unknown, ended or forged capability:
	// 401) distinct from storage uncertainty (503).
	err := h.s.read(r.Context(), func(q *store.Queries) error {
		now := h.s.l.now().Unix()
		_, _, cap, e := recoveryAuthorityFor(r.Context(), q, secret, now, "totp")
		if e == nil {
			out.methods = append(out.methods, "totp")
		} else {
			if _, _, cap, e = recoveryAuthorityFor(r.Context(), q, secret, now, "webauthn"); e != nil {
				return e
			}
		}
		if h.s.webauthnReady() {
			out.methods = append(out.methods, "webauthn")
		}
		out.id, out.expiresAt, out.selected = cap.ID, cap.ExpiresAt, cap.ReplacementAuthenticatorID.Valid
		return nil
	})
	return out, err
}

// capability wraps a handler that needs a live recovery capability. It reads the
// cookie, resolves the capability server-side and, for unsafe routes, requires the
// capability-derived CSRF token. A bad or ended capability clears the cookie.
func (h *recoveryHTTP) capability(unsafe bool, next recoveryHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, present, ok := recoverySecretFrom(r)
		if !ok {
			if present {
				h.clearCookie(w)
			}
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		view, err := h.view(r, secret)
		if err != nil {
			if errors.Is(err, ErrDenied) {
				h.clearCookie(w)
				writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		if unsafe {
			tokens := r.Header.Values(CSRFHeader)
			want := recoveryCSRF(secret, view.id)
			if len(tokens) != 1 || len(tokens[0]) != len(want) || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(want)) != 1 {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
		}
		next(w, r, secret, view)
	}
}

// recover verifies password + one saved code. Every failure (unknown user, wrong
// password, wrong/used code, throttle) is the same 403 so the route reveals nothing
// about the account. The replacement saved code is returned ONCE here and cannot be
// shown again.
func (h *recoveryHTTP) recover(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	result, err := h.s.l.Recover(r.Context(), body.Username, password, body.Code, peerIP(r))
	clear(password)
	body.Code = ""
	if err != nil {
		fault(w, err)
		return
	}
	// The response is derived ONLY from the in-memory result of the transaction that consumed the
	// saved code. There is deliberately no further storage read here: after the consumption has
	// committed, a failing read would lose the one replacement code (P1.18.4 P116-L6). The
	// capability metadata was captured in that same transaction.
	if h.s.afterRecover != nil {
		h.s.afterRecover()
	}
	meta := result.Meta()
	secret, codes := result.ExportOnce()
	defer clear(secret)
	if len(secret) == 0 || len(codes) != 1 || meta.ID == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	methods := []string{}
	if meta.TOTP {
		methods = append(methods, "totp")
	}
	if h.s.webauthnReady() {
		methods = append(methods, "webauthn")
	}
	h.setCookie(w, secret)
	writeJSON(w, http.StatusOK, map[string]any{"step": "capability", "csrf_token": recoveryCSRF(secret, meta.ID), "expires_at": meta.ExpiresAt, "methods": methods, "replacement_code": codes[0]})
}

func (h *recoveryHTTP) state(w http.ResponseWriter, _ *http.Request, secret []byte, view recoveryView) {
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": recoveryCSRF(secret, view.id), "expires_at": view.expiresAt, "methods": view.methods, "replacement_selected": view.selected})
}

func (h *recoveryHTTP) totpBegin(w http.ResponseWriter, r *http.Request, secret []byte, _ recoveryView) {
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	enrollment, err := h.s.l.BeginRecoveredTOTP(r.Context(), secret, totpAlgorithm)
	if err != nil {
		fault(w, err)
		return
	}
	seed := enrollment.ExportOnce()
	defer clear(seed)
	writeJSON(w, http.StatusOK, map[string]any{"authenticator_id": enrollment.ID, "secret": string(seed), "algorithm": totpAlgorithm, "digits": totpDigits, "period": totpPeriodSecs})
}

func (h *recoveryHTTP) totpConfirm(w http.ResponseWriter, r *http.Request, secret []byte, _ recoveryView) {
	var body struct {
		AuthenticatorID string `json:"authenticator_id"`
		Code            string `json:"code"`
	}
	if !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	err := h.s.l.ConfirmRecoveredTOTP(r.Context(), secret, body.AuthenticatorID, body.Code, peerIP(r))
	body.Code = ""
	if err != nil {
		fault(w, err)
		return
	}
	// Recovery never creates a session: the capability is finished and discarded.
	h.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"step": "completed"})
}

func (h *recoveryHTTP) keyBegin(w http.ResponseWriter, r *http.Request, secret []byte, _ recoveryView) {
	if !decodeStrict(r, &struct{}{}, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	options, err := h.s.w.BeginRecoveredRegistration(r.Context(), secret, false)
	if err != nil {
		fault(w, err)
		return
	}
	writeCeremonyOptions(w, options.ID, options.Options)
}

func (h *recoveryHTTP) keyFinish(w http.ResponseWriter, r *http.Request, secret []byte, _ recoveryView) {
	body, ok := decodeCeremony(r)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.s.w.FinishRecoveredRegistration(r.Context(), secret, body.ID, body.Response); err != nil {
		fault(w, err)
		return
	}
	h.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"step": "completed"})
}
