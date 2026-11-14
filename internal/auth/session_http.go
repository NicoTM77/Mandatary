package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
)

// Browser security boundary (TD §2.2, NIST S04/S05/S06/S07, N63B4-TLS-BOUNDARY).
//
// It owns: the host-only __Host- session cookie, exact-Origin and server-bound
// CSRF checks for every non-GET browser route, explicit per-route policy with
// default deny, fresh-authentication ("step-up") gating of sensitive operations,
// and response security headers including a strict CSP.
//
// It deliberately trusts no forwarded header, no Authorization header, no client
// assurance/role/time claim and no request-selected method override. Native TLS
// or an explicitly configured proxy hop is a deployment responsibility (P1.19).

const (
	// SessionCookieName uses the __Host- prefix: browsers then only accept it with
	// Secure, Path=/ and no Domain, so a sibling subdomain cannot set or overwrite it.
	SessionCookieName = "__Host-mandatary_session"
	// CSRFHeader carries the server-bound anti-CSRF token. It is never a cookie,
	// query or body field.
	CSRFHeader = "X-CSRF-Token"

	// APIContentSecurityPolicy is the policy for JSON/API responses: nothing may
	// load, frame, rebase or post anywhere. The SPA document keeps its own
	// strict policy in the static handler.
	APIContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

	// maxRequestBodyBytes bounds every unsafe request body read through the boundary.
	maxRequestBodyBytes = 64 << 10
)

// Requirement is what a route demands from the caller's cookie.
type Requirement int

const (
	// RequireNone is an explicit anonymous browser route (for example the first
	// login step). Unsafe methods are still Origin-checked. Any cookie is ignored.
	RequireNone Requirement = iota + 1
	// RequirePreauth admits only a live password-bound login capability.
	RequirePreauth
	// RequireSession admits only a fully authenticated normal session.
	RequireSession
)

// RoutePolicy must be provided for every route; the zero value is invalid so a
// route can never be mounted without a deliberate decision.
type RoutePolicy struct {
	Require Requirement
	// Sensitive names the TD §4.3 operation class requiring fresh authentication
	// of sufficient assurance. It implies RequireSession.
	Sensitive SensitiveOperation
	// Background marks a poll/stream route: it is authenticated but does not count
	// as user activity and so cannot keep an idle session alive (S06).
	Background bool
	// MaxBody raises the request-body bound of ONE unsafe route above the 64 KiB default. It exists only
	// for the logical-backup restore upload; zero keeps the default and the value is capped at 32 MiB.
	MaxBody int64
}

// maxRouteBodyBytes is the ceiling any route may raise its own body bound to.
const maxRouteBodyBytes = 32 << 20

// RouteInfo is the inventory entry used by route-coverage tests.
type RouteInfo struct {
	Pattern string
	Policy  RoutePolicy
}

// SensitiveOperation classes (TD §4.3). A mutation of any of these must be
// registered with its class so the gate is not left to each handler's memory.
type SensitiveOperation string

const (
	OpPasswordChange      SensitiveOperation = "password-change"
	OpAuthenticatorChange SensitiveOperation = "authenticator-change" // TOTP/WebAuthn bind, remove; recovery-code issue
	OpNotificationAddress SensitiveOperation = "notification-address-change"
	OpAgentAccessChange   SensitiveOperation = "agent-credential-change" // create/rotate/revoke (P1.10)
	OpBackupExport        SensitiveOperation = "backup-export"           // P1.18
	OpBackupRestore       SensitiveOperation = "backup-restore"          // P1.18
	OpSecurityPolicy      SensitiveOperation = "security-policy-change"  // policy administration
)

// sensitivePolicy: aal2 operations need AAL2 evidence outright; the others need
// the account's required-assurance floor (NIST E03), so a genuinely AAL1-only
// account re-verifies its password while an account that is or was AAL2-capable
// and has not deliberately retired its factors never can with a password alone.
type sensitivePolicy struct{ aal2 bool }

var sensitivePolicies = map[SensitiveOperation]sensitivePolicy{
	OpPasswordChange:      {},
	OpAuthenticatorChange: {},
	OpNotificationAddress: {},
	OpAgentAccessChange:   {aal2: true},
	OpBackupExport:        {aal2: true},
	OpBackupRestore:       {aal2: true},
	OpSecurityPolicy:      {aal2: true},
}

// SensitiveOperations lists every declared class in a stable order.
func SensitiveOperations() []SensitiveOperation {
	return []SensitiveOperation{OpPasswordChange, OpAuthenticatorChange, OpNotificationAddress, OpAgentAccessChange, OpBackupExport, OpBackupRestore, OpSecurityPolicy}
}

// RequireSensitive decides whether a session may perform op NOW. It is pure over
// the server-derived SessionInfo and the server clock, so it can be applied again
// inside any service transaction. Sensitive services must still re-check their
// own freshness inside the write (as the lifecycle services do).
func (s *Sessions) RequireSensitive(info SessionInfo, op SensitiveOperation) error {
	policy, ok := sensitivePolicies[op]
	if !ok {
		return ErrDenied
	}
	var have int64
	switch info.Assurance {
	case AssurancePasswordOnly:
		have = 1
	case AssuranceAAL2:
		have = 2
	default:
		return ErrDenied // preauth, unknown or empty labels never qualify
	}
	now := s.l.now()
	if info.AuthenticatedAt.IsZero() || info.AuthenticatedAt.After(now) {
		return ErrDenied // absent or future time is clock uncertainty
	}
	// The floor is server-derived and shared with login and the lifecycle gate.
	// An unset/out-of-range value is denied rather than defaulted to AAL1.
	if info.RequiredAssurance < 1 || info.RequiredAssurance > 2 {
		return ErrDenied
	}
	required := int64(2)
	if !policy.aal2 {
		required = info.RequiredAssurance
	}
	if have < required {
		// Only a usable factor makes a re-authentication worthwhile; capability
		// never lowers `required`.
		if info.UsableAssurance >= required {
			return ErrStepUpRequired
		}
		return ErrAssuranceUnavailable
	}
	if now.Sub(info.AuthenticatedAt) > s.settings.StepUp {
		return ErrStepUpRequired
	}
	return nil
}

// Browser applies the policy registry to an http.ServeMux. Only explicitly
// registered, method-qualified routes exist; everything else is 404/405.
type Browser struct {
	sessions *Sessions
	origin   string
	host     string
	mux      *http.ServeMux
	routes   []RouteInfo
	seen     map[string]bool
}

// NewBrowser binds the boundary to the sessions' trusted HTTPS origin.
func NewBrowser(s *Sessions) *Browser {
	return &Browser{sessions: s, origin: canonicalOrigin(s.origin.Scheme, s.origin.Host), host: canonicalHost(s.origin.Host), mux: http.NewServeMux(), seen: map[string]bool{}}
}

func canonicalHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ":443") }
func canonicalOrigin(scheme, host string) string {
	return scheme + "://" + canonicalHost(host)
}

var unsafeMethods = map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}

// Handle registers one method-qualified pattern ("POST /api/v1/...") with an
// explicit policy. It refuses ambiguous or weaker re-registrations.
func (b *Browser) Handle(pattern string, p RoutePolicy, h http.Handler) (err error) {
	if b == nil || h == nil {
		return ErrDenied
	}
	method, path, ok := strings.Cut(pattern, " ")
	if !ok || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\r\n") || (method != http.MethodGet && !unsafeMethods[method]) {
		return ErrDenied
	}
	switch p.Require {
	case RequireNone, RequirePreauth, RequireSession:
	default:
		return ErrDenied
	}
	if p.Sensitive != "" {
		// A sensitive class names a mutation. Safe methods skip the Origin and
		// CSRF checks by design, so a sensitive class may only sit on an unsafe
		// method; a read of sensitive data is not expressible here.
		if _, known := sensitivePolicies[p.Sensitive]; !known || p.Require != RequireSession || method == http.MethodGet {
			return ErrDenied
		}
	}
	if p.Background && (p.Require != RequireSession || method != http.MethodGet || p.Sensitive != "") {
		return ErrDenied
	}
	if p.MaxBody != 0 && (p.MaxBody < maxRequestBodyBytes || p.MaxBody > maxRouteBodyBytes || !unsafeMethods[method] || p.Require != RequireSession) {
		return ErrDenied
	}
	if b.seen[pattern] {
		return ErrDenied
	}
	defer func() {
		if recover() != nil { // ServeMux panics on conflicting patterns
			err = ErrDenied
		}
	}()
	b.mux.Handle(pattern, b.guard(method, p, h))
	b.seen[pattern] = true
	b.routes = append(b.routes, RouteInfo{Pattern: pattern, Policy: p})
	return nil
}

// Routes returns a copy of the route inventory.
func (b *Browser) Routes() []RouteInfo { return append([]RouteInfo(nil), b.routes...) }

type sessionContextKey struct{}

// SessionFrom returns the verified session attached by the boundary. It is
// absent on anonymous routes.
func SessionFrom(r *http.Request) (Session, bool) {
	s, ok := r.Context().Value(sessionContextKey{}).(Session)
	return s, ok
}

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", APIContentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Strict-Transport-Security", "max-age=31536000")
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// ServeHTTP sets security headers on EVERY response (including 404/405/421), then
// requires the exact configured Host. Forwarded headers are never consulted.
func (b *Browser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if r.Host == "" || canonicalHost(r.Host) != b.host {
		writeJSONError(w, http.StatusMisdirectedRequest, "misdirected_request")
		return
	}
	b.mux.ServeHTTP(w, r)
}

// SetSessionCookie writes the host-only, non-persistent session cookie. Persistence
// across browser restarts is deliberately not offered (NIST S02); server expiry is
// the authority and the cookie carries only an opaque random secret.
func (b *Browser) SetSessionCookie(w http.ResponseWriter, s IssuedSession) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: encodeSessionCookie(s.secret), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// ClearSessionCookie expires the cookie with identical scope attributes.
func (b *Browser) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func encodeSessionCookie(secret []byte) string { return base64.RawURLEncoding.EncodeToString(secret) }

// sessionSecretFrom extracts the secret from EXACTLY one session cookie. It parses
// the raw header instead of http.Request.Cookies so quoting/duplicate tricks cannot
// smuggle a different value, and it ignores every other cookie.
func sessionSecretFrom(r *http.Request) (secret []byte, present, ok bool) {
	var values []string
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			name, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && name == SessionCookieName {
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

// sameOrigin requires exactly one Origin header equal to the configured origin and,
// where the browser sends fetch metadata, a same-origin request. An absent Origin
// on an unsafe method is rejected (browsers always send it).
func (b *Browser) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || origins[0] != b.origin {
		return false
	}
	site := r.Header.Values("Sec-Fetch-Site")
	if len(site) > 1 || (len(site) == 1 && site[0] != "same-origin") {
		return false
	}
	return true
}

// jsonBody refuses simple-form content types: a request with a body must be
// application/json (optionally charset=utf-8). A bodiless request needs none.
func jsonBody(r *http.Request) bool {
	types := r.Header.Values("Content-Type")
	if len(types) == 0 {
		return r.ContentLength == 0 && len(r.TransferEncoding) == 0
	}
	if len(types) != 1 {
		return false
	}
	media, params, err := mime.ParseMediaType(types[0])
	if err != nil || media != "application/json" {
		return false
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}

func validCSRF(r *http.Request, s Session) bool {
	tokens := r.Header.Values(CSRFHeader)
	if len(tokens) != 1 {
		return false
	}
	want := s.CSRFToken()
	return len(tokens[0]) == len(want) && subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(want)) == 1
}

func (b *Browser) guard(method string, p RoutePolicy, next http.Handler) http.Handler {
	unsafe := unsafeMethods[method]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unsafe {
			if !b.sameOrigin(r) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			if !jsonBody(r) {
				writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
				return
			}
			// Bounded input before any handler or proof work (WebAuthn responses
			// are separately capped at 32 KiB by their service).
			limit := int64(maxRequestBodyBytes)
			if p.MaxBody > 0 {
				limit = p.MaxBody
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		var session Session
		if p.Require != RequireNone {
			secret, present, ok := sessionSecretFrom(r)
			if !ok {
				if present {
					b.ClearSessionCookie(w)
				}
				writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			var err error
			if p.Require == RequirePreauth {
				session, err = b.sessions.AuthenticatePreauth(r.Context(), secret)
			} else {
				session, err = b.sessions.Authenticate(r.Context(), secret, !p.Background)
			}
			if err != nil {
				if errors.Is(err, ErrDenied) {
					b.ClearSessionCookie(w)
					writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
					return
				}
				writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
				return
			}
			if unsafe && !validCSRF(r, session) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			if p.Sensitive != "" {
				switch err = b.sessions.RequireSensitive(session.SessionInfo, p.Sensitive); {
				case err == nil:
				case errors.Is(err, ErrStepUpRequired):
					writeJSONError(w, http.StatusForbidden, "step_up_required")
					return
				case errors.Is(err, ErrAssuranceUnavailable):
					writeJSONError(w, http.StatusForbidden, "assurance_unavailable")
					return
				default:
					writeJSONError(w, http.StatusForbidden, "forbidden")
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, session)))
	})
}

// LogoutHandler revokes the current session durably, then clears the cookie. Mount
// it with RequireSession so forced-logout CSRF is rejected like any other write.
func (b *Browser) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if err := b.sessions.Logout(r.Context(), session.secret); err != nil {
			if errors.Is(err, ErrDenied) {
				b.ClearSessionCookie(w)
				writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			writeJSONError(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		b.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	})
}

// SessionInfoHandler returns only server-derived labels and the CSRF token, for
// the SPA's use. Own-session listing/revocation UI remains Phase 3.
func (b *Browser) SessionInfoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		stale := b.sessions.l.now().Sub(session.AuthenticatedAt) > b.sessions.settings.StepUp
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
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
	})
}
