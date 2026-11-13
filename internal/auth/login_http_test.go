package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
)

// P1.16.3 browser account routes. Every proof is verified by the REAL services of
// the session fixture (SQLite, Lifecycle, Sessions); only the clock, the origin
// and the synthetic password are synthetic. Test names deliberately avoid the
// TestSession/TestStepUp/TestSensitive prefixes owned by the P1.08 crosswalk.

type loginHarness struct {
	t  *testing.T
	e  *sessionEnv
	b  *Browser
	id string
	en Enrollment
}

type loginCall struct {
	method, path, body string
	cookie, csrf       string // raw session cookie VALUE and CSRF header
	origin             string
	contentType        string
	noOrigin           bool
}

func newLoginHarness(t *testing.T) *loginHarness {
	t.Helper()
	e := newSessionEnv(t)
	h := &loginHarness{t: t, e: e, b: NewBrowser(e.s)}
	h.id, h.en = e.mfaAccount()
	if err := RegisterAccountRoutes(h.b, e.s); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *loginHarness) do(c loginCall) *httptest.ResponseRecorder {
	h.t.Helper()
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	r := httptest.NewRequest(c.method, "https://example.invalid"+c.path, body)
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: c.cookie})
	}
	if c.csrf != "" {
		r.Header.Set(CSRFHeader, c.csrf)
	}
	unsafe := c.method != http.MethodGet
	switch {
	case c.noOrigin:
	case c.origin != "":
		r.Header.Set("Origin", c.origin)
	case unsafe:
		r.Header.Set("Origin", sessionTestOrigin)
	}
	if c.body != "" || unsafe {
		ct := c.contentType
		if ct == "" {
			ct = "application/json"
		}
		r.Header.Set("Content-Type", ct)
	}
	r.RemoteAddr = sessionTestIP + ":4444"
	w := httptest.NewRecorder()
	h.b.ServeHTTP(w, r)
	return w
}

func (h *loginHarness) password(name, password string) *httptest.ResponseRecorder {
	return h.do(loginCall{method: "POST", path: "/api/v1/login", body: mustJSON(h.t, map[string]string{"username": name, "password": password})})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type loginBody struct {
	Step      string   `json:"step"`
	Next      []string `json:"next"`
	CSRFToken string   `json:"csrf_token"`
}

func decodeLogin(t *testing.T, w *httptest.ResponseRecorder) loginBody {
	t.Helper()
	var b loginBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("login body is not JSON: %v %q", err, w.Body.String())
	}
	return b
}

func issuedCookie(w *httptest.ResponseRecorder) (value string, cleared bool) {
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c.Value, c.MaxAge < 0 || c.Value == ""
		}
	}
	return "", false
}

type infoBody struct {
	Username          string   `json:"username"`
	Assurance         string   `json:"assurance"`
	Methods           []string `json:"methods"`
	CSRFToken         string   `json:"csrf_token"`
	RequiredAssurance int      `json:"required_assurance"`
	UsableAssurance   int      `json:"usable_assurance"`
	StepUpRequired    bool     `json:"step_up_required"`
	ExpiresAt         int64    `json:"expires_at"`
}

func (h *loginHarness) info(cookie string) (*httptest.ResponseRecorder, infoBody) {
	h.t.Helper()
	w := h.do(loginCall{method: "GET", path: "/api/v1/session", cookie: cookie})
	var i infoBody
	_ = json.Unmarshal(w.Body.Bytes(), &i)
	return w, i
}

// Password then TOTP: generic denial parity, a preauth that opens nothing else,
// CSRF on the ceremony, rotation at completion and a server-derived AAL2 session.
func TestLoginHTTPPasswordThenTOTPEndToEnd(t *testing.T) {
	h := newLoginHarness(t)
	e := h.e

	wrong := h.password("synthetic-user", "definitely not the right one")
	unknown := h.password("nobody-at-all", "definitely not the right one")
	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized {
		t.Fatalf("denial statuses %d %d", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("unknown user and wrong password are distinguishable: %q vs %q", wrong.Body.String(), unknown.Body.String())
	}
	if v, _ := issuedCookie(wrong); v != "" {
		t.Fatal("a failed password step issued a cookie")
	}

	w := h.password("synthetic-user", sessionTestPassword)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	if login.Step != "factor" || strings.Join(login.Next, ",") != "totp,no-mfa" || login.CSRFToken == "" || pre == "" {
		t.Fatalf("password step: %+v", login)
	}
	if strings.Contains(w.Body.String(), sessionTestPassword) {
		t.Fatal("response echoed the password")
	}
	set := w.Header().Get("Set-Cookie")
	for _, attr := range []string{"__Host-mandatary_session=", "Secure", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(set, attr) {
			t.Fatalf("cookie lacks %s: %s", attr, set)
		}
	}
	if strings.Contains(set, "Max-Age") || strings.Contains(set, "Expires") || strings.Contains(set, "Domain") {
		t.Fatalf("cookie must be a host-only session cookie: %s", set)
	}

	// The preauth capability opens the factor ceremony only.
	if w, _ = h.info(pre); w.Code != http.StatusUnauthorized {
		t.Fatalf("preauth opened the session route: %d", w.Code)
	}
	if w = h.do(loginCall{method: "POST", path: "/api/v1/logout", cookie: pre, csrf: login.CSRFToken}); w.Code != http.StatusUnauthorized {
		t.Fatalf("preauth reached logout: %d", w.Code)
	}
	code := e.nextCode(h.en)
	body := mustJSON(t, map[string]string{"code": code})
	if w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, body: body}); w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted on the factor step: %d", w.Code)
	}
	if w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": "000000"})}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"denied"`) {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	} else if v, _ := issuedCookie(w); v != "" {
		t.Fatal("a wrong code issued a cookie")
	}
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: body})
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	done := decodeLogin(t, w)
	session, _ := issuedCookie(w)
	if done.Step != "session" || session == "" || session == pre {
		t.Fatalf("completion did not rotate the cookie: %+v", done)
	}
	// A consumed preauth is dead: replay of the same ceremony fails.
	if w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": e.nextCode(h.en)})}); w.Code != http.StatusUnauthorized {
		t.Fatalf("consumed preauth accepted again: %d", w.Code)
	}

	w, info := h.info(session)
	if w.Code != http.StatusOK || info.Username != "synthetic-user" || info.Assurance != "aal2" || strings.Join(info.Methods, ",") != "password,totp" || info.CSRFToken == "" || info.RequiredAssurance != 2 || info.StepUpRequired {
		t.Fatalf("session info: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), session) {
		t.Fatal("session info echoed the cookie secret")
	}

	// Logout is a CSRF-protected write; success revokes the copied cookie.
	if w = h.do(loginCall{method: "POST", path: "/api/v1/logout", cookie: session}); w.Code != http.StatusForbidden {
		t.Fatalf("forced logout without CSRF: %d", w.Code)
	}
	if w = h.do(loginCall{method: "POST", path: "/api/v1/logout", cookie: session, csrf: info.CSRFToken}); w.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", w.Code)
	}
	if _, cleared := issuedCookie(w); !cleared {
		t.Fatal("logout did not clear the cookie")
	}
	if w, _ = h.info(session); w.Code != http.StatusUnauthorized {
		t.Fatalf("copied cookie survived logout: %d", w.Code)
	}
}

// The lower-assurance path is explicit, server-offered and labelled; it never
// becomes AAL2 and never carries a second-factor method.
func TestLoginHTTPPasswordOnlyIsLabelledLowerAssurance(t *testing.T) {
	h := newLoginHarness(t)
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/no-mfa", cookie: pre, csrf: login.CSRFToken, body: "{}"})
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	session, _ := issuedCookie(w)
	w, info := h.info(session)
	if w.Code != http.StatusOK || info.Assurance != "password-only" || strings.Join(info.Methods, ",") != "password" {
		t.Fatalf("password-only session mislabelled: %s", w.Body.String())
	}
	if info.RequiredAssurance != 2 || info.UsableAssurance != 2 {
		t.Fatalf("an account with a live factor must keep floor 2: %+v", info)
	}
	// An attacker holding only the password cannot reach the AAL2 step from here.
	if w = h.do(loginCall{method: "POST", path: "/api/v1/login/no-mfa", cookie: pre, csrf: login.CSRFToken, body: "{}"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("preauth reusable after the password-only login: %d", w.Code)
	}
}

// Mandatory-MFA boundary over HTTP: when policy requires MFA the server offers no
// password-only step, and calling that route directly with a valid preauth is
// refused anyway. A WebAuthn-only policy refuses TOTP even with a correct code.
func TestLoginHTTPMandatoryMFAIsNotBypassable(t *testing.T) {
	h := newLoginHarness(t)
	h.e.exec(`UPDATE users SET mfa_requirement='required'`)
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	if w.Code != http.StatusOK || login.Step != "factor" || strings.Join(login.Next, ",") != "totp" {
		t.Fatalf("required policy must offer the factor only: %d %s", w.Code, w.Body.String())
	}
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/no-mfa", cookie: pre, csrf: login.CSRFToken, body: "{}"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("password-only step accepted under required MFA: %d", w.Code)
	}
	if v, _ := issuedCookie(w); v != "" {
		t.Fatal("a refused password-only step issued a cookie")
	}
	// The capability is still only a capability: no session route opens.
	if w, _ = h.info(pre); w.Code != http.StatusUnauthorized {
		t.Fatalf("preauth opened a session route: %d", w.Code)
	}

	h = newLoginHarness(t)
	h.e.exec(`UPDATE users SET mfa_requirement='webauthn'`)
	// No usable second factor remains for this policy, so the password step itself
	// is refused (generic 401) rather than weakened to password-only.
	if w = h.password("synthetic-user", sessionTestPassword); w.Code != http.StatusUnauthorized {
		t.Fatalf("webauthn-only policy with only TOTP: %d %s", w.Code, w.Body.String())
	}
}

// The page has no authenticator identifier, so the SERVER picks the factor. With
// two live TOTP factors it must not guess (a guess would spend attempts on the
// wrong factor and could grant whichever one happens to verify): the code is
// refused as the one public denial until a selection step exists (slice 2).
func TestLoginHTTPSeveralTOTPFactorsAreNotGuessed(t *testing.T) {
	h := newLoginHarness(t)
	first := h.e.aal2TOTP(h.id, h.en)
	_, second := h.e.enrollTOTPWith(first.Secret())
	if second.secret == h.en.secret {
		t.Fatal("fixture bug: the second factor must differ")
	}
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	if w.Code != http.StatusOK || login.Step != "factor" {
		t.Fatalf("password step: %d %s", w.Code, w.Body.String())
	}
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": h.e.nextCode(h.en)})})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"denied"`) {
		t.Fatalf("an ambiguous factor was accepted or mis-reported: %d %s", w.Code, w.Body.String())
	}
	if v, _ := issuedCookie(w); v != "" {
		t.Fatal("an ambiguous factor issued a cookie")
	}
}

// The preauth capability dies five minutes after the password step.
func TestLoginHTTPPreauthExpires(t *testing.T) {
	h := newLoginHarness(t)
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	code := h.e.nextCode(h.en)
	h.e.clock.Advance(preauthLifetime + time.Second)
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": code})})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired preauth accepted: %d", w.Code)
	}
	if _, cleared := issuedCookie(w); !cleared {
		t.Fatal("an ended capability must clear its cookie")
	}
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/no-mfa", cookie: pre, csrf: login.CSRFToken, body: "{}"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired preauth reached the password-only step: %d", w.Code)
	}
}

// A session ended by the server (idle/absolute expiry) is 401 with a cleared
// cookie so the SPA can show session-ended rather than a broken page.
func TestLoginHTTPExpiredSessionIsUnauthenticated(t *testing.T) {
	h := newLoginHarness(t)
	issued := h.e.aal2TOTP(h.id, h.en)
	cookie := encodeSessionCookie(issued.Secret())
	if w, _ := h.info(cookie); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	h.e.clock.Advance(DefaultSessionIdle + time.Minute)
	w, _ := h.info(cookie)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("idle-expired session accepted: %d", w.Code)
	}
	if _, cleared := issuedCookie(w); !cleared {
		t.Fatal("expired session did not clear the cookie")
	}
}

// Browser boundary applies to every new route: exact Origin, JSON only, strict
// bodies, no method confusion.
func TestLoginHTTPBoundaryRejectsUnsafeRequests(t *testing.T) {
	h := newLoginHarness(t)
	good := mustJSON(t, map[string]string{"username": "synthetic-user", "password": sessionTestPassword})
	cases := []struct {
		name string
		call loginCall
		want int
	}{
		{"foreign origin", loginCall{method: "POST", path: "/api/v1/login", body: good, origin: "https://evil.invalid"}, http.StatusForbidden},
		{"missing origin", loginCall{method: "POST", path: "/api/v1/login", body: good, noOrigin: true}, http.StatusForbidden},
		{"form content type", loginCall{method: "POST", path: "/api/v1/login", body: good, contentType: "application/x-www-form-urlencoded"}, http.StatusUnsupportedMediaType},
		{"text/plain", loginCall{method: "POST", path: "/api/v1/login", body: good, contentType: "text/plain"}, http.StatusUnsupportedMediaType},
		{"unknown field", loginCall{method: "POST", path: "/api/v1/login", body: `{"username":"synthetic-user","password":"x","role":"admin"}`}, http.StatusBadRequest},
		{"trailing data", loginCall{method: "POST", path: "/api/v1/login", body: good + `{}`}, http.StatusBadRequest},
		{"not json", loginCall{method: "POST", path: "/api/v1/login", body: `username=synthetic-user`}, http.StatusBadRequest},
		{"GET login", loginCall{method: "GET", path: "/api/v1/login"}, http.StatusMethodNotAllowed},
		{"credentials in query", loginCall{method: "POST", path: "/api/v1/login?password=synthetic-canary", body: good}, http.StatusNotFound},
		{"unknown route", loginCall{method: "POST", path: "/api/v1/login/webauthn", body: "{}"}, http.StatusNotFound},
		{"session POST", loginCall{method: "POST", path: "/api/v1/session", body: "{}"}, http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := h.do(c.call)
			if w.Code != c.want {
				t.Fatalf("got %d want %d (%s)", w.Code, c.want, w.Body.String())
			}
			if v, _ := issuedCookie(w); v != "" {
				t.Fatal("a refused request issued a cookie")
			}
		})
	}
}

// Responses carry the strict security headers and never cache.
func TestLoginHTTPResponsesAreHardened(t *testing.T) {
	h := newLoginHarness(t)
	for _, w := range []*httptest.ResponseRecorder{
		h.password("synthetic-user", sessionTestPassword),
		h.password("nobody", "x"),
		h.do(loginCall{method: "GET", path: "/api/v1/session"}),
	} {
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") != APIContentSecurityPolicy || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("headers: %v", w.Header())
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("content type %q", ct)
		}
	}
}

// A wrong second factor never reveals whether the account is throttled, and the
// exhausted-attempt state is the same public outcome as a wrong code.
func TestLoginHTTPFactorDenialsAreUniform(t *testing.T) {
	h := newLoginHarness(t)
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	var first string
	for i := 0; i < 8; i++ {
		w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": "000000"})})
		if w.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
		if first == "" {
			first = w.Body.String()
		} else if w.Body.String() != first {
			t.Fatalf("attempt %d body differs: %q vs %q", i, w.Body.String(), first)
		}
	}
	// Even the correct code is refused while the factor's wait is running (no
	// clock advance, so the escalating wait after five failures has not lapsed).
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": enrollmentCode(t, h.en, h.e.clock.Now())})})
	if w.Code != http.StatusForbidden || w.Body.String() != first {
		t.Fatalf("throttled factor distinguishable or accepted: %d %s", w.Code, w.Body.String())
	}
}

// Password, code, cookie and CSRF values never reach the structured log, even at
// debug level, through the real logging middleware.
func TestLoginHTTPSecretsNeverReachLogs(t *testing.T) {
	h := newLoginHarness(t)
	var out bytes.Buffer
	logger, err := logging.New(&out, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}
	handler := logging.HTTP(logger, h.b)
	serve := func(c loginCall) *httptest.ResponseRecorder {
		var body io.Reader
		if c.body != "" {
			body = strings.NewReader(c.body)
		}
		r := httptest.NewRequest(c.method, "https://example.invalid"+c.path, body)
		r.Header.Set("Origin", sessionTestOrigin)
		r.Header.Set("Content-Type", "application/json")
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: c.cookie})
		}
		if c.csrf != "" {
			r.Header.Set(CSRFHeader, c.csrf)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := serve(loginCall{method: "POST", path: "/api/v1/login", body: mustJSON(t, map[string]string{"username": "synthetic-user", "password": sessionTestPassword})})
	login := decodeLogin(t, w)
	pre, _ := issuedCookie(w)
	code := h.e.nextCode(h.en)
	w = serve(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: mustJSON(t, map[string]string{"code": code})})
	session, _ := issuedCookie(w)
	for _, secret := range []string{sessionTestPassword, code, pre, session, login.CSRFToken} {
		if secret == "" || strings.Contains(out.String(), secret) {
			t.Fatalf("a secret reached the log (or the canary is empty): %q", secret)
		}
	}
	if out.Len() == 0 {
		t.Fatal("the logging middleware recorded nothing, so this test proves nothing")
	}
}

// Without a configured Sessions there is nothing to register: no half-built route.
func TestLoginHTTPRegistrationRequiresServices(t *testing.T) {
	if err := RegisterAccountRoutes(nil, nil); err == nil {
		t.Fatal("registration with no services succeeded")
	}
	e := newSessionEnv(t)
	if err := RegisterAccountRoutes(NewBrowser(e.s), nil); err == nil {
		t.Fatal("registration without sessions succeeded")
	}
	b := NewBrowser(e.s)
	if err := RegisterAccountRoutes(b, e.s); err != nil {
		t.Fatal(err)
	}
	patterns := map[string]RoutePolicy{}
	for _, r := range b.Routes() {
		patterns[r.Pattern] = r.Policy
	}
	want := map[string]Requirement{
		"POST /api/v1/login":        RequireNone,
		"POST /api/v1/login/totp":   RequirePreauth,
		"POST /api/v1/login/no-mfa": RequirePreauth,
		"GET /api/v1/session":       RequireSession,
		"POST /api/v1/logout":       RequireSession,
	}
	if len(patterns) != len(want) {
		t.Fatalf("unexpected route inventory: %v", patterns)
	}
	for pattern, requirement := range want {
		if patterns[pattern].Require != requirement {
			t.Fatalf("%s: policy %v", pattern, patterns[pattern])
		}
	}
}
