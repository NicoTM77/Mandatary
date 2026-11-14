package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
)

// Browser-layer tests. Routes are registered ONLY in this test file to exercise
// the middleware; the product binary mounts none (no fake endpoints).

type browserHarness struct {
	t     *testing.T
	e     *sessionEnv
	b     *Browser
	calls map[string]*atomic.Int32
	id    string
	en    Enrollment
}

type httpReq struct {
	method, path, body string
	cookie             string // raw cookie VALUE for the session cookie
	csrf               string
	origin             string
	noOrigin           bool
	contentType        string
	headers            map[string][]string
	host               string
	rawCookie          string // full Cookie header override
}

func newBrowserHarness(t *testing.T) *browserHarness {
	t.Helper()
	e := newSessionEnv(t)
	h := &browserHarness{t: t, e: e, b: NewBrowser(e.s), calls: map[string]*atomic.Int32{}}
	h.id, h.en = e.mfaAccount()
	count := func(name string, status int) http.Handler {
		c := &atomic.Int32{}
		h.calls[name] = c
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Add(1)
			s, _ := SessionFrom(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"user": s.UserID, "assurance": s.Assurance})
		})
	}
	must := func(pattern string, p RoutePolicy, handler http.Handler) {
		if err := h.b.Handle(pattern, p, handler); err != nil {
			t.Fatal(pattern, err)
		}
	}
	must("POST /t/anonymous", RoutePolicy{Require: RequireNone}, count("anon", 200))
	must("POST /t/preauth", RoutePolicy{Require: RequirePreauth}, count("preauth", 200))
	must("POST /t/session", RoutePolicy{Require: RequireSession}, count("session", 200))
	must("PUT /t/resource", RoutePolicy{Require: RequireSession}, count("put", 200))
	must("PATCH /t/resource", RoutePolicy{Require: RequireSession}, count("patch", 200))
	must("DELETE /t/resource", RoutePolicy{Require: RequireSession}, count("delete", 200))
	must("GET /t/read", RoutePolicy{Require: RequireSession}, count("read", 200))
	must("GET /t/poll", RoutePolicy{Require: RequireSession, Background: true}, count("poll", 200))
	must("GET /t/info", RoutePolicy{Require: RequireSession}, h.b.SessionInfoHandler())
	must("POST /t/logout", RoutePolicy{Require: RequireSession}, h.b.LogoutHandler())
	for _, op := range SensitiveOperations() {
		must("POST /t/sensitive/"+string(op), RoutePolicy{Require: RequireSession, Sensitive: op}, count("op:"+string(op), 200))
	}
	// Login/step-up adapters built from the real services (as P1.16 will).
	must("POST /t/login", RoutePolicy{Require: RequireNone}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Name, Password string }
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
			http.Error(w, "bad", 400)
			return
		}
		res, err := h.e.s.PasswordLogin(r.Context(), in.Name, []byte(in.Password), sessionTestIP)
		if err != nil {
			h.b.ClearSessionCookie(w)
			writeJSONError(w, 401, "unauthenticated")
			return
		}
		h.b.SetSessionCookie(w, res.Session)
		_ = json.NewEncoder(w).Encode(map[string]any{"csrf": res.Session.CSRFToken(), "next": res.Next, "assurance": res.Session.Info.Assurance})
	}))
	must("POST /t/login/totp", RoutePolicy{Require: RequirePreauth}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pre, _ := SessionFrom(r)
		var in struct{ ID, Code string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		issued, err := h.e.s.LoginTOTP(r.Context(), pre.Secret(), in.ID, in.Code, sessionTestIP)
		if err != nil {
			writeJSONError(w, 401, "unauthenticated")
			return
		}
		h.b.SetSessionCookie(w, issued)
		_ = json.NewEncoder(w).Encode(map[string]any{"csrf": issued.CSRFToken(), "assurance": issued.Info.Assurance})
	}))
	must("POST /t/stepup/totp", RoutePolicy{Require: RequireSession}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur, _ := SessionFrom(r)
		var in struct{ Password, ID, Code string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		issued, err := h.e.s.StepUpTOTP(r.Context(), cur.Secret(), []byte(in.Password), in.ID, in.Code, sessionTestIP)
		if err != nil {
			writeJSONError(w, 401, "unauthenticated")
			return
		}
		h.b.SetSessionCookie(w, issued)
		_ = json.NewEncoder(w).Encode(map[string]any{"csrf": issued.CSRFToken()})
	}))
	return h
}

func (h *browserHarness) do(q httpReq) *httptest.ResponseRecorder {
	h.t.Helper()
	method := q.method
	if method == "" {
		method = http.MethodGet
	}
	host := q.host
	if host == "" {
		host = "example.invalid"
	}
	var body io.Reader
	if q.body != "" {
		body = strings.NewReader(q.body)
	}
	r := httptest.NewRequest(method, "https://"+host+q.path, body)
	if q.cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	}
	if q.rawCookie != "" {
		r.Header.Set("Cookie", q.rawCookie)
	}
	if q.csrf != "" {
		r.Header.Set(CSRFHeader, q.csrf)
	}
	unsafe := method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
	switch {
	case q.noOrigin:
	case q.origin != "":
		r.Header.Set("Origin", q.origin)
	case unsafe:
		r.Header.Set("Origin", sessionTestOrigin)
	}
	if q.body != "" || unsafe {
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

func (h *browserHarness) calls0(name string) int32 { return h.calls[name].Load() }

func cookieValue(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie issued")
	return ""
}

type httpSessionSet struct {
	passwordOnly, preauth, fresh, stale struct{ cookie, csrf string }
}

// sessions builds one cookie per authentication state, via the real services.
func (h *browserHarness) sessions() httpSessionSet {
	h.t.Helper()
	e := h.e
	var set httpSessionSet
	po := e.passwordOnly()
	set.passwordOnly.cookie, set.passwordOnly.csrf = encodeSessionCookie(po.Secret()), po.CSRFToken()
	stale := e.aal2TOTP(h.id, h.en)
	set.stale.cookie, set.stale.csrf = encodeSessionCookie(stale.Secret()), stale.CSRFToken()
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	fresh := e.aal2TOTP(h.id, h.en)
	set.fresh.cookie, set.fresh.csrf = encodeSessionCookie(fresh.Secret()), fresh.CSRFToken()
	// The preauth capability lives only five minutes, so it is created last.
	r, err := e.s.PasswordLogin(h.t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		h.t.Fatal(err)
	}
	set.preauth.cookie, set.preauth.csrf = encodeSessionCookie(r.Session.Secret()), r.Session.CSRFToken()
	return set
}

func TestSessionCookieAttributes(t *testing.T) { // S05 / N63B4-SESSION-COOKIE-CSRF
	h := newBrowserHarness(t)
	w := h.do(httpReq{method: "POST", path: "/t/login", body: `{"name":"synthetic-user","password":"` + sessionTestPassword + `"}`})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	raw := w.Header().Values("Set-Cookie")
	if len(raw) != 1 {
		t.Fatal("exactly one cookie expected", raw)
	}
	c := raw[0]
	for _, want := range []string{SessionCookieName + "=", "Secure", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(c, want) {
			t.Fatalf("cookie lacks %q: %s", want, c)
		}
	}
	for _, forbidden := range []string{"Domain", "Max-Age", "Expires"} {
		if strings.Contains(c, forbidden) {
			t.Fatalf("cookie must be host-only and non-persistent (%s): %s", forbidden, c)
		}
	}
	if !strings.HasPrefix(SessionCookieName, "__Host-") {
		t.Fatal("cookie must use the __Host- prefix")
	}
	value := cookieValue(t, w)
	if len(value) != sessionCookieChars || strings.ContainsAny(value, "+/=") {
		t.Fatalf("cookie value is not unpadded base64url of 32 bytes: %q", value)
	}
	// The cookie is the opaque encoding of exactly 32 secret bytes and nothing else. Guessing state-like substrings inside a uniformly random
	// base64url value is NOT a metadata-leak proof (a random 43-character value contains "aal" or "admin" by chance now and then: P1.18.4
	// P118-note-cookie-substring-flake), so the assertion is structural: canonical strict encoding that round-trips byte for byte.
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != sessionSecretBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		t.Fatalf("cookie value is not the canonical encoding of %d secret bytes: %q (%v)", sessionSecretBytes, value, err)
	}
	clear := httptest.NewRecorder()
	h.b.ClearSessionCookie(clear)
	cc := clear.Header().Get("Set-Cookie")
	for _, want := range []string{SessionCookieName + "=", "Max-Age=0", "Secure", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(cc, want) {
			t.Fatalf("clearing cookie lacks %q: %s", want, cc)
		}
	}
	if strings.Contains(cc, "Domain") {
		t.Fatal("clearing cookie must not widen scope")
	}
}

func TestNegativeOriginsAreRejectedOnEveryUnsafeRoute(t *testing.T) { // S05, W02 / N63B4-SESSION-COOKIE-CSRF
	h := newBrowserHarness(t)
	set := h.sessions()
	origins := map[string]httpReq{
		"missing":             {noOrigin: true},
		"null":                {origin: "null"},
		"http scheme":         {origin: "http://example.invalid"},
		"other port":          {origin: "https://example.invalid:8443"},
		"subdomain":           {origin: "https://app.example.invalid"},
		"suffix attack":       {origin: "https://example.invalid.evil.test"},
		"prefix attack":       {origin: "https://evil.test/https://example.invalid"},
		"other site":          {origin: "https://evil.test"},
		"trailing slash":      {origin: "https://example.invalid/"},
		"userinfo":            {origin: "https://user@example.invalid"},
		"upper case":          {origin: "HTTPS://EXAMPLE.INVALID"},
		"empty":               {origin: " "},
		"two origins":         {headers: map[string][]string{"Origin": {sessionTestOrigin, "https://evil.test"}}, noOrigin: true},
		"sec-fetch cross":     {headers: map[string][]string{"Sec-Fetch-Site": {"cross-site"}}},
		"sec-fetch same-site": {headers: map[string][]string{"Sec-Fetch-Site": {"same-site"}}},
	}
	routes := []struct {
		name, method, path, cookie, csrf string
		counter                          string
	}{
		{"anonymous", "POST", "/t/anonymous", "", "", "anon"},
		{"preauth", "POST", "/t/preauth", set.preauth.cookie, set.preauth.csrf, "preauth"},
		{"session", "POST", "/t/session", set.fresh.cookie, set.fresh.csrf, "session"},
		{"put", "PUT", "/t/resource", set.fresh.cookie, set.fresh.csrf, "put"},
		{"patch", "PATCH", "/t/resource", set.fresh.cookie, set.fresh.csrf, "patch"},
		{"delete", "DELETE", "/t/resource", set.fresh.cookie, set.fresh.csrf, "delete"},
		{"sensitive", "POST", "/t/sensitive/" + string(OpBackupRestore), set.fresh.cookie, set.fresh.csrf, "op:" + string(OpBackupRestore)},
		{"logout", "POST", "/t/logout", set.fresh.cookie, set.fresh.csrf, ""},
	}
	for oname, o := range origins {
		for _, r := range routes {
			q := o
			q.method, q.path, q.cookie, q.csrf, q.body = r.method, r.path, r.cookie, r.csrf, `{}`
			w := h.do(q)
			if w.Code != http.StatusForbidden {
				t.Fatalf("origin %q on %s: status %d", oname, r.name, w.Code)
			}
		}
	}
	for _, r := range routes {
		if r.counter != "" && h.calls0(r.counter) != 0 {
			t.Fatalf("handler %s reached through a negative origin", r.name)
		}
	}
	// The same requests with the exact trusted origin are accepted (control).
	for _, r := range routes[:7] {
		w := h.do(httpReq{method: r.method, path: r.path, cookie: r.cookie, csrf: r.csrf, body: `{}`})
		if w.Code != 200 {
			t.Fatalf("control request %s denied: %d %s", r.name, w.Code, w.Body.String())
		}
	}
	// The logged-out check proves the tokens were genuinely valid above.
	if w := h.do(httpReq{method: "POST", path: "/t/logout", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`}); w.Code != 200 && w.Code != 204 {
		t.Fatal("control logout denied", w.Code)
	}
}

func TestCSRFTokenIsServerBoundPerSession(t *testing.T) { // S05
	h := newBrowserHarness(t)
	set := h.sessions()
	cases := map[string]string{
		"missing":                 "",
		"wrong":                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"another session's":       set.stale.csrf,
		"preauth session's":       set.preauth.csrf,
		"password-only session's": set.passwordOnly.csrf,
		"truncated":               set.fresh.csrf[:20],
		"extended":                set.fresh.csrf + "A",
		"cookie value as token":   set.fresh.cookie,
	}
	for name, token := range cases {
		w := h.do(httpReq{method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: token, body: `{}`})
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s CSRF token: status %d", name, w.Code)
		}
	}
	if h.calls0("session") != 0 {
		t.Fatal("handler reached with a bad CSRF token")
	}
	// A query/body/cookie copy of the token is not accepted in place of the header.
	if w := h.do(httpReq{method: "POST", path: "/t/session?csrf=" + set.fresh.csrf, cookie: set.fresh.cookie, body: `{"csrf":"` + set.fresh.csrf + `"}`}); w.Code != http.StatusForbidden {
		t.Fatal("CSRF token accepted outside the header")
	}
	if w := h.do(httpReq{method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`}); w.Code != 200 {
		t.Fatal("valid token denied", w.Code)
	}
}

func TestMethodConfusionNeverReachesHandlers(t *testing.T) { // S05: DELETE/PATCH/GET covered
	h := newBrowserHarness(t)
	set := h.sessions()
	tokens := httpReq{cookie: set.fresh.cookie, csrf: set.fresh.csrf}
	for _, method := range []string{"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "PROPFIND", ""} {
		q := tokens
		q.method, q.path = method, "/t/session" // registered for POST only
		if method == "" {
			q.method = "XYZ"
		}
		if w := h.do(q); w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
			t.Fatalf("%s on a POST-only route returned %d", method, w.Code)
		}
	}
	q := tokens
	q.method, q.path, q.headers = "GET", "/t/session", map[string][]string{"X-HTTP-Method-Override": {"POST"}, "X-Method-Override": {"POST"}, "X-HTTP-Method": {"POST"}}
	if w := h.do(q); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("method override header honoured", w.Code)
	}
	q.path = "/t/session?_method=POST"
	if w := h.do(q); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("_method query honoured", w.Code)
	}
	if h.calls0("session") != 0 {
		t.Fatal("POST-only handler reached by another method")
	}
	// A CORS preflight never grants anything and never carries CORS headers.
	pre := h.do(httpReq{method: "OPTIONS", path: "/t/session", origin: "https://evil.test", headers: map[string][]string{"Access-Control-Request-Method": {"POST"}}})
	for k := range pre.Header() {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Fatal("CORS header emitted:", k)
		}
	}
	// A state-changing route registered as GET is refused at registration.
	if err := h.b.Handle("GET /t/mutate", RoutePolicy{Require: RequireNone, Sensitive: OpPasswordChange}, http.NotFoundHandler()); err == nil {
		t.Fatal("sensitive route without a session requirement registered")
	}
}

func TestRouteRegistrationRequiresExplicitPolicy(t *testing.T) { // default deny / weaker-route prevention
	e := newSessionEnv(t)
	ok := http.NotFoundHandler()
	for name, c := range map[string]struct {
		pattern string
		policy  RoutePolicy
		handler http.Handler
	}{
		"zero policy":          {"POST /a", RoutePolicy{}, ok},
		"unknown requirement":  {"POST /a", RoutePolicy{Require: 99}, ok},
		"no method":            {"/a", RoutePolicy{Require: RequireSession}, ok},
		"wildcard method host": {"example.invalid/a", RoutePolicy{Require: RequireSession}, ok},
		"CONNECT":              {"CONNECT /a", RoutePolicy{Require: RequireSession}, ok},
		"TRACE":                {"TRACE /a", RoutePolicy{Require: RequireSession}, ok},
		"OPTIONS":              {"OPTIONS /a", RoutePolicy{Require: RequireSession}, ok},
		"nil handler":          {"POST /a", RoutePolicy{Require: RequireSession}, nil},
		"sensitive anonymous":  {"POST /a", RoutePolicy{Require: RequireNone, Sensitive: OpPasswordChange}, ok},
		"sensitive preauth":    {"POST /a", RoutePolicy{Require: RequirePreauth, Sensitive: OpPasswordChange}, ok},
		"unknown sensitive op": {"POST /a", RoutePolicy{Require: RequireSession, Sensitive: "made-up"}, ok},
		"background mutation":  {"POST /a", RoutePolicy{Require: RequireSession, Background: true}, ok},
		"background anonymous": {"GET /a", RoutePolicy{Require: RequireNone, Background: true}, ok},
		"background sensitive": {"GET /a", RoutePolicy{Require: RequireSession, Background: true, Sensitive: OpBackupExport}, ok},
		"anonymous read of /t": {"GET /a", RoutePolicy{Require: RequireNone}, ok},
	} {
		b := NewBrowser(e.s)
		err := b.Handle(c.pattern, c.policy, c.handler)
		wantErr := name != "anonymous read of /t"
		if (err != nil) != wantErr {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
	b := NewBrowser(e.s)
	if err := b.Handle("POST /dup", RoutePolicy{Require: RequireSession}, ok); err != nil {
		t.Fatal(err)
	}
	if err := b.Handle("POST /dup", RoutePolicy{Require: RequireNone}, ok); err == nil {
		t.Fatal("a weaker duplicate registration replaced the stronger one")
	}
	if len(b.Routes()) != 1 || b.Routes()[0].Policy.Require != RequireSession {
		t.Fatal("route inventory wrong")
	}
}

func TestWeakerRouteBypassMatrix(t *testing.T) { // N63B4-DOC-SESSION-COVERAGE, SCOPE-ADMIN, REAUTH-STRENGTH
	h := newBrowserHarness(t)
	set := h.sessions()
	states := map[string]struct{ cookie, csrf string }{
		"anonymous":     {},
		"password-only": set.passwordOnly,
		"preauth":       set.preauth,
		"stale AAL2":    set.stale,
		"fresh AAL2":    set.fresh,
	}
	for _, route := range h.b.Routes() {
		parts := strings.SplitN(route.Pattern, " ", 2)
		method, path := parts[0], parts[1]
		if strings.HasPrefix(path, "/t/login") || strings.HasPrefix(path, "/t/stepup") || path == "/t/logout" || path == "/t/info" {
			continue // adapters with their own tests below
		}
		for sname, st := range states {
			before := map[string]int32{}
			for k, v := range h.calls {
				before[k] = v.Load()
			}
			w := h.do(httpReq{method: method, path: path, cookie: st.cookie, csrf: st.csrf, body: `{}`})
			reached := false
			for k, v := range h.calls {
				reached = reached || v.Load() != before[k]
			}
			allowed := expectedAccess(route.Policy, sname)
			if allowed != reached {
				t.Fatalf("%s %s as %s: reached=%v want %v (status %d)", method, path, sname, reached, allowed, w.Code)
			}
			if allowed && w.Code != 200 {
				t.Fatalf("%s %s as %s: allowed route returned %d", method, path, sname, w.Code)
			}
			if !allowed && (w.Code < 400 || w.Code > 403) {
				t.Fatalf("%s %s as %s: denied route returned %d", method, path, sname, w.Code)
			}
		}
	}
}

// expectedAccess is the independent oracle for the matrix above.
func expectedAccess(p RoutePolicy, state string) bool {
	switch p.Require {
	case RequireNone:
		return true
	case RequirePreauth:
		return state == "preauth"
	}
	if state == "anonymous" || state == "preauth" {
		return false
	}
	if p.Sensitive == "" {
		return true
	}
	// The account is MFA-capable, so even non-AAL2-only operations need fresh AAL2.
	return state == "fresh AAL2"
}

func TestPathVariantsCannotBypassPolicy(t *testing.T) { // weaker-route bypass
	h := newBrowserHarness(t)
	set := h.sessions()
	target := "/t/sensitive/" + string(OpBackupRestore)
	variants := []string{
		"//t/sensitive/" + string(OpBackupRestore),
		"/t/./sensitive/" + string(OpBackupRestore),
		"/t/x/../sensitive/" + string(OpBackupRestore),
		target + "/",
		target + "/.",
		"/T/SENSITIVE/" + strings.ToUpper(string(OpBackupRestore)),
		"/t/%73ensitive/" + string(OpBackupRestore),
		target + "%2f",
		target + ";x=1",
		target + "%00",
		target + "?x=/../",
		"/t/sensitive%2F" + string(OpBackupRestore),
		"/api/v1/../t/sensitive/" + string(OpBackupRestore),
	}
	for _, p := range variants {
		for sname, st := range map[string]struct{ cookie, csrf string }{"anonymous": {}, "stale": set.stale, "password-only": set.passwordOnly} {
			w := h.do(httpReq{method: "POST", path: p, cookie: st.cookie, csrf: st.csrf, body: `{}`})
			if w.Code == 200 || h.calls0("op:"+string(OpBackupRestore)) != 0 {
				t.Fatalf("%q reached the sensitive handler as %s (status %d)", p, sname, w.Code)
			}
		}
	}
	if w := h.do(httpReq{method: "POST", path: target, cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`}); w.Code != 200 {
		t.Fatal("control request denied", w.Code)
	}
}

func TestUnsafeRequestsRequireJSONContentType(t *testing.T) { // CSRF via simple form posts
	h := newBrowserHarness(t)
	set := h.sessions()
	for _, ct := range []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain", "text/plain;charset=UTF-8", "application/xml", "", "application/jsonx", "application/json; charset=utf-16"} {
		var w *httptest.ResponseRecorder
		if ct == "" {
			// the helper defaults to JSON; build the Content-Type-less request manually
			r := httptest.NewRequest("POST", "https://example.invalid/t/session", strings.NewReader(`{}`))
			r.Header.Set("Origin", sessionTestOrigin)
			r.Header.Set(CSRFHeader, set.fresh.csrf)
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: set.fresh.cookie})
			w = httptest.NewRecorder()
			h.b.ServeHTTP(w, r)
		} else {
			w = h.do(httpReq{method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`, contentType: ct})
		}
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("content type %q: status %d", ct, w.Code)
		}
	}
	if h.calls0("session") != 0 {
		t.Fatal("handler reached with a non-JSON body")
	}
	if w := h.do(httpReq{method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`, contentType: "application/json; charset=utf-8"}); w.Code != 200 {
		t.Fatal("charset-qualified JSON denied", w.Code)
	}
}

func TestCookieAmbiguityAndTossingAreRejected(t *testing.T) { // S05 sibling-subdomain/cookie tossing
	h := newBrowserHarness(t)
	set := h.sessions()
	good := set.fresh.cookie
	for name, raw := range map[string]string{
		"duplicate same name":      SessionCookieName + "=" + good + "; " + SessionCookieName + "=" + set.stale.cookie,
		"duplicate attacker first": SessionCookieName + "=" + set.stale.cookie + "; " + SessionCookieName + "=" + good,
		"unprefixed name only":     "mandatary_session=" + good,
		"__Secure- name only":      "__Secure-mandatary_session=" + good,
		"padded":                   SessionCookieName + "=" + good + "=",
		"quoted":                   SessionCookieName + "=\"" + good + "\"",
		"short":                    SessionCookieName + "=" + good[:42],
		"long":                     SessionCookieName + "=" + good + "A",
		"non-base64":               SessionCookieName + "=" + strings.Repeat("!", 43),
		"empty":                    SessionCookieName + "=",
		"standard base64 alphabet": SessionCookieName + "=" + strings.NewReplacer("-", "+", "_", "/").Replace(good) + "A",
	} {
		w := h.do(httpReq{method: "GET", path: "/t/read", rawCookie: raw})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d", name, w.Code)
		}
	}
	// Unrelated cookies are ignored and never influence the session.
	if w := h.do(httpReq{method: "GET", path: "/t/read", rawCookie: "assurance=2; role=admin; " + SessionCookieName + "=" + good}); w.Code != 200 {
		t.Fatal("extra cookies broke a valid session", w.Code)
	}
	if h.calls0("read") != 1 {
		t.Fatal("handler count mismatch")
	}
}

func TestHostAndForwardedHeadersAreNotTrusted(t *testing.T) { // S04 / D-06 / N63B4-TLS-BOUNDARY (application-boundary part)
	h := newBrowserHarness(t)
	set := h.sessions()
	for _, host := range []string{"evil.test", "example.invalid.evil.test", "example.invalid:8443", "app.example.invalid", "EXAMPLE.INVALID.", "127.0.0.1:8080", "localhost"} {
		w := h.do(httpReq{method: "GET", path: "/t/read", cookie: set.fresh.cookie, host: host})
		if w.Code == 200 {
			t.Fatalf("Host %q accepted", host)
		}
	}
	// Forwarded headers are ignored: they neither rescue a bad Host nor change the origin.
	w := h.do(httpReq{method: "GET", path: "/t/read", cookie: set.fresh.cookie, host: "evil.test", headers: map[string][]string{"X-Forwarded-Host": {"example.invalid"}, "X-Forwarded-Proto": {"https"}, "Forwarded": {"host=example.invalid;proto=https"}}})
	if w.Code == 200 {
		t.Fatal("X-Forwarded-Host rescued a mismatched Host")
	}
	w = h.do(httpReq{method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: set.fresh.csrf, origin: "https://evil.test", body: `{}`, headers: map[string][]string{"X-Forwarded-Host": {"evil.test"}, "X-Forwarded-Proto": {"https"}, "X-Forwarded-For": {"203.0.113.9"}}})
	if w.Code != http.StatusForbidden {
		t.Fatal("forwarded headers changed the trusted origin", w.Code)
	}
	if w := h.do(httpReq{method: "GET", path: "/t/read", cookie: set.fresh.cookie}); w.Code != 200 {
		t.Fatal("control denied", w.Code)
	}
	// An HTTP/1.0-style request with no Host is not served.
	r := httptest.NewRequest("GET", "https://example.invalid/t/read", nil)
	r.Host = ""
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: set.fresh.cookie})
	rec := httptest.NewRecorder()
	h.b.ServeHTTP(rec, r)
	if rec.Code == 200 {
		t.Fatal("request without Host served")
	}
}

func TestAgentTokensAreNeverHumanSessions(t *testing.T) { // S08 / SCOPE-MACHINE / N63B4-TOKEN-NOT-PRESENCE
	h := newBrowserHarness(t)
	set := h.sessions()
	bearer := "Bearer mdt_" + strings.Repeat("a", 52)
	paths := []string{"/t/read", "/t/info", "/t/poll"}
	for _, p := range paths {
		w := h.do(httpReq{method: "GET", path: p, headers: map[string][]string{"Authorization": {bearer}}})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("agent bearer token authenticated a browser route %s: %d", p, w.Code)
		}
	}
	for _, op := range SensitiveOperations() {
		w := h.do(httpReq{method: "POST", path: "/t/sensitive/" + string(op), body: `{}`, headers: map[string][]string{"Authorization": {bearer}}})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("agent token satisfied step-up for %s: %d", op, w.Code)
		}
	}
	// A token or someone's session secret in the Authorization header is never a session.
	secretAsBearer := "Bearer " + set.fresh.cookie
	if w := h.do(httpReq{method: "GET", path: "/t/read", headers: map[string][]string{"Authorization": {secretAsBearer}}}); w.Code != http.StatusUnauthorized {
		t.Fatal("session secret accepted as a bearer credential")
	}
	// An agent token placed in the cookie cannot be a session either.
	if w := h.do(httpReq{method: "GET", path: "/t/read", cookie: encodeSessionCookie(bytes.Repeat([]byte("mdt_"), 8))}); w.Code != http.StatusUnauthorized {
		t.Fatal("agent token accepted as a cookie session")
	}
	// An Authorization header (for example a proxy's) never elevates a valid cookie.
	w := h.do(httpReq{method: "POST", path: "/t/sensitive/" + string(OpBackupRestore), cookie: set.stale.cookie, csrf: set.stale.csrf, body: `{}`, headers: map[string][]string{"Authorization": {bearer}}})
	if w.Code != http.StatusForbidden {
		t.Fatal("bearer header refreshed a stale session", w.Code)
	}
	for _, c := range []string{"anon", "session", "read"} {
		if h.calls0(c) != 0 && c != "read" {
			t.Fatal("handler reached through an agent token")
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) { // CSP, I09 / N63B4-THREAT-BROWSER
	h := newBrowserHarness(t)
	set := h.sessions()
	responses := []*httptest.ResponseRecorder{
		h.do(httpReq{method: "GET", path: "/t/read", cookie: set.fresh.cookie}),
		h.do(httpReq{method: "GET", path: "/t/read"}),
		h.do(httpReq{method: "GET", path: "/missing"}),
		h.do(httpReq{method: "DELETE", path: "/t/read"}),
		h.do(httpReq{method: "POST", path: "/t/session", origin: "https://evil.test"}),
		h.do(httpReq{method: "GET", path: "/t/read", host: "evil.test"}),
		h.do(httpReq{method: "POST", path: "/t/login", body: `{"name":"x","password":"y"}`}),
	}
	for i, w := range responses {
		csp := w.Header().Get("Content-Security-Policy")
		if err := checkStrictCSP(csp); err != nil {
			t.Fatalf("response %d (status %d): %v: %q", i, w.Code, err, csp)
		}
		for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin"} {
			if w.Header().Get(k) != want {
				t.Fatalf("response %d: %s = %q want %q", i, k, w.Header().Get(k), want)
			}
		}
		if !strings.HasPrefix(w.Header().Get("Strict-Transport-Security"), "max-age=") {
			t.Fatalf("response %d lacks HSTS", i)
		}
	}
	if h.do(httpReq{method: "GET", path: "/t/read"}).Header().Get("Set-Cookie") != "" {
		t.Fatal("unauthenticated request received a cookie")
	}
}

// checkStrictCSP is an independent oracle: no unsafe sources, no wildcards, framing and base denied.
func checkStrictCSP(csp string) error {
	if csp == "" {
		return errString("missing CSP")
	}
	directives := map[string][]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			directives[f[0]] = f[1:]
		}
	}
	for name, values := range directives {
		for _, v := range values {
			switch v {
			case "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "data:", "blob:", "http:", "https:", "'strict-dynamic'":
				return errString("unsafe source " + v + " in " + name)
			}
		}
	}
	if len(directives["default-src"]) != 1 || directives["default-src"][0] != "'none'" {
		return errString("default-src must be 'none'")
	}
	for _, name := range []string{"frame-ancestors", "base-uri", "form-action"} {
		if v := directives[name]; len(v) != 1 || v[0] != "'none'" {
			return errString(name + " must be 'none'")
		}
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

func TestSensitiveRoutesStepUpOverHTTP(t *testing.T) { // every sensitive class: negative + step-up positive
	h := newBrowserHarness(t)
	set := h.sessions()
	for _, op := range SensitiveOperations() {
		path := "/t/sensitive/" + string(op)
		counter := "op:" + string(op)
		// negative: anonymous, password-only, preauth, stale — none reach the handler
		for name, st := range map[string]struct{ cookie, csrf string }{"anonymous": {}, "password-only": set.passwordOnly, "preauth": set.preauth, "stale": set.stale} {
			w := h.do(httpReq{method: "POST", path: path, cookie: st.cookie, csrf: st.csrf, body: `{}`})
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Fatalf("%s as %s: %d", op, name, w.Code)
			}
			if name == "stale" || name == "password-only" {
				var out struct{ Error string }
				_ = json.Unmarshal(w.Body.Bytes(), &out)
				if w.Code != http.StatusForbidden || out.Error != "step_up_required" {
					t.Fatalf("%s as %s must ask for step-up, got %d %q", op, name, w.Code, out.Error)
				}
			}
		}
		if h.calls0(counter) != 0 {
			t.Fatalf("%s handler reached without step-up", op)
		}
		// positive: a fresh AAL2 session passes; after >15m the identical request fails again
		if w := h.do(httpReq{method: "POST", path: path, cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`}); w.Code != 200 {
			t.Fatalf("%s denied for a fresh AAL2 session: %d %s", op, w.Code, w.Body.String())
		}
		if h.calls0(counter) != 1 {
			t.Fatalf("%s handler count", op)
		}
	}
	// Freshness decays: after the window the fresh cookie must step up again.
	h.e.clock.Advance(DefaultStepUpWindow + time.Second)
	if w := h.do(httpReq{method: "POST", path: "/t/sensitive/" + string(OpBackupRestore), cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`}); w.Code != http.StatusForbidden {
		t.Fatal("expired freshness still accepted", w.Code)
	}
}

func TestLoginAndStepUpFlowOverHTTP(t *testing.T) { // REAUTH-STRENGTH, SESSION-CREATION via HTTP
	h := newBrowserHarness(t)
	e := h.e
	post := func(path string, q httpReq, body string) *httptest.ResponseRecorder {
		q.method, q.path, q.body = "POST", path, body
		return h.do(q)
	}
	// Wrong password: no cookie, generic 401.
	w := post("/t/login", httpReq{}, `{"name":"synthetic-user","password":"definitely not the right one"}`)
	if w.Code != 401 || cookieHeader(w) != "" {
		t.Fatal("wrong password produced a session", w.Code)
	}
	w = post("/t/login", httpReq{}, `{"name":"nobody","password":"definitely not the right one"}`)
	if w.Code != 401 || cookieHeader(w) != "" {
		t.Fatal("unknown user produced a session", w.Code)
	}
	w = post("/t/login", httpReq{}, `{"name":"synthetic-user","password":"`+sessionTestPassword+`"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var login struct {
		CSRF, Assurance string
		Next            []string
	}
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	pre := cookieValue(t, w)
	if login.Assurance != string(AssurancePreauth) || strings.Join(login.Next, ",") != "totp,no-mfa" {
		t.Fatalf("%+v", login)
	}
	// The preauth cookie opens only the ceremony route, never a session route.
	if w = h.do(httpReq{method: "GET", path: "/t/read", cookie: pre}); w.Code != 401 {
		t.Fatal("preauth cookie opened a session route", w.Code)
	}
	if w = post("/t/login/totp", httpReq{cookie: pre}, `{"id":"`+h.id+`","code":"000000"}`); w.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted on a ceremony route", w.Code)
	}
	w = post("/t/login/totp", httpReq{cookie: pre, csrf: login.CSRF}, `{"id":"`+h.id+`","code":"`+e.nextCode(h.en)+`"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	session := cookieValue(t, w)
	if session == pre {
		t.Fatal("cookie not rotated at authentication")
	}
	var done struct{ CSRF, Assurance string }
	_ = json.Unmarshal(w.Body.Bytes(), &done)
	if done.Assurance != string(AssuranceAAL2) {
		t.Fatal(done)
	}
	if w = h.do(httpReq{method: "GET", path: "/t/read", cookie: pre}); w.Code != 401 {
		t.Fatal("preauth cookie survived completion", w.Code)
	}
	// Info endpoint exposes the server-derived labels and the CSRF token.
	w = h.do(httpReq{method: "GET", path: "/t/info", cookie: session})
	var info struct {
		Assurance         string   `json:"assurance"`
		Methods           []string `json:"methods"`
		PhishingResistant bool     `json:"phishing_resistant"`
		CSRFToken         string   `json:"csrf_token"`
		StepUpRequired    bool     `json:"step_up_required"`
		RequiredAssurance int      `json:"required_assurance"`
		UsableAssurance   int      `json:"usable_assurance"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &info) != nil || info.Assurance != "aal2" || strings.Join(info.Methods, ",") != "password,totp" || info.PhishingResistant || info.CSRFToken != done.CSRF || info.StepUpRequired || info.RequiredAssurance != 2 || info.UsableAssurance != 2 {
		t.Fatalf("session info wrong: %d %s", w.Code, w.Body.String())
	}
	// 15m+1s later: info reports step-up, a sensitive write is refused, step-up fixes it.
	e.clock.Advance(DefaultStepUpWindow + time.Second)
	w = h.do(httpReq{method: "GET", path: "/t/info", cookie: session})
	_ = json.Unmarshal(w.Body.Bytes(), &info)
	if !info.StepUpRequired {
		t.Fatal("info did not report that step-up is required")
	}
	restore := "/t/sensitive/" + string(OpBackupRestore)
	if w = post(restore, httpReq{cookie: session, csrf: done.CSRF}, `{}`); w.Code != http.StatusForbidden {
		t.Fatal("stale session performed a sensitive write", w.Code)
	}
	if w = post("/t/stepup/totp", httpReq{cookie: session, csrf: done.CSRF}, `{"password":"`+sessionTestPassword+`","id":"`+h.id+`","code":"000000"}`); w.Code != 401 || cookieHeader(w) != "" {
		t.Fatal("failed step-up changed the cookie", w.Code)
	}
	w = post("/t/stepup/totp", httpReq{cookie: session, csrf: done.CSRF}, `{"password":"`+sessionTestPassword+`","id":"`+h.id+`","code":"`+e.nextCode(h.en)+`"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	next := cookieValue(t, w)
	var up struct{ CSRF string }
	_ = json.Unmarshal(w.Body.Bytes(), &up)
	if next == session || up.CSRF == done.CSRF {
		t.Fatal("step-up did not rotate cookie and CSRF token")
	}
	if w = post(restore, httpReq{cookie: session, csrf: done.CSRF}, `{}`); w.Code != 401 {
		t.Fatal("pre-step-up cookie still valid", w.Code)
	}
	if w = post(restore, httpReq{cookie: next, csrf: done.CSRF}, `{}`); w.Code != http.StatusForbidden {
		t.Fatal("old CSRF token valid after rotation", w.Code)
	}
	if w = post(restore, httpReq{cookie: next, csrf: up.CSRF}, `{}`); w.Code != 200 {
		t.Fatal("step-up did not unlock the sensitive write", w.Code, w.Body.String())
	}
}

func cookieHeader(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge >= 0 && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func TestLogoutOverHTTPInvalidatesCopiedCookie(t *testing.T) { // S03 / N63B4-SESSION-LOGOUT
	h := newBrowserHarness(t)
	set := h.sessions()
	if w := h.do(httpReq{method: "POST", path: "/t/logout", cookie: set.fresh.cookie, csrf: "wrong", body: `{}`}); w.Code != http.StatusForbidden {
		t.Fatal("logout without CSRF accepted (forced-logout CSRF)", w.Code)
	}
	if w := h.do(httpReq{method: "GET", path: "/t/read", cookie: set.fresh.cookie}); w.Code != 200 {
		t.Fatal("session died from a forged logout")
	}
	w := h.do(httpReq{method: "POST", path: "/t/logout", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`})
	if w.Code != 200 && w.Code != 204 {
		t.Fatal(w.Code)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		cleared = cleared || (c.Name == SessionCookieName && c.MaxAge < 0 && c.Value == "")
	}
	if !cleared {
		t.Fatal("logout did not clear the cookie")
	}
	for _, p := range []httpReq{{method: "GET", path: "/t/read"}, {method: "GET", path: "/t/info"}, {method: "POST", path: "/t/session", csrf: set.fresh.csrf, body: `{}`}} {
		p.cookie = set.fresh.cookie
		if w := h.do(p); w.Code != 401 {
			t.Fatalf("copied cookie replayed after logout on %s: %d", p.path, w.Code)
		}
	}
	// An already-dead cookie clears itself and reports 401 without error detail.
	w = h.do(httpReq{method: "GET", path: "/t/read", cookie: set.fresh.cookie})
	if w.Code != 401 || !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatal("dead cookie not cleared", w.Header().Get("Set-Cookie"))
	}
}

func TestBackgroundRoutesDoNotKeepSessionsAlive(t *testing.T) { // S06
	h := newBrowserHarness(t)
	set := h.sessions()
	po := encodeSessionCookie(h.e.passwordOnly().Secret())
	for i := 1; i <= 3; i++ {
		h.e.clock.Advance(10 * time.Minute)
		w := h.do(httpReq{method: "GET", path: "/t/poll", cookie: po})
		if i < 3 && w.Code != 200 {
			t.Fatal("poll denied early", i, w.Code)
		}
		if i == 3 && w.Code != 401 {
			t.Fatal("background polling kept an idle session alive", w.Code)
		}
	}
	// Ordinary (meaningful) requests do reset the idle clock.
	active := encodeSessionCookie(h.e.passwordOnly().Secret())
	for i := 0; i < 4; i++ {
		h.e.clock.Advance(20 * time.Minute)
		if w := h.do(httpReq{method: "GET", path: "/t/read", cookie: active}); w.Code != 200 {
			t.Fatal("active session denied", i, w.Code)
		}
	}
	_ = set
}

func TestStorageUncertaintyIsServiceUnavailableNotAccess(t *testing.T) { // fail closed
	h := newBrowserHarness(t)
	set := h.sessions()
	h.e.l.repo.FailClosed()
	for _, q := range []httpReq{{method: "GET", path: "/t/read", cookie: set.fresh.cookie}, {method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`}} {
		w := h.do(q)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("poisoned repository returned %d", w.Code)
		}
	}
	if h.calls0("read") != 0 || h.calls0("session") != 0 {
		t.Fatal("handler reached while storage was uncertain")
	}
}

func TestSessionSecretsNeverReachLogs(t *testing.T) { // P1.04 canaries extended to session material
	h := newBrowserHarness(t)
	set := h.sessions()
	for _, format := range []string{"json", "text"} {
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
			var out bytes.Buffer
			logger, err := logging.New(&out, level, format)
			if err != nil {
				t.Fatal(err)
			}
			wrapped := logging.HTTP(logger, h.b)
			for _, q := range []httpReq{
				{method: "GET", path: "/t/read", cookie: set.fresh.cookie},
				{method: "POST", path: "/t/session", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{}`},
				{method: "POST", path: "/t/session?x=" + set.fresh.cookie, cookie: set.fresh.cookie, csrf: "wrong", body: `{}`},
				{method: "GET", path: "/t/read", cookie: set.stale.cookie, host: "evil.test"},
			} {
				r := httptest.NewRequest(q.method, "https://example.invalid"+q.path, strings.NewReader(q.body))
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
				r.Header.Set(CSRFHeader, q.csrf)
				r.Header.Set("Origin", sessionTestOrigin)
				r.Header.Set("Content-Type", "application/json")
				if q.host != "" {
					r.Host = q.host
				}
				wrapped.ServeHTTP(httptest.NewRecorder(), r)
			}
			logger.Error("session", "session", Session{secret: []byte(set.fresh.cookie)}, "issued", IssuedSession{secret: []byte(set.fresh.cookie)})
			for _, canary := range []string{set.fresh.cookie, set.fresh.csrf, set.stale.cookie, set.stale.csrf, set.passwordOnly.cookie} {
				if strings.Contains(out.String(), canary) {
					t.Fatalf("%s/%s log leaked session material", format, level)
				}
			}
			if out.Len() == 0 {
				t.Fatal("logging not exercised")
			}
		}
	}
}

func TestUnsafeRequestBodiesAreBounded(t *testing.T) { // bounded input before proof work
	h := newBrowserHarness(t)
	set := h.sessions()
	var observed error
	if err := h.b.Handle("POST /t/bounded", RoutePolicy{Require: RequireSession}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, observed = io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	})); err != nil {
		t.Fatal(err)
	}
	huge := `{"x":"` + strings.Repeat("a", 1<<20) + `"}`
	h.do(httpReq{method: "POST", path: "/t/bounded", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: huge})
	if observed == nil {
		t.Fatal("a 1 MiB body was readable by a handler")
	}
	observed = nil
	h.do(httpReq{method: "POST", path: "/t/bounded", cookie: set.fresh.cookie, csrf: set.fresh.csrf, body: `{"x":"ok"}`})
	if observed != nil {
		t.Fatal("small body rejected", observed)
	}
}

// P1.18.4 P118-note-cookie-substring-flake: deterministic evidence that the cookie constructor serializes ONLY the secret bytes. The inputs
// are synthetic secrets whose bytes deliberately spell state-like words; the output must still be exactly their base64url encoding (no
// prefix, suffix, delimiter or structured claim), decode back to the same bytes, and be accepted by the parser only in that exact shape. A
// cookie carrying structured claims ("aal2.<secret>", "<user>:<secret>") is refused whatever its content. No production token is logged,
// no entropy is reduced and the cookie format is unchanged.
const sessionCookieChars = 43 // unpadded base64url of 32 bytes

func TestSessionCookieConstructorSerializesOnlyTheSecretBytes(t *testing.T) {
	t.Parallel()
	// A deterministic secret whose ENCODING contains "aal" (the substring the old assertion tripped over by chance) is an ordinary opaque cookie.
	aal, err := base64.RawURLEncoding.Strict().DecodeString("aal" + strings.Repeat("A", sessionCookieChars-3))
	if err != nil || len(aal) != sessionSecretBytes {
		t.Fatalf("the synthetic sample does not decode to %d bytes: %v", sessionSecretBytes, err)
	}
	inputs := map[string][]byte{
		"encoding contains aal": aal,
		"state words":           []byte("aal2;admin;preauth;synthetic-user!"[:sessionSecretBytes]),
		"all zero":              make([]byte, sessionSecretBytes),
		"all ones":              bytes.Repeat([]byte{0xFF}, sessionSecretBytes),
		"ascending": func() []byte {
			b := make([]byte, sessionSecretBytes)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
		"separator bytes": bytes.Repeat([]byte("=.:;/+"), 6)[:sessionSecretBytes],
	}
	for name, secret := range inputs {
		value := encodeSessionCookie(secret)
		want := base64.RawURLEncoding.EncodeToString(secret)
		if name == "encoding contains aal" && !strings.Contains(value, "aal") {
			t.Fatal("the sample no longer contains the substring it exists to cover")
		}
		if value != want || len(value) != sessionCookieChars || strings.ContainsAny(value, "+/=.:;") {
			t.Fatalf("%s: cookie %q is not exactly the unpadded base64url of the secret (%q)", name, value, want)
		}
		r := httptest.NewRequest(http.MethodGet, "https://example.invalid/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})
		got, present, ok := sessionSecretFrom(r)
		if !present || !ok || !bytes.Equal(got, secret) {
			t.Fatalf("%s: the parser did not return the same secret bytes", name)
		}
		// The same secret always yields the same cookie, whoever the session belongs to: nothing but the secret goes into it.
		if encodeSessionCookie(append([]byte(nil), secret...)) != value {
			t.Fatalf("%s: the constructor is not a pure function of the secret bytes", name)
		}
	}
	secret := inputs["ascending"]
	for name, claim := range map[string]string{
		"assurance prefix": "aal2." + encodeSessionCookie(secret),
		"user prefix":      "synthetic-user:" + encodeSessionCookie(secret),
		"padded":           encodeSessionCookie(secret) + "=",
		"role suffix":      encodeSessionCookie(secret) + ".admin",
		"standard base64":  base64.StdEncoding.EncodeToString(append(append([]byte(nil), secret...), 0xFB)),
	} {
		r := httptest.NewRequest(http.MethodGet, "https://example.invalid/", nil)
		r.Header.Set("Cookie", SessionCookieName+"="+claim)
		if got, _, ok := sessionSecretFrom(r); ok || len(got) != 0 {
			t.Fatalf("%s: a cookie that is not exactly the encoded secret was accepted", name)
		}
	}
}
