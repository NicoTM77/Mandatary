package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type setupCall struct {
	method, path, body string
	host, origin       string
	contentType        string
	cookie, csrf       string
	extra              map[string]string
}

func (e *setupEnv) call(c setupCall) *httptest.ResponseRecorder {
	e.t.Helper()
	if c.host == "" {
		c.host = "example.invalid"
	}
	if c.contentType == "" && c.method != http.MethodGet {
		c.contentType = "application/json"
	}
	if c.origin == "" && c.method != http.MethodGet {
		c.origin = setupTestOrigin
	}
	req := httptest.NewRequest(c.method, "https://"+c.host+c.path, strings.NewReader(c.body))
	req.Host = c.host
	if c.contentType != "" {
		req.Header.Set("Content-Type", c.contentType)
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	if c.csrf != "" {
		req.Header.Set(CSRFHeader, c.csrf)
	}
	for k, v := range c.extra {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w
}

func setupCookieOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == SetupCookieName && c.MaxAge >= 0 {
			return c.Name + "=" + c.Value
		}
	}
	t.Fatal("no setup cookie issued")
	return ""
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %q", w.Body.String())
	}
	return out
}

// SETUP-02/06: the entire setup surface is a 404 until a generation exists, and is
// a 404 again once nothing is live, for every method and path.
func TestSetupSurfaceDoesNotExistWithoutALiveGeneration(t *testing.T) {
	e := newSetupEnv(t)
	paths := []string{"exchange", "session", "account", "addresses/proof", "addresses/confirm", "totp", "totp/confirm", "complete", "nope"}
	probe := func(want int) {
		t.Helper()
		for _, p := range paths {
			for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
				w := e.call(setupCall{method: m, path: SetupPathPrefix + p, body: "{}"})
				if w.Code != want {
					t.Fatalf("%s %s: %d, want %d", m, p, w.Code, want)
				}
			}
		}
	}
	probe(http.StatusNotFound) // fresh install, nothing issued yet
	e.ensure()
	e.advance(SetupTokenLifetime)
	probe(http.StatusNotFound) // expired
	e2 := newSetupEnv(t)
	e2.firstAdmin()
	for _, p := range paths {
		if w := e2.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + p, body: "{}"}); w.Code != http.StatusNotFound {
			t.Fatalf("after setup, %s: %d", p, w.Code)
		}
	}
}

func TestSetupHTTPRequestHygiene(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	body := `{"token":"` + token + `"}`
	good := setupCall{method: http.MethodPost, path: SetupPathPrefix + "exchange", body: body}
	for name, c := range map[string]setupCall{
		"wrong host":              {method: good.method, path: good.path, body: good.body, host: "evil.invalid"},
		"forwarded host ignored":  {method: good.method, path: good.path, body: good.body, host: "evil.invalid", extra: map[string]string{"X-Forwarded-Host": "example.invalid"}},
		"foreign origin":          {method: good.method, path: good.path, body: good.body, origin: "https://evil.invalid"},
		"http origin":             {method: good.method, path: good.path, body: good.body, origin: "http://example.invalid"},
		"null origin":             {method: good.method, path: good.path, body: good.body, origin: "null"},
		"cross-site fetch":        {method: good.method, path: good.path, body: good.body, extra: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		"form content type":       {method: good.method, path: good.path, body: good.body, contentType: "application/x-www-form-urlencoded"},
		"text content type":       {method: good.method, path: good.path, body: good.body, contentType: "text/plain"},
		"query string":            {method: good.method, path: good.path + "?token=" + token, body: good.body},
		"trailing slash":          {method: good.method, path: good.path + "/", body: good.body},
		"path traversal":          {method: good.method, path: SetupPathPrefix + "../setup/exchange", body: good.body},
		"get method":              {method: http.MethodGet, path: good.path},
		"unknown field":           {method: good.method, path: good.path, body: `{"token":"` + token + `","extra":1}`},
		"trailing json":           {method: good.method, path: good.path, body: body + body},
		"oversized body":          {method: good.method, path: good.path, body: `{"token":"` + strings.Repeat("A", 1<<20) + `"}`},
		"token in query not body": {method: good.method, path: good.path + "?x=1", body: "{}"},
	} {
		t.Run(name, func(t *testing.T) {
			w := e.call(c)
			if w.Code < 400 || w.Code >= 500 && w.Code != 404 && w.Code != 405 && w.Code != 400 && w.Code != 403 && w.Code != 413 && w.Code != 415 && w.Code != 421 {
				t.Fatalf("status %d", w.Code)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("a rejected request issued a cookie")
			}
		})
	}
	// None of the rejected requests consumed the token.
	if e.text(`SELECT state FROM setup_tokens`) != "retrieved" {
		t.Fatal("a malformed or hostile request consumed the generation")
	}
	w := e.call(good)
	if w.Code != http.StatusOK {
		t.Fatalf("legitimate exchange: %d %s", w.Code, w.Body.String())
	}
}

func TestSetupSessionCookieAndCSRF(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	w := e.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + "exchange", body: `{"token":"` + e.reveal(PurposeInitialSetup, "") + `"}`})
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		cookie = c
	}
	if cookie == nil || cookie.Name != "__Host-mandatary_setup" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		t.Fatalf("setup cookie attributes: %+v", cookie)
	}
	if cookie.Name == "__Host-mandatary_session" || strings.HasPrefix(cookie.Name, SessionCookieName) {
		t.Fatal("setup shares the normal session cookie name")
	}
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control %q", got)
	}
	view := decode(t, w)
	csrf, _ := view["csrf_token"].(string)
	header := cookie.Name + "=" + cookie.Value
	// Read: cookie alone suffices. Unsafe: a missing or wrong CSRF token is refused.
	if r := e.call(setupCall{method: http.MethodGet, path: SetupPathPrefix + "session", cookie: header}); r.Code != http.StatusOK {
		t.Fatalf("session view %d", r.Code)
	}
	for name, token := range map[string]string{"missing": "", "wrong": strings.Repeat("0", len(csrf)), "short": "x"} {
		r := e.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + "complete", body: "{}", cookie: header, csrf: token})
		if r.Code != http.StatusForbidden {
			t.Fatalf("%s CSRF: %d", name, r.Code)
		}
	}
	// A cookie-less request, a duplicated cookie, a quoted one and a look-alike are
	// all unauthenticated. The normal-session cookie name is never accepted.
	for name, ch := range map[string]string{
		"none":       "",
		"duplicate":  header + "; " + header,
		"quoted":     cookie.Name + `="` + cookie.Value + `"`,
		"wrong name": "mandatary_setup=" + cookie.Value,
		"normal":     SessionCookieName + "=" + cookie.Value,
		"truncated":  header[:len(header)-3],
	} {
		r := e.call(setupCall{method: http.MethodGet, path: SetupPathPrefix + "session", cookie: ch})
		if r.Code != http.StatusUnauthorized {
			t.Fatalf("%s cookie: %d", name, r.Code)
		}
	}
	// The setup cookie is not a session for the ordinary authenticator: it grants
	// nothing outside the setup API and the normal verifier cannot even parse it.
	if _, err := e.sessions().Authenticate(e.ctx(), []byte(cookie.Value), true); err == nil {
		t.Fatal("a setup cookie value authenticated as a normal session")
	}
	// After expiry the same cookie stops working and is cleared.
	e.advance(SetupTokenLifetime)
	r := e.call(setupCall{method: http.MethodGet, path: SetupPathPrefix + "session", cookie: header})
	if r.Code != http.StatusNotFound && r.Code != http.StatusUnauthorized {
		t.Fatalf("expired session: %d", r.Code)
	}
}

// The whole ceremony over the HTTP adapter, including that no response (other than
// the one-time TOTP seed) carries secret-looking material back, and that
// completion issues NO login cookie.
func TestFirstAdminOverHTTP(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	post := func(path, body, cookie, csrf string) *httptest.ResponseRecorder {
		return e.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + path, body: body, cookie: cookie, csrf: csrf})
	}
	w := post("exchange", `{"token":"`+token+`"}`, "", "")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie, csrf := setupCookieOf(t, w), decode(t, w)["csrf_token"].(string)
	w = post("account", `{"username":"`+setupTestUser+`","password":"`+setupTestPassword+`","addresses":["first@example.invalid"]}`, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), setupTestPassword) {
		t.Fatal("the password was echoed")
	}
	address := decode(t, w)["addresses"].([]any)[0].(map[string]any)["id"].(string)
	if w = post("addresses/proof", `{"address_id":"`+address+`"}`, cookie, csrf); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = post("addresses/confirm", `{"address_id":"`+address+`","proof":"`+e.lastProof()+`"}`, cookie, csrf); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = post("addresses/confirm", `{"address_id":"`+address+`","proof":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}`, cookie, csrf); w.Code == http.StatusNoContent {
		t.Fatal("a wrong proof was accepted")
	}
	w = post("totp", `{"algorithm":"SHA256"}`, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	seed := decode(t, w)
	if _, ok := seed["secret"].(string); !ok || w.Header().Get("Cache-Control") == "" {
		t.Fatal("seed not delivered once over the protected response")
	}
	if w = post("complete", `{}`, cookie, csrf); w.Code == http.StatusOK {
		t.Fatal("completed before MFA was proven")
	}
	en := Enrollment{ID: seed["authenticator_id"].(string), secret: seed["secret"].(string)}
	if w = post("totp/confirm", `{"code":"000000"}`, cookie, csrf); w.Code == http.StatusNoContent && enrollmentCode(t, en, e.clock.Now()) != "000000" {
		t.Fatal("a wrong code was accepted")
	}
	e.advance(31 * time.Second)
	if w = post("totp/confirm", `{"code":"`+enrollmentCode(t, en, e.clock.Now())+`"}`, cookie, csrf); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	w = post("complete", `{}`, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	done := decode(t, w)
	if done["login_required"] != true || done["username"] != setupTestUser {
		t.Fatalf("completion view %v", done)
	}
	// Completion issues NO login cookie, only clears the setup cookie, and the
	// surface is gone afterwards.
	for _, c := range w.Result().Cookies() {
		if c.Name != SetupCookieName || c.MaxAge >= 0 {
			t.Fatalf("unexpected cookie %q on completion", c.Name)
		}
	}
	if r := e.call(setupCall{method: http.MethodGet, path: SetupPathPrefix + "session", cookie: cookie}); r.Code != http.StatusNotFound {
		t.Fatalf("setup surface after completion: %d", r.Code)
	}
	// The ordinary login now works, and only it yields a session.
	e.advance(31 * time.Second)
	login, err := e.sessions().PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.99")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.sessions().LoginTOTP(e.ctx(), login.Session.Secret(), en.ID, enrollmentCode(t, en, e.clock.Now()), "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
}

// Cleartext-safe responses: setup errors are fixed shapes that never echo input.
func TestSetupErrorsNeverEchoInput(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	canary := "CANARYCANARYCANARYCANARYCANARYCANARYCANARYCANARYCANA"
	w := e.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + "exchange", body: `{"token":"` + canary + `"}`})
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), canary) || strings.Contains(w.Body.String(), token) {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	// Wrong and unknown tokens are indistinguishable, and rate limiting does not
	// leak whether a generation exists.
	w2 := e.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + "exchange", body: `{"token":"AAAA"}`})
	if w2.Code != w.Code || w2.Body.String() != w.Body.String() {
		t.Fatalf("malformed and wrong tokens distinguishable: %q vs %q", w.Body.String(), w2.Body.String())
	}
	_ = time.Second
}
