package security_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/web"
)

// P1.08 adds session middleware, not routes: the shipped static surface must
// still expose no login/session/step-up/logout endpoint under any method, must
// never set a cookie, and its CSP must contain no unsafe source.
func TestStaticCSPIsStrictAndNoSessionRoutesAreMounted(t *testing.T) {
	paths := []string{
		"/api/v1/session", "/api/v1/sessions", "/api/v1/auth/login", "/api/v1/auth/step-up", "/api/v1/auth/stepup",
		"/api/v1/logout", "/logout", "/session", "/login/totp", "/login/webauthn", "/stepup", "/api/v1/csrf",
	}
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(method, path, nil)
			r.Header.Set("Origin", "https://example.invalid")
			r.AddCookie(&http.Cookie{Name: "__Host-mandatary_session", Value: strings.Repeat("A", 43)})
			web.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("SECURITY_ROUTE_EXPOSURE: %s %s returned %d", method, path, w.Code)
			}
			if w.Header().Get("Set-Cookie") != "" {
				t.Fatalf("static surface set a cookie on %s %s", method, path)
			}
		}
	}
	w := httptest.NewRecorder()
	web.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("static document has no CSP")
	}
	for _, forbidden := range []string{"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", " * ", "data:", "blob:", "http:", "https:"} {
		if strings.Contains(csp+" ", forbidden) {
			t.Fatalf("static CSP contains %s: %s", forbidden, csp)
		}
	}
	for _, required := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, required) {
			t.Fatalf("static CSP lacks %s: %s", required, csp)
		}
	}
}
