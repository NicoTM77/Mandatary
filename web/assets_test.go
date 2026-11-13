package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedIndexAndAssets(t *testing.T) {
	handler := Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<title>Mandatary</title>") {
		t.Fatalf("embedded index missing: status %d", response.Code)
	}
	entries, err := fs.Glob(assets, "dist/assets/*.js")
	if err != nil || len(entries) == 0 {
		t.Fatal("real built JavaScript missing")
	}
	for _, name := range entries {
		path := strings.TrimPrefix(name, "dist")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || w.Body.Len() == 0 {
			t.Fatalf("asset %s not served", path)
		}
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("static response missing security headers")
	}
}

func TestStaticSurfaceRejectsUnknownRoutesAndMethods(t *testing.T) {
	for _, path := range []string{"/api/v1/containers", "/mcp", "/healthz", "/assets/", "/assets/missing.js", "/.env", "/src/App.tsx", "/dist/index.html", "/index.html", "/other"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("unexpected route exposure: %d", w.Code)
			}
		})
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, httptest.NewRequest(method, "/", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected method exposure: %s %d", method, w.Code)
		}
	}
}

// D-ROUTE-1: the application documents are an EXACT allowlist. Each serves the
// same index.html (the SPA reads location.pathname), and nothing else becomes a
// document: no wildcard, no trailing-slash alias, no sub-path, no method but
// GET/HEAD. The API behind /setup stays closed on its own (404 when no
// generation is live); serving the shell reveals nothing.
func TestApplicationDocumentRoutesAreAnExactAllowlist(t *testing.T) {
	index := httptest.NewRecorder()
	Handler().ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, path := range []string{"/setup", "/login"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusOK || w.Body.String() != index.Body.String() {
				t.Fatalf("%s is not the application shell: %d", path, w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("content type %q", ct)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
				t.Fatalf("document headers: %v", w.Header())
			}
			head := httptest.NewRecorder()
			Handler().ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))
			if head.Code != http.StatusOK || head.Body.Len() != 0 {
				t.Fatalf("HEAD %s: %d %d", path, head.Code, head.Body.Len())
			}
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
				m := httptest.NewRecorder()
				Handler().ServeHTTP(m, httptest.NewRequest(method, path, nil))
				if m.Code != http.StatusMethodNotAllowed {
					t.Fatalf("%s %s: %d", method, path, m.Code)
				}
			}
		})
	}
	for _, path := range []string{
		"/setup/", "/login/", "/Setup", "/LOGIN", "/setup/x", "/login/totp", "/setup/exchange", "/login/..%2f", "/setup%2f", "/setup.html", "//setup", "/setup;x", "/logout", "/session", "/account", "/admin",
	} {
		t.Run("closed "+path, func(t *testing.T) {
			w := httptest.NewRecorder()
			Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s must not be a document: %d", path, w.Code)
			}
		})
	}
}

// The policy may allow same-origin fetch (the SPA calls /api/v1/*) and nothing
// else beyond the original strict policy: exactly one directive changed.
func TestStaticCSPAllowsOnlySameOriginConnect(t *testing.T) {
	const want = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
	for _, path := range []string{"/", "/setup", "/login", "/assets/missing.js", "/other"} {
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if got := w.Header().Get("Content-Security-Policy"); got != want {
			t.Fatalf("%s CSP %q", path, got)
		}
	}
}
