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
	for _, path := range []string{"/api/v1/containers", "/mcp", "/setup", "/healthz", "/assets/", "/assets/missing.js", "/.env", "/src/App.tsx", "/dist/index.html", "/other"} {
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
