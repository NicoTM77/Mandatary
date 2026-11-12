package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// P1.14: the served binary reserves the machine namespaces. Until a later row composes
// a real executor, they answer the common JSON 404 and can fall through neither to the
// static site nor to the setup mux; human /api/v1 routes (setup) keep working.
func TestServedBinaryReservesTheMachineNamespacesWithoutAnExecutor(t *testing.T) {
	f := newCLIFixture(t)
	code, _ := f.runServer(startupOrigin, func(s *http.Server) error {
		for _, c := range []struct{ method, path string }{
			{"GET", "/api/v1/readyz"}, {"GET", "/api/v1/endpoints/local/containers/edge-proxy/status"}, {"POST", "/api/v1/endpoints/local/containers/edge-proxy/stop"},
			{"POST", "/mcp"}, {"GET", "/mcp"}, {"POST", "/mcp/"}, {"GET", "/api/v1/endpoints"},
		} {
			r := httptest.NewRequest(c.method, "https://mandatary.example.invalid"+c.path, nil)
			r.Header.Set("Authorization", "Bearer mdt_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
			w := httptest.NewRecorder()
			s.Handler.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound || w.Header().Get("Content-Type") != "application/json" {
				t.Errorf("%s %s: %d %q", c.method, c.path, w.Code, w.Header().Get("Content-Type"))
			}
		}
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusOK {
			t.Errorf("static root: %d", w.Code)
		}
		return http.ErrServerClosed
	})
	if code != 0 {
		t.Fatal(code)
	}
}
