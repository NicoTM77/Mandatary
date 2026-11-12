package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/api"
)

func TestComposeReservesTheMachineNamespacesAndLeavesTheRestToTheFallback(t *testing.T) {
	tag := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("X-Who", name) })
	}
	serve := func(h http.Handler, path string) (who string, status int) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "http://x"+path, nil))
		return w.Header().Get("X-Who"), w.Code
	}
	full := api.Compose(tag("rest"), tag("mcp"), tag("fallback"))
	for path, want := range map[string]string{
		"/api/v1/readyz": "rest", "/api/v1/endpoints": "rest", "/api/v1/endpoints/local/containers/x/status": "rest", "/api/v1/endpoints/": "rest",
		"/mcp": "mcp", "/mcp/": "mcp", "/mcp/x": "mcp",
		// Human routes that live under /api/v1 and everything else belong to the fallback.
		"/api/v1/setup/exchange": "fallback", "/api/v1/admin/users": "fallback", "/api/v1/containers": "fallback", "/": "fallback", "/mcpx": "fallback",
		"/api/v1/endpointsx": "fallback", "/api/v1/readyz/": "fallback", "/API/V1/readyz": "fallback",
	} {
		if who, _ := serve(full, path); who != want {
			t.Errorf("%s routed to %q, want %q", path, who, want)
		}
	}
	// With no adapter configured the namespaces still do not fall through.
	bare := api.Compose(nil, nil, tag("fallback"))
	for _, path := range []string{"/api/v1/readyz", "/api/v1/endpoints/local/containers/x/status", "/mcp", "/mcp/"} {
		who, status := serve(bare, path)
		if who != "" || status != http.StatusNotFound {
			t.Errorf("%s: who=%q status=%d, want the common 404 and no fallback", path, who, status)
		}
	}
	if who, _ := serve(bare, "/api/v1/setup/exchange"); who != "fallback" {
		t.Error("human routes must still reach the fallback")
	}
}
