package security_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/NicoTM77/Mandatary/web"
)

// This is a static-surface regression, not evidence of future authorization.
// Injecting the public index into this denied-route fixture MUST fail the suite.
func TestUnavailableProductRoutes(t *testing.T) {
	// /setup and /login left this list deliberately (P1.16.3, D-ROUTE-1): they are
	// exact application-document routes that serve the static shell. Their
	// closed-by-default API surface is asserted where the API is mounted.
	paths := []string{"/api/v1/containers", "/mcp", "/setup/exchange", "/login/totp", "/setup/", "/login/", "/containers/json", "/v1.44/containers/json"}
	if os.Getenv("MANDATARY_NEGATIVE_FIXTURE") == "exposed-route" {
		paths = append(paths, "/")
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			web.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("SECURITY_ROUTE_EXPOSURE: unavailable route returned %d", w.Code)
			}
		})
	}
}
