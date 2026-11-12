package adapters_test

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/api"
)

func sha(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// readyz calls the unauthenticated readiness route.
func readyz(t *testing.T, e *env) (int, bool) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + "/api/v1/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body api.ReadyResult
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body.Ready
}
