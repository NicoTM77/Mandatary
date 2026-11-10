package authz_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestSuccessfulAuthorizationSecretRedaction(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			e, req := publicationSetup(t)
			ctx := context.Background()
			secret := "success-path-synthetic-human-canary-0123456789"
			if kind == "human" {
				req.Principal.SessionSecret = e.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1, RawSecret: []byte(secret)})
			} else {
				secret = "mdt_success_path_synthetic_agent_canary_0123456789"
				e.seedAgent(seedAgentOpts{ID: testAgentID1, Name: "redaction-bot"})
				e.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID1, AgentID: testAgentID1, RawToken: secret})
				e.seedPolicy(store.Policy{ID: string(testPolicyID2), AgentID: sql.NullString{String: string(testAgentID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(req.Operation), Effect: "ALLOW"})
				req.Principal = authz.PrincipalCredentials{AgentToken: secret}
			}
			dec, err := e.authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := e.authorizer.AcquireLease(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			canaries := []string{
				secret,
				hex.EncodeToString([]byte(secret)),
				base64.StdEncoding.EncodeToString([]byte(secret)),
				fmt.Sprintf("%d", []byte(secret)),
				fmt.Sprintf("%#v", []byte(secret)),
			}
			check := func(label, output string) {
				t.Helper()
				for _, canary := range canaries {
					if strings.Contains(output, canary) {
						t.Errorf("%s exposes credential material", label)
					}
				}
			}
			values := []any{dec, &dec, lease, struct{ Decision authz.Decision }{dec}, struct{ Lease *authz.Lease }{lease}}
			for i, value := range values {
				for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
					check(fmt.Sprintf("value%d/%s", i, format), fmt.Sprintf(format, value))
				}
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				check("JSON", string(data))
				for _, text := range []bool{false, true} {
					var out bytes.Buffer
					var h slog.Handler = slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})
					if text {
						h = slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})
					}
					slog.New(h).Debug("success", slog.Any("authorization", value))
					check("structured log", out.String())
				}
			}
			if err := lease.Revalidate(ctx); err != nil {
				t.Errorf("redaction must preserve usable credential: %v", err)
			}
		})
	}
}
