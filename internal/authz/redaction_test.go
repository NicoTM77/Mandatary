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
	"sync/atomic"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/logging"
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

// hookHolder is a nested holder whose every formatting/serialization hook records
// that it ran and would reveal the canary if it did.
type hookHolder struct {
	called *atomic.Bool
	secret string
}

func (h hookHolder) Error() string        { h.called.Store(true); return h.secret }
func (h hookHolder) String() string       { h.called.Store(true); return h.secret }
func (h hookHolder) GoString() string     { h.called.Store(true); return h.secret }
func (h hookHolder) LogValue() slog.Value { h.called.Store(true); return slog.StringValue(h.secret) }
func (h hookHolder) MarshalJSON() ([]byte, error) {
	h.called.Store(true)
	return []byte(`"` + h.secret + `"`), nil
}
func (h hookHolder) MarshalText() ([]byte, error) { h.called.Store(true); return []byte(h.secret), nil }

// nestedHolder keeps real credentials behind unexported fields (fmt would reflect
// them without calling PrincipalCredentials' methods).
type nestedHolder struct {
	inner struct{ creds authz.PrincipalCredentials }
	hook  hookHolder
}

// P1.18.4 P111-L3: logging.New is the supported boundary. It drops unknown Any
// values before Resolve/String/JSON/reflection, so no bearer/session canary and no
// custom formatting hook is reached for nested holders, safe and unknown keys,
// groups, WithAttrs/WithGroup and dynamic preformatted messages. Arbitrary direct
// fmt of a holder is NOT part of this guarantee (documented in docs/authorization.md).
func TestSafeLoggerDropsCredentialHoldersBeforeAnyFormattingHook(t *testing.T) {
	const sessionCanary = "p1184-synthetic-session-canary-0123456789"
	const agentCanary = "mdt_p1184_synthetic_agent_canary_0123456789"
	const hookCanary = "p1184-synthetic-hook-canary-0123456789"
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var called atomic.Bool
			holder := nestedHolder{hook: hookHolder{called: &called, secret: hookCanary}}
			holder.inner.creds = authz.PrincipalCredentials{SessionSecret: []byte(sessionCanary), AgentToken: agentCanary}
			var out bytes.Buffer
			logger, err := logging.New(&out, slog.LevelDebug, format)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			// slog.Any of nested holders under unknown AND safe keys, a safe group
			// holding unsafe values, an unknown group, WithAttrs and WithGroup loggers.
			logger.LogAttrs(ctx, slog.LevelInfo, logging.RequestCompleted,
				slog.Any("holder", holder), slog.Any("status", holder), slog.Any("method", holder.hook),
				slog.Any("creds", holder.inner.creds), slog.Any("hook", holder.hook), slog.Any("err", holder.hook),
				slog.Group("http", slog.Any("holder", holder), slog.Any("status", holder.hook)),
				slog.Group("nested", slog.Group("deeper", slog.Any("holder", holder))),
			)
			logger.With(slog.Any("holder", holder), slog.Group("http", slog.Any("holder", holder.hook))).
				LogAttrs(ctx, slog.LevelInfo, logging.RequestCompleted, slog.Int("status", 200))
			logger.WithGroup("secretgroup").With(slog.Any("holder", holder)).
				LogAttrs(ctx, slog.LevelInfo, logging.RequestCompleted, slog.Any("holder", holder.hook))
			logger.WithGroup("http").With(slog.Any("holder", holder)).
				LogAttrs(ctx, slog.LevelInfo, logging.RequestCompleted, slog.Any("holder", holder.hook))
			// Dynamic preformatted message: arbitrary text is replaced, never emitted.
			logger.Info("principal session=" + sessionCanary + " token=" + agentCanary)
			logger.Info(fmt.Sprintf("holder %v %s", holder.inner.creds, hookCanary))

			got := out.String()
			if strings.TrimSpace(got) == "" {
				t.Fatal("logger produced no output; the assertions below would be vacuous")
			}
			for _, canary := range []string{sessionCanary, agentCanary, hookCanary,
				base64.StdEncoding.EncodeToString([]byte(sessionCanary)), hex.EncodeToString([]byte(sessionCanary)),
				fmt.Sprintf("%d", []byte(sessionCanary))} {
				if strings.Contains(got, canary) {
					t.Errorf("%s output exposes a canary %q:\n%s", format, canary[:12], got)
				}
			}
			if called.Load() {
				t.Error("a custom Error/String/GoString/LogValue/MarshalJSON/MarshalText hook ran for a dropped value")
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Error("dropped values must be visibly redacted")
			}
			// Positive control: the admitted static event and the safe typed status survive.
			if !strings.Contains(got, logging.RequestCompleted) || !strings.Contains(got, "200") {
				t.Errorf("admitted static event/typed status lost:\n%s", got)
			}
		})
	}
}
