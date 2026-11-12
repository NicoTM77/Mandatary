package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

func nullInt(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

// countingBackend counts EVERY DockerBackend call before delegating, so a test can
// prove Authenticate never contacts a backend (P1.14: authenticate before any
// target resolution; closes the unauthenticated name oracle, C1 O1).
type countingBackend struct {
	*docker.MockBackend
	calls atomic.Int64
}

func (c *countingBackend) ResolveTarget(ctx context.Context, ref string) (docker.ContainerSummary, error) {
	c.calls.Add(1)
	return c.MockBackend.ResolveTarget(ctx, ref)
}
func (c *countingBackend) ListContainers(ctx context.Context) ([]docker.ContainerSummary, error) {
	c.calls.Add(1)
	return c.MockBackend.ListContainers(ctx)
}
func (c *countingBackend) InspectStatus(ctx context.Context, t docker.TargetIdentity) (docker.InspectStatus, error) {
	c.calls.Add(1)
	return c.MockBackend.InspectStatus(ctx, t)
}
func (c *countingBackend) InspectConfig(ctx context.Context, t docker.TargetIdentity) (docker.InspectConfig, error) {
	c.calls.Add(1)
	return c.MockBackend.InspectConfig(ctx, t)
}
func (c *countingBackend) Logs(ctx context.Context, t docker.TargetIdentity, o docker.LogOptions) (docker.LogStream, error) {
	c.calls.Add(1)
	return c.MockBackend.Logs(ctx, t, o)
}
func (c *countingBackend) Start(ctx context.Context, t docker.TargetIdentity) error {
	c.calls.Add(1)
	return c.MockBackend.Start(ctx, t)
}
func (c *countingBackend) Stop(ctx context.Context, t docker.TargetIdentity, o docker.StopOptions) error {
	c.calls.Add(1)
	return c.MockBackend.Stop(ctx, t, o)
}
func (c *countingBackend) Restart(ctx context.Context, t docker.TargetIdentity, o docker.RestartOptions) error {
	c.calls.Add(1)
	return c.MockBackend.Restart(ctx, t, o)
}

func TestAuthenticateVerifiesCredentialsWithoutAnyBackendContact(t *testing.T) {
	env := newTestEnv(t)
	cb := &countingBackend{MockBackend: env.backend}
	if err := env.authorizer.RegisterBackend(testLocalEndpointID, cb); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := env.clock.Now().Unix()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "owner"})
	env.seedAgent(seedAgentOpts{ID: testAgentID1, Name: "bot"})
	good := env.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID1, AgentID: testAgentID1, RawToken: "mdt_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"})
	expired := env.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID2, AgentID: testAgentID1, RawToken: "mdt_" + "1123456789abcdefghijklmnopqrstuvwxyzABCDEFG", IssuedAt: now - 7200, ExpiresAt: nullInt(now - 3600)})

	type tc struct {
		name   string
		creds  authz.PrincipalCredentials
		status int
		reason authz.DenialReason
	}
	for _, c := range []tc{
		{"valid token", authz.PrincipalCredentials{AgentToken: good}, http.StatusOK, ""},
		{"expired token", authz.PrincipalCredentials{AgentToken: expired}, http.StatusUnauthorized, authz.ReasonUnauthenticated},
		{"unknown token", authz.PrincipalCredentials{AgentToken: "mdt_" + "2123456789abcdefghijklmnopqrstuvwxyzABCDEFG"}, http.StatusUnauthorized, authz.ReasonUnauthenticated},
		{"anonymous", authz.PrincipalCredentials{}, http.StatusUnauthorized, authz.ReasonUnauthenticated},
		{"token and session together", authz.PrincipalCredentials{AgentToken: good, SessionID: testSessionID1}, http.StatusUnauthorized, authz.ReasonUnauthenticated},
		{"caller-asserted administrator", authz.PrincipalCredentials{AgentToken: expired, UntrustedCallerAdmin: true, UntrustedCallerAssurance: 2}, http.StatusUnauthorized, authz.ReasonUnauthenticated},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := env.authorizer.Authenticate(ctx, c.creds)
			if c.status == http.StatusOK {
				if err != nil {
					t.Fatalf("Authenticate = %v, want nil", err)
				}
				return
			}
			if err == nil || authz.StatusCode(err) != c.status || !authz.HasReason(err, c.reason) {
				t.Fatalf("Authenticate = %v (status %d), want %d %s", err, authz.StatusCode(err), c.status, c.reason)
			}
		})
	}

	// Revocation and clock expiry are observed on the next call.
	env.execSQL(`UPDATE agent_credentials SET state='revoked', revoked_at=? WHERE id=?`, now, string(testCredID1))
	if err := env.authorizer.Authenticate(ctx, authz.PrincipalCredentials{AgentToken: good}); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("revoked token: %v", err)
	}

	// Restore quarantine is reported as 403 restore_quarantined, exactly like Authorize.
	env.execSQL(`UPDATE installation_control SET restore_quarantined=1 WHERE singleton=1`)
	for _, creds := range []authz.PrincipalCredentials{{AgentToken: good}, {AgentToken: expired}, {}} {
		err := env.authorizer.Authenticate(ctx, creds)
		if authz.StatusCode(err) != http.StatusForbidden || !authz.HasReason(err, authz.ReasonRestoreQuarantined) {
			t.Fatalf("quarantined: %v", err)
		}
	}
	env.execSQL(`UPDATE installation_control SET restore_quarantined=0 WHERE singleton=1`)

	// A canceled context fails closed.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := env.authorizer.Authenticate(canceled, authz.PrincipalCredentials{AgentToken: expired}); err == nil {
		t.Fatal("canceled context accepted")
	}

	if n := cb.calls.Load(); n != 0 {
		t.Fatalf("Authenticate contacted the backend %d times", n)
	}

	// The clock matters: a credential valid now is rejected once the clock passes expiry.
	short := env.seedAgentCredential(seedAgentCredentialOpts{ID: "50000000-0000-4000-8000-000000000003", AgentID: testAgentID1, RawToken: "mdt_" + "3123456789abcdefghijklmnopqrstuvwxyzABCDEFG", ExpiresAt: nullInt(now + 60)})
	if err := env.authorizer.Authenticate(ctx, authz.PrincipalCredentials{AgentToken: short}); err != nil {
		t.Fatalf("short-lived token: %v", err)
	}
	env.clock.Advance(61 * time.Second)
	if err := env.authorizer.Authenticate(ctx, authz.PrincipalCredentials{AgentToken: short}); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("expired by clock: %v", err)
	}
}
