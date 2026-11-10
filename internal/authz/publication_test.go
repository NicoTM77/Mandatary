package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func publicationSetup(t *testing.T) (*testEnv, authz.AuthorizeRequest) {
	t.Helper()
	e := newTestEnv(t)
	e.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := e.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})
	e.seedSelector(store.ContainerSelector{ID: string(testSelectorID1), EndpointID: testLocalEndpointID, ContainerName: "edge-proxy"})
	e.seedPolicy(store.Policy{ID: string(testPolicyID1), UserID: sql.NullString{String: string(testUserID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerInspectStatus), Effect: "ALLOW"})
	return e, authz.AuthorizeRequest{Principal: authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret}, EndpointID: testLocalEndpointID, TargetRef: "edge-proxy", Operation: authz.OpContainerInspectStatus}
}

// Pause after the real verifier has established a SQLite read snapshot, not
// before I/O. Only the selected call blocks; notification can revalidate peers.
type publicationVerifier struct {
	entered, release chan struct{}
	calls, gateAt    atomic.Int64
}

func (v *publicationVerifier) VerifyPrincipal(ctx context.Context, q *store.Queries, c store.InstallationControl, p authz.PrincipalCredentials, now time.Time) (authz.VerifiedPrincipal, error) {
	result, err := authz.NewStoreCredentialVerifier().VerifyPrincipal(ctx, q, c, p, now)
	if v.calls.Add(1) == v.gateAt.Load() {
		close(v.entered)
		select {
		case <-v.release:
		case <-ctx.Done():
			return authz.VerifiedPrincipal{}, ctx.Err()
		}
	}
	return result, err
}
func gatedAuthorizer(t *testing.T, e *testEnv) (*authz.Authorizer, *publicationVerifier) {
	t.Helper()
	v := &publicationVerifier{entered: make(chan struct{}), release: make(chan struct{})}
	a, err := authz.NewAuthorizer(authz.Config{Repository: e.repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{testLocalEndpointID: e.backend}, CredentialVerifier: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, v
}

func TestPolicyRevocationPublicationFence(t *testing.T) {
	for _, mode := range []string{"authorize", "validate", "acquire", "acquire-revalidation", "revalidate"} {
		t.Run(mode, func(t *testing.T) {
			e, req := publicationSetup(t)
			a, v := gatedAuthorizer(t, e)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dec, err := a.Authorize(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			var lease *authz.Lease
			if mode == "revalidate" {
				lease, err = a.AcquireLease(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
			}
			gate := v.calls.Load() + 1
			if mode == "acquire-revalidation" {
				gate++
			}
			v.gateAt.Store(gate)
			done := make(chan error, 1)
			go func() {
				switch mode {
				case "authorize":
					_, err := a.Authorize(ctx, req)
					done <- err
				case "validate":
					done <- a.ValidateDecision(ctx, dec)
				case "acquire", "acquire-revalidation":
					l, err := a.AcquireLease(ctx, req)
					if l != nil {
						l.Release()
					}
					done <- err
				case "revalidate":
					done <- lease.Revalidate(ctx)
				}
			}()
			select {
			case <-v.entered:
			case <-ctx.Done():
				close(v.release)
				workerErr := <-done // Join before failing the barrier assertion.
				t.Fatalf("snapshot barrier not entered (worker result: %v)", workerErr)
			}
			e.execSQL(`DELETE FROM policies WHERE id=?`, string(testPolicyID1))
			if err := a.NotifyPolicyChange(ctx); err != nil {
				t.Error(err)
			}
			close(v.release)
			err = <-done
			before := e.backend.Counters().TotalOperational()
			// Exercise the same validation-before-dispatch contract as later execution.
			if mode == "validate" && err == nil {
				_ = dispatchDecision(ctx, e.backend, dec)
			}
			if !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("stale snapshot published after completed policy revocation: %v", err)
			}
			if delta := e.backend.Counters().TotalOperational() - before; delta != 0 {
				t.Errorf("post-revocation dispatch: %d operations", delta)
			}
			if a.ActiveLeaseCount() != 0 {
				t.Error("revoked lease remains registered")
			}
			if _, err := a.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("fresh revoked control: %v", err)
			}
		})
	}
}
