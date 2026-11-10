package authz_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

func replacementBackend(t *testing.T) *docker.MockBackend {
	t.Helper()
	cfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
	b, err := docker.NewMockBackend(docker.MockOptions{EndpointID: testLocalEndpointID, Identity: cfg, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecisionIssuingBindings(t *testing.T) {
	for _, change := range []string{"rebind", "same-backend-rebind", "remove-reregister", "invalidate", "other-authorizer"} {
		t.Run(change, func(t *testing.T) {
			e, req := publicationSetup(t)
			ctx := context.Background()
			dec, err := e.authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			validator := e.authorizer
			switch change {
			case "rebind":
				err = e.authorizer.RegisterBackend(testLocalEndpointID, replacementBackend(t))
			case "same-backend-rebind":
				err = e.authorizer.RegisterBackend(testLocalEndpointID, e.backend)
			case "remove-reregister":
				e.authorizer.RemoveBackend(testLocalEndpointID)
				err = e.authorizer.RegisterBackend(testLocalEndpointID, e.backend)
			case "invalidate":
				e.authorizer.InvalidateAll()
			case "other-authorizer":
				validator, _ = gatedAuthorizer(t, e)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.ValidateDecision(ctx, dec); !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("old decision crossed %s: %v", change, err)
			}
			fresh, err := validator.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("fresh decision: %v", err)
			}
			if err := validator.ValidateDecision(ctx, fresh); err != nil {
				t.Errorf("fresh validation: %v", err)
			}
		})
	}
}

func TestConcurrentDecisionBindingPublication(t *testing.T) {
	for _, change := range []string{"rebind", "invalidate"} {
		for _, mode := range []string{"authorize", "validate", "acquire-registration", "acquire-revalidation", "revalidate"} {
			t.Run(change+"/"+mode, func(t *testing.T) {
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
					case "revalidate":
						done <- lease.Revalidate(ctx)
					default:
						l, err := a.AcquireLease(ctx, req)
						if l != nil {
							l.Release()
						}
						done <- err
					}
				}()
				select {
				case <-v.entered:
				case <-ctx.Done():
					close(v.release)
					_ = <-done // Join the worker before failing the barrier assertion.
					t.Fatal("snapshot barrier not entered")
				}
				if change == "rebind" {
					if err := a.RegisterBackend(testLocalEndpointID, replacementBackend(t)); err != nil {
						t.Error(err)
					}
				} else {
					a.InvalidateAll()
				}
				close(v.release)
				if err := <-done; !errors.Is(err, authz.ErrForbidden) {
					t.Errorf("in-flight result crossed completed %s: %v", change, err)
				}
				if a.ActiveLeaseCount() != 0 {
					t.Error("stale lease remains registered")
				}
				fresh, err := a.Authorize(ctx, req)
				if err != nil {
					t.Fatalf("fresh authorization: %v", err)
				}
				if err := a.ValidateDecision(ctx, fresh); err != nil {
					t.Errorf("fresh validation: %v", err)
				}
			})
		}
	}
}
