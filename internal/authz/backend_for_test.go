package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
)

// BackendFor lets the P1.13 execution service dispatch on exactly the backend
// instance that authorized a decision. It must refuse every decision whose issuing
// binding, backend instance or backend safety no longer holds.
func TestBackendForReturnsOnlyTheBackendBoundToAFreshDecision(t *testing.T) {
	e, req := publicationSetup(t)
	ctx := context.Background()
	dec, err := e.authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.authorizer.BackendFor(dec)
	if err != nil || got != e.backend {
		t.Fatalf("BackendFor = %v, %v; want the issuing backend", got, err)
	}

	// The zero Decision (never issued) is refused.
	if b, err := e.authorizer.BackendFor(authz.Decision{}); b != nil || !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("zero decision accepted: %v, %v", b, err)
	}

	// A decision from another Authorizer is refused even over the same endpoint.
	other, _ := gatedAuthorizer(t, e)
	if b, err := other.BackendFor(dec); b != nil || !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("foreign authorizer returned a backend: %v, %v", b, err)
	}
}

func TestBackendForRefusesAfterRebindInvalidationRemovalOrSafetyLoss(t *testing.T) {
	for _, change := range []string{"rebind", "same-backend-rebind", "remove", "invalidate", "safety-loss"} {
		t.Run(change, func(t *testing.T) {
			e, req := publicationSetup(t)
			ctx := context.Background()
			dec, err := e.authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "rebind":
				err = e.authorizer.RegisterBackend(testLocalEndpointID, replacementBackend(t))
			case "same-backend-rebind":
				err = e.authorizer.RegisterBackend(testLocalEndpointID, e.backend)
			case "remove":
				e.authorizer.RemoveBackend(testLocalEndpointID)
			case "invalidate":
				e.authorizer.InvalidateAll()
			case "safety-loss":
				e.backend.SimulateEventDiscontinuity()
			}
			if err != nil {
				t.Fatal(err)
			}
			b, err := e.authorizer.BackendFor(dec)
			if b != nil || !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("%s: BackendFor = %v, %v; want nil + forbidden", change, b, err)
			}
			wantReason := authz.ReasonDecisionStale
			if change == "safety-loss" {
				wantReason = authz.ReasonSafetyUnverified
			}
			if !authz.HasReason(err, wantReason) {
				t.Fatalf("%s: reason %v, want %v", change, err, wantReason)
			}
		})
	}
}
