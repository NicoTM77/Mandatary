package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18.4 P115-L3: the two attribution sites of AcquireLease that no earlier test
// killed deterministically: (1) the refusal at lease REGISTRATION (the decision went
// stale between Authorize and registration) and (2) the FINAL stale check at
// publication. Package-private seams (export_test.go) place a concurrent change exactly
// between the stages: no sleeps, no stress loop. Every refused operation key carries
// the original attribution of the verified principal (so the shared service counts it
// exactly once), registers no lease and makes zero operational backend attempts.
func TestAcquireLeaseStaleBranchesKeepOriginalAttribution(t *testing.T) {
	type trigger struct {
		name string
		// stage is "register" (before registration) or "publish" (before publication).
		stage string
		fire  func(a *authz.Authorizer, e *testEnv, cancel context.CancelFunc)
		// wantLease: an epoch-only move at publication is explicitly NOT a denial.
		wantLease bool
	}
	triggers := []trigger{
		{"register/policy-epoch-moved", "register", func(a *authz.Authorizer, _ *testEnv, _ context.CancelFunc) {
			_ = a.NotifyPolicyChange(context.Background())
		}, false},
		{"register/caller-canceled", "register", func(_ *authz.Authorizer, _ *testEnv, cancel context.CancelFunc) { cancel() }, false},
		{"register/backend-rebound", "register", func(a *authz.Authorizer, e *testEnv, _ context.CancelFunc) {
			_ = a.RegisterBackend(testLocalEndpointID, e.backend)
		}, false},
		{"register/invalidate-all", "register", func(a *authz.Authorizer, _ *testEnv, _ context.CancelFunc) { a.InvalidateAll() }, false},
		{"publish/caller-canceled", "publish", func(_ *authz.Authorizer, _ *testEnv, cancel context.CancelFunc) { cancel() }, false},
		{"publish/backend-rebound", "publish", func(a *authz.Authorizer, e *testEnv, _ context.CancelFunc) {
			_ = a.RegisterBackend(testLocalEndpointID, e.backend)
		}, false},
		{"publish/invalidate-all", "publish", func(a *authz.Authorizer, _ *testEnv, _ context.CancelFunc) { a.InvalidateAll() }, false},
		// Control: the lease is already registered, so a later epoch move revalidates it itself.
		{"publish/policy-epoch-moved-is-not-a-denial", "publish", func(a *authz.Authorizer, _ *testEnv, _ context.CancelFunc) {
			_ = a.NotifyPolicyChange(context.Background())
		}, true},
	}
	for _, tr := range triggers {
		for i, op := range authz.AllOperations() {
			t.Run(tr.name+"/"+string(op), func(t *testing.T) {
				e, req := publicationSetup(t)
				// Allow every operation key for alice on the same selector.
				for j, other := range authz.AllOperations() {
					if other == authz.OpContainerInspectStatus {
						continue
					}
					e.seedPolicy(store.Policy{
						ID: fmt.Sprintf("73000000-0000-4000-8000-%012d", j+1), UserID: sql.NullString{String: string(testUserID1), Valid: true},
						EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(other), Effect: "ALLOW", State: "active", AuthorityGeneration: 1,
					})
				}
				req.Operation = op
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fire := func() { tr.fire(e.authorizer, e, cancel) }
				var fired int
				once := func() { fired++; fire() }
				switch tr.stage {
				case "register":
					e.authorizer.SetAcquireSeamsForTest(once, nil)
				default:
					e.authorizer.SetAcquireSeamsForTest(nil, once)
				}
				lease, err := e.authorizer.AcquireLease(ctx, req)
				if fired != 1 {
					t.Fatalf("seam fired %d times, want exactly 1 (op index %d)", fired, i)
				}
				if tr.wantLease {
					if err != nil || lease == nil {
						t.Fatalf("an epoch-only move at publication must not deny: %v", err)
					}
					lease.Release()
					return
				}
				if lease != nil {
					lease.Release()
					t.Fatal("a stale acquisition must not return a lease")
				}
				if !errors.Is(err, authz.ErrForbidden) || !authz.HasReason(err, authz.ReasonDecisionStale) {
					t.Fatalf("got %v, want a 403 decision_stale refusal", err)
				}
				attr, ok := authz.AttributionOf(err)
				if !ok {
					t.Fatal("the stale refusal of a VERIFIED principal lost its attribution")
				}
				want := authz.Attribution{UserID: testUserID1, EndpointID: testLocalEndpointID, SelectorID: testSelectorID1, Operation: op}
				if attr != want {
					t.Fatalf("attribution %+v, want %+v", attr, want)
				}
				if n := e.authorizer.ActiveLeaseCount(); n != 0 {
					t.Fatalf("%d leases stay registered after a refused acquisition", n)
				}
				if n := e.backend.Counters().TotalOperational(); n != 0 {
					t.Fatalf("%d operational backend attempts", n)
				}
			})
		}
	}
}
