package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
)

func TestSharedPolicyLeaseFailureIsolation(t *testing.T) {
	for _, failure := range []string{"canceled-context", "revoked-session", "backend-safety", "shared-deny"} {
		t.Run(failure, func(t *testing.T) {
			e, req := publicationSetup(t)
			ctx := context.Background()
			e.seedUser(seedUserOpts{ID: testUserID2, Username: "bob"})
			secret2 := e.seedSession(seedSessionOpts{ID: testSessionID2, UserID: testUserID2})
			e.seedGroup(testGroupID1, "shared", "active", 1)
			e.seedUserGroupMembership(testUserID1, testGroupID1, "active", 1)
			e.seedUserGroupMembership(testUserID2, testGroupID1, "active", 1)
			e.execSQL(`UPDATE policies SET user_id=NULL,group_id=? WHERE id=?`, string(testGroupID1), string(testPolicyID1))
			alice, err := e.authorizer.AcquireLease(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			defer alice.Release()
			req.Principal = authz.PrincipalCredentials{SessionID: testSessionID2, SessionSecret: secret2}
			bob, err := e.authorizer.AcquireLease(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			defer bob.Release()
			checkCtx := ctx
			switch failure {
			case "canceled-context":
				var cancel context.CancelFunc
				checkCtx, cancel = context.WithCancel(ctx)
				cancel()
			case "revoked-session":
				e.execSQL(`UPDATE sessions SET state='revoked',revoked_at=? WHERE id=?`, e.clock.Now().Unix(), string(testSessionID1))
			case "backend-safety":
				e.backend.SimulateEventDiscontinuity()
			case "shared-deny":
				e.execSQL(`UPDATE policies SET effect='DENY' WHERE id=?`, string(testPolicyID1))
				if err := e.authorizer.NotifyPolicyChange(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := alice.Revalidate(checkCtx); !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("alice must deny: %v", err)
			}
			if alice.Context().Err() == nil {
				t.Error("affected lease not canceled")
			}
			if failure == "backend-safety" || failure == "shared-deny" {
				if bob.Context().Err() == nil {
					t.Error("shared failure must cancel peer")
				}
				if _, err := e.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
					t.Errorf("shared failure fresh control: %v", err)
				}
			} else {
				if bob.Context().Err() != nil {
					t.Error("alice's local failure canceled bob's healthy lease")
				}
				if err := bob.Revalidate(ctx); err != nil {
					t.Errorf("bob healthy revalidation: %v", err)
				}
				if _, err := e.authorizer.Authorize(ctx, req); err != nil {
					t.Errorf("bob healthy authorization: %v", err)
				}
			}
		})
	}
}
