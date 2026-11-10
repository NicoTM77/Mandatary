package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestObservableClockRollbackDenies(t *testing.T) {
	for _, evidence := range []string{"created", "authenticated", "activity", "agent-issued", "nonexpiring-agent-issued", "decision"} {
		t.Run(evidence, func(t *testing.T) {
			e, req := publicationSetup(t)
			ctx := context.Background()
			now := e.clock.Now().Unix()
			switch evidence {
			case "created":
				req.Principal.SessionSecret = e.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1, CreatedAt: now, LastActivityAt: now})
			case "authenticated":
				e.execSQL(`UPDATE sessions SET authenticated_at=? WHERE id=?`, now, string(testSessionID1))
			case "activity":
				e.execSQL(`UPDATE sessions SET last_activity_at=? WHERE id=?`, now, string(testSessionID1))
			case "agent-issued", "nonexpiring-agent-issued":
				e.seedAgent(seedAgentOpts{ID: testAgentID1, Name: "clock-bot"})
				opts := seedAgentCredentialOpts{ID: testCredID1, AgentID: testAgentID1, IssuedAt: now}
				if evidence == "nonexpiring-agent-issued" {
					opts.NonexpiringApproved = 1
				}
				token := e.seedAgentCredential(opts)
				e.seedPolicy(store.Policy{ID: string(testPolicyID2), AgentID: sql.NullString{String: string(testAgentID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(req.Operation), Effect: "ALLOW"})
				req.Principal = authz.PrincipalCredentials{AgentToken: token}
			}
			dec, err := e.authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("healthy exact-time control: %v", err)
			}
			if err := e.authorizer.ValidateDecision(ctx, dec); err != nil {
				t.Fatalf("healthy validation: %v", err)
			}
			e.clock.Advance(-time.Second)
			if evidence != "decision" {
				if _, err := e.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrUnauthenticated) {
					t.Errorf("future %s evidence authorized: %v", evidence, err)
				}
			}
			if err := e.authorizer.ValidateDecision(ctx, dec); !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("rollback revalidation: %v", err)
			}
			e.clock.Advance(time.Second)
			fresh, err := e.authorizer.Authorize(ctx, req)
			if err != nil {
				t.Fatalf("restored exact-time control: %v", err)
			}
			if err := e.authorizer.ValidateDecision(ctx, fresh); err != nil {
				t.Errorf("restored fresh validation: %v", err)
			}
		})
	}
}
