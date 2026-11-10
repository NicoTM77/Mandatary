package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestDeterministicClockExpiryBoundaries(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	start := env.clock.Now().Unix()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	// Session expires at start+600, idle timeout 300s (last activity at start)
	secret := env.seedSession(seedSessionOpts{
		ID:                 testSessionID1,
		UserID:             testUserID1,
		CreatedAt:          start,
		ExpiresAt:          start + 600,
		LastActivityAt:     start,
		IdleTimeoutSeconds: 300,
	})

	env.seedAgent(seedAgentOpts{ID: testAgentID1, Name: "bot"})
	// Agent token expires at start+500, rotation overlap until start+200
	tok := env.seedAgentCredential(seedAgentCredentialOpts{
		ID:                   testCredID1,
		AgentID:              testAgentID1,
		IssuedAt:             start,
		ExpiresAt:            sql.NullInt64{Int64: start + 500, Valid: true},
		RotationOverlapUntil: sql.NullInt64{Int64: start + 200, Valid: true},
	})

	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID1),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerInspectStatus),
		Effect:     "ALLOW",
	})
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID2),
		AgentID:    sql.NullString{String: string(testAgentID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerInspectStatus),
		Effect:     "ALLOW",
	})

	userReq := authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}
	agentReq := authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{AgentToken: tok},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}

	// At t = start + 199s: both user session and agent token (overlap window) are valid.
	env.clock.Advance(199 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, userReq); err != nil {
		t.Fatalf("t+199s user Authorize: %v", err)
	}
	if _, err := env.authorizer.Authorize(ctx, agentReq); err != nil {
		t.Fatalf("t+199s agent Authorize: %v", err)
	}

	// At t = start + 200s: agent rotation_overlap_until boundary reached -> 401!
	env.clock.Advance(1 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, agentReq); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("t+200s agent overlap boundary: expected 401, got %v", err)
	}

	// Clear rotation_overlap_until to test main ExpiresAt boundary at start+500.
	env.execSQL(`UPDATE agent_credentials SET rotation_overlap_until = NULL WHERE id = ?`, string(testCredID1))
	if _, err := env.authorizer.Authorize(ctx, agentReq); err != nil {
		t.Fatalf("t+200s agent without overlap: %v", err)
	}

	// At t = start + 299s: user idle timeout is 299 < 300 -> allowed.
	env.clock.Advance(99 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, userReq); err != nil {
		t.Fatalf("t+299s user Authorize: %v", err)
	}

	// At t = start + 300s: user idle timeout boundary (300 == 300) -> 401!
	env.clock.Advance(1 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, userReq); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("t+300s user idle boundary: expected 401, got %v", err)
	}

	// Update LastActivityAt to start+400 so we can test absolute session ExpiresAt at start+600.
	env.execSQL(`UPDATE sessions SET last_activity_at = ? WHERE id = ?`, start+400, string(testSessionID1))

	// At t = start + 499s: agent ExpiresAt-1s -> allowed; at t = start + 500s -> 401!
	env.clock.Advance(199 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, agentReq); err != nil {
		t.Fatalf("t+499s agent Authorize: %v", err)
	}
	env.clock.Advance(1 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, agentReq); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("t+500s agent ExpiresAt boundary: expected 401, got %v", err)
	}

	// At t = start + 599s: user ExpiresAt-1s -> allowed; at t = start + 600s -> 401!
	env.clock.Advance(99 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, userReq); err != nil {
		t.Fatalf("t+599s user Authorize: %v", err)
	}
	env.clock.Advance(1 * time.Second)
	if _, err := env.authorizer.Authorize(ctx, userReq); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("t+600s user ExpiresAt boundary: expected 401, got %v", err)
	}
}

func TestPolicyChangeInvalidatesActiveAuthorizations(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})
	creds := authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret}

	env.seedGroup(testGroupID1, "devs", "active", 1)
	env.seedUserGroupMembership(testUserID1, testGroupID1, "active", 1)

	// Selector 1: edge-proxy; Selector 2: billing-worker
	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})
	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID2),
		EndpointID:    testLocalEndpointID,
		ContainerName: "billing-worker",
		NameIsGlob:    0,
	})

	// Policy 1: group ALLOW on edge-proxy logs (log_tail_max = 500)
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID1),
		GroupID:    sql.NullString{String: string(testGroupID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerLogs),
		Effect:     "ALLOW",
		LogTailMax: sql.NullInt64{Int64: 500, Valid: true},
	})
	// Policy 2: direct ALLOW on billing-worker logs
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID2),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID2),
		Operation:  string(authz.OpContainerLogs),
		Effect:     "ALLOW",
	})

	edgeReq := authz.AuthorizeRequest{
		Principal:  creds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerLogs,
		LogOptions: &docker.LogOptions{Tail: 300, Stdout: true, Follow: true},
	}
	billingReq := authz.AuthorizeRequest{
		Principal:  creds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "billing-worker",
		Operation:  authz.OpContainerLogs,
		LogOptions: &docker.LogOptions{Tail: 100, Stdout: true, Follow: true},
	}

	leaseEdge, err := env.authorizer.AcquireLease(ctx, edgeReq)
	if err != nil {
		t.Fatalf("AcquireLease edge-proxy: %v", err)
	}
	defer leaseEdge.Release()

	leaseBilling, err := env.authorizer.AcquireLease(ctx, billingReq)
	if err != nil {
		t.Fatalf("AcquireLease billing-worker: %v", err)
	}
	defer leaseBilling.Release()

	if env.authorizer.ActiveLeaseCount() != 2 {
		t.Fatalf("ActiveLeaseCount = %d, want 2", env.authorizer.ActiveLeaseCount())
	}

	// 1. Tighten Policy 1 log_tail_max from 500 to 100 (< 300 used by leaseEdge) -> invalidates leaseEdge ONLY!
	env.execSQL(`UPDATE policies SET log_tail_max = 100 WHERE id = ?`, string(testPolicyID1))
	if err := env.authorizer.NotifyPolicyChange(ctx); err != nil {
		t.Fatalf("NotifyPolicyChange: %v", err)
	}
	if leaseEdge.Context().Err() == nil {
		t.Fatalf("expected leaseEdge context to be canceled after tightening log_tail_max")
	}
	if err := env.authorizer.ValidateDecision(ctx, leaseEdge.Decision); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected ValidateDecision on stale leaseEdge to fail with 403, got %v", err)
	}
	if leaseBilling.Context().Err() != nil {
		t.Fatalf("unrelated leaseBilling should remain active, got %v", leaseBilling.Context().Err())
	}

	// Restore log_tail_max = 500 and re-acquire leaseEdge
	env.execSQL(`UPDATE policies SET log_tail_max = 500 WHERE id = ?`, string(testPolicyID1))
	leaseEdge2, err := env.authorizer.AcquireLease(ctx, edgeReq)
	if err != nil {
		t.Fatalf("AcquireLease edge-proxy 2: %v", err)
	}
	defer leaseEdge2.Release()

	// 2. Add an explicit DENY rule on edge-proxy -> cancels leaseEdge2!
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID3),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerLogs),
		Effect:     "DENY",
	})
	if err := env.authorizer.NotifyPolicyChange(ctx); err != nil {
		t.Fatalf("NotifyPolicyChange after DENY: %v", err)
	}
	if leaseEdge2.Context().Err() == nil {
		t.Fatalf("expected leaseEdge2 to be canceled after adding explicit DENY")
	}

	// Remove DENY rule, re-acquire leaseEdge3, then revoke group membership -> cancels leaseEdge3!
	env.execSQL(`DELETE FROM policies WHERE id = ?`, string(testPolicyID3))
	leaseEdge3, err := env.authorizer.AcquireLease(ctx, edgeReq)
	if err != nil {
		t.Fatalf("AcquireLease edge-proxy 3: %v", err)
	}
	defer leaseEdge3.Release()

	env.execSQL(`UPDATE user_group_memberships SET state = 'disabled' WHERE user_id = ? AND group_id = ?`, string(testUserID1), string(testGroupID1))
	if err := env.authorizer.NotifyPolicyChange(ctx); err != nil {
		t.Fatalf("NotifyPolicyChange after group disable: %v", err)
	}
	if leaseEdge3.Context().Err() == nil {
		t.Fatalf("expected leaseEdge3 to be canceled after group membership disable")
	}
	if leaseBilling.Context().Err() != nil {
		t.Fatalf("direct-authorized leaseBilling should still be active, got %v", leaseBilling.Context().Err())
	}

	// 3. Enter restore quarantine -> cancels remaining leaseBilling and rejects ValidateDecision!
	env.execSQL(`UPDATE installation_control SET restore_quarantined = 1 WHERE singleton = 1`)
	if err := env.authorizer.NotifyPolicyChange(ctx); err != nil {
		t.Fatalf("NotifyPolicyChange after restore quarantine: %v", err)
	}
	if leaseBilling.Context().Err() == nil {
		t.Fatalf("expected leaseBilling to be canceled upon restore_quarantined=1")
	}
	if err := env.authorizer.ValidateDecision(ctx, leaseBilling.Decision); err == nil {
		t.Fatalf("expected ValidateDecision to fail during restore quarantine")
	}
}

func TestConcurrentAuthorizeAndPolicyInvalidationRace(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})
	creds := authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret}

	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID1),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerInspectStatus),
		Effect:     "ALLOW",
	})

	req := authz.AuthorizeRequest{
		Principal:  creds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				if id%2 == 0 {
					dec, err := env.authorizer.Authorize(ctx, req)
					if err == nil {
						_ = env.authorizer.ValidateDecision(ctx, dec)
					}
				} else {
					lease, err := env.authorizer.AcquireLease(ctx, req)
					if err == nil {
						_ = lease.Revalidate(ctx)
						lease.Release()
					}
					_ = env.authorizer.NotifyPolicyChange(ctx)
				}
			}
		}(worker)
	}
	wg.Wait()
}
