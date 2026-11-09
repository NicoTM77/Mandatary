package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// TestSelfProtectionContracts_SELF01_to_SELF13 verifies every row SELF-01 through SELF-13
// from security-contracts.md §S1.3 at the P1.11 service/authorizer level.
func TestSelfProtectionContracts_SELF01_to_SELF13(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Seed super_admin user with wildcard ALLOW policy across all 6 operations on local endpoint.
	env.seedUser(seedUserOpts{ID: testAdminID, Username: "admin_all"})
	secret := env.seedSession(seedSessionOpts{
		ID:                testAdminSess,
		UserID:            testAdminID,
		AchievedAssurance: 2,
		Methods:           8,
		PhishingResistant: 1,
	})
	env.execSQL(
		`INSERT INTO administrative_roles (id, user_id, role, endpoint_id, state, authority_generation)
		 VALUES ('80000000-0000-4000-8000-000000000099', ?, 'super_admin', NULL, 'active', 1)`,
		string(testAdminID),
	)
	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "*",
		NameIsGlob:    1,
	})
	for i, op := range authz.AllOperations() {
		env.seedPolicy(store.Policy{
			ID:         "75000000-0000-4000-8000-00000000000" + string(rune('1'+i)),
			UserID:     sql.NullString{String: string(testAdminID), Valid: true},
			EndpointID: testLocalEndpointID,
			SelectorID: string(testSelectorID1),
			Operation:  string(op),
			Effect:     "ALLOW",
		})
	}
	adminCreds := authz.PrincipalCredentials{SessionID: testAdminSess, SessionSecret: secret}

	assertDeniedZeroOps := func(t *testing.T, backend *docker.MockBackend, targetRef string, op docker.Operation) {
		t.Helper()
		before := backend.Counters().TotalOperational()
		_, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  targetRef,
			Operation:  op,
		})
		if !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("target %q op %s: expected 403 ErrForbidden, got %v", targetRef, op, err)
		}
		if delta := backend.Counters().TotalOperational() - before; delta != 0 {
			t.Fatalf("target %q op %s: expected 0 operational backend calls, got %d", targetRef, op, delta)
		}
	}

	t.Run("SELF-01_no_runtime_evidence_and_no_deployment_binding", func(t *testing.T) {
		_, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, err := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity: docker.SelfIdentityConfig{
				EndpointID:     testLocalEndpointID,
				EvidenceReader: func(context.Context) (docker.ProcessEvidence, error) { return docker.ProcessEvidence{}, nil },
			},
			Containers: containers,
		})
		if err != nil {
			t.Fatalf("NewMockBackend: %v", err)
		}
		if err := b.VerifySelf(ctx); !errors.Is(err, docker.ErrUnverified) {
			t.Fatalf("expected VerifySelf to fail with ErrUnverified, got %v", err)
		}
		if b.Ready() {
			t.Fatalf("expected Ready() == false")
		}
		if err := env.authorizer.RegisterBackend(testLocalEndpointID, b); err != nil {
			t.Fatalf("RegisterBackend: %v", err)
		}
		for _, op := range authz.AllOperations() {
			assertDeniedZeroOps(t, b, "edge-proxy", op)
		}
	})

	t.Run("SELF-02_partial_nonexistent_or_conflicting_explicit_id", func(t *testing.T) {
		_, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, err := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity: docker.SelfIdentityConfig{
				EndpointID:          testLocalEndpointID,
				ExplicitContainerID: string(testEdgeProxyID), // Conflicts with processID MockSelfContainerID
				EvidenceReader: func(context.Context) (docker.ProcessEvidence, error) {
					return docker.ProcessEvidence{ContainerID: string(docker.MockSelfContainerID)}, nil
				},
			},
			Containers: containers,
		})
		if err != nil {
			t.Fatalf("NewMockBackend: %v", err)
		}
		if err := b.VerifySelf(ctx); !errors.Is(err, docker.ErrUnverified) {
			t.Fatalf("expected conflicting explicit ID to fail VerifySelf, got %v", err)
		}
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)
		assertDeniedZeroOps(t, b, "edge-proxy", authz.OpContainerInspectStatus)
		assertDeniedZeroOps(t, b, "nonexistent-container", authz.OpContainerInspectStatus)
	})

	t.Run("SELF-03_unique_label_without_proof_denies_and_multiple_peers_with_one_proven_id_allows_ordinary", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		// Label only, no process/UUID proof -> denies
		bUnproven, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity: docker.SelfIdentityConfig{
				EndpointID:     testLocalEndpointID,
				EvidenceReader: func(context.Context) (docker.ProcessEvidence, error) { return docker.ProcessEvidence{}, nil },
			},
			Containers: containers,
		})
		_ = bUnproven.VerifySelf(ctx)
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, bUnproven)
		assertDeniedZeroOps(t, bUnproven, "edge-proxy", authz.OpContainerInspectStatus)

		// Positive control: several labelled peers + one proven own ID -> ordinary allowed, peers denied
		bProven, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		if err := bProven.VerifySelf(ctx); err != nil {
			t.Fatalf("VerifySelf proven: %v", err)
		}
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, bProven)
		if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		}); err != nil {
			t.Fatalf("expected positive control on edge-proxy to succeed, got %v", err)
		}
	})

	t.Run("SELF-04_wildcard_and_explicit_allow_and_admin_targeting_self_denied", func(t *testing.T) {
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, env.backend)
		// Also add an explicit selector for "mandatary-self" pinned to MockSelfContainerID
		env.seedSelector(store.ContainerSelector{
			ID:                string(testSelectorID2),
			EndpointID:        testLocalEndpointID,
			ContainerName:     "mandatary-self",
			NameIsGlob:        0,
			PinnedContainerID: sql.NullString{String: string(docker.MockSelfContainerID), Valid: true},
		})
		env.seedPolicy(store.Policy{
			ID:         "76000000-0000-4000-8000-000000000001",
			UserID:     sql.NullString{String: string(testAdminID), Valid: true},
			EndpointID: testLocalEndpointID,
			SelectorID: string(testSelectorID2),
			Operation:  string(authz.OpContainerInspectStatus),
			Effect:     "ALLOW",
		})
		for _, op := range authz.AllOperations() {
			assertDeniedZeroOps(t, env.backend, "mandatary-self", op)
			assertDeniedZeroOps(t, env.backend, string(docker.MockSelfContainerID), op)
		}
	})

	t.Run("SELF-05_recreate_self_invalidates_proof_until_fresh_verify", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		_ = b.VerifySelf(ctx)
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)

		// Recreate self container with new StartedAt timestamp -> invalidates continuity proof!
		_ = b.UpsertContainer(docker.MockContainerFixture{
			ID:        docker.MockSelfContainerID,
			Name:      "mandatary-self",
			Image:     "ghcr.io/nicotm77/mandatary:dev",
			State:     "running",
			Created:   "2026-11-09T12:00:00Z",
			StartedAt: "2026-11-09T12:00:05Z",
			Labels: map[string]string{
				docker.SelfLabelKey:             docker.SelfLabelValue,
				docker.SelfInstanceUUIDLabelKey: docker.MockSelfUUID,
			},
		})
		assertDeniedZeroOps(t, b, "edge-proxy", authz.OpContainerInspectStatus)
		if b.Ready() {
			t.Fatalf("expected backend Ready() == false after self recreation continuity change")
		}
		// Re-verifying restores ordinary target access while keeping self protected.
		if err := b.VerifySelf(ctx); err != nil {
			t.Fatalf("re-VerifySelf: %v", err)
		}
		if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		}); err != nil {
			t.Fatalf("expected edge-proxy allowed after fresh VerifySelf, got %v", err)
		}
	})

	t.Run("SELF-06_name_reassigned_to_new_self_labelled_replacement_denied", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		_ = b.VerifySelf(ctx)
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)

		// Authorize edge-proxy first
		dec, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}

		// Replace "edge-proxy" with a newly created self-labelled peer missing from earlier inventory
		b.RemoveContainer(testEdgeProxyID)
		newPeerID := docker.ContainerID("3333333333333333333333333333333333333333333333333333333333333333")
		_ = b.UpsertContainer(docker.MockContainerFixture{
			ID:    newPeerID,
			Name:  "edge-proxy",
			Image: "nginx:1.27-alpine",
			State: "running",
			Labels: map[string]string{
				docker.SelfLabelKey: docker.SelfLabelValue,
			},
		})
		// ValidateDecision on prior decision fails closed, and new Authorize on "edge-proxy" fails with ReasonSelfProtected!
		if err := env.authorizer.ValidateDecision(ctx, dec); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("expected ValidateDecision to fail when original container removed, got %v", err)
		}
		assertDeniedZeroOps(t, b, "edge-proxy", authz.OpContainerInspectStatus)
	})

	t.Run("SELF-07_lose_verification_after_allow_before_dispatch_and_cancel_active_stream", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		_ = b.VerifySelf(ctx)
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)

		lease, err := env.authorizer.AcquireLease(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerLogs,
			LogOptions: &docker.LogOptions{Tail: 50, Stdout: true, Follow: true},
		})
		if err != nil {
			t.Fatalf("AcquireLease: %v", err)
		}
		defer lease.Release()

		// Lose verification before dispatch / during active follow lease
		b.SimulateEventDiscontinuity()
		if err := env.authorizer.ValidateDecision(ctx, lease.Decision); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("expected ValidateDecision to fail after SimulateEventDiscontinuity, got %v", err)
		}
		if err := lease.Revalidate(ctx); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("expected lease.Revalidate to fail after continuity loss, got %v", err)
		}
		if lease.Context().Err() == nil {
			t.Fatalf("expected lease context to be canceled upon safety continuity loss")
		}
		assertDeniedZeroOps(t, b, "edge-proxy", authz.OpContainerInspectStatus)
	})

	t.Run("SELF-08_multi_instance_peers_all_protected_regardless_of_names", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		opsPeerID := docker.ContainerID("4444444444444444444444444444444444444444444444444444444444444444")
		extraPeerID := docker.ContainerID("5555555555555555555555555555555555555555555555555555555555555555")
		containers = append(containers,
			docker.MockContainerFixture{
				ID:     opsPeerID,
				Name:   "mandatary-ops-only",
				Image:  "ghcr.io/nicotm77/mandatary:dev",
				State:  "running",
				Labels: map[string]string{docker.SelfLabelKey: docker.SelfLabelValue},
			},
			docker.MockContainerFixture{
				ID:     extraPeerID,
				Name:   "innocuous-app-name",
				Image:  "nginx:1.27-alpine",
				State:  "running",
				Labels: map[string]string{"io.mandatary.role": "helper"},
			},
		)
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		_ = b.VerifySelf(ctx)
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)

		assertDeniedZeroOps(t, b, "mandatary-ops-only", authz.OpContainerInspectStatus)
		assertDeniedZeroOps(t, b, string(opsPeerID), authz.OpContainerLogs)
		assertDeniedZeroOps(t, b, "innocuous-app-name", authz.OpContainerRestart)
	})

	t.Run("SELF-09_unverified_startup_after_restore_cannot_use_cached_proof", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		// Do NOT call b.VerifySelf(ctx) -> simulates fresh/restored startup before runtime verification.
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)
		assertDeniedZeroOps(t, b, "edge-proxy", authz.OpContainerInspectStatus)
	})

	t.Run("SELF-10_shared_authorizer_blocks_all_operations_on_protected_targets", func(t *testing.T) {
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, env.backend)
		for _, op := range authz.AllOperations() {
			assertDeniedZeroOps(t, env.backend, "mandatary-self", op)
			assertDeniedZeroOps(t, env.backend, "mandatary-peer-stopped", op)
		}
	})

	t.Run("SELF-11_private_cgroup_namespace_with_instance_uuid_binding_and_overlap_rejection", func(t *testing.T) {
		_, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity: docker.SelfIdentityConfig{
				EndpointID:   testLocalEndpointID,
				InstanceUUID: docker.MockSelfUUID,
				EvidenceReader: func(context.Context) (docker.ProcessEvidence, error) {
					return docker.ProcessEvidence{PrivateCgroupNS: true}, nil
				},
			},
			Containers: containers,
		})
		if err := b.VerifySelf(ctx); err != nil {
			t.Fatalf("VerifySelf private cgroup + UUID: %v", err)
		}
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)
		// Ordinary target allowed, own target denied
		if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		}); err != nil {
			t.Fatalf("expected edge-proxy allowed under private cgroup UUID proof, got %v", err)
		}
		assertDeniedZeroOps(t, b, "mandatary-self", authz.OpContainerInspectStatus)

		// Duplicate instance UUID during recreation overlap -> invalidates proof and denies all!
		_ = b.UpsertContainer(docker.MockContainerFixture{
			ID:    "6666666666666666666666666666666666666666666666666666666666666666",
			Name:  "mandatary-recreating-overlap",
			Image: "ghcr.io/nicotm77/mandatary:dev",
			State: "created",
			Labels: map[string]string{
				docker.SelfLabelKey:             docker.SelfLabelValue,
				docker.SelfInstanceUUIDLabelKey: docker.MockSelfUUID,
			},
		})
		assertDeniedZeroOps(t, b, "edge-proxy", authz.OpContainerInspectStatus)
	})

	t.Run("SELF-12_all_state_protected_peers_denied_across_all_operations", func(t *testing.T) {
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		states := []string{"created", "running", "paused", "restarting", "exited", "removing", "dead"}
		for i, st := range states {
			cid := docker.ContainerID(string(rune('1'+i)) + "777777777777777777777777777777777777777777777777777777777777777")
			containers = append(containers, docker.MockContainerFixture{
				ID:     cid,
				Name:   "peer-" + st,
				Image:  "ghcr.io/nicotm77/mandatary:dev",
				State:  st,
				Labels: map[string]string{docker.SelfLabelKey: docker.SelfLabelValue},
			})
		}
		b, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		if err := b.VerifySelf(ctx); err != nil {
			t.Fatalf("VerifySelf all states: %v", err)
		}
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, b)

		for _, st := range states {
			for _, op := range authz.AllOperations() {
				if op == authz.OpContainerLogs {
					assertDeniedZeroOps(t, b, "peer-"+st, op)
				} else {
					assertDeniedZeroOps(t, b, "peer-"+st, op)
				}
			}
		}
	})

	t.Run("SELF-13_endpoint_rebind_clears_cached_verification_and_native_mock_makes_zero_real_calls", func(t *testing.T) {
		_ = env.authorizer.RegisterBackend(testLocalEndpointID, env.backend)
		lease, err := env.authorizer.AcquireLease(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		})
		if err != nil {
			t.Fatalf("AcquireLease: %v", err)
		}
		defer lease.Release()

		// Rebinding the endpoint to a new unverified backend cancels active leases and requires fresh verification!
		idCfg, containers := docker.DefaultMockFixtures(testLocalEndpointID)
		reboundBackend, _ := docker.NewMockBackend(docker.MockOptions{
			EndpointID: testLocalEndpointID,
			Identity:   idCfg,
			Containers: containers,
		})
		if err := env.authorizer.RegisterBackend(testLocalEndpointID, reboundBackend); err != nil {
			t.Fatalf("RegisterBackend rebind: %v", err)
		}
		if lease.Context().Err() == nil {
			t.Fatalf("expected active lease to be canceled when endpoint backend is rebound")
		}
		assertDeniedZeroOps(t, reboundBackend, "edge-proxy", authz.OpContainerInspectStatus)

		// After explicit VerifySelf on the rebound backend, access works again.
		if err := reboundBackend.VerifySelf(ctx); err != nil {
			t.Fatalf("rebound VerifySelf: %v", err)
		}
		dec, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  adminCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		})
		if err != nil {
			t.Fatalf("Authorize after rebind VerifySelf: %v", err)
		}
		if dec.DecidedAt.Equal(time.Time{}) {
			t.Fatalf("expected non-zero DecidedAt")
		}
	})
}
