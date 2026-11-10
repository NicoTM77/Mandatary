package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestSelectorEvaluationMatrix(t *testing.T) {
	baseTarget := docker.ContainerSummary{
		EndpointID:     testLocalEndpointID,
		ContainerID:    testEdgeProxyID,
		Name:           "edge-proxy",
		State:          "running",
		Image:          "nginx:1.27-alpine",
		ImageDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ComposeProject: "platform",
		ComposeService: "edge-proxy",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "edge-proxy",
		},
	}

	baseSelector := store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	}

	cases := []struct {
		name      string
		mutateSel func(*store.ContainerSelector)
		mutateTgt func(*docker.ContainerSummary)
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "broad_name_only_grant_matches_without_optional_guardrails",
			wantMatch: true,
		},
		{
			name: "broad_name_only_grant_matches_container_without_compose_labels",
			mutateTgt: func(c *docker.ContainerSummary) {
				c.ComposeProject = ""
				c.ComposeService = ""
				c.Labels = nil
			},
			wantMatch: true,
		},
		{
			name: "exact_name_strips_leading_slash_on_target",
			mutateTgt: func(c *docker.ContainerSummary) {
				c.Name = "/edge-proxy"
			},
			wantMatch: true,
		},
		{
			name: "exact_name_does_not_treat_star_as_glob_when_name_is_glob_zero",
			mutateSel: func(s *store.ContainerSelector) {
				s.ContainerName = "edge-*"
				s.NameIsGlob = 0
			},
			wantMatch: false,
		},
		{
			name: "glob_name_matches_when_name_is_glob_one",
			mutateSel: func(s *store.ContainerSelector) {
				s.ContainerName = "edge-*"
				s.NameIsGlob = 1
			},
			wantMatch: true,
		},
		{
			name: "glob_name_question_and_char_class_match",
			mutateSel: func(s *store.ContainerSelector) {
				s.ContainerName = "[d-f]dge-prox?"
				s.NameIsGlob = 1
			},
			wantMatch: true,
		},
		{
			name: "glob_name_malformed_pattern_fails_closed",
			mutateSel: func(s *store.ContainerSelector) {
				s.ContainerName = "edge-[unclosed"
				s.NameIsGlob = 1
			},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name: "invalid_name_is_glob_value_fails_closed",
			mutateSel: func(s *store.ContainerSelector) {
				s.NameIsGlob = 2
			},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name: "compose_project_and_service_guardrails_match",
			mutateSel: func(s *store.ContainerSelector) {
				s.ComposeProject = sql.NullString{String: "platform", Valid: true}
				s.ComposeService = sql.NullString{String: "edge-proxy", Valid: true}
			},
			wantMatch: true,
		},
		{
			name: "compose_project_mismatch_denies",
			mutateSel: func(s *store.ContainerSelector) {
				s.ComposeProject = sql.NullString{String: "other-project", Valid: true}
			},
			wantMatch: false,
		},
		{
			name: "compose_service_mismatch_denies",
			mutateSel: func(s *store.ContainerSelector) {
				s.ComposeService = sql.NullString{String: "billing-worker", Valid: true}
			},
			wantMatch: false,
		},
		{
			name: "compose_label_disagreement_on_target_fails_closed",
			mutateSel: func(s *store.ContainerSelector) {
				s.ComposeProject = sql.NullString{String: "platform", Valid: true}
			},
			mutateTgt: func(c *docker.ContainerSummary) {
				c.ComposeProject = "platform"
				c.Labels = map[string]string{"com.docker.compose.project": "spoofed"}
			},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name: "image_pattern_exact_and_wildcard_match",
			mutateSel: func(s *store.ContainerSelector) {
				s.ImagePattern = sql.NullString{String: "nginx:1.27*", Valid: true}
			},
			wantMatch: true,
		},
		{
			name: "image_pattern_with_registry_slashes_matches",
			mutateSel: func(s *store.ContainerSelector) {
				s.ImagePattern = sql.NullString{String: "ghcr.io/example/billing:v1.*", Valid: true}
			},
			mutateTgt: func(c *docker.ContainerSummary) {
				c.Image = "ghcr.io/example/billing:v1.4.0"
			},
			wantMatch: true,
		},
		{
			name: "image_pattern_mismatch_denies",
			mutateSel: func(s *store.ContainerSelector) {
				s.ImagePattern = sql.NullString{String: "postgres:16*", Valid: true}
			},
			wantMatch: false,
		},
		{
			name: "pinned_container_id_matches_exact_id",
			mutateSel: func(s *store.ContainerSelector) {
				s.PinnedContainerID = sql.NullString{String: string(testEdgeProxyID), Valid: true}
			},
			wantMatch: true,
		},
		{
			name: "pinned_container_id_mismatch_after_recreation_denies",
			mutateSel: func(s *store.ContainerSelector) {
				s.PinnedContainerID = sql.NullString{String: string(testEdgeProxyID), Valid: true}
			},
			mutateTgt: func(c *docker.ContainerSummary) {
				c.ContainerID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			},
			wantMatch: false,
		},
		{
			name: "pinned_container_id_malformed_fails_closed",
			mutateSel: func(s *store.ContainerSelector) {
				s.PinnedContainerID = sql.NullString{String: "short-id", Valid: true}
			},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name: "pinned_image_digest_matches_exact_sha256",
			mutateSel: func(s *store.ContainerSelector) {
				s.PinnedImageDigest = sql.NullString{
					String: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					Valid:  true,
				}
			},
			wantMatch: true,
		},
		{
			name: "pinned_image_digest_mismatch_denies",
			mutateSel: func(s *store.ContainerSelector) {
				s.PinnedImageDigest = sql.NullString{
					String: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					Valid:  true,
				}
			},
			wantMatch: false,
		},
		{
			name: "pinned_image_digest_malformed_fails_closed",
			mutateSel: func(s *store.ContainerSelector) {
				s.PinnedImageDigest = sql.NullString{String: "md5:1234", Valid: true}
			},
			wantMatch: false,
			wantErr:   true,
		},
		{
			name: "cross_endpoint_collision_prevented",
			mutateTgt: func(c *docker.ContainerSummary) {
				c.EndpointID = testOtherEndpointID
			},
			wantMatch: false,
		},
		{
			name: "protected_self_label_target_rejected",
			mutateTgt: func(c *docker.ContainerSummary) {
				c.Labels = map[string]string{docker.SelfLabelKey: docker.SelfLabelValue}
			},
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel := baseSelector
			tgt := baseTarget
			if tc.mutateSel != nil {
				tc.mutateSel(&sel)
			}
			if tc.mutateTgt != nil {
				tc.mutateTgt(&tgt)
			}
			matched, err := authz.MatchSelector(sel, tgt)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil (matched=%v)", matched)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matched != tc.wantMatch {
				t.Fatalf("MatchSelector() = %v, want %v", matched, tc.wantMatch)
			}
		})
	}
}

func TestContainerLifecycleRenameRecreateMissingMatrix(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})

	// Selector 1: Guardrailed unpinned selector for edge-proxy (compose_project=platform, compose_service=edge-proxy, image_pattern=nginx:1.27*)
	env.seedSelector(store.ContainerSelector{
		ID:             string(testSelectorID1),
		EndpointID:     testLocalEndpointID,
		ContainerName:  "edge-proxy",
		NameIsGlob:     0,
		ComposeProject: sql.NullString{String: "platform", Valid: true},
		ComposeService: sql.NullString{String: "edge-proxy", Valid: true},
		ImagePattern:   sql.NullString{String: "nginx:1.27*", Valid: true},
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
		Principal: authz.PrincipalCredentials{
			SessionID:     testSessionID1,
			SessionSecret: secret,
		},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}

	// 1. Initial authorization succeeds and binds immutable testEdgeProxyID.
	dec1, err := env.authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("initial Authorize failed: %v", err)
	}
	if dec1.Target.ContainerID != testEdgeProxyID {
		t.Fatalf("bound ContainerID = %s, want %s", dec1.Target.ContainerID, testEdgeProxyID)
	}

	// 2. Rename edge-proxy -> edge-proxy-renamed: access by original name fails closed; access by new name fails selector.
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:          testEdgeProxyID,
		Name:        "edge-proxy-renamed",
		Image:       "nginx:1.27-alpine",
		ImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:       "running",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "edge-proxy",
		},
	}); err != nil {
		t.Fatalf("UpsertContainer rename: %v", err)
	}
	if _, err := env.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected 403 after rename for old name, got %v", err)
	}
	reqRenamed := req
	reqRenamed.TargetRef = "edge-proxy-renamed"
	if _, err := env.authorizer.Authorize(ctx, reqRenamed); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected 403 for renamed container not matching selector name, got %v", err)
	}

	// 3. Another container (billing-worker) renamed into "edge-proxy": blocked by compose_service & image_pattern guardrails!
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:    testBillingWorkerID,
		Name:  "edge-proxy",
		Image: "ghcr.io/example/billing:v1.4.0",
		State: "running",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "billing-worker",
		},
	}); err != nil {
		t.Fatalf("UpsertContainer impostor: %v", err)
	}
	if _, err := env.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected 403 when different workload takes name edge-proxy, got %v", err)
	}
	// Restore billing-worker name
	_ = env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:    testBillingWorkerID,
		Name:  "billing-worker",
		Image: "ghcr.io/example/billing:v1.4.0",
		State: "running",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "billing-worker",
		},
	})

	// 4. Same-name container recreation (docker compose up -d: new 64-hex ID, same name/project/service/image):
	// Unpinned guardrailed policy seamlessly preserves authorization and binds the NEW ContainerID.
	env.backend.RemoveContainer(testEdgeProxyID)
	recreatedID := docker.ContainerID("abababababababababababababababababababababababababababababababab")
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:          recreatedID,
		Name:        "edge-proxy",
		Image:       "nginx:1.27.3-alpine",
		ImageDigest: "sha256:abababababababababababababababababababababababababababababababab",
		State:       "running",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "edge-proxy",
		},
	}); err != nil {
		t.Fatalf("UpsertContainer recreated: %v", err)
	}
	decRecreated, err := env.authorizer.Authorize(ctx, req)
	if err != nil {
		t.Fatalf("expected unpinned guardrailed policy to allow compliant recreation, got %v", err)
	}
	if decRecreated.Target.ContainerID != recreatedID {
		t.Fatalf("recreated bound ContainerID = %s, want %s", decRecreated.Target.ContainerID, recreatedID)
	}

	// 5. Same-name recreation with changed labels (different compose_service) or unauthorized image fails closed.
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:    recreatedID,
		Name:  "edge-proxy",
		Image: "nginx:1.27.3-alpine",
		State: "running",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "different-service-on-recreate",
		},
	}); err != nil {
		t.Fatalf("UpsertContainer label change recreation: %v", err)
	}
	if _, err := env.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected 403 when recreated with different compose_service label, got %v", err)
	}

	// 6. Pinned container ID fails closed when recreated under the same name/image/labels.
	env.seedSelector(store.ContainerSelector{
		ID:                string(testSelectorID1),
		EndpointID:        testLocalEndpointID,
		ContainerName:     "edge-proxy",
		NameIsGlob:        0,
		ComposeProject:    sql.NullString{String: "platform", Valid: true},
		ComposeService:    sql.NullString{String: "edge-proxy", Valid: true},
		ImagePattern:      sql.NullString{String: "nginx:1.27*", Valid: true},
		PinnedContainerID: sql.NullString{String: string(testEdgeProxyID), Valid: true},
	})
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:    recreatedID,
		Name:  "edge-proxy",
		Image: "nginx:1.27.3-alpine",
		State: "running",
		Labels: map[string]string{
			"com.docker.compose.project": "platform",
			"com.docker.compose.service": "edge-proxy",
		},
	}); err != nil {
		t.Fatalf("UpsertContainer pinned test: %v", err)
	}
	if _, err := env.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected 403 when pinned_container_id does not match recreated container ID, got %v", err)
	}

	// 7. Container deletion: policy remains in store as "Inactive / Target Missing" (TD §7.2) and denies access.
	env.backend.RemoveContainer(recreatedID)
	_, err = env.authorizer.Authorize(ctx, req)
	if !errors.Is(err, authz.ErrForbidden) || !authz.HasReason(err, authz.ReasonTargetMissing) {
		t.Fatalf("expected 403 ReasonTargetMissing on deleted container, got %v", err)
	}
	statuses, err := env.authorizer.InspectEndpointPolicyTargets(ctx, testLocalEndpointID)
	if err != nil {
		t.Fatalf("InspectEndpointPolicyTargets: %v", err)
	}
	if len(statuses) != 1 || statuses[0].PolicyID != testPolicyID1 || !statuses[0].TargetMissing {
		t.Fatalf("expected policy %s to remain in store with TargetMissing=true, got %+v", testPolicyID1, statuses)
	}
}

func TestImmutableTargetIdentityDispatchBinding(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})
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
		Operation:  string(authz.OpContainerStart),
		Effect:     "ALLOW",
	})

	dec, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerStart,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if dec.Target.ContainerID != testEdgeProxyID {
		t.Fatalf("Target.ContainerID = %s, want %s", dec.Target.ContainerID, testEdgeProxyID)
	}

	// Simulate race after Authorize: edge-proxy is renamed to edge-proxy-old, and a new container takes the name edge-proxy.
	_ = env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:    testEdgeProxyID,
		Name:  "edge-proxy-old",
		Image: "nginx:1.27-alpine",
		State: "exited",
	})
	replacementID := docker.ContainerID("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")
	_ = env.backend.UpsertContainer(docker.MockContainerFixture{
		ID:    replacementID,
		Name:  "edge-proxy",
		Image: "malicious:latest",
		State: "exited",
	})

	// ValidateDecision before dispatch detects that testEdgeProxyID no longer matches selector "edge-proxy"!
	if err := env.authorizer.ValidateDecision(ctx, dec); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected ValidateDecision to reject stale decision after target rename, got %v", err)
	}

	// Even if a caller dispatches dec.Target directly to the backend, it targets testEdgeProxyID, NEVER replacementID.
	if err := dispatchDecision(ctx, env.backend, dec); err != nil {
		t.Fatalf("dispatchDecision by immutable ID: %v", err)
	}
	replacementStatus, err := env.backend.InspectStatus(ctx, docker.TargetIdentity{
		EndpointID:  testLocalEndpointID,
		ContainerID: replacementID,
	})
	if err != nil {
		t.Fatalf("InspectStatus replacement: %v", err)
	}
	if replacementStatus.Running {
		t.Fatalf("replacement container was started; mutable name was re-resolved instead of using immutable ContainerID")
	}
}
