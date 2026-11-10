package authz_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestAuthorizerPrecedenceOrder(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})
	validCreds := authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret}

	// Wildcard selector matching "*" on local endpoint
	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "*",
		NameIsGlob:    1,
	})
	// Direct ALLOW on "*" for container:inspect_status
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID1),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerInspectStatus),
		Effect:     "ALLOW",
	})

	// 1. Precedence 1: Self-protection check beats wildcard ALLOW and even invalid credentials!
	for _, selfRef := range []string{string(docker.MockSelfContainerID), "mandatary-self", string(docker.MockPeerContainerID), "mandatary-peer-stopped"} {
		_, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  validCreds,
			EndpointID: testLocalEndpointID,
			TargetRef:  selfRef,
			Operation:  authz.OpContainerInspectStatus,
		})
		if !errors.Is(err, authz.ErrForbidden) || authz.StatusCode(err) != http.StatusForbidden || !authz.HasReason(err, authz.ReasonSelfProtected) {
			t.Fatalf("target %q: expected 403 ReasonSelfProtected, got %v", selfRef, err)
		}
	}

	// 2. Precedence 2: Authentication & Credential Status (401) beats target existence and policy!
	for _, targetRef := range []string{"edge-proxy", "nonexistent-container-name"} {
		_, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  authz.PrincipalCredentials{SessionID: "99999999-0000-4000-8000-000000000099"},
			EndpointID: testLocalEndpointID,
			TargetRef:  targetRef,
			Operation:  authz.OpContainerInspectStatus,
		})
		if !errors.Is(err, authz.ErrUnauthenticated) || authz.StatusCode(err) != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request for %q: expected 401 ErrUnauthenticated, got %v", targetRef, err)
		}
		if err.Error() != "authentication required" {
			t.Fatalf("unauthenticated error message = %q, want %q", err.Error(), "authentication required")
		}
	}

	// 3. Precedence 4: Explicit ALLOW on ordinary container succeeds when no DENY matches.
	dec, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  validCreds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	})
	if err != nil {
		t.Fatalf("expected ALLOW on edge-proxy, got %v", err)
	}
	if dec.Target.ContainerID != testEdgeProxyID {
		t.Fatalf("Target.ContainerID = %s, want %s", dec.Target.ContainerID, testEdgeProxyID)
	}

	// 4. Precedence 3: Explicit DENY (via group) overrides direct wildcard ALLOW.
	env.seedGroup(testGroupID1, "ops-group", "active", 1)
	env.seedUserGroupMembership(testUserID1, testGroupID1, "active", 1)
	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID2),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID2),
		GroupID:    sql.NullString{String: string(testGroupID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID2),
		Operation:  string(authz.OpContainerInspectStatus),
		Effect:     "DENY",
	})
	_, err = env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  validCreds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	})
	if !errors.Is(err, authz.ErrForbidden) || !authz.HasReason(err, authz.ReasonExplicitDeny) {
		t.Fatalf("expected 403 ReasonExplicitDeny when group DENY overrides direct ALLOW, got %v", err)
	}

	// 5. Precedence 5: Default Fallback (403 ReasonDefaultDeny) when no policy matches operation.
	_, err = env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  validCreds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerStart,
	})
	if !errors.Is(err, authz.ErrForbidden) || !authz.HasReason(err, authz.ReasonDefaultDeny) {
		t.Fatalf("expected 403 ReasonDefaultDeny for ungranted operation, got %v", err)
	}
}

func TestStorageFailClosedAndDenialRedaction(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	canarySessionSecret := []byte("CANARY_SESSION_SECRET_VALUE_9999999999999999")
	canaryAgentToken := "mdt_CANARY_BEARER_TOKEN_VALUE_8888888888888888"
	canaryTargetName := "CANARY_SECRET_TARGET_NAME_777777"

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1, RawSecret: canarySessionSecret})
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

	var logBuf bytes.Buffer
	logger, err := logging.New(&logBuf, slog.LevelDebug, "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	// Acquire an active lease before poisoning storage.
	lease, err := env.authorizer.AcquireLease(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: canarySessionSecret},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	})
	if err != nil {
		t.Fatalf("AcquireLease before FailClosed: %v", err)
	}
	defer lease.Release()

	// Denial with synthetic canaries in PrincipalCredentials and TargetRef must never leak canaries.
	_, denyErr := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{AgentToken: canaryAgentToken},
		EndpointID: testLocalEndpointID,
		TargetRef:  canaryTargetName,
		Operation:  authz.OpContainerInspectStatus,
	})
	if !errors.Is(denyErr, authz.ErrUnauthenticated) {
		t.Fatalf("expected 401 ErrUnauthenticated, got %v", denyErr)
	}
	logger.Error("authz failure", "principal", authz.PrincipalCredentials{
		SessionSecret: canarySessionSecret,
		AgentToken:    canaryAgentToken,
	}, "err", denyErr)

	formatted := fmt.Sprintf("%v | %+v | %#v | %s", denyErr, denyErr, denyErr, logBuf.String())
	for _, canary := range []string{string(canarySessionSecret), canaryAgentToken, canaryTargetName} {
		if strings.Contains(formatted, canary) {
			t.Fatalf("synthetic canary %q leaked in error/log output: %s", canary, formatted)
		}
	}

	// Poison repository handle via FailClosed: all authorizer operations must fail closed with 403 and zero ops.
	env.repo.FailClosed()
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: canarySessionSecret},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected 403 ErrForbidden after repo.FailClosed(), got %v", err)
	}
	if err := env.authorizer.ValidateDecision(ctx, lease.Decision); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected ValidateDecision to fail closed after repo.FailClosed(), got %v", err)
	}
	if lease.Context().Err() == nil {
		t.Fatalf("expected active lease to be canceled when ValidateDecision fails on poisoned repo")
	}
	if _, err := env.authorizer.InspectEndpointPolicyTargets(ctx, testLocalEndpointID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("expected InspectEndpointPolicyTargets to fail closed after repo.FailClosed(), got %v", err)
	}
	if ops := env.backend.Counters().TotalOperational(); ops != 0 {
		t.Fatalf("expected 0 operational calls, got %d", ops)
	}
}
