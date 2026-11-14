package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

// ListEndpointContainers backs the policy-administration inventory and preview (P1.17). It is a read of
// what the shared evaluator itself can see, so it must never name Mandatary, its peers or an unverified
// endpoint (SELF-04/SELF-08), and it must not widen what any request could reach.
func TestListEndpointContainersNeverNamesSelfOrPeersAndRequiresAVerifiedBackend(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID: docker.ContainerID("9999999999999999999999999999999999999999999999999999999999999999"), Name: "innocent-name", Image: "mandatary:peer", State: "running",
		Labels: map[string]string{"io.mandatary.self": "true"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.backend.UpsertContainer(docker.MockContainerFixture{
		ID: docker.ContainerID("8888888888888888888888888888888888888888888888888888888888888888"), Name: "reserved-label", Image: "x:1", State: "running",
		Labels: map[string]string{"io.mandatary.anything": "1"},
	}); err != nil {
		t.Fatal(err)
	}
	list, err := env.authorizer.ListEndpointContainers(ctx, testLocalEndpointID)
	if err != nil {
		t.Fatalf("ListEndpointContainers: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range list {
		seen[c.Name] = true
		if docker.HasProtectedNamespaceLabel(c.Labels) {
			t.Fatalf("a protected container was listed: %q", c.Name)
		}
	}
	if !seen["edge-proxy"] || seen["innocent-name"] || seen["reserved-label"] {
		t.Fatalf("unexpected listing %v", seen)
	}

	// Unknown endpoint, malformed endpoint and an unverified backend fail closed with the shared sentinel.
	if _, err := env.authorizer.ListEndpointContainers(ctx, "not-a-uuid"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("malformed endpoint: %v", err)
	}
	if _, err := env.authorizer.ListEndpointContainers(ctx, testOtherEndpointID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("unregistered endpoint: %v", err)
	}
	env.backend.SimulateEventDiscontinuity()
	if _, err := env.authorizer.ListEndpointContainers(ctx, testLocalEndpointID); !errors.Is(err, authz.ErrForbidden) || !authz.HasReason(err, authz.ReasonSafetyUnverified) {
		t.Fatalf("unverified backend: %v", err)
	}
}
