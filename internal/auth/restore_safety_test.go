package auth_test

// RESTORE-06 / security-contracts.md S2.2.1 and S2.2.6: self-protection must be INDEPENDENTLY re-verified after a restore.
// An authenticated archive says nothing about the Docker daemon, the peers around Mandatary or Mandatary's own identity,
// so a restore commit and the reapproval that makes the endpoint effective again both drop the shared safety proof; no
// operation reaches the backend until a fresh verification succeeds. The proof lives in the backend's safety monitor, which
// the administrative service does not own, so the composition root wires the reset (Admin.WithSafetyReset, here the shared
// authorizer's InvalidateSelfProtection). The Docker daemon is the in-memory MockBackend: this is component evidence, not
// a real-daemon test.

import (
	"errors"
	"net/http"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

var safetyUnverified = outcome{status: 403, code: "forbidden", reason: "safety_unverified"}

func TestARestoreAndTheEndpointReapprovalDropTheSelfProtectionProofUntilItIsVerifiedAgain(t *testing.T) {
	t.Parallel()
	w := newWorldFrom(t, auth.NewPolicyE2EWithBackup(t))
	w.p.Admin.WithSafetyReset(w.az.InvalidateSelfProtection)
	A := "edge-proxy"
	_, groupID, agentID, oldToken := w.newAgent("alice", "ops", "ci-runner")
	selector := `"selector":{"container_name":"edge-proxy","compose_project":"platform","compose_service":"edge-proxy"}`
	w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:inspect_status"],`+selector+`}`, http.StatusCreated)
	w.both(oldToken, "status", A, okOutcome, "", nil)
	if w.mock.VerificationState() != docker.StateVerified {
		t.Fatal("the fixture backend is not verified before the restore")
	}

	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"full"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	if w.mock.VerificationState() != docker.StateVerified {
		t.Fatal("an export dropped the safety proof: only a restore and an endpoint reapproval may")
	}
	body := `{"archive":` + archive + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	if c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf); c != http.StatusOK {
		t.Fatalf("restore: %d %s", c, out)
	}

	t.Run("the restore commit drops the proof and the endpoint reads as unverified", func(t *testing.T) {
		if w.mock.VerificationState() != docker.StateUnverified {
			t.Fatal("a committed restore left the self-protection proof in place")
		}
		_, err := w.az.ListEndpointContainers(t.Context(), w.p.EndpointID)
		var denial *authz.DenialError
		if !errors.As(err, &denial) || denial.Reason != authz.ReasonSafetyUnverified {
			t.Fatalf("the endpoint inventory without a proof: %v", err)
		}
	})

	// The composition root's own verification runs independently of anything the archive said. It is what re-establishes the proof.
	if err := w.mock.VerifySelf(t.Context()); err != nil {
		t.Fatal(err)
	}
	w.hostRecover()
	items := w.manifestItems()
	notEndpoint := pick(items, func(m manifestItem) bool {
		return m.Approvable && m.ID != "u" && m.Kind != "endpoint" && m.Kind != "policy"
	})
	endpoint := pick(items, func(m manifestItem) bool { return m.Approvable && m.Kind == "endpoint" })
	rules := pick(items, func(m manifestItem) bool { return m.Approvable && m.Kind == "policy" && m.Origin == "imported" })
	if len(notEndpoint) < 3 || len(endpoint) != 1 || len(rules) != 1 {
		t.Fatalf("manifest shape: %d identity, %d endpoint, %d rules (%+v)", len(notEndpoint), len(endpoint), len(rules), items)
	}
	if c, out := w.approve(notEndpoint...); c != http.StatusOK {
		t.Fatalf("approving the identities: %d %s", c, out)
	}
	if c, out := w.approve(rules...); c != http.StatusOK {
		t.Fatalf("approving the rule: %d %s", c, out)
	}
	newToken := w.issue(agentID)
	if w.mock.VerificationState() != docker.StateVerified {
		t.Fatal("approving principals or rules dropped a proof that nothing about them affects")
	}

	t.Run("reapproving the endpoint drops the proof again and nothing dispatches until it is verified", func(t *testing.T) {
		calls := len(w.spy.calls())
		if c, out := w.approve(endpoint...); c != http.StatusOK {
			t.Fatalf("approving the endpoint: %d %s", c, out)
		}
		if w.mock.VerificationState() != docker.StateUnverified {
			t.Fatal("the endpoint became effective with the earlier proof still in place")
		}
		w.both(newToken, "status", A, safetyUnverified, "", nil)
		if got := w.spy.calls(); len(got) != calls {
			t.Fatalf("a refused request reached Docker: %v", got[calls:])
		}
		if err := w.mock.VerifySelf(t.Context()); err != nil {
			t.Fatal(err)
		}
		w.both(newToken, "status", A, okOutcome, "", nil)
		w.both(oldToken, "status", A, unauth, "", nil)
	})
}
