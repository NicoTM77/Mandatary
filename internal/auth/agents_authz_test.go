package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
)

// End-to-end adapter tests: credentials issued by the REAL administrative service
// are presented to the REAL shared authorizer (the single place REST and MCP
// adapters will call), over the same SQLite repository, with a container-free
// mock backend. They prove old-generation, expired, revoked and rotated-out tokens
// are rejected by the shared acceptance path, that active leases die on
// revocation, and that owning an agent grants nothing.

const authzEndpoint = domain.EndpointID("00000000-0000-4000-8000-000000000001")

type authzHarness struct {
	*adminEnv
	az *authz.Authorizer
}

func newAuthzHarness(t *testing.T) *authzHarness {
	t.Helper()
	e := newAdminEnv(t)
	e.exec(`UPDATE endpoints SET id=?,state='active',authority_generation=1 WHERE slug='local'`, string(authzEndpoint))
	e.exec(`INSERT INTO container_selectors(id,endpoint_id,container_name,name_is_glob) VALUES ('sel-edge',?,'edge-proxy',0)`, string(authzEndpoint))
	identity, containers := docker.DefaultMockFixtures(authzEndpoint)
	backend, err := docker.NewMockBackend(docker.MockOptions{EndpointID: authzEndpoint, Identity: identity, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if err = backend.VerifySelf(t.Context()); err != nil {
		t.Fatal(err)
	}
	az, err := authz.NewAuthorizer(authz.Config{Repository: e.l.repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{authzEndpoint: backend}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = az.Close() })
	e.hook = az.NotifyPolicyChange // administrative changes revalidate active leases
	return &authzHarness{adminEnv: e, az: az}
}

func (h *authzHarness) allow(subjectColumn, subjectID string) {
	h.t.Helper()
	h.exec(`INSERT INTO policies(id,`+subjectColumn+`,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES (?,?,?,'sel-edge','container:inspect_status','ALLOW','active',1)`, "pol-"+subjectColumn+"-"+subjectID, subjectID, string(authzEndpoint))
}

func (h *authzHarness) request(token []byte) authz.AuthorizeRequest {
	return authz.AuthorizeRequest{Principal: authz.PrincipalCredentials{AgentToken: string(token)}, EndpointID: authzEndpoint, TargetRef: "edge-proxy", Operation: authz.OpContainerInspectStatus}
}

func (h *authzHarness) authorize(token []byte) error {
	_, err := h.az.Authorize(h.t.Context(), h.request(token))
	return err
}

func TestOwningAnAgentGrantsNothingEndToEnd(t *testing.T) { // acceptance: no inherited owner grant
	h := newAuthzHarness(t)
	ctx := t.Context()
	owner, group := h.person("owner"), h.group("owners")
	userOwned := h.agentOwnedBy("user-owned", owner)
	groupOwned, err := h.a.CreateAgent(ctx, h.secret, AgentRequest{Name: "group-owned", OwnerGroupID: group})
	if err != nil {
		t.Fatal(err)
	}
	_, userToken := h.issue(userOwned, CredentialRequest{})
	_, groupToken := h.issue(groupOwned.ID, CredentialRequest{})
	// The owner and the owning group are granted the operation explicitly...
	h.allow("user_id", owner)
	h.allow("group_id", group)
	// ...and neither agent inherits it, although both tokens are valid.
	for name, token := range map[string][]byte{"user-owned agent": userToken, "group-owned agent": groupToken} {
		if err := h.authorize(token); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("%s inherited its owner's grant or failed unexpectedly: %v", name, err)
		}
	}
	// Control: an explicit grant to the agent itself works, so the denial above is the owner rule.
	h.allow("agent_id", userOwned)
	if err := h.authorize(userToken); err != nil {
		t.Fatalf("explicit agent grant refused: %v", err)
	}
	// Group-owned agents receive the group's permission only through explicit membership,
	// and lose it the moment membership is removed.
	if err := h.a.AddMember(ctx, h.secret, group, MemberAgent, groupOwned.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.authorize(groupToken); err != nil {
		t.Fatalf("explicit membership refused: %v", err)
	}
	if err := h.a.RemoveMember(ctx, h.secret, group, MemberAgent, groupOwned.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.authorize(groupToken); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("removed member keeps the group grant: %v", err)
	}
	// An administrative role is never an operation grant either: the administrator's
	// own agent has no more authority than any other.
	adminAgent := h.agentOwnedBy("admins-agent", "u")
	_, adminToken := h.issue(adminAgent, CredentialRequest{})
	if err := h.authorize(adminToken); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("an administrator's agent inherited authority: %v", err)
	}
}

// Every way a token stops being acceptable is observed through the shared
// authorizer: a fresh Authorize returns 401, and a lease acquired while the token
// was good is revalidated to failure (the active-stream termination primitive).
func TestRetiredTokensAreRejectedByTheSharedAuthorizerAndLeases(t *testing.T) { // acceptance: every applicable adapter
	type scenario struct {
		name   string
		retire func(h *authzHarness, agent string, credential string)
	}
	scenarios := []scenario{
		{"revoked", func(h *authzHarness, agent, cred string) {
			if err := h.a.RevokeCredential(h.t.Context(), h.secret, agent, cred); err != nil {
				h.t.Fatal(err)
			}
		}},
		{"expired", func(h *authzHarness, _, _ string) { h.clock.Advance(time.Hour) }},
		{"rotated out", func(h *authzHarness, agent, _ string) {
			res, err := h.a.RotateCredential(h.t.Context(), h.secret, agent, RotateRequest{Overlap: 10 * time.Minute})
			if err != nil {
				h.t.Fatal(err)
			}
			_ = res.New.ExportOnce()
			h.clock.Advance(10 * time.Minute)
		}},
		{"rotated out without overlap", func(h *authzHarness, agent, _ string) {
			res, err := h.a.RotateCredential(h.t.Context(), h.secret, agent, RotateRequest{Immediate: true})
			if err != nil {
				h.t.Fatal(err)
			}
			_ = res.New.ExportOnce()
		}},
		{"agent disabled", func(h *authzHarness, agent, _ string) {
			if err := h.a.DisableAgent(h.t.Context(), h.secret, agent); err != nil {
				h.t.Fatal(err)
			}
		}},
		{"old credential generation", func(h *authzHarness, _, _ string) {
			h.exec(`UPDATE installation_control SET credential_generation=2`)
		}},
		{"old authority generation", func(h *authzHarness, _, _ string) {
			h.exec(`UPDATE installation_control SET authority_generation=2`)
		}},
		{"restore quarantine", func(h *authzHarness, _, _ string) {
			h.exec(`UPDATE installation_control SET restore_quarantined=1`)
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			h := newAuthzHarness(t)
			// A ONE-HOUR token, so "expired" is a real expiry and every other case
			// retires a still-unexpired one.
			agent := h.agentOwnedBy("bot", h.person("owner"))
			cred, token := h.issue(agent, CredentialRequest{TTL: time.Hour})
			h.allow("agent_id", agent)
			lease, err := h.az.AcquireLease(t.Context(), h.request(token))
			if err != nil {
				t.Fatalf("baseline lease: %v", err)
			}
			defer lease.Release()
			if err := h.authorize(token); err != nil {
				t.Fatalf("baseline authorize: %v", err)
			}
			sc.retire(h, agent, cred.Credential.ID)
			// 401 for every credential state; restore quarantine is refused by the
			// authorizer's own earlier gate (403). Either way: refused.
			want := authz.ErrUnauthenticated
			if sc.name == "restore quarantine" {
				want = authz.ErrForbidden
			}
			if err := h.authorize(token); !errors.Is(err, want) {
				t.Fatalf("retired token not refused with %v: %v", want, err)
			}
			if err := lease.Revalidate(t.Context()); err == nil {
				t.Fatal("lease for a retired token survived revalidation")
			}
			if lease.Context().Err() == nil {
				t.Fatal("lease context not cancelled")
			}
		})
	}
}

func TestAdministrativeRevocationTerminatesActiveLeasesBeforeReturning(t *testing.T) { // C2: token revocation immediately invalidates acceptance
	for name, act := range map[string]func(h *authzHarness, agent, cred string) error{
		"revoke credential": func(h *authzHarness, agent, cred string) error {
			return h.a.RevokeCredential(h.t.Context(), h.secret, agent, cred)
		},
		"disable agent": func(h *authzHarness, agent, _ string) error { return h.a.DisableAgent(h.t.Context(), h.secret, agent) },
		"rotate immediately": func(h *authzHarness, agent, _ string) error {
			r, err := h.a.RotateCredential(h.t.Context(), h.secret, agent, RotateRequest{Immediate: true})
			_ = r.New.ExportOnce()
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newAuthzHarness(t)
			agent := h.agentOwnedBy("bot", h.person("owner"))
			cred, token := h.issue(agent, CredentialRequest{})
			h.allow("agent_id", agent)
			lease, err := h.az.AcquireLease(t.Context(), h.request(token))
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			if h.az.ActiveLeaseCount() != 1 {
				t.Fatal("baseline lease count")
			}
			if err := act(h, agent, cred.Credential.ID); err != nil {
				t.Fatal(err)
			}
			// No polling: the change was acknowledged only after the lease was cancelled.
			if lease.Context().Err() == nil || h.az.ActiveLeaseCount() != 0 {
				t.Fatal("administrative change returned while the old token's lease was still live")
			}
		})
	}
}

func TestRotationOverlapKeepsTheOldTokensLeaseUntilTheBoundary(t *testing.T) {
	h := newAuthzHarness(t)
	agent := h.agentOwnedBy("bot", h.person("owner"))
	_, oldToken := h.issue(agent, CredentialRequest{})
	h.allow("agent_id", agent)
	res, err := h.a.RotateCredential(t.Context(), h.secret, agent, RotateRequest{Overlap: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	newToken := res.New.ExportOnce()
	oldLease, err := h.az.AcquireLease(t.Context(), h.request(oldToken))
	if err != nil {
		t.Fatalf("old token during overlap: %v", err)
	}
	defer oldLease.Release()
	newLease, err := h.az.AcquireLease(t.Context(), h.request(newToken))
	if err != nil {
		t.Fatal(err)
	}
	defer newLease.Release()
	h.clock.Advance(10*time.Minute - time.Second)
	if err := oldLease.Revalidate(t.Context()); err != nil {
		t.Fatalf("old lease one second before the boundary: %v", err)
	}
	h.clock.Advance(time.Second)
	if err := oldLease.Revalidate(t.Context()); err == nil {
		t.Fatal("old lease survived the overlap boundary")
	}
	if err := h.authorize(oldToken); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("old token after the boundary: %v", err)
	}
	if err := newLease.Revalidate(t.Context()); err != nil {
		t.Fatalf("new token's lease must be unaffected: %v", err)
	}
}

func TestAgentTokensNeverAuthenticateAdministration(t *testing.T) { // N63B4-SCOPE-MACHINE at the service boundary
	h := newAuthzHarness(t)
	agent := h.agentOwnedBy("bot", "u")
	_, token := h.issue(agent, CredentialRequest{})
	mutations, reads := h.adminCalls(token, agent)
	before := h.snapshot()
	for name, call := range mutations {
		if err := call(); !errors.Is(err, ErrDenied) {
			t.Errorf("%s with an agent token: %v", name, err)
		}
	}
	for name, call := range reads {
		if err := call(); !errors.Is(err, ErrDenied) {
			t.Errorf("%s with an agent token: %v", name, err)
		}
	}
	h.mustNoChange("agent token administration", before)
}
