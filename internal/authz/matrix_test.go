package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestAuthorizationCrossProductMatrix(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	now := env.clock.Now().Unix()

	// Seed users & sessions across all states
	activeUserID := domain.UserID("11000000-0000-4000-8000-000000000001")
	disabledUserID := domain.UserID("11000000-0000-4000-8000-000000000002")
	quarantinedUserID := domain.UserID("11000000-0000-4000-8000-000000000003")
	compromisedUserID := domain.UserID("11000000-0000-4000-8000-000000000004")
	staleUserGenID := domain.UserID("11000000-0000-4000-8000-000000000005")

	env.seedUser(seedUserOpts{ID: activeUserID, Username: "u_active", State: "active"})
	env.seedUser(seedUserOpts{ID: disabledUserID, Username: "u_disabled", State: "disabled"})
	env.seedUser(seedUserOpts{ID: quarantinedUserID, Username: "u_quarantined", State: "quarantined"})
	env.seedUser(seedUserOpts{ID: compromisedUserID, Username: "u_compromised", State: "active", Compromised: 1})
	env.seedUser(seedUserOpts{ID: staleUserGenID, Username: "u_stalegen", State: "active", AuthorityGeneration: 99})

	sessActiveID := authz.SessionID("21000000-0000-4000-8000-000000000001")
	sessDisabledUserID := authz.SessionID("21000000-0000-4000-8000-000000000002")
	sessQuarantinedUserID := authz.SessionID("21000000-0000-4000-8000-000000000003")
	sessCompromisedUserID := authz.SessionID("21000000-0000-4000-8000-000000000004")
	sessStaleUserGenID := authz.SessionID("21000000-0000-4000-8000-000000000005")
	sessExpiredID := authz.SessionID("21000000-0000-4000-8000-000000000006")
	sessIdleExpiredID := authz.SessionID("21000000-0000-4000-8000-000000000007")
	sessRevokedID := authz.SessionID("21000000-0000-4000-8000-000000000008")
	sessQuarantinedID := authz.SessionID("21000000-0000-4000-8000-000000000009")
	sessStaleGenID := authz.SessionID("21000000-0000-4000-8000-000000000010")

	secActive := env.seedSession(seedSessionOpts{ID: sessActiveID, UserID: activeUserID})
	secDisabledU := env.seedSession(seedSessionOpts{ID: sessDisabledUserID, UserID: disabledUserID})
	secQuarU := env.seedSession(seedSessionOpts{ID: sessQuarantinedUserID, UserID: quarantinedUserID})
	secCompU := env.seedSession(seedSessionOpts{ID: sessCompromisedUserID, UserID: compromisedUserID})
	secStaleUGen := env.seedSession(seedSessionOpts{ID: sessStaleUserGenID, UserID: staleUserGenID})
	secExpired := env.seedSession(seedSessionOpts{ID: sessExpiredID, UserID: activeUserID, CreatedAt: now - 3600, ExpiresAt: now, LastActivityAt: now - 10})
	secIdleExp := env.seedSession(seedSessionOpts{ID: sessIdleExpiredID, UserID: activeUserID, CreatedAt: now - 3600, ExpiresAt: now + 3600, LastActivityAt: now - 1800, IdleTimeoutSeconds: 1800})
	secRevoked := env.seedSession(seedSessionOpts{ID: sessRevokedID, UserID: activeUserID, State: "revoked", RevokedAt: sql.NullInt64{Int64: now - 10, Valid: true}})
	secQuar := env.seedSession(seedSessionOpts{ID: sessQuarantinedID, UserID: activeUserID, State: "quarantined"})
	secStaleGen := env.seedSession(seedSessionOpts{ID: sessStaleGenID, UserID: activeUserID, SessionGeneration: 99})

	// Seed agents & agent credentials across all states
	activeAgentID := domain.AgentID("41000000-0000-4000-8000-000000000001")
	disabledAgentID := domain.AgentID("41000000-0000-4000-8000-000000000002")
	quarantinedAgentID := domain.AgentID("41000000-0000-4000-8000-000000000003")

	ownerU := sql.NullString{String: string(activeUserID), Valid: true}
	env.seedAgent(seedAgentOpts{ID: activeAgentID, Name: "ag_active", OwnerUserID: ownerU, State: "active"})
	env.seedAgent(seedAgentOpts{ID: disabledAgentID, Name: "ag_disabled", OwnerUserID: ownerU, State: "disabled"})
	env.seedAgent(seedAgentOpts{ID: quarantinedAgentID, Name: "ag_quarantined", OwnerUserID: ownerU, State: "quarantined"})

	credActiveID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000001")
	credNonExpiringID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000002")
	credDisabledAgID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000003")
	credQuarAgID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000004")
	credExpiredID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000005")
	credOverlapExpID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000006")
	credRevokedID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000007")
	credQuarantinedID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000008")
	credStaleGenID := authz.AgentCredentialID("51000000-0000-4000-8000-000000000009")

	tokActive := env.seedAgentCredential(seedAgentCredentialOpts{ID: credActiveID, AgentID: activeAgentID})
	tokNonExpiring := env.seedAgentCredential(seedAgentCredentialOpts{ID: credNonExpiringID, AgentID: activeAgentID, NonexpiringApproved: 1})
	tokDisabledAg := env.seedAgentCredential(seedAgentCredentialOpts{ID: credDisabledAgID, AgentID: disabledAgentID})
	tokQuarAg := env.seedAgentCredential(seedAgentCredentialOpts{ID: credQuarAgID, AgentID: quarantinedAgentID})
	tokExpired := env.seedAgentCredential(seedAgentCredentialOpts{ID: credExpiredID, AgentID: activeAgentID, IssuedAt: now - 3600, ExpiresAt: sql.NullInt64{Int64: now, Valid: true}})
	tokOverlapExp := env.seedAgentCredential(seedAgentCredentialOpts{ID: credOverlapExpID, AgentID: activeAgentID, IssuedAt: now - 3600, ExpiresAt: sql.NullInt64{Int64: now + 3600, Valid: true}, RotationOverlapUntil: sql.NullInt64{Int64: now, Valid: true}})
	tokRevoked := env.seedAgentCredential(seedAgentCredentialOpts{ID: credRevokedID, AgentID: activeAgentID, State: "revoked", RevokedAt: sql.NullInt64{Int64: now - 10, Valid: true}})
	tokQuar := env.seedAgentCredential(seedAgentCredentialOpts{ID: credQuarantinedID, AgentID: activeAgentID, State: "quarantined"})
	tokStaleGen := env.seedAgentCredential(seedAgentCredentialOpts{ID: credStaleGenID, AgentID: activeAgentID, CredentialGeneration: 99})

	// Groups: groupA and groupB (active), groupDisabled (disabled), groupQuarantined (quarantined)
	groupA := domain.GroupID("31000000-0000-4000-8000-000000000001")
	groupB := domain.GroupID("31000000-0000-4000-8000-000000000002")
	groupDisabled := domain.GroupID("31000000-0000-4000-8000-000000000003")
	groupQuarantined := domain.GroupID("31000000-0000-4000-8000-000000000004")

	env.seedGroup(groupA, "group_a", "active", 1)
	env.seedGroup(groupB, "group_b", "active", 1)
	env.seedGroup(groupDisabled, "group_disabled", "disabled", 1)
	env.seedGroup(groupQuarantined, "group_quarantined", "quarantined", 1)

	for _, uid := range []domain.UserID{activeUserID, disabledUserID, quarantinedUserID, compromisedUserID, staleUserGenID} {
		env.seedUserGroupMembership(uid, groupA, "active", 1)
		env.seedUserGroupMembership(uid, groupB, "active", 1)
		env.seedUserGroupMembership(uid, groupDisabled, "active", 1)
		env.seedUserGroupMembership(uid, groupQuarantined, "active", 1)
	}
	for _, aid := range []domain.AgentID{activeAgentID, disabledAgentID, quarantinedAgentID} {
		env.seedAgentGroupMembership(aid, groupA, "active", 1)
		env.seedAgentGroupMembership(aid, groupB, "active", 1)
		env.seedAgentGroupMembership(aid, groupDisabled, "active", 1)
		env.seedAgentGroupMembership(aid, groupQuarantined, "active", 1)
	}

	// Endpoint 2 (foreign endpoint) in SQLite and MockBackend with same-named "edge-proxy" container
	env.execSQL(
		`INSERT INTO endpoints (id, slug, name, transport, state, authority_generation) VALUES (?, 'remote-2', 'Remote 2', 'mtls', 'disabled', 1)`,
		string(testOtherEndpointID),
	)
	foreignIDCfg, foreignContainers := docker.DefaultMockFixtures(testOtherEndpointID)
	foreignBackend, err := docker.NewMockBackend(docker.MockOptions{
		EndpointID: testOtherEndpointID,
		Identity:   foreignIDCfg,
		Containers: foreignContainers,
	})
	if err != nil {
		t.Fatalf("NewMockBackend foreign: %v", err)
	}
	if err := foreignBackend.VerifySelf(ctx); err != nil {
		t.Fatalf("foreignBackend.VerifySelf: %v", err)
	}
	if err := env.authorizer.RegisterBackend(testOtherEndpointID, foreignBackend); err != nil {
		t.Fatalf("RegisterBackend foreign: %v", err)
	}

	// Selector on local endpoint for edge-proxy
	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})

	type principalCase struct {
		name      string
		isAgent   bool
		userID    domain.UserID
		agentID   domain.AgentID
		creds     authz.PrincipalCredentials
		validAuth bool
	}

	principals := []principalCase{
		{
			name:      "user_active",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessActiveID, SessionSecret: secActive},
			validAuth: true,
		},
		{
			name:      "user_missing_session",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: "21000000-0000-4000-8000-000000000999"},
			validAuth: false,
		},
		{
			name:      "user_disabled",
			userID:    disabledUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessDisabledUserID, SessionSecret: secDisabledU},
			validAuth: false,
		},
		{
			name:      "user_quarantined",
			userID:    quarantinedUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessQuarantinedUserID, SessionSecret: secQuarU},
			validAuth: false,
		},
		{
			name:      "user_compromised",
			userID:    compromisedUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessCompromisedUserID, SessionSecret: secCompU},
			validAuth: false,
		},
		{
			name:      "user_stale_authority_gen",
			userID:    staleUserGenID,
			creds:     authz.PrincipalCredentials{SessionID: sessStaleUserGenID, SessionSecret: secStaleUGen},
			validAuth: false,
		},
		{
			name:      "session_expired_at_boundary",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessExpiredID, SessionSecret: secExpired},
			validAuth: false,
		},
		{
			name:      "session_idle_expired_at_boundary",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessIdleExpiredID, SessionSecret: secIdleExp},
			validAuth: false,
		},
		{
			name:      "session_revoked",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessRevokedID, SessionSecret: secRevoked},
			validAuth: false,
		},
		{
			name:      "session_quarantined",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessQuarantinedID, SessionSecret: secQuar},
			validAuth: false,
		},
		{
			name:      "session_stale_generation",
			userID:    activeUserID,
			creds:     authz.PrincipalCredentials{SessionID: sessStaleGenID, SessionSecret: secStaleGen},
			validAuth: false,
		},
		{
			name:      "agent_active_timed_token",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentCredentialID: credActiveID, AgentToken: tokActive},
			validAuth: true,
		},
		{
			name:      "agent_active_nonexpiring_token",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokNonExpiring},
			validAuth: true,
		},
		{
			name:      "agent_disabled",
			isAgent:   true,
			agentID:   disabledAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokDisabledAg},
			validAuth: false,
		},
		{
			name:      "agent_quarantined",
			isAgent:   true,
			agentID:   quarantinedAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokQuarAg},
			validAuth: false,
		},
		{
			name:      "agent_token_expired_at_boundary",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokExpired},
			validAuth: false,
		},
		{
			name:      "agent_token_rotation_overlap_expired",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokOverlapExp},
			validAuth: false,
		},
		{
			name:      "agent_token_revoked",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokRevoked},
			validAuth: false,
		},
		{
			name:      "agent_token_quarantined",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokQuar},
			validAuth: false,
		},
		{
			name:      "agent_token_stale_generation",
			isAgent:   true,
			agentID:   activeAgentID,
			creds:     authz.PrincipalCredentials{AgentToken: tokStaleGen},
			validAuth: false,
		},
	}

	type policyMatrixCase struct {
		name         string
		directEffect string // "", "ALLOW", "DENY", "ALLOW_QUARANTINED", "ALLOW_DISABLED"
		// directDeny seeds an additional direct DENY for the same principal as directEffect.
		directDeny bool
		// denyKind is the subject kind of the DENY rows the fixture must contain: "direct" (user/agent
		// subject), "group" or "" (none expected). It makes the row name and its semantics checkable.
		denyKind     string
		groupAEffect string // "", "ALLOW", "DENY"
		groupBEffect string // "", "ALLOW", "DENY", "DENY_QUARANTINED"
		disabledGrp  string // "", "ALLOW"
		quarGrp      string // "", "ALLOW"
		wantAllow    bool
		wantReason   authz.DenialReason
	}

	policyCases := []policyMatrixCase{
		{name: "no_policy_default_deny", wantAllow: false, wantReason: authz.ReasonDefaultDeny},
		{name: "direct_allow_only", directEffect: "ALLOW", wantAllow: true},
		{name: "direct_deny_only", directEffect: "DENY", denyKind: "direct", wantAllow: false, wantReason: authz.ReasonExplicitDeny},
		// P1.18.4 P111-NIT-matrix-row: the former "direct_allow_and_direct_deny" seeded a GROUP deny. It
		// is renamed to what it does and the true direct ALLOW + direct DENY row is added beside it.
		{name: "direct_allow_and_groupA_deny", directEffect: "ALLOW", groupAEffect: "DENY", denyKind: "group", wantAllow: false, wantReason: authz.ReasonExplicitDeny},
		{name: "direct_allow_and_direct_deny", directEffect: "ALLOW", directDeny: true, denyKind: "direct", wantAllow: false, wantReason: authz.ReasonExplicitDeny},
		{name: "groupA_allow_only", groupAEffect: "ALLOW", wantAllow: true},
		{name: "groupA_allow_and_groupB_allow", groupAEffect: "ALLOW", groupBEffect: "ALLOW", wantAllow: true},
		{name: "groupA_allow_overridden_by_groupB_deny", groupAEffect: "ALLOW", groupBEffect: "DENY", denyKind: "group", wantAllow: false, wantReason: authz.ReasonExplicitDeny},
		{name: "direct_deny_overrides_groupA_allow", directEffect: "DENY", groupAEffect: "ALLOW", denyKind: "direct", wantAllow: false, wantReason: authz.ReasonExplicitDeny},
		{name: "quarantined_direct_allow_never_grants", directEffect: "ALLOW_QUARANTINED", wantAllow: false, wantReason: authz.ReasonDefaultDeny},
		{name: "disabled_direct_allow_never_grants", directEffect: "ALLOW_DISABLED", wantAllow: false, wantReason: authz.ReasonDefaultDeny},
		{name: "disabled_group_allow_never_grants", disabledGrp: "ALLOW", wantAllow: false, wantReason: authz.ReasonDefaultDeny},
		{name: "quarantined_group_allow_never_grants", quarGrp: "ALLOW", wantAllow: false, wantReason: authz.ReasonDefaultDeny},
		{name: "quarantined_groupB_deny_conservatively_blocks_groupA_allow_RESTORE03", groupAEffect: "ALLOW", groupBEffect: "DENY_QUARANTINED", wantAllow: false, wantReason: authz.ReasonExplicitDeny},
	}

	for _, pc := range policyCases {
		for _, op := range authz.AllOperations() {
			env.execSQL(`DELETE FROM policies`)

			addRule := func(idx int, userID domain.UserID, agentID domain.AgentID, groupID domain.GroupID, effectSpec string) {
				if effectSpec == "" {
					return
				}
				effect := effectSpec
				state := "active"
				switch effectSpec {
				case "ALLOW_QUARANTINED":
					effect = "ALLOW"
					state = "quarantined"
				case "ALLOW_DISABLED":
					effect = "ALLOW"
					state = "disabled"
				case "DENY_QUARANTINED":
					effect = "DENY"
					state = "quarantined"
				}
				p := store.Policy{
					ID:                  fmt.Sprintf("71000000-0000-4000-8000-%012d", idx),
					EndpointID:          testLocalEndpointID,
					SelectorID:          string(testSelectorID1),
					Operation:           string(op),
					Effect:              effect,
					State:               state,
					AuthorityGeneration: 1,
				}
				if userID != "" {
					p.UserID = sql.NullString{String: string(userID), Valid: true}
				} else if agentID != "" {
					p.AgentID = sql.NullString{String: string(agentID), Valid: true}
				} else if groupID != "" {
					p.GroupID = sql.NullString{String: string(groupID), Valid: true}
				}
				env.seedPolicy(p)
			}

			// Seed direct rules for activeUserID and activeAgentID, plus group rules
			addRule(1, activeUserID, "", "", pc.directEffect)
			addRule(2, "", activeAgentID, "", pc.directEffect)
			addRule(3, "", "", groupA, pc.groupAEffect)
			addRule(4, "", "", groupB, pc.groupBEffect)
			addRule(5, "", "", groupDisabled, pc.disabledGrp)
			addRule(6, "", "", groupQuarantined, pc.quarGrp)
			if pc.directDeny {
				addRule(7, activeUserID, "", "", "DENY")
				addRule(8, "", activeAgentID, "", "DENY")
			}
			assertDenySubjectKinds(t, env, pc.name, op, pc.denyKind)
			opsBefore := env.backend.Counters().TotalOperational()

			endpoints := []struct {
				name    string
				id      domain.EndpointID
				isLocal bool
			}{
				{name: "ep_local", id: testLocalEndpointID, isLocal: true},
				{name: "ep_foreign", id: testOtherEndpointID, isLocal: false},
			}

			for _, ep := range endpoints {
				for _, pr := range principals {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", pc.name, ep.name, op, pr.name), func(t *testing.T) {
						dec, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
							Principal:  pr.creds,
							EndpointID: ep.id,
							TargetRef:  "edge-proxy",
							Operation:  op,
						})
						if !pr.validAuth {
							if !errors.Is(err, authz.ErrUnauthenticated) || authz.StatusCode(err) != http.StatusUnauthorized {
								t.Fatalf("expected 401 ErrUnauthenticated, got %v", err)
							}
							return
						}
						if !ep.isLocal {
							if !errors.Is(err, authz.ErrForbidden) || !authz.HasReason(err, authz.ReasonEndpointInactive) {
								t.Fatalf("expected 403 ReasonEndpointInactive on foreign endpoint, got %v", err)
							}
							return
						}
						if pc.wantAllow {
							if err != nil {
								t.Fatalf("expected ALLOW, got %v", err)
							}
							if dec.Target.EndpointID != testLocalEndpointID || dec.Target.ContainerID != testEdgeProxyID {
								t.Fatalf("unexpected target identity: %+v", dec.Target)
							}
							if dec.Operation != op {
								t.Fatalf("Decision.Operation = %s, want %s", dec.Operation, op)
							}
						} else {
							if !errors.Is(err, authz.ErrForbidden) || authz.StatusCode(err) != http.StatusForbidden {
								t.Fatalf("expected 403 ErrForbidden, got %v", err)
							}
							if pc.wantReason != "" && !authz.HasReason(err, pc.wantReason) {
								r, _ := authz.ReasonOf(err)
								t.Fatalf("reason = %q, want %q", r, pc.wantReason)
							}
						}
					})
				}
			}
			// Authorize is decision-only: no row (direct or group DENY, ALLOW or refusal) may
			// reach the backend operational surface.
			if got := env.backend.Counters().TotalOperational(); got != opsBefore {
				t.Errorf("%s/%s: %d operational backend attempts during authorization-only matrix rows", pc.name, op, got-opsBefore)
			}
		}
	}
}

// assertDenySubjectKinds proves the seeded fixture really contains the DENY subject kind the row
// name claims: "direct" = a user or agent subject, "group" = a group subject, "" = no DENY at all.
func assertDenySubjectKinds(t *testing.T, env *testEnv, row string, op docker.Operation, want string) {
	t.Helper()
	var direct, group int
	err := env.rawDB.QueryRowContext(context.Background(),
		`SELECT COALESCE(SUM(CASE WHEN user_id IS NOT NULL OR agent_id IS NOT NULL THEN 1 ELSE 0 END),0),
		        COALESCE(SUM(CASE WHEN group_id IS NOT NULL THEN 1 ELSE 0 END),0)
		   FROM policies WHERE effect='DENY' AND state='active' AND operation=?`, string(op)).Scan(&direct, &group)
	if err != nil {
		t.Fatalf("%s: deny subject-kind query: %v", row, err)
	}
	switch want {
	case "direct":
		if direct == 0 || group != 0 {
			t.Fatalf("%s: row claims direct DENY but fixture has direct=%d group=%d", row, direct, group)
		}
	case "group":
		if group == 0 || direct != 0 {
			t.Fatalf("%s: row claims group DENY but fixture has direct=%d group=%d", row, direct, group)
		}
	}
}

func TestAgentOwnerNonInheritanceAndAdminZeroGrant(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Seed human owner and admin
	env.seedUser(seedUserOpts{ID: testUserID1, Username: "owner_human"})
	env.seedUser(seedUserOpts{ID: testAdminID, Username: "super_admin_user"})
	adminSecret := env.seedSession(seedSessionOpts{ID: testAdminSess, UserID: testAdminID, AchievedAssurance: 2, Methods: 8, PhishingResistant: 1})

	// Grant super_admin role to testAdminID
	env.execSQL(
		`INSERT INTO administrative_roles (id, user_id, role, endpoint_id, state, authority_generation)
		 VALUES ('80000000-0000-4000-8000-000000000001', ?, 'super_admin', NULL, 'active', 1)`,
		string(testAdminID),
	)

	// Seed owning group
	env.seedGroup(testGroupID1, "owning-group", "active", 1)

	// Agent 1 owned by testUserID1; Agent 2 owned by testGroupID1 (without membership in testGroupID1)
	env.seedAgent(seedAgentOpts{
		ID:          testAgentID1,
		Name:        "user-owned-agent",
		OwnerUserID: sql.NullString{String: string(testUserID1), Valid: true},
	})
	env.seedAgent(seedAgentOpts{
		ID:           testAgentID2,
		Name:         "group-owned-agent",
		OwnerGroupID: sql.NullString{String: string(testGroupID1), Valid: true},
	})
	tok1 := env.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID1, AgentID: testAgentID1})
	tok2 := env.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID2, AgentID: testAgentID2})

	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})

	// Grant all 6 operations to owner_human (testUserID1) and owning-group (testGroupID1)
	for i, op := range authz.AllOperations() {
		env.seedPolicy(store.Policy{
			ID:         fmt.Sprintf("72000000-0000-4000-8000-%012d", i+1),
			UserID:     sql.NullString{String: string(testUserID1), Valid: true},
			EndpointID: testLocalEndpointID,
			SelectorID: string(testSelectorID1),
			Operation:  string(op),
			Effect:     "ALLOW",
		})
		env.seedPolicy(store.Policy{
			ID:         fmt.Sprintf("73000000-0000-4000-8000-%012d", i+1),
			GroupID:    sql.NullString{String: string(testGroupID1), Valid: true},
			EndpointID: testLocalEndpointID,
			SelectorID: string(testSelectorID1),
			Operation:  string(op),
			Effect:     "ALLOW",
		})
	}

	for _, op := range authz.AllOperations() {
		// 1. User-owned agent does NOT inherit owner_user_id permissions.
		_, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  authz.PrincipalCredentials{AgentToken: tok1},
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  op,
		})
		if !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("op %s: user-owned agent inherited owner permissions: %v", op, err)
		}

		// 2. Group-owned agent without agent_group_memberships does NOT inherit owner_group_id permissions.
		_, err = env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  authz.PrincipalCredentials{AgentToken: tok2},
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  op,
		})
		if !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("op %s: group-owned agent without group membership inherited permissions: %v", op, err)
		}

		// 3. super_admin role alone grants zero container operations.
		_, err = env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal:  authz.PrincipalCredentials{SessionID: testAdminSess, SessionSecret: adminSecret},
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  op,
		})
		if !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("op %s: super_admin granted container operation without policy: %v", op, err)
		}
	}
}

func TestAssuranceAndPurposeBoundaries(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	uOpt := domain.UserID("12000000-0000-4000-8000-000000000001")
	uReq := domain.UserID("12000000-0000-4000-8000-000000000002")
	uWebAuthn := domain.UserID("12000000-0000-4000-8000-000000000003")
	uAdminOpt := domain.UserID("12000000-0000-4000-8000-000000000004")

	env.seedUser(seedUserOpts{ID: uOpt, Username: "u_opt", MfaRequirement: "optional"})
	env.seedUser(seedUserOpts{ID: uReq, Username: "u_req", MfaRequirement: "required"})
	env.seedUser(seedUserOpts{ID: uWebAuthn, Username: "u_webauthn", MfaRequirement: "webauthn"})
	env.seedUser(seedUserOpts{ID: uAdminOpt, Username: "u_admin_opt", MfaRequirement: "optional"})

	// uAdminOpt has an active admin role -> MFA (AAL2) is mandatory per TD §4.1!
	env.execSQL(
		`INSERT INTO administrative_roles (id, user_id, role, endpoint_id, state, authority_generation)
		 VALUES ('80000000-0000-4000-8000-000000000002', ?, 'super_admin', NULL, 'active', 1)`,
		string(uAdminOpt),
	)

	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})
	for i, uid := range []domain.UserID{uOpt, uReq, uWebAuthn, uAdminOpt} {
		env.seedPolicy(store.Policy{
			ID:         fmt.Sprintf("74000000-0000-4000-8000-%012d", i+1),
			UserID:     sql.NullString{String: string(uid), Valid: true},
			EndpointID: testLocalEndpointID,
			SelectorID: string(testSelectorID1),
			Operation:  string(authz.OpContainerInspectStatus),
			Effect:     "ALLOW",
		})
	}

	// 1. Preauth, setup, and recovery sessions are ALWAYS rejected (401), even if caller asserts AAL2/admin.
	for i, purpose := range []string{"preauth", "setup", "recovery"} {
		sid := authz.SessionID(fmt.Sprintf("22000000-0000-4000-8000-%012d", i+1))
		var methods int64
		if purpose == "recovery" {
			methods = 16
		}
		sec := env.seedSession(seedSessionOpts{
			ID:                sid,
			UserID:            uOpt,
			Purpose:           purpose,
			AchievedAssurance: 0,
			Methods:           methods,
			AuthenticatedAt:   sql.NullInt64{},
		})
		_, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
			Principal: authz.PrincipalCredentials{
				SessionID:                sid,
				SessionSecret:            sec,
				UntrustedCallerAssurance: 2,
				UntrustedCallerAdmin:     true,
			},
			EndpointID: testLocalEndpointID,
			TargetRef:  "edge-proxy",
			Operation:  authz.OpContainerInspectStatus,
		})
		if !errors.Is(err, authz.ErrUnauthenticated) {
			t.Fatalf("purpose %q: expected 401 ErrUnauthenticated, got %v", purpose, err)
		}
	}

	// 2. Password-only session (AAL1) on mfa_requirement='required' -> rejected (401).
	sidReqAAL1 := authz.SessionID("22000000-0000-4000-8000-000000000010")
	secReqAAL1 := env.seedSession(seedSessionOpts{
		ID:                sidReqAAL1,
		UserID:            uReq,
		AchievedAssurance: 1,
		Methods:           1,
		PhishingResistant: 0,
	})
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: sidReqAAL1, SessionSecret: secReqAAL1, UntrustedCallerAssurance: 2},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("expected 401 for password-only session when mfa_requirement=required, got %v", err)
	}

	// 3. TOTP AAL2 session on mfa_requirement='webauthn' -> rejected (401); WebAuthn UV session -> allowed!
	sidWebTOTP := authz.SessionID("22000000-0000-4000-8000-000000000011")
	secWebTOTP := env.seedSession(seedSessionOpts{
		ID:                sidWebTOTP,
		UserID:            uWebAuthn,
		AchievedAssurance: 2,
		Methods:           3,
		PhishingResistant: 0,
	})
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: sidWebTOTP, SessionSecret: secWebTOTP},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("expected 401 for non-WebAuthn session when mfa_requirement=webauthn, got %v", err)
	}

	sidWebOK := authz.SessionID("22000000-0000-4000-8000-000000000012")
	secWebOK := env.seedSession(seedSessionOpts{
		ID:                sidWebOK,
		UserID:            uWebAuthn,
		AchievedAssurance: 2,
		Methods:           8,
		PhishingResistant: 1,
	})
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: sidWebOK, SessionSecret: secWebOK},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}); err != nil {
		t.Fatalf("expected ALLOW for phishing-resistant WebAuthn session, got %v", err)
	}

	// 4. Admin account with password-only session -> rejected (401) per TD §4.1!
	sidAdminAAL1 := authz.SessionID("22000000-0000-4000-8000-000000000013")
	secAdminAAL1 := env.seedSession(seedSessionOpts{
		ID:                sidAdminAAL1,
		UserID:            uAdminOpt,
		AchievedAssurance: 1,
		Methods:           1,
		PhishingResistant: 0,
	})
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: sidAdminAAL1, SessionSecret: secAdminAAL1},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("expected 401 for admin user with password-only session, got %v", err)
	}

	// 5. Non-admin optional-MFA user with password-only session: allowed for standard op, rejected when RequireAAL2=true!
	sidOptAAL1 := authz.SessionID("22000000-0000-4000-8000-000000000014")
	secOptAAL1 := env.seedSession(seedSessionOpts{
		ID:                sidOptAAL1,
		UserID:            uOpt,
		AchievedAssurance: 1,
		Methods:           1,
		PhishingResistant: 0,
	})
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  authz.PrincipalCredentials{SessionID: sidOptAAL1, SessionSecret: secOptAAL1},
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectStatus,
	}); err != nil {
		t.Fatalf("expected ALLOW for optional-MFA user on standard operation, got %v", err)
	}
	if _, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
		Principal:   authz.PrincipalCredentials{SessionID: sidOptAAL1, SessionSecret: secOptAAL1},
		EndpointID:  testLocalEndpointID,
		TargetRef:   "edge-proxy",
		Operation:   authz.OpContainerInspectStatus,
		RequireAAL2: true,
	}); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("expected 401 when RequireAAL2=true for password-only session, got %v", err)
	}
}

// P1.18.4 P111-NIT-missing-credential-row: a verified, ACTIVE agent that holds an explicit ALLOW for
// every operation is still refused (401, no decision) when the presented credential is absent from
// storage or revoked, for all six operation keys, with zero operational backend attempts. The
// control row proves the same agent+policy succeeds with its real credential, so the credential is
// the only varied input. (Complements the C1 wrong-token fixture in c1_substrate_test.go.)
func TestMissingAgentCredentialRefusedAcrossAllOperations(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	now := env.clock.Now().Unix()
	env.seedSelector(store.ContainerSelector{ID: string(testSelectorID1), EndpointID: testLocalEndpointID, ContainerName: "edge-proxy"})
	env.seedUser(seedUserOpts{ID: testUserID1, Username: "agent_owner"})
	env.seedAgent(seedAgentOpts{ID: testAgentID1, Name: "cred-less-agent", OwnerUserID: sql.NullString{String: string(testUserID1), Valid: true}})
	liveToken := env.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID1, AgentID: testAgentID1})
	revokedToken := env.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID2, AgentID: testAgentID1, State: "revoked", RevokedAt: sql.NullInt64{Int64: now - 10, Valid: true}})
	for i, op := range authz.AllOperations() {
		env.seedPolicy(store.Policy{
			ID: fmt.Sprintf("72000000-0000-4000-8000-%012d", i+1), AgentID: sql.NullString{String: string(testAgentID1), Valid: true},
			EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(op), Effect: "ALLOW", State: "active", AuthorityGeneration: 1,
		})
	}
	if got := len(authz.AllOperations()); got != 6 {
		t.Fatalf("expected the six Phase 1 operation keys, got %d", got)
	}
	cases := []struct {
		name  string
		creds authz.PrincipalCredentials
		ok    bool
	}{
		{"control_live_credential", authz.PrincipalCredentials{AgentCredentialID: testCredID1, AgentToken: liveToken}, true},
		{"absent_credential_id", authz.PrincipalCredentials{AgentCredentialID: "50000000-0000-4000-8000-0000000000ff", AgentToken: "mdt_p1184_synthetic_absent_credential_0123456789"}, false},
		{"absent_credential_token_only", authz.PrincipalCredentials{AgentToken: "mdt_p1184_synthetic_absent_credential_abcdef0123"}, false},
		{"revoked_credential", authz.PrincipalCredentials{AgentCredentialID: testCredID2, AgentToken: revokedToken}, false},
		{"live_id_with_absent_token", authz.PrincipalCredentials{AgentCredentialID: testCredID1, AgentToken: "mdt_p1184_synthetic_wrong_secret_0123456789"}, false},
	}
	for _, tc := range cases {
		for _, op := range authz.AllOperations() {
			t.Run(tc.name+"/"+string(op), func(t *testing.T) {
				before := env.backend.Counters().TotalOperational()
				_, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{Principal: tc.creds, EndpointID: testLocalEndpointID, TargetRef: "edge-proxy", Operation: op})
				if tc.ok {
					if err != nil {
						t.Fatalf("control must be allowed: %v", err)
					}
					return
				}
				if !errors.Is(err, authz.ErrUnauthenticated) || authz.StatusCode(err) != http.StatusUnauthorized {
					t.Fatalf("expected 401 ErrUnauthenticated, got %v", err)
				}
				if got := env.backend.Counters().TotalOperational(); got != before {
					t.Fatalf("%d operational backend attempts for a credential-less agent", got-before)
				}
			})
		}
	}
}
