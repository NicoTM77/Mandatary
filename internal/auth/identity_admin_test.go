package auth

import (
	"errors"
	"testing"
)

// P1.17 identity lifecycle: disable/enable users, groups and agents, group deletion and owner
// transfer. Every method runs inside the same fresh-administrator transaction as P1.10 (the
// privilege-escalation matrices in agents_authority_test.go drive them through adminCalls), and the
// cascades below are the behaviour the management screens describe in words.

// ownedAgentWithToken creates an agent owned by userID (or groupID when userID is empty) and issues its token.
func (e *adminEnv) ownedAgentWithToken(name, userID, groupID string) (string, []byte) {
	e.t.Helper()
	a, err := e.a.CreateAgent(e.t.Context(), e.secret, AgentRequest{Name: name, OwnerUserID: userID, OwnerGroupID: groupID})
	if err != nil {
		e.t.Fatal(err)
	}
	_, token := e.issue(a.ID, CredentialRequest{})
	if !e.accepted(token) {
		e.t.Fatalf("fixture token for %s is not accepted", name)
	}
	return a.ID, token
}

func (e *adminEnv) agentState(id string) string {
	e.t.Helper()
	var s string
	if err := e.db.QueryRow(`SELECT state FROM agents WHERE id=?`, id).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *adminEnv) userState(id string) string {
	e.t.Helper()
	var s string
	if err := e.db.QueryRow(`SELECT state FROM users WHERE id=?`, id).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *adminEnv) groupState(id string) string {
	e.t.Helper()
	var s string
	if err := e.db.QueryRow(`SELECT state FROM groups WHERE id=?`, id).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func TestDisablingAUserEndsItsSessionsAndRevokesTheAgentsItOwns(t *testing.T) { // owner-state cascade
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	alice := e.person("alice")
	owned, token := e.ownedAgentWithToken("alice-bot", alice, "")
	other := e.person("bob")
	otherAgent, otherToken := e.ownedAgentWithToken("bob-bot", other, "")
	grp := e.group("ops")
	if err := e.a.AddMember(ctx, e.secret, grp, MemberAgent, owned); err != nil {
		t.Fatal(err)
	}
	e.exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,authenticated_at,created_at,expires_at,last_activity_at,credential_generation,session_generation,state) VALUES('alice-s',?,randomblob(32),'normal',2,3,1,1,3601,1,1,1,'active')`, alice)
	before := e.notifications()

	if err := e.a.DisableUser(ctx, e.secret, alice); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if e.userState(alice) != "disabled" {
		t.Fatal("user is not disabled")
	}
	if got := e.scalar(`SELECT count(*) FROM sessions WHERE user_id=? AND state!='revoked'`, alice); got != 0 {
		t.Fatalf("%d sessions of the disabled user are still live", got)
	}
	if e.agentState(owned) != "disabled" || e.accepted(token) {
		t.Fatal("an agent owned by the disabled user must be disabled and its token refused")
	}
	if e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state!='revoked'`, owned) != 0 {
		t.Fatal("the owned agent still has a live credential row")
	}
	if e.agentState(otherAgent) != "active" || !e.accepted(otherToken) {
		t.Fatal("another user's agent was affected")
	}
	// Memberships are kept (disable is reversible), they simply grant nothing while the agent is disabled.
	if e.scalar(`SELECT count(*) FROM agent_group_memberships WHERE agent_id=? AND group_id=? AND state='active'`, owned, grp) != 1 {
		t.Fatal("membership was deleted by the cascade")
	}
	if e.notifications() != before+1 {
		t.Fatalf("expected exactly one policy notification after the commit, got %d", e.notifications()-before)
	}
	// Repeating is harmless and still notifies, so a failed notification can be retried.
	if err := e.a.DisableUser(ctx, e.secret, alice); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if e.notifications() != before+2 {
		t.Fatal("a repeat did not notify")
	}
}

func TestEnablingAUserDoesNotReviveItsAgentsOrTokens(t *testing.T) {
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	alice := e.person("alice")
	owned, token := e.ownedAgentWithToken("alice-bot", alice, "")
	if err := e.a.DisableUser(ctx, e.secret, alice); err != nil {
		t.Fatal(err)
	}
	if err := e.a.EnableUser(ctx, e.secret, alice); err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	if e.userState(alice) != "active" {
		t.Fatal("user not active again")
	}
	if e.agentState(owned) != "disabled" || e.accepted(token) {
		t.Fatal("enabling the owner must not re-enable the agent or revive its revoked token")
	}
	if err := e.a.EnableUser(ctx, e.secret, alice); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling an active user: %v", err)
	}
}

func TestUserLifecycleRefusals(t *testing.T) {
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	alice := e.person("alice")
	// The one policy administrator has no lifecycle controls: disabling it would lock administration out.
	if err := e.a.DisableUser(ctx, e.secret, "u"); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("disabling the administrator: %v", err)
	}
	if e.userState("u") != "active" {
		t.Fatal("administrator was changed")
	}
	if err := e.a.DisableUser(ctx, e.secret, "no-such-user"); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := e.a.DisableUser(ctx, e.secret, "bad id!"); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("malformed: %v", err)
	}
	// A restored (quarantined), compromised or stale-generation account can only be approved by the restore flow.
	e.exec(`UPDATE users SET state='disabled' WHERE id=?`, alice)
	e.exec(`UPDATE users SET compromised=1 WHERE id=?`, alice)
	if err := e.a.EnableUser(ctx, e.secret, alice); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("compromised: %v", err)
	}
	e.exec(`UPDATE users SET compromised=0, authority_generation=0, state='quarantined' WHERE id=?`, alice)
	if err := e.a.EnableUser(ctx, e.secret, alice); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("quarantined: %v", err)
	}
	if e.userState(alice) != "quarantined" {
		t.Fatal("a refused enable changed the account")
	}
}

func TestDisablingAGroupRevokesTheAgentsItOwnsAndKeepsMembers(t *testing.T) {
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	grp := e.group("platform")
	member := e.person("carol")
	if err := e.a.AddMember(ctx, e.secret, grp, MemberUser, member); err != nil {
		t.Fatal(err)
	}
	owned, token := e.ownedAgentWithToken("shared-bot", "", grp)
	loose, looseToken := e.ownedAgentWithToken("loose-bot", e.person("dave"), "")
	if err := e.a.AddMember(ctx, e.secret, grp, MemberAgent, loose); err != nil {
		t.Fatal(err)
	}
	before := e.notifications()
	if err := e.a.DisableGroup(ctx, e.secret, grp); err != nil {
		t.Fatalf("DisableGroup: %v", err)
	}
	if e.groupState(grp) != "disabled" {
		t.Fatal("group still active")
	}
	if e.agentState(owned) != "disabled" || e.accepted(token) {
		t.Fatal("an agent the group owns must be disabled with its tokens revoked")
	}
	// A member agent is not owned by the group: it stays active (it merely loses what the group granted).
	if e.agentState(loose) != "active" || !e.accepted(looseToken) {
		t.Fatal("a member agent must not be disabled by the group's state")
	}
	if e.scalar(`SELECT count(*) FROM user_group_memberships WHERE group_id=? AND state='active'`, grp) != 1 {
		t.Fatal("memberships were not kept")
	}
	if e.notifications() != before+1 {
		t.Fatal("the group disable did not notify exactly once")
	}
	if err := e.a.EnableGroup(ctx, e.secret, grp); err != nil {
		t.Fatalf("EnableGroup: %v", err)
	}
	if e.groupState(grp) != "active" || e.agentState(owned) != "disabled" {
		t.Fatal("enabling a group must not re-enable the agents it owns")
	}
	if err := e.a.EnableGroup(ctx, e.secret, grp); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling an active group: %v", err)
	}
	if err := e.a.DisableGroup(ctx, e.secret, "nope"); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("unknown group: %v", err)
	}
}

func TestDeletingAGroupIsRefusedWhileAnythingStillReliesOnIt(t *testing.T) {
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	member := e.person("carol")
	for _, c := range []struct {
		name, group string
		setup       func(grp string)
	}{
		{"an active member", "g-member", func(grp string) {
			if err := e.a.AddMember(ctx, e.secret, grp, MemberUser, member); err != nil {
				t.Fatal(err)
			}
		}},
		{"an owned agent", "g-owner", func(grp string) { e.agentOwnedByGroup("owned-bot", grp) }},
		{"a rule naming it", "g-rule", func(grp string) { e.seedRule("group_id", grp) }},
	} {
		grp := e.group(c.group)
		c.setup(grp)
		before := e.snapshot()
		if err := e.a.DeleteGroup(ctx, e.secret, grp); !errors.Is(err, ErrAdminConflict) {
			t.Errorf("%s: %v", c.name, err)
		}
		e.mustNoChange("refused group delete ("+c.name+")", before)
	}
	// Removed (disabled) memberships do not block, and are deleted with the group.
	grp := e.group("empty")
	if err := e.a.AddMember(ctx, e.secret, grp, MemberUser, member); err != nil {
		t.Fatal(err)
	}
	if err := e.a.RemoveMember(ctx, e.secret, grp, MemberUser, member); err != nil {
		t.Fatal(err)
	}
	before := e.notifications()
	if err := e.a.DeleteGroup(ctx, e.secret, grp); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if e.scalar(`SELECT count(*) FROM groups WHERE id=?`, grp) != 0 || e.scalar(`SELECT count(*) FROM user_group_memberships WHERE group_id=?`, grp) != 0 {
		t.Fatal("group or its removed memberships remain")
	}
	if e.notifications() != before+1 {
		t.Fatal("group deletion did not notify")
	}
	if err := e.a.DeleteGroup(ctx, e.secret, grp); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func (e *adminEnv) agentOwnedByGroup(name, groupID string) string {
	e.t.Helper()
	a, err := e.a.CreateAgent(e.t.Context(), e.secret, AgentRequest{Name: name, OwnerGroupID: groupID})
	if err != nil {
		e.t.Fatal(err)
	}
	return a.ID
}

// seedRule stores a bare active allow rule naming the given subject column (fixture only: the rule service is
// exercised by policy_admin_test.go).
func (e *adminEnv) seedRule(column, subject string) {
	e.t.Helper()
	ep := e.localEndpoint()
	e.exec(`INSERT OR IGNORE INTO container_selectors(id,endpoint_id,container_name) VALUES('sel-seed',?, 'web')`, ep)
	e.exec(`INSERT INTO policies(id,`+column+`,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES(?,?,?,'sel-seed','container:logs','ALLOW','active',1)`, "pol-"+subject, subject, ep)
}

func (e *adminEnv) localEndpoint() string {
	e.t.Helper()
	var id string
	if err := e.db.QueryRow(`SELECT id FROM endpoints WHERE slug='local'`).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func TestAgentEnableRequiresAnActiveOwnerAndIssuesNoToken(t *testing.T) {
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	alice := e.person("alice")
	ag, token := e.ownedAgentWithToken("bot", alice, "")
	if err := e.a.DisableAgent(ctx, e.secret, ag); err != nil {
		t.Fatal(err)
	}
	if err := e.a.EnableAgent(ctx, e.secret, ag); err != nil {
		t.Fatalf("EnableAgent: %v", err)
	}
	if e.agentState(ag) != "active" {
		t.Fatal("agent still disabled")
	}
	if e.accepted(token) || e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state!='revoked'`, ag) != 0 {
		t.Fatal("enabling an agent revived a revoked credential")
	}
	if err := e.a.EnableAgent(ctx, e.secret, ag); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling an active agent: %v", err)
	}
	// An agent whose owner is not active cannot be enabled: its accountable party is gone.
	if err := e.a.DisableUser(ctx, e.secret, alice); err != nil {
		t.Fatal(err)
	}
	if e.agentState(ag) != "disabled" {
		t.Fatal("cascade did not disable the agent")
	}
	if err := e.a.EnableAgent(ctx, e.secret, ag); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling an agent with a disabled owner: %v", err)
	}
}

func TestTransferringAnAgentChangesOnlyAccountability(t *testing.T) {
	t.Parallel()
	e := newAdminEnv(t)
	ctx := t.Context()
	alice, bob := e.person("alice"), e.person("bob")
	grp := e.group("ops")
	ag, token := e.ownedAgentWithToken("bot", alice, "")
	if err := e.a.AddMember(ctx, e.secret, grp, MemberAgent, ag); err != nil {
		t.Fatal(err)
	}
	e.seedRule("agent_id", ag)
	before := e.snapshot()
	creds := e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state='active'`, ag)

	if err := e.a.TransferAgent(ctx, e.secret, ag, AgentOwner{GroupID: grp}); err != nil {
		t.Fatalf("to group: %v", err)
	}
	var ownerUser, ownerGroup *string
	if err := e.db.QueryRow(`SELECT owner_user_id,owner_group_id FROM agents WHERE id=?`, ag).Scan(&ownerUser, &ownerGroup); err != nil {
		t.Fatal(err)
	}
	if ownerUser != nil || ownerGroup == nil || *ownerGroup != grp {
		t.Fatalf("owner after transfer: user=%v group=%v", ownerUser, ownerGroup)
	}
	if err := e.a.TransferAgent(ctx, e.secret, ag, AgentOwner{UserID: bob}); err != nil {
		t.Fatalf("to user: %v", err)
	}
	after := e.snapshot()
	for _, table := range []string{"policies", "agent_group_memberships", "user_group_memberships", "agent_credentials", "users", "groups", "administrative_roles"} {
		if after[table] != before[table] {
			t.Errorf("transfer changed %s", table)
		}
	}
	if !e.accepted(token) || e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state='active'`, ag) != creds {
		t.Fatal("transfer changed the agent's credentials")
	}
	// Exactly one owner, and only an active one.
	for name, o := range map[string]AgentOwner{"both": {UserID: alice, GroupID: grp}, "neither": {}, "unknown user": {UserID: "ghost"}, "unknown group": {GroupID: "ghost"}, "malformed": {UserID: "bad id"}} {
		if err := e.a.TransferAgent(ctx, e.secret, ag, o); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := e.a.DisableUser(ctx, e.secret, alice); err != nil {
		t.Fatal(err)
	}
	if err := e.a.TransferAgent(ctx, e.secret, ag, AgentOwner{UserID: alice}); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("a disabled owner: %v", err)
	}
	if err := e.a.TransferAgent(ctx, e.secret, "ghost-agent", AgentOwner{UserID: bob}); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
}
