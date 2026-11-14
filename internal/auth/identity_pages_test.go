package auth

import (
	"reflect"
	"strings"
	"testing"
)

// The page-shaped reads decide server-side what the screens may only display. They are secret-free and
// read from one repository snapshot.

func TestIdentityPagesReportOwnershipMembershipRulesAndRemovalFromServerState(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t) // user alice, group ops, agent bot (owned by alice)
	ctx := t.Context()
	if err := e.a.AddMember(ctx, e.secret, e.group, MemberUser, e.user); err != nil {
		t.Fatal(err)
	}
	if err := e.a.AddMember(ctx, e.secret, e.group, MemberAgent, e.agent); err != nil {
		t.Fatal(err)
	}
	e.allow(RuleSubject{Kind: "user", ID: e.user}, name("web"), opLogs, opStatus)
	e.allow(RuleSubject{Kind: "group", ID: e.group}, name("web"), opLogs)
	_, token := e.issue(e.agent, CredentialRequest{})

	users, err := e.a.UsersPage(ctx, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]UserPageRow{}
	for _, u := range users {
		byName[u.Username] = u
	}
	alice := byName["alice"]
	var admin UserPageRow
	for _, u := range users {
		if u.ID == "u" {
			admin = u
		}
	}
	if !admin.Administrator || alice.Administrator {
		t.Fatalf("administrator flag: %+v %+v", admin, alice)
	}
	if !reflect.DeepEqual(alice.Groups, []string{"ops"}) || !reflect.DeepEqual(alice.OwnedAgents, []string{"bot"}) || alice.RuleCount != 2 || alice.State != "active" {
		t.Fatalf("alice %+v", alice)
	}
	if alice.Removal.Allowed || len(alice.Removal.Blockers) == 0 {
		t.Fatalf("accounts are disabled, not deleted: %+v", alice.Removal)
	}

	gp, err := e.a.GroupsPage(ctx, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(gp.Groups) != 1 {
		t.Fatalf("groups %+v", gp.Groups)
	}
	g := gp.Groups[0]
	if g.RuleCount != 1 || len(g.Members) != 2 || g.Removal.Allowed {
		t.Fatalf("group %+v", g)
	}
	if got := strings.Join(g.Removal.Blockers, "; "); got != "has 2 members; has 1 rule" {
		t.Fatalf("blockers %q", got)
	}
	if g.Members[0].Kind != "agent" || g.Members[0].Name != "bot" || g.Members[0].Membership != "active" || g.Members[1].Name != "alice" {
		t.Fatalf("members %+v", g.Members)
	}
	if len(gp.Candidates.Users) < 2 || len(gp.Candidates.Agents) != 1 {
		t.Fatalf("candidates %+v", gp.Candidates)
	}
	// A removed member is not shown; a restored membership is shown as quarantined (grants nothing).
	if err = e.a.RemoveMember(ctx, e.secret, e.group, MemberUser, e.user); err != nil {
		t.Fatal(err)
	}
	e.exec(`UPDATE agent_group_memberships SET state='quarantined', authority_generation=0 WHERE agent_id=?`, e.agent)
	if gp, err = e.a.GroupsPage(ctx, e.secret); err != nil {
		t.Fatal(err)
	}
	if m := gp.Groups[0].Members; len(m) != 1 || m[0].Membership != "quarantined" {
		t.Fatalf("members after removal %+v", m)
	}

	ap, err := e.a.AgentsPage(ctx, e.secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(ap.Agents) != 1 {
		t.Fatalf("agents %+v", ap.Agents)
	}
	a := ap.Agents[0]
	if a.Owner.Kind != "user" || a.Owner.Name != "alice" || a.LiveTokens != 1 || a.RuleCount != 0 || a.State != "active" {
		t.Fatalf("agent %+v", a)
	}
	// The pages carry identity only: never a token, hash or secret.
	if err = e.a.RevokeCredential(ctx, e.secret, e.agent, mustCredentialID(t, e, e.agent)); err != nil {
		t.Fatal(err)
	}
	if ap, _ = e.a.AgentsPage(ctx, e.secret); ap.Agents[0].LiveTokens != 0 {
		t.Fatal("a revoked credential still counts as live")
	}
	for _, page := range []any{users, gp, ap} {
		if strings.Contains(strings.ToLower(mustJSON(t, page)), strings.ToLower(string(token))) {
			t.Fatal("a page carried a token")
		}
	}
}

func TestEmptyGroupCanBeDeletedAndThePageSaysSo(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	gp, err := e.a.GroupsPage(t.Context(), e.secret)
	if err != nil {
		t.Fatal(err)
	}
	if g := gp.Groups[0]; !g.Removal.Allowed || len(g.Removal.Blockers) != 0 || g.Members == nil || g.OwnedAgents == nil {
		t.Fatalf("empty group %+v", g)
	}
}

func mustCredentialID(t *testing.T, e *ruleEnv, agent string) string {
	t.Helper()
	var id string
	if err := e.db.QueryRow(`SELECT id FROM agent_credentials WHERE agent_id=? AND state='active'`, agent).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
