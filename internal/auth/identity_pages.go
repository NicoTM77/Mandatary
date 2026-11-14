package auth

import (
	"context"
	"fmt"
	"sort"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.17 page-shaped administrative reads for the Users, Groups and Agents screens. Each is one consistent
// repository snapshot (Repository.Read) behind the same administrator check as every other administrative
// read, carries no credential, verifier or token, and decides server-side what the page may only display:
// who is the administrator, what blocks a deletion, how many rules name a subject.

// Removal is whether something can be deleted, decided here and never by the page. Blockers are short plain
// phrases naming what still relies on it.
type Removal struct {
	Allowed  bool     `json:"allowed"`
	Blockers []string `json:"blockers"`
}

type NamedView struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type UserPageRow struct {
	ID            string   `json:"id"`
	Username      string   `json:"username"`
	State         string   `json:"state"`
	Administrator bool     `json:"administrator"`
	Groups        []string `json:"groups"`
	OwnedAgents   []string `json:"owned_agents"`
	RuleCount     int      `json:"rule_count"`
	Removal       Removal  `json:"removal"`
}

type MemberPageRow struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Membership string `json:"membership"`
}

type GroupPageRow struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	State       string          `json:"state"`
	Members     []MemberPageRow `json:"members"`
	OwnedAgents []string        `json:"owned_agents"`
	RuleCount   int             `json:"rule_count"`
	Removal     Removal         `json:"removal"`
}

type GroupsPage struct {
	Groups     []GroupPageRow `json:"groups"`
	Candidates struct {
		Users  []NamedView `json:"users"`
		Agents []NamedView `json:"agents"`
	} `json:"candidates"`
}

type OwnerView struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type AgentPageRow struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	State      string    `json:"state"`
	Owner      OwnerView `json:"owner"`
	Groups     []string  `json:"groups"`
	LiveTokens int       `json:"live_tokens"`
	RuleCount  int       `json:"rule_count"`
	Removal    Removal   `json:"removal"`
}

type AgentsPage struct {
	Agents []AgentPageRow `json:"agents"`
	Owners struct {
		Users  []NamedView `json:"users"`
		Groups []NamedView `json:"groups"`
	} `json:"owners"`
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// identityFacts is everything the three pages derive from, read once.
type identityFacts struct {
	c        store.InstallationControl
	now      int64
	users    []store.User
	groups   []store.Group
	agents   []store.Agent
	policies []store.Policy
	// active (effective) membership group names per member and member lists per group
	userGroups, agentGroups map[string][]string
	groupUsers              map[string][]store.UserGroupMembership
	groupAgentMem           map[string][]store.AgentGroupMembership
	admins                  map[string]bool
	creds                   map[string][]store.AgentCredential
}

func readIdentityFacts(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) (*identityFacts, error) {
	f := &identityFacts{c: c, now: now, userGroups: map[string][]string{}, agentGroups: map[string][]string{}, groupUsers: map[string][]store.UserGroupMembership{},
		groupAgentMem: map[string][]store.AgentGroupMembership{}, admins: map[string]bool{}, creds: map[string][]store.AgentCredential{}}
	var err error
	if f.users, err = q.ListUsers(ctx); err != nil {
		return nil, err
	}
	if f.groups, err = q.ListGroups(ctx); err != nil {
		return nil, err
	}
	if f.agents, err = q.ListAgents(ctx); err != nil {
		return nil, err
	}
	if f.policies, err = allPolicies(ctx, q); err != nil {
		return nil, err
	}
	groupName := map[string]string{}
	for _, g := range f.groups {
		groupName[g.ID] = g.Name
	}
	for _, u := range f.users {
		if f.admins[u.ID], err = isAdministratorAccount(ctx, q, u.ID); err != nil {
			return nil, err
		}
	}
	for _, g := range f.groups {
		um, e := q.ListGroupUserMemberships(ctx, g.ID)
		if e != nil {
			return nil, e
		}
		f.groupUsers[g.ID] = um
		for _, m := range um {
			if effectiveMembership(m.State, m.AuthorityGeneration, c) {
				f.userGroups[m.UserID] = append(f.userGroups[m.UserID], g.Name)
			}
		}
		am, e := q.ListGroupAgentMemberships(ctx, g.ID)
		if e != nil {
			return nil, e
		}
		f.groupAgentMem[g.ID] = am
		for _, m := range am {
			if effectiveMembership(m.State, m.AuthorityGeneration, c) {
				f.agentGroups[m.AgentID] = append(f.agentGroups[m.AgentID], g.Name)
			}
		}
	}
	for _, ag := range f.agents {
		if f.creds[ag.ID], err = q.ListAgentMachineRecords(ctx, ag.ID); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func effectiveMembership(state string, generation int64, c store.InstallationControl) bool {
	return state == "active" && generation == c.AuthorityGeneration
}

func (f *identityFacts) ruleCount(kind, id string) int {
	n := 0
	for _, p := range f.policies {
		switch kind {
		case "user":
			if p.UserID.Valid && p.UserID.String == id {
				n++
			}
		case "group":
			if p.GroupID.Valid && p.GroupID.String == id {
				n++
			}
		default:
			if p.AgentID.Valid && p.AgentID.String == id {
				n++
			}
		}
	}
	return n
}

func (f *identityFacts) ownedAgents(userID, groupID string) []string {
	out := []string{}
	for _, ag := range f.agents {
		if (userID != "" && ag.OwnerUserID.Valid && ag.OwnerUserID.String == userID) || (groupID != "" && ag.OwnerGroupID.Valid && ag.OwnerGroupID.String == groupID) {
			out = append(out, ag.Name)
		}
	}
	return out
}

func sortedNames(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// UsersPage lists every user with what the Users screen displays.
func (a *Admin) UsersPage(ctx context.Context, secret []byte) ([]UserPageRow, error) {
	out := []UserPageRow{}
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		f, e := readIdentityFacts(ctx, q, c, now)
		if e != nil {
			return e
		}
		for _, u := range f.users {
			out = append(out, UserPageRow{
				ID: u.ID, Username: u.Username, State: u.State, Administrator: f.admins[u.ID], Groups: sortedNames(f.userGroups[u.ID]), OwnedAgents: sortedNames(f.ownedAgents(u.ID, "")),
				RuleCount: f.ruleCount("user", u.ID),
				// Accounts keep their history (sessions, usage and security events refer to them), so Phase 1 offers
				// disabling and never deletion. The page does not offer a Delete control for it.
				Removal: Removal{Allowed: false, Blockers: []string{"accounts are disabled, not deleted"}},
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GroupsPage lists every group with its members (any member state except removed) and the people and agents
// that could be added.
func (a *Admin) GroupsPage(ctx context.Context, secret []byte) (GroupsPage, error) {
	page := GroupsPage{Groups: []GroupPageRow{}}
	page.Candidates.Users, page.Candidates.Agents = []NamedView{}, []NamedView{}
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		f, e := readIdentityFacts(ctx, q, c, now)
		if e != nil {
			return e
		}
		userName, agentName := map[string]store.User{}, map[string]store.Agent{}
		for _, u := range f.users {
			userName[u.ID] = u
			page.Candidates.Users = append(page.Candidates.Users, NamedView{ID: u.ID, Name: u.Username, State: u.State})
		}
		for _, ag := range f.agents {
			agentName[ag.ID] = ag
			page.Candidates.Agents = append(page.Candidates.Agents, NamedView{ID: ag.ID, Name: ag.Name, State: ag.State})
		}
		for _, g := range f.groups {
			row := GroupPageRow{ID: g.ID, Name: g.Name, State: g.State, Members: []MemberPageRow{}, OwnedAgents: sortedNames(f.ownedAgents("", g.ID)), RuleCount: f.ruleCount("group", g.ID)}
			for _, m := range f.groupUsers[g.ID] {
				if m.State == "disabled" {
					continue // removed
				}
				u := userName[m.UserID]
				row.Members = append(row.Members, MemberPageRow{Kind: "user", ID: u.ID, Name: u.Username, State: u.State, Membership: membershipState(m.State, m.AuthorityGeneration, c)})
			}
			for _, m := range f.groupAgentMem[g.ID] {
				if m.State == "disabled" {
					continue
				}
				ag := agentName[m.AgentID]
				row.Members = append(row.Members, MemberPageRow{Kind: "agent", ID: ag.ID, Name: ag.Name, State: ag.State, Membership: membershipState(m.State, m.AuthorityGeneration, c)})
			}
			sort.SliceStable(row.Members, func(i, j int) bool {
				if row.Members[i].Kind != row.Members[j].Kind {
					return row.Members[i].Kind < row.Members[j].Kind
				}
				return row.Members[i].Name < row.Members[j].Name
			})
			blockers, e := groupBlockerPhrases(g, f)
			if e != nil {
				return e
			}
			row.Removal = Removal{Allowed: len(blockers) == 0, Blockers: blockers}
			page.Groups = append(page.Groups, row)
		}
		return nil
	})
	if err != nil {
		return GroupsPage{}, err
	}
	return page, nil
}

// membershipState maps a stored membership to what it does now: a current active one is "active", a restored
// or stale-generation one is "quarantined" (it grants nothing until the restore flow approves it).
func membershipState(state string, generation int64, c store.InstallationControl) string {
	if effectiveMembership(state, generation, c) {
		return "active"
	}
	return "quarantined"
}

// groupBlockerPhrases names what still relies on a group. It decides both the page's Delete state and the
// refusal in DeleteGroup, so the two can never disagree. Removed (disabled) memberships do not block.
func groupBlockerPhrases(g store.Group, f *identityFacts) ([]string, error) {
	blockers := []string{}
	members := 0
	for _, m := range f.groupUsers[g.ID] {
		if m.State != "disabled" {
			members++
		}
	}
	for _, m := range f.groupAgentMem[g.ID] {
		if m.State != "disabled" {
			members++
		}
	}
	if members > 0 {
		blockers = append(blockers, "has "+plural(members, "member", "members"))
	}
	for _, name := range sortedNames(f.ownedAgents("", g.ID)) {
		blockers = append(blockers, "owns agent "+name)
	}
	if n := f.ruleCount("group", g.ID); n > 0 {
		blockers = append(blockers, "has "+plural(n, "rule", "rules"))
	}
	return blockers, nil
}

// AgentsPage lists every agent (identity and ownership only: never a token) and the active owners that can
// be chosen.
func (a *Admin) AgentsPage(ctx context.Context, secret []byte) (AgentsPage, error) {
	page := AgentsPage{Agents: []AgentPageRow{}}
	page.Owners.Users, page.Owners.Groups = []NamedView{}, []NamedView{}
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		f, e := readIdentityFacts(ctx, q, c, now)
		if e != nil {
			return e
		}
		users, groups := map[string]store.User{}, map[string]store.Group{}
		for _, u := range f.users {
			users[u.ID] = u
			page.Owners.Users = append(page.Owners.Users, NamedView{ID: u.ID, Name: u.Username, State: u.State})
		}
		for _, g := range f.groups {
			groups[g.ID] = g
			page.Owners.Groups = append(page.Owners.Groups, NamedView{ID: g.ID, Name: g.Name, State: g.State})
		}
		for _, ag := range f.agents {
			row := AgentPageRow{ID: ag.ID, Name: ag.Name, State: ag.State, Groups: sortedNames(f.agentGroups[ag.ID]), LiveTokens: len(liveCredentials(f.creds[ag.ID], c, now)), RuleCount: f.ruleCount("agent", ag.ID),
				Removal: Removal{Allowed: false, Blockers: []string{"agents are disabled, not deleted"}}}
			if ag.OwnerUserID.Valid {
				u := users[ag.OwnerUserID.String]
				row.Owner = OwnerView{Kind: "user", ID: u.ID, Name: u.Username, State: u.State}
			} else {
				g := groups[ag.OwnerGroupID.String]
				row.Owner = OwnerView{Kind: "group", ID: g.ID, Name: g.Name, State: g.State}
			}
			page.Agents = append(page.Agents, row)
		}
		return nil
	})
	if err != nil {
		return AgentsPage{}, err
	}
	return page, nil
}
