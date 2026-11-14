package backup

import (
	"strings"
	"unicode/utf8"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

// Scope is the documented backup scope (TD 6.3): users, groups, agent definitions, container
// policy rules, endpoint definitions and the security-relevant settings of principals, plus the
// identity of each credential that existed. Sessions, rate-limit counters, usage aggregates,
// setup/recovery control state, security notices and every local control value are NOT here.
//
// SourceState fields record what the exporting installation said. They are informational for the
// reviewing administrator and are NEVER read by the importer to decide a state or generation.
type Scope struct {
	Endpoints        []EndpointRecord        `json:"endpoints"`
	Users            []UserRecord            `json:"users"`
	Groups           []GroupRecord           `json:"groups"`
	Agents           []AgentRecord           `json:"agents"`
	UserMemberships  []UserMembershipRecord  `json:"user_memberships"`
	AgentMemberships []AgentMembershipRecord `json:"agent_memberships"`
	Roles            []RoleRecord            `json:"roles"`
	Selectors        []SelectorRecord        `json:"selectors"`
	Policies         []PolicyRecord          `json:"policies"`
	Addresses        []AddressRecord         `json:"addresses"`
	Authenticators   []AuthenticatorRecord   `json:"authenticators"`
	AgentCredentials []AgentCredentialRecord `json:"agent_credentials"`
}

type EndpointRecord struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Transport   string `json:"transport"`
	SourceState string `json:"source_state"`
}

type UserRecord struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	MFARequirement string `json:"mfa_requirement"`
	Compromised    bool   `json:"compromised"`
	SourceState    string `json:"source_state"`
}

type GroupRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SourceState string `json:"source_state"`
}

type AgentRecord struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	OwnerUserID  *string `json:"owner_user_id"`
	OwnerGroupID *string `json:"owner_group_id"`
	SourceState  string  `json:"source_state"`
}

type UserMembershipRecord struct {
	UserID      string `json:"user_id"`
	GroupID     string `json:"group_id"`
	SourceState string `json:"source_state"`
}

type AgentMembershipRecord struct {
	AgentID     string `json:"agent_id"`
	GroupID     string `json:"group_id"`
	SourceState string `json:"source_state"`
}

type RoleRecord struct {
	ID          string  `json:"id"`
	UserID      string  `json:"user_id"`
	Role        string  `json:"role"`
	EndpointID  *string `json:"endpoint_id"`
	SourceState string  `json:"source_state"`
}

type SelectorRecord struct {
	ID                string  `json:"id"`
	EndpointID        string  `json:"endpoint_id"`
	ContainerName     string  `json:"container_name"`
	NameIsGlob        bool    `json:"name_is_glob"`
	ComposeProject    *string `json:"compose_project"`
	ComposeService    *string `json:"compose_service"`
	ImagePattern      *string `json:"image_pattern"`
	PinnedContainerID *string `json:"pinned_container_id"`
	PinnedImageDigest *string `json:"pinned_image_digest"`
}

type PolicyRecord struct {
	ID             string  `json:"id"`
	UserID         *string `json:"user_id"`
	GroupID        *string `json:"group_id"`
	AgentID        *string `json:"agent_id"`
	EndpointID     string  `json:"endpoint_id"`
	SelectorID     string  `json:"selector_id"`
	Operation      string  `json:"operation"`
	Effect         string  `json:"effect"`
	LogTailMax     *int64  `json:"log_tail_max"`
	StopTimeoutMax *int64  `json:"stop_timeout_max"`
	SourceState    string  `json:"source_state"`
}

type AddressRecord struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Address   string `json:"address"`
	Version   int64  `json:"version"`
	CreatedAt int64  `json:"created_at"`
}

// AuthenticatorRecord names a credential that existed; everything credential-specific is sealed.
type AuthenticatorRecord struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	Kind        string `json:"kind"`
	SourceState string `json:"source_state"`
}

// AgentCredentialRecord carries the non-secret facts of an agent token: the original issue time and
// expiry are kept exactly (never extended or restarted) so historical expiry stays enforced; the
// token hash is sealed.
type AgentCredentialRecord struct {
	ID                  string `json:"id"`
	AgentID             string `json:"agent_id"`
	DisplayPrefix       string `json:"display_prefix"`
	IssuedAt            int64  `json:"issued_at"`
	ExpiresAt           *int64 `json:"expires_at"`
	NonexpiringApproved bool   `json:"nonexpiring_approved"`
	SourceState         string `json:"source_state"`
}

const (
	maxRecordsPerKind = 20000
	maxNameBytes      = 255
)

var operations = map[string]bool{
	"container:logs": true, "container:inspect_status": true, "container:inspect_config": true,
	"container:start": true, "container:stop": true, "container:restart": true,
}

func validID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

func validText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.TrimSpace(s) != "" && !strings.ContainsAny(s, "\x00\r\n")
}

func validOptionalText(p *string, max int) bool {
	return p == nil || (len(*p) <= max && utf8.ValidString(*p) && !strings.ContainsAny(*p, "\x00\r\n"))
}

func validState(s string) bool {
	switch s {
	case "active", "quarantined", "disabled", "revoked", "pending":
		return true
	}
	return false
}

// validateScope checks that the scope is a consistent snapshot WITHOUT touching storage. It is the
// first of two defences: the import transaction runs SQLite's own foreign-key check again before
// commit. The error names a rule, never a value.
func validateScope(s Scope, mode Mode) error {
	for _, n := range []int{len(s.Endpoints), len(s.Users), len(s.Groups), len(s.Agents), len(s.UserMemberships), len(s.AgentMemberships), len(s.Roles), len(s.Selectors), len(s.Policies), len(s.Addresses), len(s.Authenticators), len(s.AgentCredentials)} {
		if n > maxRecordsPerKind {
			return inconsistent("limit")
		}
	}
	// Phase 1 has exactly one endpoint: the local unix endpoint. Remote endpoints may be described
	// only inactive in a later phase, so an archive naming any other endpoint is refused.
	if len(s.Endpoints) != 1 {
		return inconsistent("endpoint_scope")
	}
	ep := s.Endpoints[0]
	if _, err := domain.ParseEndpointID(ep.ID); err != nil || ep.Slug != "local" || ep.Transport != "unix" || !validText(ep.Name, maxNameBytes) || !validState(ep.SourceState) {
		return inconsistent("endpoint_scope")
	}
	users := map[string]bool{}
	names := map[string]bool{}
	for _, u := range s.Users {
		if !validID(u.ID) || !validText(u.Username, maxNameBytes) || users[u.ID] || names[u.Username] || !validState(u.SourceState) {
			return inconsistent("user")
		}
		switch u.MFARequirement {
		case "optional", "required", "webauthn":
		default:
			return inconsistent("user")
		}
		users[u.ID], names[u.Username] = true, true
	}
	groups := map[string]bool{}
	names = map[string]bool{}
	for _, g := range s.Groups {
		if !validID(g.ID) || !validText(g.Name, maxNameBytes) || groups[g.ID] || names[g.Name] || !validState(g.SourceState) {
			return inconsistent("group")
		}
		groups[g.ID], names[g.Name] = true, true
	}
	agents := map[string]bool{}
	names = map[string]bool{}
	for _, a := range s.Agents {
		if !validID(a.ID) || !validText(a.Name, maxNameBytes) || agents[a.ID] || names[a.Name] || !validState(a.SourceState) {
			return inconsistent("agent")
		}
		if (a.OwnerUserID != nil) == (a.OwnerGroupID != nil) {
			return inconsistent("agent_owner")
		}
		if (a.OwnerUserID != nil && !users[*a.OwnerUserID]) || (a.OwnerGroupID != nil && !groups[*a.OwnerGroupID]) {
			return inconsistent("unknown_reference")
		}
		agents[a.ID], names[a.Name] = true, true
	}
	seen := map[[2]string]bool{}
	for _, m := range s.UserMemberships {
		k := [2]string{m.UserID, m.GroupID}
		if !users[m.UserID] || !groups[m.GroupID] || seen[k] || !validState(m.SourceState) {
			return inconsistent("user_membership")
		}
		seen[k] = true
	}
	seen = map[[2]string]bool{}
	for _, m := range s.AgentMemberships {
		k := [2]string{m.AgentID, m.GroupID}
		if !agents[m.AgentID] || !groups[m.GroupID] || seen[k] || !validState(m.SourceState) {
			return inconsistent("agent_membership")
		}
		seen[k] = true
	}
	roles := map[string]bool{}
	for _, r := range s.Roles {
		if !validID(r.ID) || roles[r.ID] || !users[r.UserID] || !validState(r.SourceState) {
			return inconsistent("role")
		}
		switch {
		case r.Role == "super_admin" && r.EndpointID == nil:
		case r.Role == "endpoint_admin" && r.EndpointID != nil && *r.EndpointID == ep.ID:
		default:
			return inconsistent("role")
		}
		roles[r.ID] = true
	}
	selectors := map[string]SelectorRecord{}
	for _, sel := range s.Selectors {
		if !validID(sel.ID) || sel.EndpointID != ep.ID || !validText(sel.ContainerName, maxNameBytes) || selectors[sel.ID].ID != "" ||
			!validOptionalText(sel.ComposeProject, maxNameBytes) || !validOptionalText(sel.ComposeService, maxNameBytes) || !validOptionalText(sel.ImagePattern, maxNameBytes) ||
			!validOptionalText(sel.PinnedContainerID, maxNameBytes) || !validOptionalText(sel.PinnedImageDigest, maxNameBytes) {
			return inconsistent("selector")
		}
		selectors[sel.ID] = sel
	}
	policies := map[string]bool{}
	for _, p := range s.Policies {
		subjects := 0
		for _, ref := range []struct {
			id  *string
			set map[string]bool
		}{{p.UserID, users}, {p.GroupID, groups}, {p.AgentID, agents}} {
			if ref.id != nil {
				subjects++
				if !ref.set[*ref.id] {
					return inconsistent("unknown_reference")
				}
			}
		}
		sel, ok := selectors[p.SelectorID]
		if !validID(p.ID) || policies[p.ID] || subjects != 1 || !ok || sel.EndpointID != p.EndpointID || p.EndpointID != ep.ID ||
			!operations[p.Operation] || (p.Effect != "ALLOW" && p.Effect != "DENY") || !validState(p.SourceState) ||
			(p.LogTailMax != nil && (*p.LogTailMax < 1 || *p.LogTailMax > 10000)) || (p.StopTimeoutMax != nil && (*p.StopTimeoutMax < 1 || *p.StopTimeoutMax > 300)) {
			return inconsistent("policy")
		}
		policies[p.ID] = true
	}
	addresses := map[string]bool{}
	for _, a := range s.Addresses {
		if !validID(a.ID) || addresses[a.ID] || !users[a.UserID] || len(a.Address) < 3 || len(a.Address) > 254 || !utf8.ValidString(a.Address) ||
			strings.ContainsAny(a.Address, "\x00\r\n") || a.Version < 1 || a.CreatedAt < 0 {
			return inconsistent("address")
		}
		addresses[a.ID] = true
	}
	if mode == ModeClean && (len(s.Authenticators) != 0 || len(s.AgentCredentials) != 0) {
		return inconsistent("clean_carries_credentials")
	}
	auths := map[string]string{}
	for _, a := range s.Authenticators {
		switch a.Kind {
		case "password", "totp", "webauthn", "recovery_code":
		default:
			return inconsistent("authenticator")
		}
		if !validID(a.ID) || auths[a.ID] != "" || !users[a.UserID] || a.SourceState != "active" {
			return inconsistent("authenticator")
		}
		auths[a.ID] = a.Kind
	}
	creds := map[string]bool{}
	for _, c := range s.AgentCredentials {
		if !validID(c.ID) || creds[c.ID] || !agents[c.AgentID] || len(c.DisplayPrefix) < 1 || len(c.DisplayPrefix) > 16 || !utf8.ValidString(c.DisplayPrefix) ||
			c.IssuedAt < 0 || (c.ExpiresAt != nil && *c.ExpiresAt <= c.IssuedAt) || (c.ExpiresAt == nil && !c.NonexpiringApproved) || c.SourceState != "active" {
			return inconsistent("agent_credential")
		}
		creds[c.ID] = true
	}
	return nil
}
