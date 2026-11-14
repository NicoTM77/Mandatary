package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.10 identity/group administration and agent-credential lifecycle (TD §§3.1-3.2).
//
// Authority model. Every method takes only the opaque session secret and decides
// from persisted state inside one Repository.Control transaction (shared lock,
// FULL durability): the caller must hold a live normal AAL2 session of the single
// active super administrator (the administrator's role is the only authority; it
// grants no container operation), mutations additionally need authentication no
// older than 15 minutes (freshSession), and the installation must not be in
// restore quarantine. Nothing a caller says about itself is an input. Phase 1 has
// exactly one policy administrator: no method here creates, grants or moves an
// administrative role, and the schema forbids a second active one.
//
// Agents. An agent has exactly one owner, an active user XOR an active group.
// Ownership is accountability only: it creates no membership and no permission
// (TD §3.1). Credentials are 256-bit bearer tokens (agent_token.go) whose
// plaintext exists solely in the IssuedCredential returned AFTER the creating
// transaction is durable; SQLite holds only the SHA-256. An agent has at most two
// live credentials: the current one and, during a rotation overlap, the one being
// rotated out. Revocation, rotation expiry, expiry and generation changes are
// enforced by the shared authorizer verifier on every request, so no adapter can
// accept a token this service has retired.

// Administration refusals. ErrDenied (the repository-wide opaque refusal) is used
// for every authentication/authorization failure, so a probe learns nothing about
// which check failed. The three request errors are returned only to the caller
// already proven to be the fresh administrator.
var (
	ErrAdminInvalid     = errors.New("invalid administrative request")
	ErrAdminNotFound    = errors.New("administrative target not found")
	ErrAdminConflict    = errors.New("administrative state conflict")
	ErrAdminUnavailable = errors.New("administration unavailable")
)

// Defaults and ceilings. MaxTTL ceiling and MaxOverlap are deployment settings
// bounded here so a mistaken value cannot create an effectively permanent token.
const (
	DefaultCredentialTTL       = 90 * 24 * time.Hour // TD §3.2
	DefaultRotationOverlap     = time.Hour
	DefaultMaxRotationOverlap  = 24 * time.Hour
	hardMaxCredentialTTL       = 10 * 365 * 24 * time.Hour
	maxLiveCredentialsPerAgent = 2
)

// AdminSettings are trusted deployment configuration, never request input.
type AdminSettings struct {
	// DefaultTTL applies when a request names no lifetime; MaxTTL bounds every request.
	DefaultTTL, MaxTTL time.Duration
	// DefaultOverlap applies to a rotation naming none; MaxOverlap bounds it.
	DefaultOverlap, MaxOverlap time.Duration
	// AllowNonExpiring is the administrator-approved exception for non-expiring
	// service tokens (TD §3.2). It is off unless the deployment enables it.
	AllowNonExpiring bool
}

// DefaultAdminSettings returns the approved TD §3.2 policy: 90 day tokens, no
// non-expiring tokens, rotation overlap of one hour (at most 24 hours).
func DefaultAdminSettings() AdminSettings {
	return AdminSettings{DefaultTTL: DefaultCredentialTTL, MaxTTL: DefaultCredentialTTL, DefaultOverlap: DefaultRotationOverlap, MaxOverlap: DefaultMaxRotationOverlap}
}

func whole(d time.Duration) bool { return d >= time.Second && d%time.Second == 0 }

func (s AdminSettings) valid() bool {
	return whole(s.DefaultTTL) && whole(s.MaxTTL) && whole(s.DefaultOverlap) && whole(s.MaxOverlap) &&
		s.DefaultTTL <= s.MaxTTL && s.MaxTTL <= hardMaxCredentialTTL &&
		s.DefaultOverlap <= s.MaxOverlap && s.MaxOverlap <= s.MaxTTL
}

// Admin is the administrative service. It is safe for concurrent use.
type Admin struct {
	l        *Lifecycle
	settings AdminSettings
	random   io.Reader
	notify   func(context.Context) error
	// targets is the optional read-only container source for the policy pages (policy_admin.go).
	targets targetHolder
	// backup is the optional logical backup service (backup_admin.go). Without it the backup and
	// restore routes do not exist.
	backup *backup.Service
	// safetyReset drops the shared self-protection proof (backup_admin.go, WithSafetyReset).
	safetyReset atomic.Pointer[func()]
	// afterVerify is a test-only observation seam (nil in production): it receives the opened
	// archive this Admin owns, right after Verify, so a test can prove it is wiped on every exit
	// path (P1.18.4 P118-L3). It never sees secrets the Verified value does not already export.
	afterVerify func(*backup.Verified)
}

// NewAdmin binds the service to the lifecycle's repository and clock. notify, when
// non-nil, is invoked AFTER every commit that can reduce or change authority
// (revocation, rotation, disabling, membership change) and before the call
// returns, so active leases/streams are revalidated; pass the shared
// authz.Authorizer's NotifyPolicyChange. A notification failure is reported as
// ErrAdminUnavailable but never undoes the already durable change.
func NewAdmin(l *Lifecycle, settings AdminSettings, notify func(context.Context) error) (*Admin, error) {
	if l == nil || l.repo == nil || !settings.valid() {
		return nil, ErrDenied
	}
	return &Admin{l: l, settings: settings, random: rand.Reader, notify: notify}, nil
}

// MemberKind names what a group member is.
type MemberKind string

const (
	MemberUser  MemberKind = "user"
	MemberAgent MemberKind = "agent"
)

// UserView, GroupView and AgentView never carry a credential, verifier or any
// secret. Group membership lists only effective (active, current-generation) members.
type UserView struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	State    string `json:"state"`
}

type GroupView struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	State  string   `json:"state"`
	Users  []string `json:"users"`
	Agents []string `json:"agents"`
}

type AgentView struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	State        string           `json:"state"`
	OwnerUserID  string           `json:"owner_user_id,omitempty"`
	OwnerGroupID string           `json:"owner_group_id,omitempty"`
	Credentials  []CredentialView `json:"credentials"`
}

// AgentRequest names exactly one owner: OwnerUserID XOR OwnerGroupID.
type AgentRequest struct{ Name, OwnerUserID, OwnerGroupID string }

// CredentialRequest selects a lifetime. TTL zero means the configured default.
// NonExpiring requires deployment approval and no TTL.
type CredentialRequest struct {
	TTL         time.Duration
	NonExpiring bool
}

// RotateRequest also selects the overlap during which the credential being
// rotated out stays valid: zero means the configured default, Immediate means no
// overlap (the old token is revoked at once). Overlap and Immediate are exclusive.
type RotateRequest struct {
	CredentialRequest
	Overlap   time.Duration
	Immediate bool
}

// RotationResult carries the new one-time token and the labelled credentials that
// were rotated out (overlapping until their end, or revoked at once).
type RotationResult struct {
	New        IssuedCredential
	RotatedOut []CredentialView
}

func isAdminLogical(err error) bool {
	return errors.Is(err, ErrDenied) || errors.Is(err, ErrAdminInvalid) || errors.Is(err, ErrAdminNotFound) || errors.Is(err, ErrAdminConflict)
}

// requireAdministrator is the single role check: the user holds the ACTIVE super
// administrator role at the CURRENT authority generation. An administrative role
// is never an operation grant (TD §2.1) and endpoint administration is a later phase.
func requireAdministrator(ctx context.Context, q *store.Queries, c store.InstallationControl, u store.User) error {
	roles, err := q.ListUserAdministrativeRoles(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, r := range roles {
		if r.Role == "super_admin" && r.EndpointID == nil && r.State == "active" && r.AuthorityGeneration == c.AuthorityGeneration {
			return nil
		}
	}
	return ErrDenied
}

// mutate runs fn as the fresh administrator in one durable control transaction.
func (a *Admin) mutate(ctx context.Context, secret []byte, fn func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error) error {
	if ctx.Err() != nil {
		return ErrDenied
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var logical error
	err := a.l.repo.Control(bounded, func(q *store.Queries) error {
		now := a.l.now().Unix()
		c, u, _, e := freshSession(bounded, q, secret, now)
		if e == nil {
			if e = requireAdministrator(bounded, q, c, u); e == nil {
				e = fn(bounded, q, c, now)
			}
		}
		if e != nil && isAdminLogical(e) {
			logical = e
		}
		return e
	}, nil)
	if err != nil {
		if logical != nil {
			return logical
		}
		return ErrAdminUnavailable
	}
	return nil
}

// view runs fn as the administrator without the 15-minute freshness requirement.
func (a *Admin) view(ctx context.Context, secret []byte, fn func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error) error {
	if ctx.Err() != nil {
		return ErrDenied
	}
	var logical error
	err := a.l.repo.Read(ctx, func(q *store.Queries) error {
		now := a.l.now().Unix()
		c, u, _, e := sessionWithin(ctx, q, secret, now, -1)
		if e == nil {
			if e = requireAdministrator(ctx, q, c, u); e == nil {
				e = fn(ctx, q, c, now)
			}
		}
		if e != nil && isAdminLogical(e) {
			logical = e
		}
		return e
	})
	if err != nil {
		if logical != nil {
			return logical
		}
		return ErrAdminUnavailable
	}
	return nil
}

// changed notifies the shared authorizer after a durable change.
func (a *Admin) changed(ctx context.Context) error {
	if a.notify == nil {
		return nil
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if a.notify(bounded) != nil {
		return ErrAdminUnavailable
	}
	return nil
}

// validPrincipalID bounds identifiers taken from requests before any lookup.
func validPrincipalID(id string) bool {
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

func (a *Admin) newID() (string, error) { return domain.NewUUID(a.random) }

func notFoundIs(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// activeUser reports whether a user may own or join anything right now.
func activeUser(u store.User, c store.InstallationControl) bool {
	return u.State == "active" && u.Compromised == 0 && u.CredentialGeneration == c.CredentialGeneration && u.AuthorityGeneration == c.AuthorityGeneration
}

func activeGroup(g store.Group, c store.InstallationControl) bool {
	return g.State == "active" && g.AuthorityGeneration == c.AuthorityGeneration
}

func activeAgent(g store.Agent, c store.InstallationControl) bool {
	return g.State == "active" && g.CredentialGeneration == c.CredentialGeneration && g.AuthorityGeneration == c.AuthorityGeneration && g.OwnerUserID.Valid != g.OwnerGroupID.Valid
}

// CreateUser provisions an inert human account: active record, compulsory-MFA
// policy, NO authenticator, session, role, membership or policy. It cannot sign in
// until credentials are enrolled by the account flows (P1.16); creating it grants nothing.
func (a *Admin) CreateUser(ctx context.Context, secret []byte, username string) (UserView, error) {
	var out UserView
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if !validSetupUsername(username) {
			return ErrAdminInvalid
		}
		if _, e := q.GetUserByUsername(ctx, username); e == nil {
			return ErrAdminConflict
		} else if !notFoundIs(e) {
			return e
		}
		id, e := a.newID()
		if e != nil {
			return e
		}
		if e = q.CreateActiveUser(ctx, store.CreateActiveUserParams{ID: id, Username: username, CredentialGeneration: c.CredentialGeneration, AuthorityGeneration: c.AuthorityGeneration}); e != nil {
			return e
		}
		out = UserView{ID: id, Username: username, State: "active"}
		return nil
	})
	if err != nil {
		return UserView{}, err
	}
	return out, nil
}

// CreateGroup provisions an empty group. Groups hold no authority until policies
// (P1.11/P1.17) are written for them and members are added explicitly.
func (a *Admin) CreateGroup(ctx context.Context, secret []byte, name string) (GroupView, error) {
	var out GroupView
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if !validSetupUsername(name) {
			return ErrAdminInvalid
		}
		if _, e := q.GetGroupByName(ctx, name); e == nil {
			return ErrAdminConflict
		} else if !notFoundIs(e) {
			return e
		}
		id, e := a.newID()
		if e != nil {
			return e
		}
		if e = q.CreateActiveGroup(ctx, store.CreateActiveGroupParams{ID: id, Name: name, AuthorityGeneration: c.AuthorityGeneration}); e != nil {
			return e
		}
		out = GroupView{ID: id, Name: name, State: "active", Users: []string{}, Agents: []string{}}
		return nil
	})
	if err != nil {
		return GroupView{}, err
	}
	return out, nil
}

// CreateAgent registers a machine principal with exactly one active owner. It
// issues no credential, joins no group and grants nothing.
func (a *Admin) CreateAgent(ctx context.Context, secret []byte, req AgentRequest) (AgentView, error) {
	var out AgentView
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if !validSetupUsername(req.Name) || (req.OwnerUserID == "") == (req.OwnerGroupID == "") {
			return ErrAdminInvalid
		}
		owner := sql.NullString{}
		ownerGroup := sql.NullString{}
		if req.OwnerUserID != "" {
			if !validPrincipalID(req.OwnerUserID) {
				return ErrAdminInvalid
			}
			u, e := q.GetUser(ctx, req.OwnerUserID)
			if notFoundIs(e) {
				return ErrAdminInvalid
			} else if e != nil {
				return e
			}
			if !activeUser(u, c) {
				return ErrAdminInvalid
			}
			owner = sql.NullString{String: u.ID, Valid: true}
		} else {
			if !validPrincipalID(req.OwnerGroupID) {
				return ErrAdminInvalid
			}
			g, e := q.GetGroup(ctx, req.OwnerGroupID)
			if notFoundIs(e) {
				return ErrAdminInvalid
			} else if e != nil {
				return e
			}
			if !activeGroup(g, c) {
				return ErrAdminInvalid
			}
			ownerGroup = sql.NullString{String: g.ID, Valid: true}
		}
		if _, e := q.GetAgentByName(ctx, req.Name); e == nil {
			return ErrAdminConflict
		} else if !notFoundIs(e) {
			return e
		}
		id, e := a.newID()
		if e != nil {
			return e
		}
		if e = q.CreateActiveAgent(ctx, store.CreateActiveAgentParams{ID: id, Name: req.Name, OwnerUserID: owner, OwnerGroupID: ownerGroup, CredentialGeneration: c.CredentialGeneration, AuthorityGeneration: c.AuthorityGeneration}); e != nil {
			return e
		}
		out = AgentView{ID: id, Name: req.Name, State: "active", OwnerUserID: owner.String, OwnerGroupID: ownerGroup.String, Credentials: []CredentialView{}}
		return nil
	})
	if err != nil {
		return AgentView{}, err
	}
	return out, nil
}

// AddMember makes a user or agent an explicit, active member of a group at the
// current authority generation. Membership is the only way an agent receives a
// group's permissions; adding someone who is already a current member is a no-op.
func (a *Admin) AddMember(ctx context.Context, secret []byte, groupID string, kind MemberKind, memberID string) error {
	changed := false
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if (kind != MemberUser && kind != MemberAgent) || !validPrincipalID(groupID) || !validPrincipalID(memberID) {
			return ErrAdminInvalid
		}
		g, e := q.GetGroup(ctx, groupID)
		if notFoundIs(e) {
			return ErrAdminNotFound
		} else if e != nil {
			return e
		}
		if !activeGroup(g, c) {
			return ErrAdminInvalid
		}
		switch kind {
		case MemberUser:
			u, e := q.GetUser(ctx, memberID)
			if notFoundIs(e) {
				return ErrAdminNotFound
			} else if e != nil {
				return e
			}
			if !activeUser(u, c) {
				return ErrAdminInvalid
			}
			m, e := q.GetUserGroupMembership(ctx, store.GetUserGroupMembershipParams{UserID: u.ID, GroupID: g.ID})
			switch {
			case notFoundIs(e):
				changed = true
				return q.CreateActiveUserGroupMembership(ctx, store.CreateActiveUserGroupMembershipParams{UserID: u.ID, GroupID: g.ID, AuthorityGeneration: c.AuthorityGeneration})
			case e != nil:
				return e
			case m.State == "active" && m.AuthorityGeneration == c.AuthorityGeneration:
				return nil
			case m.State != "disabled":
				return ErrAdminConflict // quarantined/stale: explicit reapproval belongs to restore (P1.18)
			}
			n, e := q.ReenableUserGroupMembership(ctx, store.ReenableUserGroupMembershipParams{UserID: u.ID, GroupID: g.ID, Generation: c.AuthorityGeneration})
			if e != nil || n != 1 {
				return ErrAdminConflict
			}
			changed = true
		default:
			ag, e := q.GetAgent(ctx, memberID)
			if notFoundIs(e) {
				return ErrAdminNotFound
			} else if e != nil {
				return e
			}
			if !activeAgent(ag, c) {
				return ErrAdminInvalid
			}
			m, e := q.GetAgentGroupMembership(ctx, store.GetAgentGroupMembershipParams{AgentID: ag.ID, GroupID: g.ID})
			switch {
			case notFoundIs(e):
				changed = true
				return q.CreateActiveAgentGroupMembership(ctx, store.CreateActiveAgentGroupMembershipParams{AgentID: ag.ID, GroupID: g.ID, AuthorityGeneration: c.AuthorityGeneration})
			case e != nil:
				return e
			case m.State == "active" && m.AuthorityGeneration == c.AuthorityGeneration:
				return nil
			case m.State != "disabled":
				return ErrAdminConflict
			}
			n, e := q.ReenableAgentGroupMembership(ctx, store.ReenableAgentGroupMembershipParams{AgentID: ag.ID, GroupID: g.ID, Generation: c.AuthorityGeneration})
			if e != nil || n != 1 {
				return ErrAdminConflict
			}
			changed = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	if changed {
		return a.changed(ctx)
	}
	return nil
}

// RemoveMember disables a membership immediately. Repeating it is harmless and
// still notifies, so a failed notification can be retried.
func (a *Admin) RemoveMember(ctx context.Context, secret []byte, groupID string, kind MemberKind, memberID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		if (kind != MemberUser && kind != MemberAgent) || !validPrincipalID(groupID) || !validPrincipalID(memberID) {
			return ErrAdminInvalid
		}
		var e error
		if kind == MemberUser {
			if _, e = q.GetUserGroupMembership(ctx, store.GetUserGroupMembershipParams{UserID: memberID, GroupID: groupID}); e == nil {
				_, e = q.DisableUserGroupMembership(ctx, store.DisableUserGroupMembershipParams{UserID: memberID, GroupID: groupID})
			}
		} else {
			if _, e = q.GetAgentGroupMembership(ctx, store.GetAgentGroupMembershipParams{AgentID: memberID, GroupID: groupID}); e == nil {
				_, e = q.DisableAgentGroupMembership(ctx, store.DisableAgentGroupMembershipParams{AgentID: memberID, GroupID: groupID})
			}
		}
		if notFoundIs(e) {
			return ErrAdminNotFound
		}
		return e
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// lifetime validates a requested lifetime against the deployment settings.
func (a *Admin) lifetime(req CredentialRequest, now int64) (expires sql.NullInt64, nonExpiring int64, err error) {
	if req.NonExpiring {
		if req.TTL != 0 || !a.settings.AllowNonExpiring {
			return sql.NullInt64{}, 0, ErrAdminInvalid
		}
		return sql.NullInt64{}, 1, nil
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = a.settings.DefaultTTL
	}
	if !whole(ttl) || ttl > a.settings.MaxTTL {
		return sql.NullInt64{}, 0, ErrAdminInvalid
	}
	return sql.NullInt64{Int64: now + int64(ttl/time.Second), Valid: true}, 0, nil
}

// usableAgent loads the agent a credential operation targets and requires it to
// be active at the current generations. Anything else is a conflict: restored,
// stale or disabled agents need explicit re-approval before they can hold tokens.
func usableAgent(ctx context.Context, q *store.Queries, c store.InstallationControl, id string) (store.Agent, error) {
	if !validPrincipalID(id) {
		return store.Agent{}, ErrAdminInvalid
	}
	ag, e := q.GetAgent(ctx, id)
	if notFoundIs(e) {
		return store.Agent{}, ErrAdminNotFound
	} else if e != nil {
		return store.Agent{}, e
	}
	if !activeAgent(ag, c) {
		return store.Agent{}, ErrAdminConflict
	}
	return ag, nil
}

// liveCredentials returns the agent's credentials the verifier could accept now.
func liveCredentials(creds []store.AgentCredential, c store.InstallationControl, now int64) []store.AgentCredential {
	var live []store.AgentCredential
	for _, cred := range creds {
		if credentialStatus(c, cred, now).Live() {
			live = append(live, cred)
		}
	}
	return live
}

// newCredential draws the token and stores its hash; the caller returns the
// plaintext only after the transaction is durable.
func (a *Admin) newCredential(ctx context.Context, q *store.Queries, c store.InstallationControl, agentID string, req CredentialRequest, now int64) (store.AgentCredential, []byte, error) {
	expires, nonExpiring, err := a.lifetime(req, now)
	if err != nil {
		return store.AgentCredential{}, nil, err
	}
	token, err := newAgentToken(a.random)
	if err != nil {
		return store.AgentCredential{}, nil, err
	}
	id, err := a.newID()
	if err != nil {
		clear(token)
		return store.AgentCredential{}, nil, err
	}
	row := store.AgentCredential{ID: id, AgentID: agentID, TokenHash: agentTokenHash(token), DisplayPrefix: AgentTokenPrefix + id[:8], IssuedAt: now, ExpiresAt: expires, NonexpiringApproved: nonExpiring, CredentialGeneration: c.CredentialGeneration, State: "active"}
	if err = q.InsertAgentMachineRecord(ctx, store.InsertAgentMachineRecordParams{ID: row.ID, AgentID: row.AgentID, TokenHash: row.TokenHash, DisplayPrefix: row.DisplayPrefix, IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt, NonexpiringApproved: row.NonexpiringApproved, CredentialGeneration: row.CredentialGeneration}); err != nil {
		clear(token)
		return store.AgentCredential{}, nil, err
	}
	return row, token, nil
}

// IssueCredential issues an agent's first (or replacement after revocation)
// bearer token. It refuses while a live credential exists: use RotateCredential.
// The plaintext is returned once, only after the commit is durable.
func (a *Admin) IssueCredential(ctx context.Context, secret []byte, agentID string, req CredentialRequest) (IssuedCredential, error) {
	var out IssuedCredential
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		ag, e := usableAgent(ctx, q, c, agentID)
		if e != nil {
			return e
		}
		creds, e := q.ListAgentMachineRecords(ctx, ag.ID)
		if e != nil {
			return e
		}
		if len(liveCredentials(creds, c, now)) != 0 {
			return ErrAdminConflict
		}
		row, token, e := a.newCredential(ctx, q, c, ag.ID, req, now)
		if e != nil {
			return e
		}
		out = IssuedCredential{Credential: credentialView(c, row, now), secret: token}
		return nil
	})
	if err != nil {
		if len(out.secret) != 0 {
			clear(out.secret)
		}
		return IssuedCredential{}, err
	}
	return out, nil
}

// RotateCredential issues a new token and starts the overlap window of the one
// being replaced. A credential that was already overlapping is revoked at once, so
// an agent never has more than two live credentials. The old token is accepted for
// exactly [now, now+overlap): the verifier rejects it at the boundary second.
func (a *Admin) RotateCredential(ctx context.Context, secret []byte, agentID string, req RotateRequest) (RotationResult, error) {
	var out RotationResult
	// keptPredecessor: a non-immediate rotation left a rotated-out credential live with its
	// grace, so an undelivered successor is worth discarding on a failed notification.
	keptPredecessor := false
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		ag, e := usableAgent(ctx, q, c, agentID)
		if e != nil {
			return e
		}
		overlap := req.Overlap
		switch {
		case req.Immediate && req.Overlap != 0:
			return ErrAdminInvalid
		case req.Immediate:
		case overlap == 0:
			overlap = a.settings.DefaultOverlap
		}
		if !req.Immediate && (!whole(overlap) || overlap > a.settings.MaxOverlap) {
			return ErrAdminInvalid
		}
		creds, e := q.ListAgentMachineRecords(ctx, ag.ID)
		if e != nil {
			return e
		}
		live := liveCredentials(creds, c, now)
		if len(live) == 0 {
			return ErrAdminConflict
		}
		if len(live) > maxLiveCredentialsPerAgent {
			return ErrAdminConflict // unreachable through this service; refuse rather than guess
		}
		// Validate the new credential's lifetime before changing anything.
		if _, _, e = a.lifetime(req.CredentialRequest, now); e != nil {
			return e
		}
		rotated := map[string]bool{}
		for _, cred := range live {
			rotated[cred.ID] = true
			if sole := len(live) == 1; !req.Immediate && sole && credentialStatus(c, cred, now) == CredentialOverlapping {
				// The ONLY live credential is already inside its overlap window (its successor was
				// revoked, or a failed rotation's undelivered successor was discarded). Two live
				// credentials are allowed, so nothing has to be retired: the in-use credential keeps
				// exactly its remaining approved grace. It is never extended (the overlap only
				// shrinks) and never longer than the CURRENT configured maximum.
				if limit := now + int64(a.settings.MaxOverlap/time.Second); cred.RotationOverlapUntil.Valid && cred.RotationOverlapUntil.Int64 > limit {
					if n, e := q.ShortenMachineRecordOverlap(ctx, store.ShortenMachineRecordOverlapParams{ID: cred.ID, Until: sql.NullInt64{Int64: limit, Valid: true}}); e != nil || n != 1 {
						return ErrAdminConflict
					}
				}
				continue
			}
			if req.Immediate || credentialStatus(c, cred, now) == CredentialOverlapping {
				if n, e := q.RetireAgentMachineRecord(ctx, store.RetireAgentMachineRecordParams{ID: cred.ID, AgentID: ag.ID, Now: sql.NullInt64{Int64: now, Valid: true}}); e != nil || n != 1 {
					return ErrAdminConflict
				}
				continue
			}
			if n, e := q.ShortenMachineRecordOverlap(ctx, store.ShortenMachineRecordOverlapParams{ID: cred.ID, Until: sql.NullInt64{Int64: now + int64(overlap/time.Second), Valid: true}}); e != nil || n != 1 {
				return ErrAdminConflict
			}
		}
		row, token, e := a.newCredential(ctx, q, c, ag.ID, req.CredentialRequest, now)
		if e != nil {
			return e
		}
		after, e := q.ListAgentMachineRecords(ctx, ag.ID)
		if e != nil {
			clear(token)
			return e
		}
		out = RotationResult{New: IssuedCredential{Credential: credentialView(c, row, now), secret: token}}
		for _, cred := range after {
			if rotated[cred.ID] {
				out.RotatedOut = append(out.RotatedOut, credentialView(c, cred, now))
				if credentialStatus(c, cred, now) == CredentialOverlapping {
					keptPredecessor = true
				}
			}
		}
		return nil
	})
	if err != nil {
		if len(out.New.secret) != 0 {
			clear(out.New.secret)
		}
		return RotationResult{}, err
	}
	if err = a.changed(ctx); err != nil {
		// The rotation is durable but not acknowledged: never hand out the token. Nobody holds
		// it, so it is also discarded instead of being left as a live credential no one can
		// use: that keeps the in-use predecessor's remaining grace intact for a retry (which
		// then sees only that credential live, see above) and never counts a phantom credential
		// against the two-live bound. Best effort: if this second write fails the state is
		// exactly the durable rotation, still fail closed.
		newID := out.New.Credential.ID
		clear(out.New.secret)
		out.New.secret = nil
		if keptPredecessor {
			a.discardUndeliveredCredential(context.WithoutCancel(ctx), secret, agentID, newID)
		}
		return RotationResult{}, err
	}
	return out, nil
}

// discardUndeliveredCredential revokes a credential that was durably issued by a rotation
// whose notification failed, and only while it is still exactly what that rotation created
// (active, never in an overlap window). Failures are deliberately silent: the caller already
// returns the sanitized unavailable error and the durable state remains fail closed.
func (a *Admin) discardUndeliveredCredential(ctx context.Context, secret []byte, agentID, credentialID string) {
	_ = a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		cred, e := q.GetMachineRecord(ctx, credentialID)
		if e != nil || cred.AgentID != agentID || cred.State != "active" || cred.RotationOverlapUntil.Valid {
			return nil // missing, foreign, already retired or already rotated out by a later call
		}
		if n, e := q.RetireAgentMachineRecord(ctx, store.RetireAgentMachineRecordParams{ID: cred.ID, AgentID: agentID, Now: sql.NullInt64{Int64: now, Valid: true}}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
}

// RevokeCredential retires one credential immediately and permanently. It is
// idempotent, and credential identifiers resolve only under their own agent.
func (a *Admin) RevokeCredential(ctx context.Context, secret []byte, agentID, credentialID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, now int64) error {
		if !validPrincipalID(agentID) || !validPrincipalID(credentialID) {
			return ErrAdminInvalid
		}
		cred, e := q.GetMachineRecord(ctx, credentialID)
		if notFoundIs(e) || (e == nil && cred.AgentID != agentID) {
			return ErrAdminNotFound
		} else if e != nil {
			return e
		}
		if cred.State == "revoked" {
			return nil
		}
		if n, e := q.RetireAgentMachineRecord(ctx, store.RetireAgentMachineRecordParams{ID: cred.ID, AgentID: agentID, Now: sql.NullInt64{Int64: now, Valid: true}}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// DisableAgent revokes every credential of the agent and then disables it, in one
// transaction. The order is defence in depth, not a schema guarantee: migration 00012
// deliberately has NO trigger coupling agent state to credential state, so SQLite itself
// would accept an active credential behind a non-active agent. What makes that state
// harmless is the shared verifier, which rejects such a credential on every request
// (TestCredentialBehindANonActiveAgentIsRejectedByTheVerifierNotByTheSchema).
func (a *Admin) DisableAgent(ctx context.Context, secret []byte, agentID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, now int64) error {
		if !validPrincipalID(agentID) {
			return ErrAdminInvalid
		}
		ag, e := q.GetAgent(ctx, agentID)
		if notFoundIs(e) {
			return ErrAdminNotFound
		} else if e != nil {
			return e
		}
		if e = q.RetireAgentMachineRecords(ctx, store.RetireAgentMachineRecordsParams{AgentID: ag.ID, Now: sql.NullInt64{Int64: now, Valid: true}}); e != nil {
			return e
		}
		_, e = q.DisableAgent(ctx, ag.ID)
		return e
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// ListUsers, ListGroups and ListAgents are read-only administrative views.
func (a *Admin) ListUsers(ctx context.Context, secret []byte) ([]UserView, error) {
	out := []UserView{}
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		users, e := q.ListUsers(ctx)
		for _, u := range users {
			out = append(out, UserView{ID: u.ID, Username: u.Username, State: u.State})
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Admin) ListGroups(ctx context.Context, secret []byte) ([]GroupView, error) {
	out := []GroupView{}
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		groups, e := q.ListGroups(ctx)
		if e != nil {
			return e
		}
		for _, g := range groups {
			v := GroupView{ID: g.ID, Name: g.Name, State: g.State, Users: []string{}, Agents: []string{}}
			users, e := q.ListGroupUserMemberships(ctx, g.ID)
			if e != nil {
				return e
			}
			for _, m := range users {
				if m.State == "active" && m.AuthorityGeneration == c.AuthorityGeneration {
					v.Users = append(v.Users, m.UserID)
				}
			}
			agents, e := q.ListGroupAgentMemberships(ctx, g.ID)
			if e != nil {
				return e
			}
			for _, m := range agents {
				if m.State == "active" && m.AuthorityGeneration == c.AuthorityGeneration {
					v.Agents = append(v.Agents, m.AgentID)
				}
			}
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Admin) ListAgents(ctx context.Context, secret []byte) ([]AgentView, error) {
	out := []AgentView{}
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		agents, e := q.ListAgents(ctx)
		if e != nil {
			return e
		}
		for _, ag := range agents {
			v := AgentView{ID: ag.ID, Name: ag.Name, State: ag.State, OwnerUserID: ag.OwnerUserID.String, OwnerGroupID: ag.OwnerGroupID.String, Credentials: []CredentialView{}}
			creds, e := q.ListAgentMachineRecords(ctx, ag.ID)
			if e != nil {
				return e
			}
			for _, cred := range creds {
				v.Credentials = append(v.Credentials, credentialView(c, cred, now))
			}
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
