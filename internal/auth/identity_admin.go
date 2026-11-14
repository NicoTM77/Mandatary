package auth

import (
	"context"
	"database/sql"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.17 identity lifecycle: disabling and enabling users and groups, deleting an unused group, enabling
// an agent and transferring an agent's accountable owner.
//
// Same authority model as P1.10 (agents.go): every method runs through Admin.mutate, so it needs the live
// fresh AAL2 session of the single policy administrator, an installation outside restore quarantine and
// the current control generations, all decided from persisted state inside one durable transaction. Nothing
// here grants a container operation: lifecycle changes only REMOVE or RESTORE the standing of an account
// that rules already name. Creating or changing a rule is policy_admin.go.
//
// Cascades (the owner-state rule). An agent is accountable to exactly one owner (a user XOR a group) and
// ownership is accountability only (TD §3.1), but an agent whose accountable party has been disabled must
// not keep working. So disabling a user or a group disables every ACTIVE agent that party owns, revoking all
// of its credentials first (the order is defence in depth: migration 00012 has no trigger coupling agent state to credential state, the shared verifier rejects such a credential at runtime). Disabling
// never deletes anything: memberships and rules are kept and simply grant nothing while their subject is
// inactive. The reverse is deliberately NOT automatic: enabling an owner never re-enables its agents or
// revives a revoked token, because that would be an authority grant nobody asked for. Re-enabling an agent
// and issuing it a new token are separate administrator actions. A group disabled directly does not disable
// the agents that are merely MEMBERS of it; they stay active and lose only what the group granted.

// isAdministratorAccount reports whether the user holds (or held an unrevoked) administrative role. The
// policy administrator has no lifecycle controls: disabling it would lock administration out.
func isAdministratorAccount(ctx context.Context, q *store.Queries, userID string) (bool, error) {
	roles, err := q.ListUserAdministrativeRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.State == "active" {
			return true, nil
		}
	}
	return false, nil
}

// disableOwnedAgents revokes every credential of, then disables, each active agent owned by the given
// party. Disabled and quarantined agents are left exactly as they are.
func disableOwnedAgents(ctx context.Context, q *store.Queries, now int64, ownerUser, ownerGroup string) error {
	agents, err := q.ListAgents(ctx)
	if err != nil {
		return err
	}
	for _, ag := range agents {
		owned := (ownerUser != "" && ag.OwnerUserID.String == ownerUser && ag.OwnerUserID.Valid) ||
			(ownerGroup != "" && ag.OwnerGroupID.String == ownerGroup && ag.OwnerGroupID.Valid)
		if !owned || ag.State != "active" {
			continue
		}
		if err = q.RetireAgentMachineRecords(ctx, store.RetireAgentMachineRecordsParams{AgentID: ag.ID, Now: sql.NullInt64{Int64: now, Valid: true}}); err != nil {
			return err
		}
		if n, e := q.DisableAgent(ctx, ag.ID); e != nil || n != 1 {
			if e == nil {
				e = ErrAdminConflict
			}
			return e
		}
	}
	return nil
}

// loadUser fetches a user the request names, refusing malformed and unknown identifiers.
func loadUser(ctx context.Context, q *store.Queries, id string) (store.User, error) {
	if !validPrincipalID(id) {
		return store.User{}, ErrAdminInvalid
	}
	u, err := q.GetUser(ctx, id)
	if notFoundIs(err) {
		return store.User{}, ErrAdminNotFound
	}
	return u, err
}

func loadGroup(ctx context.Context, q *store.Queries, id string) (store.Group, error) {
	if !validPrincipalID(id) {
		return store.Group{}, ErrAdminInvalid
	}
	g, err := q.GetGroup(ctx, id)
	if notFoundIs(err) {
		return store.Group{}, ErrAdminNotFound
	}
	return g, err
}

func loadAgent(ctx context.Context, q *store.Queries, id string) (store.Agent, error) {
	if !validPrincipalID(id) {
		return store.Agent{}, ErrAdminInvalid
	}
	g, err := q.GetAgent(ctx, id)
	if notFoundIs(err) {
		return store.Agent{}, ErrAdminNotFound
	}
	return g, err
}

// DisableUser makes an account unable to sign in or act: it revokes the account's sessions and disables the
// agents it owns (see the cascade rule above). The administrator account cannot be disabled. Repeating it
// is harmless and still notifies, so a failed notification can be retried.
func (a *Admin) DisableUser(ctx context.Context, secret []byte, userID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, now int64) error {
		u, e := loadUser(ctx, q, userID)
		if e != nil {
			return e
		}
		if admin, e := isAdministratorAccount(ctx, q, u.ID); e != nil {
			return e
		} else if admin || (u.State != "active" && u.State != "disabled") {
			return ErrAdminConflict
		}
		if u.State == "active" {
			if n, e := q.DisableUserAccount(ctx, u.ID); e != nil || n != 1 {
				return ErrAdminConflict
			}
		}
		if e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: u.ID, Now: sql.NullInt64{Int64: now, Valid: true}}); e != nil {
			return e
		}
		return disableOwnedAgents(ctx, q, now, u.ID, "")
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// EnableUser restores a disabled account at the current generations. A restored (quarantined),
// compromised or stale-generation account is a conflict: those are approved only by the restore and
// compromise flows. Agents the account owns stay disabled.
func (a *Admin) EnableUser(ctx context.Context, secret []byte, userID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		u, e := loadUser(ctx, q, userID)
		if e != nil {
			return e
		}
		if u.State != "disabled" {
			return ErrAdminConflict
		}
		if n, e := q.EnableUserAccount(ctx, store.EnableUserAccountParams{ID: u.ID, CredentialGeneration: c.CredentialGeneration, AuthorityGeneration: c.AuthorityGeneration}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// DisableGroup removes a group's standing: its rules and its members' memberships stay but grant nothing
// while it is disabled, and agents the group OWNS are disabled with their credentials revoked.
func (a *Admin) DisableGroup(ctx context.Context, secret []byte, groupID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, now int64) error {
		g, e := loadGroup(ctx, q, groupID)
		if e != nil {
			return e
		}
		if g.State != "active" && g.State != "disabled" {
			return ErrAdminConflict
		}
		if g.State == "active" {
			if n, e := q.DisableGroupRecord(ctx, g.ID); e != nil || n != 1 {
				return ErrAdminConflict
			}
		}
		return disableOwnedAgents(ctx, q, now, "", g.ID)
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// EnableGroup restores a disabled group at the current generation; owned agents stay disabled.
func (a *Admin) EnableGroup(ctx context.Context, secret []byte, groupID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		g, e := loadGroup(ctx, q, groupID)
		if e != nil {
			return e
		}
		if g.State != "disabled" {
			return ErrAdminConflict
		}
		if n, e := q.EnableGroupRecord(ctx, store.EnableGroupRecordParams{ID: g.ID, AuthorityGeneration: c.AuthorityGeneration}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// DeleteGroup permanently removes a group nothing relies on: no member, no owned agent and no rule. This is
// refused as a conflict otherwise, so deleting can never silently drop a Deny rule, an owner or a member.
func (a *Admin) DeleteGroup(ctx context.Context, secret []byte, groupID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error {
		g, e := loadGroup(ctx, q, groupID)
		if e != nil {
			return e
		}
		f, e := readIdentityFacts(ctx, q, c, now)
		if e != nil {
			return e
		}
		// The same decision the Groups page shows, so the page and the refusal can never disagree.
		blockers, e := groupBlockerPhrases(g, f)
		if e != nil {
			return e
		}
		if len(blockers) != 0 {
			return ErrAdminConflict
		}
		if e = q.DeleteDisabledGroupUserMemberships(ctx, g.ID); e != nil {
			return e
		}
		if e = q.DeleteDisabledGroupAgentMemberships(ctx, g.ID); e != nil {
			return e
		}
		if n, e := q.DeleteGroupRecord(ctx, g.ID); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// EnableAgent re-activates a disabled agent whose accountable owner is active. It issues no token and
// revives none: every credential the disable revoked stays revoked.
func (a *Admin) EnableAgent(ctx context.Context, secret []byte, agentID string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		ag, e := loadAgent(ctx, q, agentID)
		if e != nil {
			return e
		}
		if ag.State != "disabled" {
			return ErrAdminConflict
		}
		if ok, e := ownerActive(ctx, q, c, ag); e != nil {
			return e
		} else if !ok {
			return ErrAdminConflict
		}
		if n, e := q.EnableAgentRecord(ctx, store.EnableAgentRecordParams{ID: ag.ID, CredentialGeneration: c.CredentialGeneration, AuthorityGeneration: c.AuthorityGeneration}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// ownerActive reports whether the agent's single owner is active at the current generations.
func ownerActive(ctx context.Context, q *store.Queries, c store.InstallationControl, ag store.Agent) (bool, error) {
	switch {
	case ag.OwnerUserID.Valid:
		u, err := q.GetUser(ctx, ag.OwnerUserID.String)
		if err != nil {
			return false, err
		}
		return activeUser(u, c), nil
	case ag.OwnerGroupID.Valid:
		g, err := q.GetGroup(ctx, ag.OwnerGroupID.String)
		if err != nil {
			return false, err
		}
		return activeGroup(g, c), nil
	default:
		return false, nil
	}
}

// AgentOwner names exactly one accountable owner: UserID XOR GroupID.
type AgentOwner struct{ UserID, GroupID string }

// TransferAgent changes only who is accountable for an agent. It touches no rule, membership or
// credential, so the agent keeps exactly the access it has (ownership is accountability only), and it
// therefore needs no policy notification. The new owner must be active. A restored (quarantined) agent
// can only be approved by the restore flow.
func (a *Admin) TransferAgent(ctx context.Context, secret []byte, agentID string, owner AgentOwner) error {
	return a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if (owner.UserID == "") == (owner.GroupID == "") {
			return ErrAdminInvalid
		}
		var set store.SetAgentOwnerParams
		if owner.UserID != "" {
			if !validPrincipalID(owner.UserID) {
				return ErrAdminInvalid
			}
			u, e := q.GetUser(ctx, owner.UserID)
			if notFoundIs(e) {
				return ErrAdminInvalid
			} else if e != nil {
				return e
			}
			if !activeUser(u, c) {
				return ErrAdminInvalid
			}
			set.OwnerUserID = sql.NullString{String: u.ID, Valid: true}
		} else {
			if !validPrincipalID(owner.GroupID) {
				return ErrAdminInvalid
			}
			g, e := q.GetGroup(ctx, owner.GroupID)
			if notFoundIs(e) {
				return ErrAdminInvalid
			} else if e != nil {
				return e
			}
			if !activeGroup(g, c) {
				return ErrAdminInvalid
			}
			set.OwnerGroupID = sql.NullString{String: g.ID, Valid: true}
		}
		ag, e := loadAgent(ctx, q, agentID)
		if e != nil {
			return e
		}
		set.ID = ag.ID
		if n, e := q.SetAgentOwner(ctx, set); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
}
