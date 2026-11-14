package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// Initiator names who started a restore; it is recorded in the non-secret report.
type Initiator string

const (
	// InitiatorAdmin: the live administrator, authenticated at AAL2 with fresh step-up evidence,
	// verified by the Authorizer inside the transition.
	InitiatorAdmin Initiator = "admin"
	// InitiatorHost: the trusted host operator (fresh-instance recovery, S2.2.1). The caller is the
	// host helper, which has already established that trust; there is no web route for it.
	InitiatorHost Initiator = "host"
)

// RestoreOptions parameterizes Restore.
type RestoreOptions struct {
	Initiator Initiator
	// Authorize is mandatory. For the administrator it re-verifies the fresh AAL2 administrator
	// session in the transition's own transaction; for the host it is the helper's trust decision.
	Authorize Authorizer
	// AcknowledgeUnauthenticated must be true to restore an archive whose integrity tag this
	// installation's key cannot verify (a clean archive from another key).
	AcknowledgeUnauthenticated bool
}

// Report is the safe, non-secret result of a committed restore. It is also what the UI shows.
type Report struct {
	BackupID          string         `json:"backup_id"`
	Mode              Mode           `json:"mode"`
	Provenance        Provenance     `json:"provenance"`
	Initiator         Initiator      `json:"initiator"`
	RestoreGeneration int64          `json:"restore_generation"`
	State             string         `json:"state"` // always "restore_quarantine"
	NextStep          string         `json:"next_step"`
	Imported          map[string]int `json:"imported"`
	RetainedLocal     map[string]int `json:"retained_local"`
	// InactiveCredentials counts imported credential rows kept for provenance only (always inactive).
	InactiveCredentials map[string]int `json:"inactive_credentials"`
	CredentialsStripped bool           `json:"credentials_stripped"`
	Excluded            []string       `json:"excluded"`
}

// excluded is the documented list of what a restore neither reads nor changes... or never carries.
var excludedScope = []string{"sessions", "rate_limit_state", "usage_statistics", "setup_and_recovery_state", "security_notices", "control_generations_and_quarantine", "master_key_and_installation_binding"}

// Restore applies a verified archive in two durable control transactions.
//
//  1. The availability-changing transition (S2.2.1): authorize the initiator, enter the persisted
//     RESTORE_QUARANTINE, rotate every control generation and revoke every browser session. It is
//     committed before any archive record is applied, so the instance is already inert when the
//     import runs and stays inert if anything after it fails or the process dies.
//  2. The import: retire local authority, apply the archive as INACTIVE records, run the integrity
//     checks and write the manifest, all in ONE transaction that rolls back completely on any
//     failure. A crash or rollback therefore leaves quarantine in place and no partial import.
//
// Nothing here ends quarantine. Only the host-authorized recovery ceremony does (S2.2.5).
func (s *Service) Restore(ctx context.Context, v *Verified, o RestoreOptions) (Report, error) {
	if v == nil || o.Authorize == nil || (o.Initiator != InitiatorAdmin && o.Initiator != InitiatorHost) {
		return Report{}, ErrInvalid
	}
	if v.provenance == ProvenanceUnauthenticated && !o.AcknowledgeUnauthenticated {
		return Report{}, ErrUnauthenticated
	}
	sealed, err := s.resealSecrets(v)
	if err != nil {
		return Report{}, err
	}
	defer sealed.clear()
	// The caller's cancellation must not tear a started transition in half; both transactions are
	// bounded instead.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()

	var generation int64
	var denied error
	err = s.repo.Control(bounded, func(q *store.Queries) error {
		c, e := q.GetInstallationControl(bounded)
		if e != nil {
			return e
		}
		now := s.now().Unix()
		if e = o.Authorize(bounded, q, c, now); e != nil {
			denied = ErrDenied
			return denied
		}
		if n, e := q.BackupEnterQuarantine(bounded); e != nil || n != 1 {
			return ErrUnavailable
		}
		if e = q.BackupRevokeAllSessions(bounded, now); e != nil {
			return e
		}
		generation = c.RestoreGeneration + 1
		return nil
	}, nil)
	if denied != nil {
		return Report{}, denied
	}
	if err != nil {
		return Report{}, ErrUnavailable
	}
	if err := s.hook("restore:after-quarantine"); err != nil {
		return Report{}, afterTransition(ErrUnavailable)
	}

	var report Report
	var superseded, inconsistentImport bool
	err = s.repo.Control(bounded, func(q *store.Queries) error {
		c, e := q.GetInstallationControl(bounded)
		if e != nil {
			return e
		}
		if c.RestoreQuarantined != 1 || c.RestoreGeneration != generation {
			superseded = true
			return ErrSuperseded
		}
		report, e = s.apply(bounded, q, v, o, sealed, generation, s.now().Unix())
		if e != nil {
			inconsistentImport = errors.Is(e, ErrConsistency)
			return e
		}
		if e = s.hook("restore:after-import"); e != nil {
			return e
		}
		// Post-restore integrity (TD 6.3): the data is structurally sound, nothing the restore
		// touched is effective, the control state is exactly what the transition produced.
		if n, e := q.ForeignKeyViolations(bounded); e != nil || n != 0 {
			inconsistentImport = true
			return ErrConsistency
		}
		if n, e := q.BackupCountActiveAuthority(bounded); e != nil || n != 0 {
			inconsistentImport = true
			return ErrConsistency
		}
		after, e := q.GetInstallationControl(bounded)
		if e != nil || after != c {
			inconsistentImport = true
			return ErrConsistency
		}
		return s.hook("restore:before-commit")
	}, nil)
	if superseded {
		return Report{}, afterTransition(ErrSuperseded)
	}
	if inconsistentImport {
		return Report{}, afterTransition(ErrConsistency)
	}
	if err != nil {
		return Report{}, afterTransition(ErrUnavailable)
	}
	return report, nil
}

// sealedMaterial holds the re-encrypted TOTP and WebAuthn records for the TARGET installation. They
// are produced before the transaction (the repository's cipher takes its own lock) and cleared after.
type sealedMaterial struct {
	totp     map[string][]byte
	webauthn map[string][]byte
}

func (m *sealedMaterial) clear() {}

func (s *Service) resealSecrets(v *Verified) (*sealedMaterial, error) {
	m := &sealedMaterial{totp: map[string][]byte{}, webauthn: map[string][]byte{}}
	for id, sec := range v.payload.Authenticators {
		if len(sec.TOTPSeed) == 0 {
			continue
		}
		env, err := s.repo.EncryptSecret("totp", id, sec.TOTPSeed)
		if err != nil {
			return nil, ErrUnavailable
		}
		m.totp[id] = env
	}
	for id, plain := range v.payload.WebauthnRecords {
		env, err := s.repo.EncryptSecret("webauthn-credential", id, plain)
		if err != nil {
			return nil, ErrUnavailable
		}
		m.webauthn[id] = env
	}
	return m, nil
}

func strictness(mfa string) int {
	switch mfa {
	case "webauthn":
		return 2
	case "required":
		return 1
	}
	return 0
}

// effectiveMFA: an imported setting may never weaken the accepted security floor (RESTORE-11): the
// floor is "required" (MFA compulsory), and a stronger imported or already-live requirement is kept.
func effectiveMFA(imported, live string) string {
	best := 1
	for _, m := range []string{imported, live} {
		if strictness(m) > best {
			best = strictness(m)
		}
	}
	if best == 2 {
		return "webauthn"
	}
	return "required"
}

func (s *Service) apply(ctx context.Context, q *store.Queries, v *Verified, o RestoreOptions, sealed *sealedMaterial, generation, now int64) (Report, error) {
	sc := v.archive.Scope
	live, err := q.GetLocalEndpoint(ctx)
	if err != nil {
		return Report{}, ErrConsistency
	}
	archiveEndpoint := sc.Endpoints[0].ID
	mapEndpoint := func(id string) domain.EndpointID {
		if id == archiveEndpoint {
			return live.ID
		}
		return domain.EndpointID(id)
	}

	// 1. Retire local authority in place. Nothing is deleted (history and foreign keys stay intact,
	// usage aggregates survive) and nothing is reactivated: every active record becomes
	// quarantined, every live agent token is revoked for good. A quarantined DENY still blocks.
	for _, f := range []func(context.Context) error{q.BackupQuarantineUsers, q.BackupQuarantineGroups, q.BackupQuarantineAgents, q.BackupQuarantineUserMemberships,
		q.BackupQuarantineAgentMemberships, q.BackupQuarantineRoles, q.BackupQuarantinePolicies, q.BackupQuarantineEndpoints, q.BackupQuarantineAddresses, q.BackupQuarantineAuthenticators} {
		if err := f(ctx); err != nil {
			return Report{}, err
		}
	}
	if err := q.BackupRevokeLiveMachineRecords(ctx, now); err != nil {
		return Report{}, err
	}

	imported := map[string]int{}
	inArchive := map[string]map[string]bool{}
	mark := func(kind, id string) {
		if inArchive[kind] == nil {
			inArchive[kind] = map[string]bool{}
		}
		inArchive[kind][id] = true
		imported[kind]++
	}

	// 2. Apply the archive, always inactive (the SQL fixes state='quarantined' and generation 0).
	liveUsers := map[string]store.User{}
	if all, err := q.ListUsers(ctx); err == nil {
		for _, u := range all {
			liveUsers[u.ID] = u
		}
	} else {
		return Report{}, err
	}
	imports := map[string]map[string]string{} // kind -> id -> imported-settings JSON
	effective := map[string]map[string]string{}
	set := func(m map[string]map[string]string, kind, id, value string) {
		if m[kind] == nil {
			m[kind] = map[string]string{}
		}
		m[kind][id] = value
	}
	for _, u := range sc.Users {
		eff := effectiveMFA(u.MFARequirement, liveUsers[u.ID].MfaRequirement)
		if err := q.BackupRenameUserForImport(ctx, store.BackupRenameUserForImportParams{Username: u.Username, ID: u.ID}); err != nil {
			return Report{}, err
		}
		if err := q.BackupUpsertUser(ctx, store.BackupUpsertUserParams{ID: u.ID, Username: u.Username, MfaRequirement: eff, Compromised: boolInt(u.Compromised)}); err != nil {
			return Report{}, err
		}
		mark("user", u.ID)
		set(imports, "user", u.ID, jsonObj("mfa_requirement", u.MFARequirement, "compromised", u.Compromised))
		set(effective, "user", u.ID, jsonObj("mfa_requirement", eff, "credentials", "none"))
	}
	for _, g := range sc.Groups {
		if err := q.BackupRenameGroupForImport(ctx, store.BackupRenameGroupForImportParams{Name: g.Name, ID: g.ID}); err != nil {
			return Report{}, err
		}
		if err := q.BackupUpsertGroup(ctx, store.BackupUpsertGroupParams{ID: g.ID, Name: g.Name}); err != nil {
			return Report{}, err
		}
		mark("group", g.ID)
	}
	for _, a := range sc.Agents {
		if err := q.BackupRenameAgentForImport(ctx, store.BackupRenameAgentForImportParams{Name: a.Name, ID: a.ID}); err != nil {
			return Report{}, err
		}
		if err := q.BackupUpsertAgent(ctx, store.BackupUpsertAgentParams{ID: a.ID, Name: a.Name, OwnerUserID: nullStr(a.OwnerUserID), OwnerGroupID: nullStr(a.OwnerGroupID)}); err != nil {
			return Report{}, err
		}
		mark("agent", a.ID)
		set(effective, "agent", a.ID, jsonObj("credentials", "none"))
	}
	for _, m := range sc.UserMemberships {
		if err := q.BackupUpsertUserMembership(ctx, store.BackupUpsertUserMembershipParams{UserID: m.UserID, GroupID: m.GroupID}); err != nil {
			return Report{}, err
		}
		mark("user_membership", m.UserID+":"+m.GroupID)
	}
	for _, m := range sc.AgentMemberships {
		if err := q.BackupUpsertAgentMembership(ctx, store.BackupUpsertAgentMembershipParams{AgentID: m.AgentID, GroupID: m.GroupID}); err != nil {
			return Report{}, err
		}
		mark("agent_membership", m.AgentID+":"+m.GroupID)
	}
	for _, r := range sc.Roles {
		var ep *domain.EndpointID
		if r.EndpointID != nil {
			id := mapEndpoint(*r.EndpointID)
			ep = &id
			if err := q.BackupDeleteCollidingEndpointRole(ctx, store.BackupDeleteCollidingEndpointRoleParams{UserID: r.UserID, Role: r.Role, EndpointID: ep, ID: r.ID}); err != nil {
				return Report{}, err
			}
		} else if err := q.BackupDeleteCollidingGlobalRole(ctx, store.BackupDeleteCollidingGlobalRoleParams{UserID: r.UserID, Role: r.Role, ID: r.ID}); err != nil {
			return Report{}, err
		}
		if err := q.BackupUpsertRole(ctx, store.BackupUpsertRoleParams{ID: r.ID, UserID: r.UserID, Role: r.Role, EndpointID: ep}); err != nil {
			return Report{}, err
		}
		mark("role", r.ID)
	}
	for _, sel := range sc.Selectors {
		if existing, err := q.GetContainerSelector(ctx, sel.ID); err == nil {
			// Selectors are immutable, shared rows. The same id must mean the same selector.
			if !sameSelector(existing, sel, live.ID) {
				return Report{}, ErrConsistency
			}
		} else if err != sql.ErrNoRows {
			return Report{}, err
		}
		if err := q.BackupInsertSelector(ctx, store.BackupInsertSelectorParams{ID: sel.ID, EndpointID: live.ID, ContainerName: sel.ContainerName, NameIsGlob: boolInt(sel.NameIsGlob),
			ComposeProject: nullStr(sel.ComposeProject), ComposeService: nullStr(sel.ComposeService), ImagePattern: nullStr(sel.ImagePattern),
			PinnedContainerID: nullStr(sel.PinnedContainerID), PinnedImageDigest: nullStr(sel.PinnedImageDigest)}); err != nil {
			return Report{}, err
		}
	}
	policyNotes := map[string]string{}
	for _, p := range sc.Policies {
		// A live DENY is a restriction this installation knows about and the archive may not: an
		// imported ALLOW for the same rule never overwrites it (RESTORE-03). It stays (quarantined).
		if existing, err := q.GetPolicy(ctx, p.ID); err == nil && existing.Effect == "DENY" && p.Effect == "ALLOW" {
			policyNotes[p.ID] = "local_deny_retained"
			set(imports, "policy", p.ID, jsonObj("effect", p.Effect, "operation", p.Operation))
			set(effective, "policy", p.ID, jsonObj("effect", "DENY", "note", "a local DENY with this id was kept"))
			mark("policy", p.ID)
			continue
		} else if err != nil && err != sql.ErrNoRows {
			return Report{}, err
		}
		if err := q.BackupUpsertPolicy(ctx, store.BackupUpsertPolicyParams{ID: p.ID, UserID: nullStr(p.UserID), GroupID: nullStr(p.GroupID), AgentID: nullStr(p.AgentID),
			EndpointID: live.ID, SelectorID: p.SelectorID, Operation: p.Operation, Effect: p.Effect, LogTailMax: nullInt(p.LogTailMax), StopTimeoutMax: nullInt(p.StopTimeoutMax)}); err != nil {
			return Report{}, err
		}
		mark("policy", p.ID)
		set(imports, "policy", p.ID, jsonObj("effect", p.Effect, "operation", p.Operation))
		set(effective, "policy", p.ID, jsonObj("effect", p.Effect, "operation", p.Operation, "scope", "none until approved"))
	}
	for _, a := range sc.Addresses {
		if err := q.BackupInsertAddress(ctx, store.BackupInsertAddressParams{ID: a.ID, UserID: a.UserID, Address: a.Address, Version: a.Version, CreatedAt: a.CreatedAt}); err != nil {
			return Report{}, err
		}
		mark("address", a.ID)
	}
	inactive := map[string]int{}
	for _, a := range sc.Authenticators {
		sec := v.payload.Authenticators[a.ID]
		params := store.BackupInsertAuthenticatorParams{ID: a.ID, UserID: a.UserID, Kind: a.Kind, CreatedAt: sec.CreatedAt, BoundAt: nullInt(sec.BoundAt), ExpiresAt: nullInt(sec.ExpiresAt),
			VerifierHash: sec.VerifierHash, PublicKey: sec.PublicKey, ExternalCredentialID: sec.ExternalCredentialID, PasswordCodepoints: nullInt(sec.PasswordCodepoints),
			PasswordFormat: nullStr(sec.PasswordFormat), MaxAssurance: sec.MaxAssurance, PhishingResistant: nullInt(sec.PhishingResistant), RetryCeiling: sec.RetryCeiling,
			LastAcceptedTotpStep: nullInt(sec.LastAcceptedTOTPStep), SignCount: nullInt(sec.SignCount), BackupEligible: nullInt(sec.BackupEligible), BackupState: nullInt(sec.BackupState),
			UserVerified: nullInt(sec.UserVerified), TotpAlgorithm: nullStr(sec.TOTPAlgorithm)}
		if a.Kind == "totp" {
			params.EncryptedSecret = sealed.totp[a.ID]
		}
		if err := q.BackupInsertAuthenticator(ctx, params); err != nil {
			return Report{}, err
		}
		inactive["authenticators"]++
	}
	for _, uid := range sortedKeys(v.payload.WebauthnUsers) {
		if err := q.BackupInsertWebauthnUser(ctx, store.BackupInsertWebauthnUserParams{UserID: uid, Handle: v.payload.WebauthnUsers[uid]}); err != nil {
			return Report{}, err
		}
	}
	for _, id := range sortedKeys(v.payload.WebauthnRecords) {
		if err := q.BackupInsertWebauthnRecord(ctx, store.BackupInsertWebauthnRecordParams{AuthenticatorID: id, Label: "restored", Envelope: sealed.webauthn[id]}); err != nil {
			return Report{}, err
		}
	}
	for _, c := range sc.AgentCredentials {
		if err := q.BackupInsertMachineRecord(ctx, store.BackupInsertMachineRecordParams{ID: c.ID, AgentID: c.AgentID, TokenHash: v.payload.AgentCredentials[c.ID], DisplayPrefix: c.DisplayPrefix,
			IssuedAt: c.IssuedAt, ExpiresAt: nullInt(c.ExpiresAt), NonexpiringApproved: boolInt(c.NonexpiringApproved)}); err != nil {
			return Report{}, err
		}
		inactive["agent_credentials"]++
	}

	// 3. The manifest: every record now in quarantine, whether it came from the archive or was
	// retired from local authority, with what the archive claimed and what is effective.
	retained := map[string]int{}
	var items []store.InsertRestoreManifestItemParams
	add := func(kind, id, label string, srcState *string, origin string) error {
		imp, eff := "{}", "{}"
		if origin == "imported" {
			if x := imports[kind][id]; x != "" {
				imp = x
			}
		}
		if x := effective[kind][id]; x != "" {
			eff = x
		}
		if origin == "local_retained" {
			retained[kind]++
		}
		src := sql.NullString{}
		if srcState != nil {
			src = sql.NullString{String: *srcState, Valid: true}
		}
		items = append(items, store.InsertRestoreManifestItemParams{RestoreGeneration: generation, Kind: kind, ItemID: id, Label: truncate(label, 300),
			Origin: origin, SourceState: src, Imported: imp, Effective: eff})
		return nil
	}
	srcStates := sourceStates(sc)
	originOf := func(kind, id string) string {
		if inArchive[kind][id] {
			return "imported"
		}
		return "local_retained"
	}
	stateOf := func(kind, id string) *string {
		if st, ok := srcStates[kind+"\x00"+id]; ok {
			return &st
		}
		return nil
	}
	endpoints, err := q.BackupListEndpoints(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, e := range endpoints {
		if e.State != "quarantined" || e.Slug != "local" {
			continue
		}
		st := sc.Endpoints[0].SourceState
		if err := add("endpoint", string(e.ID), e.Name, &st, "imported"); err != nil {
			return Report{}, err
		}
		imported["endpoint"]++
	}
	users, err := q.BackupListQuarantinedUsers(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, u := range users {
		if err := add("user", u.ID, u.Username, stateOf("user", u.ID), originOf("user", u.ID)); err != nil {
			return Report{}, err
		}
	}
	groups, err := q.BackupListQuarantinedGroups(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, g := range groups {
		if err := add("group", g.ID, g.Name, stateOf("group", g.ID), originOf("group", g.ID)); err != nil {
			return Report{}, err
		}
	}
	agents, err := q.BackupListQuarantinedAgents(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, a := range agents {
		if err := add("agent", a.ID, a.Name, stateOf("agent", a.ID), originOf("agent", a.ID)); err != nil {
			return Report{}, err
		}
	}
	userMem, err := q.BackupListQuarantinedUserMemberships(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, m := range userMem {
		id := m.UserID + ":" + m.GroupID
		if err := add("user_membership", id, "user "+m.UserID+" in group "+m.GroupID, stateOf("user_membership", id), originOf("user_membership", id)); err != nil {
			return Report{}, err
		}
	}
	agentMem, err := q.BackupListQuarantinedAgentMemberships(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, m := range agentMem {
		id := m.AgentID + ":" + m.GroupID
		if err := add("agent_membership", id, "agent "+m.AgentID+" in group "+m.GroupID, stateOf("agent_membership", id), originOf("agent_membership", id)); err != nil {
			return Report{}, err
		}
	}
	roles, err := q.BackupListQuarantinedRoles(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, r := range roles {
		if err := add("role", r.ID, r.Role+" of user "+r.UserID, stateOf("role", r.ID), originOf("role", r.ID)); err != nil {
			return Report{}, err
		}
	}
	policies, err := q.BackupListQuarantinedPolicies(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, p := range policies {
		if err := add("policy", p.ID, p.Effect+" "+p.Operation, stateOf("policy", p.ID), originOf("policy", p.ID)); err != nil {
			return Report{}, err
		}
	}
	addresses, err := q.BackupListQuarantinedAddresses(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, a := range addresses {
		// Only the user it belongs to: a contact address is personal data and the manifest is review output.
		if err := add("address", a.ID, "notification address of user "+a.UserID, nil, originOf("address", a.ID)); err != nil {
			return Report{}, err
		}
	}

	stripped := v.archive.Mode == ModeClean
	report := Report{BackupID: v.archive.BackupID, Mode: v.archive.Mode, Provenance: v.provenance, Initiator: o.Initiator, RestoreGeneration: generation,
		State: "restore_quarantine", NextStep: "host_recovery_required", Imported: imported, RetainedLocal: retained, InactiveCredentials: inactive,
		CredentialsStripped: stripped, Excluded: append([]string(nil), excludedScope...)}
	summary, err := json.Marshal(struct {
		Imported            map[string]int    `json:"imported"`
		RetainedLocal       map[string]int    `json:"retained_local"`
		InactiveCredentials map[string]int    `json:"inactive_credentials"`
		CredentialsStripped bool              `json:"credentials_stripped"`
		Excluded            []string          `json:"excluded"`
		PolicyNotes         map[string]string `json:"policy_notes,omitempty"`
	}{imported, retained, inactive, stripped, report.Excluded, policyNotes})
	if err != nil {
		return Report{}, ErrUnavailable
	}
	if err := q.InsertRestoreReport(ctx, store.InsertRestoreReportParams{RestoreGeneration: generation, BackupID: v.archive.BackupID, Mode: string(v.archive.Mode),
		Provenance: string(v.provenance), Initiator: string(o.Initiator), RestoredAt: now, Summary: string(summary)}); err != nil {
		return Report{}, err
	}
	for _, item := range items { // the report row is the foreign-key parent of every entry
		if err := q.InsertRestoreManifestItem(ctx, item); err != nil {
			return Report{}, err
		}
	}
	return report, nil
}

func sameSelector(e store.ContainerSelector, a SelectorRecord, liveEndpoint domain.EndpointID) bool {
	eq := func(n sql.NullString, p *string) bool {
		return (!n.Valid && p == nil) || (n.Valid && p != nil && n.String == *p)
	}
	return e.EndpointID == liveEndpoint && e.ContainerName == a.ContainerName && (e.NameIsGlob != 0) == a.NameIsGlob && eq(e.ComposeProject, a.ComposeProject) &&
		eq(e.ComposeService, a.ComposeService) && eq(e.ImagePattern, a.ImagePattern) && eq(e.PinnedContainerID, a.PinnedContainerID) && eq(e.PinnedImageDigest, a.PinnedImageDigest)
}

func sourceStates(sc Scope) map[string]string {
	m := map[string]string{}
	for _, u := range sc.Users {
		m["user\x00"+u.ID] = u.SourceState
	}
	for _, g := range sc.Groups {
		m["group\x00"+g.ID] = g.SourceState
	}
	for _, a := range sc.Agents {
		m["agent\x00"+a.ID] = a.SourceState
	}
	for _, x := range sc.UserMemberships {
		m["user_membership\x00"+x.UserID+":"+x.GroupID] = x.SourceState
	}
	for _, x := range sc.AgentMemberships {
		m["agent_membership\x00"+x.AgentID+":"+x.GroupID] = x.SourceState
	}
	for _, r := range sc.Roles {
		m["role\x00"+r.ID] = r.SourceState
	}
	for _, p := range sc.Policies {
		m["policy\x00"+p.ID] = p.SourceState
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// jsonObj builds a small flat JSON object from key/value pairs (all values are non-secret settings).
func jsonObj(kv ...any) string {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}
