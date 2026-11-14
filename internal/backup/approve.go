package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// ItemRef names one manifest entry. Memberships use "<member id>:<group id>".
type ItemRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// ItemResult is the outcome of an approved entry.
type ItemResult struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Result string `json:"result"` // "approved"
}

// MaxApprovalsPerRequest bounds one reapproval request.
const MaxApprovalsPerRequest = 500

// kindOrder makes a request approve dependencies first (an endpoint, then principals, then the
// memberships and rules that name them), so one request can approve a user and its rule together.
var kindOrder = map[string]int{"endpoint": 0, "user": 1, "group": 2, "agent": 3, "user_membership": 4, "agent_membership": 5, "policy": 6}

// Approvable reports whether the manifest can approve this kind at all in Phase 1, and why not.
func approvableKind(kind string) (bool, string) {
	switch kind {
	case "endpoint", "user", "group", "agent", "user_membership", "agent_membership", "policy":
		return true, ""
	case "role":
		return false, "single_administrator" // Phase 1 has exactly one administrator: the recovery administrator
	case "address":
		return false, "needs_reverification" // an address is proven by its owner again, never approved
	}
	return false, "unsupported"
}

func needsOf(kind string) string {
	switch kind {
	case "user":
		return "credential_enrollment"
	case "agent":
		return "token_reissue"
	case "role":
		return "none_in_phase_1"
	case "address":
		return "reverification"
	}
	return "approval"
}

// ManifestItem is one reviewable entry. Imported is what the archive claimed (settings only);
// Effective is what is true now. A pending entry grants nothing.
type ManifestItem struct {
	Kind          string          `json:"kind"`
	ID            string          `json:"id"`
	Label         string          `json:"label"`
	Origin        string          `json:"origin"` // "imported" or "local_retained"
	SourceState   *string         `json:"source_state"`
	Imported      json.RawMessage `json:"imported"`
	Effective     json.RawMessage `json:"effective"`
	Decision      string          `json:"decision"` // "pending" or "approved"
	Approvable    bool            `json:"approvable"`
	BlockedReason string          `json:"blocked_reason,omitempty"`
	Needs         string          `json:"needs"`
}

// ManifestView is the redacted authority manifest of the latest restore.
type ManifestView struct {
	BackupID            string          `json:"backup_id"`
	Mode                Mode            `json:"mode"`
	Provenance          Provenance      `json:"provenance"`
	Initiator           Initiator       `json:"initiator"`
	RestoreGeneration   int64           `json:"restore_generation"`
	RestoredAt          int64           `json:"restored_at"`
	Summary             json.RawMessage `json:"summary"`
	Items               []ManifestItem  `json:"items"`
	Pending             int             `json:"pending"`
	Approved            int             `json:"approved"`
	InactiveCredentials map[string]int  `json:"inactive_credentials"`
}

// Manifest reads the latest restore's report and entries. It authorizes nothing: the caller has
// already required the administrator. It never includes a credential, verifier, hash or ciphertext.
func Manifest(ctx context.Context, q *store.Queries) (ManifestView, error) {
	rep, err := q.LatestRestoreReport(ctx)
	if err == sql.ErrNoRows {
		return ManifestView{}, ErrNoRestore
	}
	if err != nil {
		return ManifestView{}, err
	}
	rows, err := q.ListRestoreManifest(ctx, rep.RestoreGeneration)
	if err != nil {
		return ManifestView{}, err
	}
	counts, err := q.BackupCountInactiveRecords(ctx)
	if err != nil {
		return ManifestView{}, err
	}
	view := ManifestView{BackupID: rep.BackupID, Mode: Mode(rep.Mode), Provenance: Provenance(rep.Provenance), Initiator: Initiator(rep.Initiator),
		RestoreGeneration: rep.RestoreGeneration, RestoredAt: rep.RestoredAt, Summary: json.RawMessage(rep.Summary), Items: []ManifestItem{},
		InactiveCredentials: map[string]int{"authenticators": int(counts.Authenticators), "agent_credentials": int(counts.AgentCredentials)}}
	for _, r := range rows {
		ok, why := approvableKind(r.Kind)
		it := ManifestItem{Kind: r.Kind, ID: r.ItemID, Label: r.Label, Origin: r.Origin, Imported: json.RawMessage(r.Imported), Effective: json.RawMessage(r.Effective),
			Decision: r.Decision, Approvable: ok && r.Decision == "pending", BlockedReason: why, Needs: needsOf(r.Kind)}
		if r.SourceState.Valid {
			s := r.SourceState.String
			it.SourceState = &s
		}
		if r.Decision == "approved" {
			view.Approved++
		} else {
			view.Pending++
		}
		view.Items = append(view.Items, it)
	}
	return view, nil
}

func splitPair(id string) (string, string, bool) {
	a, b, ok := strings.Cut(id, ":")
	return a, b, ok && validID(a) && validID(b)
}

// Approve activates explicitly named manifest entries at the CURRENT control generations. It is the
// only way imported (or locally retired) authority becomes effective again, one entry at a time:
// there is no approve-everything form. The request is all-or-nothing: if any entry cannot be
// approved the caller's transaction must roll back, and every refusal is reported in a
// ConflictError. Approving a record never issues or restores a credential; users enroll fresh
// credentials and agents get new tokens through their own lifecycle once approved.
//
// The caller has already established that the initiator is the fresh AAL2 administrator and that the
// installation is outside quarantine; Approve re-checks the latter itself.
func Approve(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64, refs []ItemRef) ([]ItemResult, error) {
	if len(refs) == 0 || len(refs) > MaxApprovalsPerRequest {
		return nil, ErrInvalid
	}
	if c.RestoreQuarantined != 0 || c.CredentialGeneration <= 0 || c.SessionGeneration <= 0 || c.AuthorityGeneration <= 0 || c.RestoreGeneration <= 0 {
		return nil, ErrQuarantined
	}
	seen := map[ItemRef]bool{}
	for _, r := range refs {
		if _, ok := kindOrder[r.Kind]; !ok && r.Kind != "role" && r.Kind != "address" {
			return nil, ErrInvalid
		}
		valid := validID(r.ID)
		if r.Kind == "user_membership" || r.Kind == "agent_membership" {
			_, _, valid = splitPair(r.ID)
		}
		if !valid || seen[r] {
			return nil, ErrInvalid
		}
		seen[r] = true
	}
	rep, err := q.LatestRestoreReport(ctx)
	if err == sql.ErrNoRows {
		return nil, ErrNoRestore
	}
	if err != nil {
		return nil, err
	}
	ordered := append([]ItemRef(nil), refs...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := kindOrder[ordered[i].Kind], kindOrder[ordered[j].Kind]
		if a != b {
			return a < b
		}
		return ordered[i].ID < ordered[j].ID
	})
	var failures []Failure
	var results []ItemResult
	for _, r := range ordered {
		fail := func(reason string) { failures = append(failures, Failure{Kind: r.Kind, ID: r.ID, Reason: reason}) }
		item, err := q.GetRestoreManifestItem(ctx, store.GetRestoreManifestItemParams{RestoreGeneration: rep.RestoreGeneration, Kind: r.Kind, ItemID: r.ID})
		if err == sql.ErrNoRows {
			fail("not_in_manifest")
			continue
		}
		if err != nil {
			return nil, err
		}
		if item.Decision != "pending" {
			fail("already_approved")
			continue
		}
		if ok, why := approvableKind(r.Kind); !ok {
			fail(why)
			continue
		}
		reason, err := activate(ctx, q, c, r)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			fail(reason)
			continue
		}
		eff := jsonObj("state", "active", "needs", needsOf(r.Kind))
		if n, err := q.ApproveRestoreManifestItem(ctx, store.ApproveRestoreManifestItemParams{Now: sql.NullInt64{Int64: now, Valid: true}, Effective: eff,
			RestoreGeneration: rep.RestoreGeneration, Kind: r.Kind, ItemID: r.ID}); err != nil || n != 1 {
			if err == nil {
				fail("already_approved")
				continue
			}
			return nil, err
		}
		results = append(results, ItemResult{Kind: r.Kind, ID: r.ID, Result: "approved"})
	}
	if len(failures) > 0 {
		return nil, &ConflictError{Failures: failures}
	}
	return results, nil
}

// activate applies the per-kind precondition and write. It returns a fixed refusal code, or "".
func activate(ctx context.Context, q *store.Queries, c store.InstallationControl, r ItemRef) (string, error) {
	authority := c.AuthorityGeneration
	one := func(n int64, err error) (string, error) {
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "not_quarantined", nil
		}
		return "", nil
	}
	switch r.Kind {
	case "endpoint":
		return one(q.BackupActivateEndpoint(ctx, store.BackupActivateEndpointParams{AuthorityGeneration: authority, ID: domainEndpoint(r.ID)}))
	case "user":
		u, err := q.GetUser(ctx, r.ID)
		if err != nil {
			return "", err
		}
		if u.Compromised != 0 {
			return "compromised", nil
		}
		return one(q.BackupActivateUser(ctx, store.BackupActivateUserParams{CredentialGeneration: c.CredentialGeneration, AuthorityGeneration: authority, ID: r.ID}))
	case "group":
		return one(q.BackupActivateGroup(ctx, store.BackupActivateGroupParams{AuthorityGeneration: authority, ID: r.ID}))
	case "agent":
		a, err := q.GetAgent(ctx, r.ID)
		if err != nil {
			return "", err
		}
		owner, err := ownerActive(ctx, q, a)
		if err != nil {
			return "", err
		}
		if !owner {
			return "owner_not_active", nil
		}
		return one(q.BackupActivateAgent(ctx, store.BackupActivateAgentParams{CredentialGeneration: c.CredentialGeneration, AuthorityGeneration: authority, ID: r.ID}))
	case "user_membership":
		uid, gid, _ := splitPair(r.ID)
		if reason, err := requireActive(ctx, q, "user", uid, "group", gid); reason != "" || err != nil {
			return reason, err
		}
		return one(q.BackupActivateUserMembership(ctx, store.BackupActivateUserMembershipParams{AuthorityGeneration: authority, UserID: uid, GroupID: gid}))
	case "agent_membership":
		aid, gid, _ := splitPair(r.ID)
		if reason, err := requireActive(ctx, q, "agent", aid, "group", gid); reason != "" || err != nil {
			return reason, err
		}
		return one(q.BackupActivateAgentMembership(ctx, store.BackupActivateAgentMembershipParams{AuthorityGeneration: authority, AgentID: aid, GroupID: gid}))
	case "policy":
		p, err := q.GetPolicy(ctx, r.ID)
		if err != nil {
			return "", err
		}
		subject := [2]string{}
		switch {
		case p.UserID.Valid:
			subject = [2]string{"user", p.UserID.String}
		case p.GroupID.Valid:
			subject = [2]string{"group", p.GroupID.String}
		case p.AgentID.Valid:
			subject = [2]string{"agent", p.AgentID.String}
		}
		if reason, err := requireActive(ctx, q, subject[0], subject[1], "", ""); reason != "" || err != nil {
			return reason, err
		}
		return one(q.BackupActivatePolicy(ctx, store.BackupActivatePolicyParams{AuthorityGeneration: authority, ID: r.ID}))
	}
	return "unsupported", nil
}

func ownerActive(ctx context.Context, q *store.Queries, a store.Agent) (bool, error) {
	switch {
	case a.OwnerUserID.Valid:
		u, err := q.GetUser(ctx, a.OwnerUserID.String)
		return err == nil && u.State == "active", ignoreNoRows(err)
	case a.OwnerGroupID.Valid:
		g, err := q.GetGroup(ctx, a.OwnerGroupID.String)
		return err == nil && g.State == "active", ignoreNoRows(err)
	}
	return false, nil
}

func ignoreNoRows(err error) error {
	if err == sql.ErrNoRows {
		return nil
	}
	return err
}

// requireActive refuses with "subject_not_active" unless every named record is already active: an
// approval can only build on principals that were themselves approved (a partially reviewed
// principal stays denied).
func requireActive(ctx context.Context, q *store.Queries, kindA, idA, kindB, idB string) (string, error) {
	for _, p := range [][2]string{{kindA, idA}, {kindB, idB}} {
		if p[0] == "" {
			continue
		}
		var state string
		var err error
		switch p[0] {
		case "user":
			var u store.User
			u, err = q.GetUser(ctx, p[1])
			state = u.State
		case "group":
			var g store.Group
			g, err = q.GetGroup(ctx, p[1])
			state = g.State
		case "agent":
			var a store.Agent
			a, err = q.GetAgent(ctx, p[1])
			state = a.State
		}
		if err == sql.ErrNoRows || (err == nil && state != "active") {
			return "subject_not_active", nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", nil
}

func domainEndpoint(id string) domain.EndpointID { return domain.EndpointID(id) }
