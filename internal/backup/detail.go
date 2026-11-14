package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18.4 FC4-1. A restored rule or membership is approved "by name", so the manifest must name
// EXACTLY the authority an approval would make effective: the effect and operation, the subject
// (kind, stable ID and display name), the endpoint, the selector with every constraint, and for a
// membership BOTH the principal and the group. Everything here is resolved from the stored rows
// by their stable IDs, never by display-name equality or list order; a record that no longer
// exists falls back to its ID and is flagged Missing. No credential, verifier, token hash or
// secret configuration is ever part of a detail.

// NamedRef identifies a record by kind, immutable ID and display name.
type NamedRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Name is the display name; it equals ID when the record cannot be found.
	Name string `json:"name"`
	// Missing is true when no record with this ID exists (the name is then only the ID).
	Missing bool `json:"missing,omitempty"`
}

// SelectorDetail is the exact container selector of a rule. Absent constraints are empty.
type SelectorDetail struct {
	ID                string `json:"id"`
	NameType          string `json:"name_type"` // "exact" or "glob"
	ContainerName     string `json:"container_name"`
	ComposeProject    string `json:"compose_project,omitempty"`
	ComposeService    string `json:"compose_service,omitempty"`
	ImagePattern      string `json:"image_pattern,omitempty"`
	PinnedContainerID string `json:"pinned_container_id,omitempty"`
	PinnedImageDigest string `json:"pinned_image_digest,omitempty"`
}

// ItemDetail is the identifying detail of one manifest entry (nil for kinds without one).
type ItemDetail struct {
	// Policy rule: the effect and operation, the subject, the endpoint and the selector.
	Effect         string          `json:"effect,omitempty"`
	Operation      string          `json:"operation,omitempty"`
	Subject        *NamedRef       `json:"subject,omitempty"`
	Endpoint       *NamedRef       `json:"endpoint,omitempty"`
	Selector       *SelectorDetail `json:"selector,omitempty"`
	LogTailMax     *int64          `json:"log_tail_max,omitempty"`
	StopTimeoutMax *int64          `json:"stop_timeout_max,omitempty"`
	// Membership: the named principal AND the group.
	Member *NamedRef `json:"member,omitempty"`
	Group  *NamedRef `json:"group,omitempty"`
	// Compromised marks a known-compromised principal: it is never approvable (RESTORE-02).
	Compromised bool `json:"compromised,omitempty"`
}

func ref(kind, id, name string, found bool) *NamedRef {
	if !found || name == "" {
		return &NamedRef{Kind: kind, ID: id, Name: id, Missing: !found}
	}
	return &NamedRef{Kind: kind, ID: id, Name: name}
}

// lookupName resolves one principal/group/endpoint by ID.
func lookupName(ctx context.Context, q *store.Queries, kind, id string) (*NamedRef, error) {
	switch kind {
	case "user":
		u, err := q.GetUser(ctx, id)
		if err == sql.ErrNoRows {
			return ref(kind, id, "", false), nil
		}
		return ref(kind, id, u.Username, err == nil), err
	case "group":
		g, err := q.GetGroup(ctx, id)
		if err == sql.ErrNoRows {
			return ref(kind, id, "", false), nil
		}
		return ref(kind, id, g.Name, err == nil), err
	case "agent":
		a, err := q.GetAgent(ctx, id)
		if err == sql.ErrNoRows {
			return ref(kind, id, "", false), nil
		}
		return ref(kind, id, a.Name, err == nil), err
	case "endpoint":
		e, err := q.GetEndpoint(ctx, domainEndpoint(id))
		if err == sql.ErrNoRows {
			return ref(kind, id, "", false), nil
		}
		return ref(kind, id, e.Slug, err == nil), err
	}
	return ref(kind, id, "", false), nil
}

func nullInt64(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// DetailOf resolves the identifying detail of one entry from the stored rows. It returns nil for
// kinds that carry none (endpoint, group, agent, role, address) and an ItemDetail otherwise.
func DetailOf(ctx context.Context, q *store.Queries, kind, id string) (*ItemDetail, error) {
	switch kind {
	case "user":
		u, err := q.GetUser(ctx, id)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if u.Compromised == 0 {
			return nil, nil
		}
		return &ItemDetail{Compromised: true}, nil
	case "user_membership", "agent_membership":
		memberKind := "user"
		if kind == "agent_membership" {
			memberKind = "agent"
		}
		mid, gid, ok := splitPair(id)
		if !ok {
			return nil, nil
		}
		member, err := lookupName(ctx, q, memberKind, mid)
		if err != nil {
			return nil, err
		}
		group, err := lookupName(ctx, q, "group", gid)
		if err != nil {
			return nil, err
		}
		return &ItemDetail{Member: member, Group: group}, nil
	case "policy":
		p, err := q.GetPolicy(ctx, id)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		d := &ItemDetail{Effect: p.Effect, Operation: p.Operation, LogTailMax: nullInt64(p.LogTailMax), StopTimeoutMax: nullInt64(p.StopTimeoutMax)}
		switch {
		case p.UserID.Valid:
			d.Subject, err = lookupName(ctx, q, "user", p.UserID.String)
		case p.GroupID.Valid:
			d.Subject, err = lookupName(ctx, q, "group", p.GroupID.String)
		case p.AgentID.Valid:
			d.Subject, err = lookupName(ctx, q, "agent", p.AgentID.String)
		}
		if err != nil {
			return nil, err
		}
		if d.Endpoint, err = lookupName(ctx, q, "endpoint", string(p.EndpointID)); err != nil {
			return nil, err
		}
		sel, err := q.GetContainerSelector(ctx, p.SelectorID)
		switch {
		case err == sql.ErrNoRows:
			d.Selector = &SelectorDetail{ID: p.SelectorID, NameType: "unknown"}
		case err != nil:
			return nil, err
		default:
			d.Selector = &SelectorDetail{ID: sel.ID, NameType: "exact", ContainerName: sel.ContainerName, ComposeProject: sel.ComposeProject.String,
				ComposeService: sel.ComposeService.String, ImagePattern: sel.ImagePattern.String, PinnedContainerID: sel.PinnedContainerID.String, PinnedImageDigest: sel.PinnedImageDigest.String}
			if sel.NameIsGlob != 0 {
				d.Selector.NameType = "glob"
			}
		}
		return d, nil
	}
	return nil, nil
}

// DetailDigest fingerprints exactly what an administrator was shown for one entry: the entry's
// identity, its detail and the imported and effective claims. An approval that names a digest is
// refused as stale when the stored state changed after the manifest was displayed, so an
// approval can never apply to something other than what was reviewed.
func DetailDigest(kind, id string, detail *ItemDetail, imported, effective []byte) string {
	h := sha256.New()
	put := func(b []byte) {
		h.Write([]byte(strconv.Itoa(len(b))))
		h.Write([]byte{':'})
		h.Write(b)
	}
	put([]byte(kind))
	put([]byte(id))
	enc := []byte("null")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			enc = b
		}
	}
	put(enc)
	put(imported)
	put(effective)
	return hex.EncodeToString(h.Sum(nil))
}
