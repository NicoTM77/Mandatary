package auth

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.17 policy-rule administration (TD §§3.3, 7; docs/authorization.md).
//
// Authority. Exactly the P1.10 model (agents.go): every method needs the live, fresh (<= 15 min) AAL2 session
// of the single policy administrator, decided from persisted state inside one durable transaction, with
// restore quarantine absent and the control generations current. The administrator role is the authority to
// WRITE rules and is never itself a rule: nothing in this file grants a container operation to any caller,
// and an administrator receives access only from a rule that names it, like anyone else.
//
// Rules. One stored policy per operation (the six approved keys, no wildcard and no other value), naming
// exactly one subject (user, group or agent) that must be ACTIVE now, one composite container selector on the
// local endpoint, an effect (ALLOW/DENY) and, for an ALLOW only, the two ceilings the evaluator enforces.
// Creating several operations at once is all-or-none (one transaction). Selector rows are shared between
// identical selectors. Editing changes only effect, selector and ceilings; subject and operation are fixed
// for the life of a rule. Nothing here ever re-approves a rule from an earlier authority generation or from a
// restore: such a rule can only be deleted (RESTORE-02, S2.4/P1.18 owns reapproval).
//
// Notification. Every committed change is followed by the injected notify (the shared Authorizer's
// NotifyPolicyChange) before the call returns, so a tightened or removed rule cuts open streams; a notify
// failure is ErrAdminUnavailable and never undoes the durable change.
//
// Targets. Whether a rule currently matches anything, and the editor's inventory and preview, come from an
// optional read-only TargetSource (the shared authorizer's view of the endpoint, which never lists Mandatary
// or its peers). It is consulted OUTSIDE the control transaction. Without a source, or when it fails or the
// backend is unverified, every rule's target is UNKNOWN: never present and never missing.

// TargetSource lists the containers of one endpoint as the evaluator sees them. The shared authorizer
// implements it; nothing here lists or contacts Docker itself.
type TargetSource interface {
	Containers(ctx context.Context, endpoint domain.EndpointID) ([]docker.ContainerSummary, error)
}

// AuthorizerTargets adapts the shared authorizer to TargetSource.
type AuthorizerTargets struct{ A *authz.Authorizer }

func (t AuthorizerTargets) Containers(ctx context.Context, endpoint domain.EndpointID) ([]docker.ContainerSummary, error) {
	return t.A.ListEndpointContainers(ctx, endpoint)
}

type targetHolder struct {
	mu  sync.RWMutex
	src TargetSource
}

func (h *targetHolder) get() TargetSource {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.src
}

// WithTargetSource installs (or, with nil, removes) the read-only container source. It is deployment wiring,
// not request input.
func (a *Admin) WithTargetSource(src TargetSource) *Admin {
	a.targets.mu.Lock()
	a.targets.src = src
	a.targets.mu.Unlock()
	return a
}

// Wire types. They never carry a secret, a verifier or an internal generation.

// RuleSubject names who a rule applies to.
type RuleSubject struct {
	Kind string `json:"kind"` // user | group | agent
	ID   string `json:"id"`
}

// SelectorSpec is the composite container selector (TD §7.1). Empty optional fields mean "not set".
type SelectorSpec struct {
	ContainerName     string `json:"container_name"`
	NameIsGlob        bool   `json:"name_is_glob"`
	ComposeProject    string `json:"compose_project,omitempty"`
	ComposeService    string `json:"compose_service,omitempty"`
	ImagePattern      string `json:"image_pattern,omitempty"`
	PinnedContainerID string `json:"pinned_container_id,omitempty"`
	PinnedImageDigest string `json:"pinned_image_digest,omitempty"`
}

// RuleRequest creates one rule per operation, all or none. Effect is ALLOW or DENY.
type RuleRequest struct {
	Subject        RuleSubject
	Effect         string
	Operations     []string
	Selector       SelectorSpec
	LogTailMax     *int
	StopTimeoutMax *int
}

// RuleEdit replaces effect, selector and ceilings of one existing rule.
type RuleEdit struct {
	Effect         string
	Selector       SelectorSpec
	LogTailMax     *int
	StopTimeoutMax *int
}

type SubjectView struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	State         string `json:"state"`
	Administrator bool   `json:"administrator,omitempty"`
}

// TargetView is whether a rule's selector currently matches anything: present, missing (TD §7.2 "Inactive /
// Target Missing"), or unknown (the endpoint cannot be inspected; never presented as a match).
type TargetView struct {
	Status  string `json:"status"`
	Matches int    `json:"matches"`
}

type RuleView struct {
	ID             string       `json:"id"`
	Subject        SubjectView  `json:"subject"`
	Effect         string       `json:"effect"`
	Operation      string       `json:"operation"`
	Selector       SelectorSpec `json:"selector"`
	LogTailMax     *int         `json:"log_tail_max"`
	StopTimeoutMax *int         `json:"stop_timeout_max"`
	State          string       `json:"state"`
	Target         TargetView   `json:"target"`
}

// InventoryItem is one container the evaluator can see. Mandatary and its peers are never listed.
type InventoryItem struct {
	Name           string `json:"name"`
	ShortID        string `json:"short_id"`
	Image          string `json:"image"`
	Running        bool   `json:"running"`
	ComposeProject string `json:"compose_project,omitempty"`
	ComposeService string `json:"compose_service,omitempty"`
}

type EndpointView struct {
	Name   string `json:"name"`
	Safety string `json:"safety"` // verified | unverified
}

type RulesPage struct {
	Rules     []RuleView      `json:"rules"`
	Subjects  []SubjectView   `json:"subjects"`
	Endpoint  EndpointView    `json:"endpoint"`
	Inventory []InventoryItem `json:"inventory"` // nil when the endpoint cannot be listed
}

// Preview is the explanatory result of "which containers does this selector match".
type Preview struct {
	Available bool            `json:"available"`
	Matches   []InventoryItem `json:"matches"`
}

// Limits (docs/authorization.md, TD §3.3).
const (
	maxSelectorText = 255
	maxRulesPerCall = 6 // the six approved operation keys, each at most once
	targetTimeout   = 8 * time.Second
)

var authzOperations = authz.AllOperations()

func operationIndex(op string) int {
	for i, o := range authzOperations {
		if string(o) == op {
			return i
		}
	}
	return -1
}

// plainText reports whether s is printable ASCII with no edge space and no backslash. Names, labels and
// patterns are matched byte for byte against Docker's own ASCII identifiers, so anything else can only be
// a typing mistake or a look-alike (and the evaluator would never match it).
func plainText(s string) bool {
	if s == "" || len(s) > maxSelectorText || s != strings.TrimSpace(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e || s[i] == '\\' {
			return false
		}
	}
	return true
}

func validGlob(p string) bool {
	_, err := authz.MatchGlob(p, "x")
	return err == nil
}

// validateSelector applies the evaluator's own limits to a selector taken from a request.
func validateSelector(s SelectorSpec) error {
	if !plainText(s.ContainerName) {
		return ErrAdminInvalid
	}
	if s.NameIsGlob {
		if !validGlob(s.ContainerName) {
			return ErrAdminInvalid
		}
	} else if strings.ContainsAny(s.ContainerName, "*?[]") {
		return ErrAdminInvalid // an exact name never contains pattern characters
	}
	for _, opt := range []string{s.ComposeProject, s.ComposeService} {
		if opt != "" && !plainText(opt) {
			return ErrAdminInvalid
		}
	}
	if s.ImagePattern != "" && (!plainText(s.ImagePattern) || !validGlob(s.ImagePattern)) {
		return ErrAdminInvalid
	}
	if s.PinnedContainerID != "" {
		id, err := docker.ParseContainerID(s.PinnedContainerID)
		if err != nil || string(id) != s.PinnedContainerID {
			return ErrAdminInvalid
		}
	}
	if s.PinnedImageDigest != "" && !authz.IsValidImageDigest(s.PinnedImageDigest) {
		return ErrAdminInvalid
	}
	return nil
}

func nullText(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func (s SelectorSpec) row(endpoint domain.EndpointID, id string) store.ContainerSelector {
	glob := int64(0)
	if s.NameIsGlob {
		glob = 1
	}
	return store.ContainerSelector{
		ID: id, EndpointID: endpoint, ContainerName: s.ContainerName, NameIsGlob: glob,
		ComposeProject: nullText(s.ComposeProject), ComposeService: nullText(s.ComposeService), ImagePattern: nullText(s.ImagePattern),
		PinnedContainerID: nullText(s.PinnedContainerID), PinnedImageDigest: nullText(s.PinnedImageDigest),
	}
}

func selectorSpecOf(r store.ContainerSelector) SelectorSpec {
	return SelectorSpec{
		ContainerName: r.ContainerName, NameIsGlob: r.NameIsGlob == 1, ComposeProject: r.ComposeProject.String, ComposeService: r.ComposeService.String,
		ImagePattern: r.ImagePattern.String, PinnedContainerID: r.PinnedContainerID.String, PinnedImageDigest: r.PinnedImageDigest.String,
	}
}

func validEffect(e string) bool { return e == "ALLOW" || e == "DENY" }

// capsFor validates the two ceilings for one operation and effect. Only an ALLOW takes a ceiling and each
// ceiling belongs to the operations the evaluator accepts it on (internal/authz SatisfiesPolicyConstraints);
// any other combination is refused rather than silently dropped.
func capsFor(op, effect string, tail, timeout *int) (sql.NullInt64, sql.NullInt64, error) {
	var logMax, stopMax sql.NullInt64
	if tail != nil {
		if effect != "ALLOW" || op != string(authz.OpContainerLogs) || *tail < docker.MinLogTail || *tail > docker.MaxLogTail {
			return logMax, stopMax, ErrAdminInvalid
		}
		logMax = sql.NullInt64{Int64: int64(*tail), Valid: true}
	}
	if timeout != nil {
		if effect != "ALLOW" || (op != string(authz.OpContainerStop) && op != string(authz.OpContainerRestart)) || *timeout < docker.MinStopTimeoutSeconds || *timeout > docker.MaxStopTimeoutSeconds {
			return logMax, stopMax, ErrAdminInvalid
		}
		stopMax = sql.NullInt64{Int64: int64(*timeout), Valid: true}
	}
	return logMax, stopMax, nil
}

// checkCapsReachable refuses a ceiling that no selected operation would carry.
func checkCapsReachable(ops []string, tail, timeout *int) error {
	logs, stops := false, false
	for _, op := range ops {
		logs = logs || op == string(authz.OpContainerLogs)
		stops = stops || op == string(authz.OpContainerStop) || op == string(authz.OpContainerRestart)
	}
	if (tail != nil && !logs) || (timeout != nil && !stops) {
		return ErrAdminInvalid
	}
	return nil
}

func validateOperations(ops []string) error {
	if len(ops) == 0 || len(ops) > maxRulesPerCall {
		return ErrAdminInvalid
	}
	seen := map[string]bool{}
	for _, op := range ops {
		if operationIndex(op) < 0 || seen[op] {
			return ErrAdminInvalid
		}
		seen[op] = true
	}
	return nil
}

// subjectRef resolves the rule's one subject, which must be active now, and returns the policy column it
// belongs in plus its view. Unknown, malformed and inactive subjects are all "invalid": the request named
// something that cannot take a rule.
func subjectRef(ctx context.Context, q *store.Queries, c store.InstallationControl, s RuleSubject) (user, group, agent sql.NullString, view SubjectView, err error) {
	if !validPrincipalID(s.ID) {
		return user, group, agent, view, ErrAdminInvalid
	}
	switch s.Kind {
	case "user":
		u, e := q.GetUser(ctx, s.ID)
		if notFoundIs(e) || (e == nil && !activeUser(u, c)) {
			return user, group, agent, view, ErrAdminInvalid
		} else if e != nil {
			return user, group, agent, view, e
		}
		admin, e := isAdministratorAccount(ctx, q, u.ID)
		if e != nil {
			return user, group, agent, view, e
		}
		return sql.NullString{String: u.ID, Valid: true}, group, agent, SubjectView{Kind: "user", ID: u.ID, Name: u.Username, State: u.State, Administrator: admin}, nil
	case "group":
		g, e := q.GetGroup(ctx, s.ID)
		if notFoundIs(e) || (e == nil && !activeGroup(g, c)) {
			return user, group, agent, view, ErrAdminInvalid
		} else if e != nil {
			return user, group, agent, view, e
		}
		return user, sql.NullString{String: g.ID, Valid: true}, agent, SubjectView{Kind: "group", ID: g.ID, Name: g.Name, State: g.State}, nil
	case "agent":
		ag, e := q.GetAgent(ctx, s.ID)
		if notFoundIs(e) || (e == nil && !activeAgent(ag, c)) {
			return user, group, agent, view, ErrAdminInvalid
		} else if e != nil {
			return user, group, agent, view, e
		}
		return user, group, sql.NullString{String: ag.ID, Valid: true}, SubjectView{Kind: "agent", ID: ag.ID, Name: ag.Name, State: ag.State}, nil
	default:
		return user, group, agent, view, ErrAdminInvalid
	}
}

// ensureSelector returns the id of the stored selector equal to s, creating it when none exists.
func (a *Admin) ensureSelector(ctx context.Context, q *store.Queries, endpoint domain.EndpointID, s SelectorSpec) (string, error) {
	glob := int64(0)
	if s.NameIsGlob {
		glob = 1
	}
	found, err := q.FindSelector(ctx, store.FindSelectorParams{
		EndpointID: endpoint, ContainerName: s.ContainerName, NameIsGlob: glob, ComposeProject: nullText(s.ComposeProject), ComposeService: nullText(s.ComposeService),
		ImagePattern: nullText(s.ImagePattern), PinnedContainerID: nullText(s.PinnedContainerID), PinnedImageDigest: nullText(s.PinnedImageDigest),
	})
	if err == nil {
		return found.ID, nil
	}
	if !notFoundIs(err) {
		return "", err
	}
	id, err := a.newID()
	if err != nil {
		return "", err
	}
	row := s.row(endpoint, id)
	if err = q.CreateSelector(ctx, store.CreateSelectorParams(row)); err != nil {
		return "", err
	}
	return id, nil
}

func ruleView(p store.Policy, sel store.ContainerSelector, subject SubjectView) RuleView {
	v := RuleView{ID: p.ID, Subject: subject, Effect: p.Effect, Operation: p.Operation, Selector: selectorSpecOf(sel), State: p.State, Target: TargetView{Status: "unknown"}}
	if p.LogTailMax.Valid {
		n := int(p.LogTailMax.Int64)
		v.LogTailMax = &n
	}
	if p.StopTimeoutMax.Valid {
		n := int(p.StopTimeoutMax.Int64)
		v.StopTimeoutMax = &n
	}
	return v
}

// CreateRules writes one active rule per requested operation, all or none, for one active subject.
func (a *Admin) CreateRules(ctx context.Context, secret []byte, req RuleRequest) ([]RuleView, error) {
	var out []RuleView
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if !validEffect(req.Effect) || validateOperations(req.Operations) != nil || validateSelector(req.Selector) != nil || checkCapsReachable(req.Operations, req.LogTailMax, req.StopTimeoutMax) != nil {
			return ErrAdminInvalid
		}
		for _, op := range req.Operations { // every ceiling must suit every operation it will be stored on
			if _, _, e := capsForOperation(op, req.Effect, req.LogTailMax, req.StopTimeoutMax); e != nil {
				return e
			}
		}
		user, group, agent, subject, e := subjectRef(ctx, q, c, req.Subject)
		if e != nil {
			return e
		}
		endpoint, e := q.GetLocalEndpoint(ctx)
		if e != nil {
			return e
		}
		selectorID, e := a.ensureSelector(ctx, q, endpoint.ID, req.Selector)
		if e != nil {
			return e
		}
		sel := req.Selector.row(endpoint.ID, selectorID)
		for _, op := range req.Operations {
			logMax, stopMax, e := capsForOperation(op, req.Effect, req.LogTailMax, req.StopTimeoutMax)
			if e != nil {
				return e
			}
			dup, e := q.CountEquivalentPolicies(ctx, store.CountEquivalentPoliciesParams{UserID: user, GroupID: group, AgentID: agent, EndpointID: endpoint.ID, SelectorID: selectorID, Operation: op, Effect: req.Effect})
			if e != nil {
				return e
			}
			if dup != 0 {
				return ErrAdminConflict
			}
			id, e := a.newID()
			if e != nil {
				return e
			}
			if e = q.CreateActivePolicy(ctx, store.CreateActivePolicyParams{ID: id, UserID: user, GroupID: group, AgentID: agent, EndpointID: endpoint.ID, SelectorID: selectorID, Operation: op, Effect: req.Effect,
				AuthorityGeneration: c.AuthorityGeneration, LogTailMax: logMax, StopTimeoutMax: stopMax}); e != nil {
				return e
			}
			p := store.Policy{ID: id, UserID: user, GroupID: group, AgentID: agent, EndpointID: endpoint.ID, SelectorID: selectorID, Operation: op, Effect: req.Effect, State: "active", AuthorityGeneration: c.AuthorityGeneration, LogTailMax: logMax, StopTimeoutMax: stopMax}
			out = append(out, ruleView(p, sel, subject))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = a.changed(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// capsForOperation picks the ceilings that apply to one operation and validates them.
func capsForOperation(op, effect string, tail, timeout *int) (sql.NullInt64, sql.NullInt64, error) {
	var t, s *int
	if op == string(authz.OpContainerLogs) {
		t = tail
	}
	if op == string(authz.OpContainerStop) || op == string(authz.OpContainerRestart) {
		s = timeout
	}
	if effect == "DENY" && (tail != nil || timeout != nil) {
		return sql.NullInt64{}, sql.NullInt64{}, ErrAdminInvalid
	}
	return capsFor(op, effect, t, s)
}

// loadPolicy reads a rule the request names.
func loadPolicy(ctx context.Context, q *store.Queries, id string) (store.Policy, error) {
	if !validPrincipalID(id) {
		return store.Policy{}, ErrAdminInvalid
	}
	p, err := q.GetPolicy(ctx, id)
	if notFoundIs(err) {
		return store.Policy{}, ErrAdminNotFound
	}
	return p, err
}

// UpdateRule changes the effect, selector and ceilings of a current-generation active or disabled rule. It
// never changes the subject, the operation or the state, so an edit can neither enable a disabled rule nor
// move a rule to someone else.
func (a *Admin) UpdateRule(ctx context.Context, secret []byte, id string, edit RuleEdit) (RuleView, error) {
	var out RuleView
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		if !validEffect(edit.Effect) || validateSelector(edit.Selector) != nil {
			return ErrAdminInvalid
		}
		p, e := loadPolicy(ctx, q, id)
		if e != nil {
			return e
		}
		if e = checkCapsReachable([]string{p.Operation}, edit.LogTailMax, edit.StopTimeoutMax); e != nil {
			return e // a ceiling this operation cannot take is refused, never dropped
		}
		logMax, stopMax, e := capsForOperation(p.Operation, edit.Effect, edit.LogTailMax, edit.StopTimeoutMax)
		if e != nil {
			return e
		}
		if (p.State != "active" && p.State != "disabled") || p.AuthorityGeneration != c.AuthorityGeneration {
			return ErrAdminConflict
		}
		selectorID, e := a.ensureSelector(ctx, q, p.EndpointID, edit.Selector)
		if e != nil {
			return e
		}
		dup, e := q.CountEquivalentPolicies(ctx, store.CountEquivalentPoliciesParams{UserID: p.UserID, GroupID: p.GroupID, AgentID: p.AgentID, EndpointID: p.EndpointID, SelectorID: selectorID, Operation: p.Operation, Effect: edit.Effect, ExceptID: p.ID})
		if e != nil {
			return e
		}
		if dup != 0 {
			return ErrAdminConflict
		}
		if n, e := q.UpdatePolicyRule(ctx, store.UpdatePolicyRuleParams{ID: p.ID, Effect: edit.Effect, SelectorID: selectorID, LogTailMax: logMax, StopTimeoutMax: stopMax, Generation: c.AuthorityGeneration}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		p.Effect, p.SelectorID, p.LogTailMax, p.StopTimeoutMax = edit.Effect, selectorID, logMax, stopMax
		subject, e := subjectOfPolicy(ctx, q, p)
		if e != nil {
			return e
		}
		out = ruleView(p, edit.Selector.row(p.EndpointID, selectorID), subject)
		return nil
	})
	if err != nil {
		return RuleView{}, err
	}
	if err = a.changed(ctx); err != nil {
		return RuleView{}, err
	}
	return out, nil
}

// subjectOfPolicy builds the subject view of a stored rule (any state of the subject).
func subjectOfPolicy(ctx context.Context, q *store.Queries, p store.Policy) (SubjectView, error) {
	switch {
	case p.UserID.Valid:
		u, err := q.GetUser(ctx, p.UserID.String)
		if err != nil {
			return SubjectView{}, err
		}
		admin, err := isAdministratorAccount(ctx, q, u.ID)
		return SubjectView{Kind: "user", ID: u.ID, Name: u.Username, State: u.State, Administrator: admin}, err
	case p.GroupID.Valid:
		g, err := q.GetGroup(ctx, p.GroupID.String)
		return SubjectView{Kind: "group", ID: g.ID, Name: g.Name, State: g.State}, err
	default:
		ag, err := q.GetAgent(ctx, p.AgentID.String)
		return SubjectView{Kind: "agent", ID: ag.ID, Name: ag.Name, State: ag.State}, err
	}
}

// EnableRule activates a disabled, current-generation rule.
func (a *Admin) EnableRule(ctx context.Context, secret []byte, id string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		p, e := loadPolicy(ctx, q, id)
		if e != nil {
			return e
		}
		if n, e := q.SetPolicyEnabled(ctx, store.SetPolicyEnabledParams{ID: p.ID, Generation: c.AuthorityGeneration}); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// DisableRule deactivates an active rule. Repeating it is harmless and still notifies, so a failed
// notification can be retried. A restored (quarantined) rule is never touched: it can only be deleted.
func (a *Admin) DisableRule(ctx context.Context, secret []byte, id string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		p, e := loadPolicy(ctx, q, id)
		if e != nil {
			return e
		}
		switch p.State {
		case "disabled":
			return nil
		case "active":
			if n, e := q.SetPolicyDisabled(ctx, p.ID); e != nil || n != 1 {
				return ErrAdminConflict
			}
			return nil
		default:
			return ErrAdminConflict
		}
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// DeleteRule removes a rule in any state. The selector it used stays (it is shared and may be referenced by
// usage history).
func (a *Admin) DeleteRule(ctx context.Context, secret []byte, id string) error {
	err := a.mutate(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		p, e := loadPolicy(ctx, q, id)
		if e != nil {
			return e
		}
		if n, e := q.DeletePolicy(ctx, p.ID); e != nil || n != 1 {
			return ErrAdminConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.changed(ctx)
}

// allPolicies lists every stored rule on every endpoint (only the local one is active in Phase 1).
func allPolicies(ctx context.Context, q *store.Queries) ([]store.Policy, error) {
	return q.ListAllPolicies(ctx)
}

func inventoryItem(c docker.ContainerSummary) InventoryItem {
	short := string(c.ContainerID)
	if len(short) > 12 {
		short = short[:12]
	}
	return InventoryItem{
		Name: strings.TrimPrefix(c.Name, "/"), ShortID: short, Image: c.Image, Running: c.State == "running",
		ComposeProject: c.ComposeProject, ComposeService: c.ComposeService,
	}
}

// containers asks the source for the endpoint's visible containers, bounded in time. ok is false for any
// reason the endpoint cannot be inspected.
func (a *Admin) containers(ctx context.Context, endpoint domain.EndpointID) (list []docker.ContainerSummary, ok bool) {
	src := a.targets.get()
	if src == nil {
		return nil, false
	}
	bounded, cancel := context.WithTimeout(ctx, targetTimeout)
	defer cancel()
	list, err := src.Containers(bounded, endpoint)
	if err != nil {
		return nil, false
	}
	return list, true
}

func countMatches(sel store.ContainerSelector, list []docker.ContainerSummary) (matches int, ok bool) {
	for _, c := range list {
		m, err := authz.MatchSelector(sel, c)
		if err != nil {
			return 0, false // an unreadable selector is never "present" or "missing"
		}
		if m {
			matches++
		}
	}
	return matches, true
}

// RulesPage returns every rule with its subject and, when the endpoint can be inspected, whether its target
// exists. Read-only: it needs the administrator session but not a fresh one.
func (a *Admin) RulesPage(ctx context.Context, secret []byte) (RulesPage, error) {
	page := RulesPage{Rules: []RuleView{}, Subjects: []SubjectView{}}
	var rows []store.ContainerSelector
	var endpoint store.Endpoint
	byID := map[string]store.ContainerSelector{}
	var policies []store.Policy
	err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, c store.InstallationControl, _ int64) error {
		var e error
		if endpoint, e = q.GetLocalEndpoint(ctx); e != nil {
			return e
		}
		if rows, e = q.ListSelectorsByEndpoint(ctx, endpoint.ID); e != nil {
			return e
		}
		if policies, e = allPolicies(ctx, q); e != nil {
			return e
		}
		page.Subjects, e = subjectViews(ctx, q)
		return e
	})
	if err != nil {
		return RulesPage{}, err
	}
	for _, r := range rows {
		byID[r.ID] = r
	}
	subjects := map[string]SubjectView{}
	for _, s := range page.Subjects {
		subjects[s.Kind+"/"+s.ID] = s
	}
	list, inspected := a.containers(ctx, endpoint.ID)
	page.Endpoint = EndpointView{Name: "Local (Docker socket on this host)", Safety: "unverified"}
	if inspected {
		page.Endpoint.Safety = "verified"
		page.Inventory = make([]InventoryItem, 0, len(list))
		for _, c := range list {
			page.Inventory = append(page.Inventory, inventoryItem(c))
		}
	}
	for _, p := range policies {
		sel, found := byID[p.SelectorID]
		if !found {
			continue // cannot happen (foreign key); never invent a rule from a missing selector
		}
		kind, id := "agent", p.AgentID.String
		if p.UserID.Valid {
			kind, id = "user", p.UserID.String
		} else if p.GroupID.Valid {
			kind, id = "group", p.GroupID.String
		}
		v := ruleView(p, sel, subjects[kind+"/"+id])
		if inspected {
			if n, ok := countMatches(sel, list); ok {
				v.Target = TargetView{Status: "present", Matches: n}
				if n == 0 {
					v.Target.Status = "missing"
				}
			}
		}
		page.Rules = append(page.Rules, v)
	}
	sort.SliceStable(page.Rules, func(i, j int) bool {
		x, y := page.Rules[i], page.Rules[j]
		if x.Selector.ContainerName != y.Selector.ContainerName {
			return x.Selector.ContainerName < y.Selector.ContainerName
		}
		if x.Subject.Name != y.Subject.Name {
			return x.Subject.Name < y.Subject.Name
		}
		return operationIndex(x.Operation) < operationIndex(y.Operation)
	})
	return page, nil
}

// subjectViews lists every user, group and agent with its state, so the editor can show disabled ones as
// unavailable instead of hiding them. The role is never a subject.
func subjectViews(ctx context.Context, q *store.Queries) ([]SubjectView, error) {
	var out []SubjectView
	users, err := q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		admin, e := isAdministratorAccount(ctx, q, u.ID)
		if e != nil {
			return nil, e
		}
		out = append(out, SubjectView{Kind: "user", ID: u.ID, Name: u.Username, State: u.State, Administrator: admin})
	}
	groups, err := q.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		out = append(out, SubjectView{Kind: "group", ID: g.ID, Name: g.Name, State: g.State})
	}
	agents, err := q.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	for _, ag := range agents {
		out = append(out, SubjectView{Kind: "agent", ID: ag.ID, Name: ag.Name, State: ag.State})
	}
	return out, nil
}

// PreviewSelector reports which visible containers a selector matches right now, using the evaluator's own
// matcher. It is explanatory only: every request is evaluated again when it arrives. It writes nothing.
func (a *Admin) PreviewSelector(ctx context.Context, secret []byte, s SelectorSpec) (Preview, error) {
	if validateSelector(s) != nil {
		// The refusal is only meaningful to the proven administrator, so authenticate first.
		if err := a.view(ctx, secret, func(context.Context, *store.Queries, store.InstallationControl, int64) error { return nil }); err != nil {
			return Preview{}, err
		}
		return Preview{}, ErrAdminInvalid
	}
	var endpoint store.Endpoint
	if err := a.view(ctx, secret, func(ctx context.Context, q *store.Queries, _ store.InstallationControl, _ int64) error {
		var e error
		endpoint, e = q.GetLocalEndpoint(ctx)
		return e
	}); err != nil {
		return Preview{}, err
	}
	out := Preview{Matches: []InventoryItem{}}
	list, ok := a.containers(ctx, endpoint.ID)
	if !ok {
		return out, nil
	}
	out.Available = true
	sel := s.row(endpoint.ID, "preview")
	for _, c := range list {
		if m, err := authz.MatchSelector(sel, c); err == nil && m {
			out.Matches = append(out.Matches, inventoryItem(c))
		}
	}
	return out, nil
}
