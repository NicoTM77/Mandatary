package authz

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// Config configures a shared Authorizer instance.
type Config struct {
	Repository         *store.Repository
	Clock              func() time.Time
	Backends           map[domain.EndpointID]docker.DockerBackend
	CredentialVerifier CredentialVerifier
}

// AuthorizeRequest represents a single container operation authorization check.
type AuthorizeRequest struct {
	Principal           PrincipalCredentials
	EndpointID          domain.EndpointID
	TargetRef           string
	Target              *docker.ContainerSummary
	Operation           docker.Operation
	LogOptions          *docker.LogOptions
	StopOptions         *docker.StopOptions
	RestartOptions      *docker.RestartOptions
	ExpectedGenerations *store.Generations
	RequireAAL2         bool
}

// Decision captures an approved authorization bound to an immutable TargetIdentity
// and the exact control/policy generations observed at decision time.
type Decision struct {
	Target          docker.TargetIdentity
	ContainerName   string
	Operation       docker.Operation
	Principal       VerifiedPrincipal
	MatchedPolicyID PolicyID
	SelectorID      domain.SelectorID
	Generations     store.Generations
	PolicyEpoch     uint64
	LogOptions      *docker.LogOptions
	TimeoutSeconds  *int
	DecidedAt       time.Time

	creds       PrincipalCredentials
	requireAAL2 bool
	binding     decisionBinding
}

// Unlike a policy revision (which permits fresh re-evaluation), these bindings
// are permanent issuance boundaries. Rebinding even the same backend revokes
// earlier decisions; re-registering an old instance cannot resurrect them.
type decisionBinding struct {
	issuer               *Authorizer
	backendRevision      uint64
	invalidationRevision uint64
}

// Lease represents an active, cancellable authorization handle (e.g., for streaming logs).
type Lease struct {
	Decision   Decision
	id         uint64
	authorizer *Authorizer
	ctx        context.Context
	cancel     context.CancelFunc
	releaseOne sync.Once
}

// Context returns the Lease's context, which is canceled when the Lease is
// released or invalidated by a policy, principal, or safety state change.
func (l *Lease) Context() context.Context {
	if l == nil || l.ctx == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return l.ctx
}

// Release cancels the Lease and removes it from the Authorizer's active set.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.releaseOne.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}
		if l.authorizer != nil {
			l.authorizer.removeLease(l.id)
		}
	})
}

// Revalidate checks whether the Lease's authorization decision remains valid
// against current storage, principal, policy, and backend safety state.
// If revalidation fails, the Lease is immediately canceled and released.
func (l *Lease) Revalidate(ctx context.Context) error {
	if l == nil || l.authorizer == nil {
		return newForbidden(ReasonDecisionStale)
	}
	if l.Context().Err() != nil {
		return newForbidden(ReasonDecisionStale)
	}
	if err := l.authorizer.ValidateDecision(ctx, l.Decision); err != nil {
		l.Release()
		return err
	}
	return nil
}

// PolicyTargetStatus reports whether a stored policy's selector currently matches
// any extant non-protected container on its endpoint (TD §7.2).
type PolicyTargetStatus struct {
	PolicyID            PolicyID
	SelectorID          domain.SelectorID
	ContainerName       string
	TargetMissing       bool
	MatchedContainerIDs []docker.ContainerID
}

// Authorizer is the unified default-deny policy engine.
type Authorizer struct {
	repo        *store.Repository
	clock       func() time.Time
	verifier    CredentialVerifier
	mu          sync.RWMutex
	backends    map[domain.EndpointID]docker.DockerBackend
	leases      map[uint64]*Lease
	nextLeaseID atomic.Uint64
	// policyEpoch is protected by mu. Never hold mu across storage/backend
	// evaluation I/O; compare the captured revision at publication instead.
	policyEpoch          uint64
	backendRevisions     map[domain.EndpointID]uint64
	invalidationRevision uint64
	// notifySem serializes NotifyPolicyChange's epoch bump and lease
	// revalidation so concurrent notifications cannot continuously invalidate
	// each other's in-flight revalidations (capacity 1; context-aware).
	notifySem chan struct{}
}

// NewAuthorizer constructs a shared default-deny Authorizer.
func NewAuthorizer(cfg Config) (*Authorizer, error) {
	if cfg.Repository == nil {
		return nil, ErrInvalidConfig
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	verifier := cfg.CredentialVerifier
	if verifier == nil {
		verifier = NewStoreCredentialVerifier()
	}

	backends := make(map[domain.EndpointID]docker.DockerBackend, len(cfg.Backends))
	for epID, b := range cfg.Backends {
		if _, err := domain.ParseEndpointID(string(epID)); err != nil || b == nil || b.EndpointID() != epID {
			return nil, ErrInvalidConfig
		}
		backends[epID] = b
	}

	az := &Authorizer{
		repo:             cfg.Repository,
		clock:            clock,
		verifier:         verifier,
		backends:         backends,
		leases:           make(map[uint64]*Lease),
		backendRevisions: make(map[domain.EndpointID]uint64),
		notifySem:        make(chan struct{}, 1),
	}
	az.policyEpoch = 1
	return az, nil
}

// RegisterBackend binds or replaces the DockerBackend for endpointID.
// Rebinding an endpoint invalidates active leases on that endpoint so cached
// self-verification or target bindings cannot cross backend instances (SELF-13).
func (a *Authorizer) RegisterBackend(endpointID domain.EndpointID, backend docker.DockerBackend) error {
	if _, err := domain.ParseEndpointID(string(endpointID)); err != nil || backend == nil || backend.EndpointID() != endpointID {
		return ErrInvalidConfig
	}
	var toCancel []*Lease
	a.mu.Lock()
	a.backends[endpointID] = backend
	a.backendRevisions[endpointID]++
	a.policyEpoch++
	for _, l := range a.leases {
		if l.Decision.Target.EndpointID == endpointID {
			toCancel = append(toCancel, l)
		}
	}
	a.mu.Unlock()

	for _, l := range toCancel {
		l.Release()
	}
	return nil
}

// RemoveBackend unregisters the DockerBackend for endpointID and cancels active leases on it.
func (a *Authorizer) RemoveBackend(endpointID domain.EndpointID) {
	var toCancel []*Lease
	a.mu.Lock()
	delete(a.backends, endpointID)
	a.backendRevisions[endpointID]++
	a.policyEpoch++
	for _, l := range a.leases {
		if l.Decision.Target.EndpointID == endpointID {
			toCancel = append(toCancel, l)
		}
	}
	a.mu.Unlock()

	for _, l := range toCancel {
		l.Release()
	}
}

func (a *Authorizer) getBackend(endpointID domain.EndpointID) (docker.DockerBackend, bool) {
	a.mu.RLock()
	b, ok := a.backends[endpointID]
	a.mu.RUnlock()
	return b, ok
}

// BackendFor returns the DockerBackend that authorized dec so a dispatcher
// executes on exactly the instance the decision was issued against (P1.13). It
// refuses a zero or foreign decision, any decision whose issuing binding was
// revoked (rebinding, removal or InvalidateAll), and an endpoint whose backend is
// no longer ready and self/peer verified; so a refusal causes zero backend calls.
func (a *Authorizer) BackendFor(dec Decision) (docker.DockerBackend, error) {
	a.mu.RLock()
	backend, ok := a.backends[dec.Target.EndpointID]
	bound := a.validBindingLocked(dec)
	a.mu.RUnlock()
	if !bound || !ok || backend == nil {
		return nil, newForbidden(ReasonDecisionStale)
	}
	if !backendSafe(backend) {
		return nil, newForbidden(ReasonSafetyUnverified)
	}
	return backend, nil
}

// validBindingLocked requires mu to be held for reading or writing.
func (a *Authorizer) validBindingLocked(dec Decision) bool {
	return dec.binding.issuer == a &&
		dec.binding.backendRevision == a.backendRevisions[dec.Target.EndpointID] &&
		dec.binding.invalidationRevision == a.invalidationRevision
}

func (a *Authorizer) removeLease(id uint64) {
	a.mu.Lock()
	delete(a.leases, id)
	a.mu.Unlock()
}

func (a *Authorizer) cancelMatchingLeases(dec Decision) {
	a.cancelLeases(dec, true)
}

// Shared target/safety failures invalidate peers too; local validation and
// credential failures must not revoke another principal using the same rule.
func (a *Authorizer) cancelLeases(dec Decision, principalOnly bool) {
	var toCancel []*Lease
	a.mu.RLock()
	for _, l := range a.leases {
		p, other := dec.Principal, l.Decision.Principal
		samePrincipal := p.Kind == other.Kind && p.UserID == other.UserID &&
			p.SessionID == other.SessionID && p.AgentID == other.AgentID &&
			p.AgentCredentialID == other.AgentCredentialID
		if l.Decision.binding == dec.binding && l.Decision.Target == dec.Target &&
			l.Decision.Operation == dec.Operation && l.Decision.MatchedPolicyID == dec.MatchedPolicyID &&
			(!principalOnly || samePrincipal) {
			toCancel = append(toCancel, l)
		}
	}
	a.mu.RUnlock()
	for _, l := range toCancel {
		l.Release()
	}
}

// Authorize evaluates a single container operation request in strict precedence order:
//  1. Self-Protection & Runtime Safety State (403)
//  2. Principal & Credential Status Verification (401)
//  3. Explicit DENY across direct and group policies (403)
//  4. Explicit ALLOW with parameter constraint satisfaction (200)
//  5. Default Deny fallback (403)
func (a *Authorizer) Authorize(ctx context.Context, req AuthorizeRequest) (Decision, error) {
	if ctx.Err() != nil {
		return Decision{}, newForbidden(ReasonDefaultDeny)
	}
	if _, err := domain.ParseEndpointID(string(req.EndpointID)); err != nil {
		return Decision{}, newForbidden(ReasonEndpointInactive)
	}

	// Precedence 1: Self-protection & runtime safety verification precede auth and policy.
	if req.Target != nil && docker.HasProtectedNamespaceLabel(req.Target.Labels) {
		return Decision{}, newForbidden(ReasonSelfProtected)
	}

	a.mu.RLock()
	backend, hasBackend := a.backends[req.EndpointID]
	epoch := a.policyEpoch
	binding := decisionBinding{
		issuer:               a,
		backendRevision:      a.backendRevisions[req.EndpointID],
		invalidationRevision: a.invalidationRevision,
	}
	a.mu.RUnlock()
	if !hasBackend || backend == nil || !backend.Ready() || backend.VerificationState() != docker.StateVerified {
		return Decision{}, newForbidden(ReasonSafetyUnverified)
	}

	targetRef := strings.TrimSpace(req.TargetRef)
	if targetRef == "" && req.Target != nil {
		targetRef = strings.TrimSpace(string(req.Target.ContainerID))
		if targetRef == "" {
			targetRef = strings.TrimSpace(req.Target.Name)
		}
	}

	var resolvedTarget docker.ContainerSummary
	var resolveErr error
	if targetRef == "" {
		resolveErr = docker.ErrInvalidTarget
	} else {
		resolvedTarget, resolveErr = backend.ResolveTarget(ctx, targetRef)
		if errors.Is(resolveErr, docker.ErrProtectedTarget) {
			return Decision{}, newForbidden(ReasonSelfProtected)
		}
		if errors.Is(resolveErr, docker.ErrUnverified) {
			return Decision{}, newForbidden(ReasonSafetyUnverified)
		}
		if resolveErr == nil {
			if docker.HasProtectedNamespaceLabel(resolvedTarget.Labels) {
				return Decision{}, newForbidden(ReasonSelfProtected)
			}
			if resolvedTarget.EndpointID != req.EndpointID {
				return Decision{}, newForbidden(ReasonEndpointInactive)
			}
		}
	}

	now := a.clock()

	var decision Decision
	var decisionErr error
	// attr is set once the principal is verified (never before): it lets the shared
	// operation service account a denial of an authenticated principal (TD 9.1).
	var attr *Attribution

	readErr := a.repo.Read(ctx, func(q *store.Queries) error {
		control, err := q.GetInstallationControl(ctx)
		if err != nil {
			return err
		}
		if !activeInstallationControl(control) {
			decisionErr = newForbidden(ReasonRestoreQuarantined)
			return nil
		}

		currentGens := store.Generations{
			Credential: control.CredentialGeneration,
			Session:    control.SessionGeneration,
			Authority:  control.AuthorityGeneration,
			Restore:    control.RestoreGeneration,
		}
		if req.ExpectedGenerations != nil && currentGens != *req.ExpectedGenerations {
			decisionErr = newForbidden(ReasonDecisionStale)
			return nil
		}

		// Precedence 2: Principal & Credential Status (401).
		principal, vErr := a.verifier.VerifyPrincipal(ctx, q, control, req.Principal, now)
		if vErr != nil {
			decisionErr = vErr
			return nil
		}
		if req.RequireAAL2 && (principal.Kind != PrincipalUser || principal.AchievedAssurance < 2) {
			decisionErr = newUnauthenticated(ReasonUnauthenticated)
			return nil
		}
		base := principalAttribution(principal)
		base.EndpointID, base.Operation = req.EndpointID, req.Operation
		attr = &base

		// Endpoint DB activation & authority generation check (403).
		ep, epErr := q.GetEndpoint(ctx, req.EndpointID)
		if epErr != nil {
			decisionErr = newForbidden(ReasonEndpointInactive)
			return nil
		}
		if ep.State != "active" || ep.Slug != "local" || ep.Transport != "unix" || ep.AuthorityGeneration <= 0 || ep.AuthorityGeneration != control.AuthorityGeneration {
			decisionErr = newForbidden(ReasonEndpointInactive)
			return nil
		}

		// Operation catalog & parameter validation (403).
		normLog, normTimeout, pErr := ValidateRequestParameters(req.Operation, req.LogOptions, req.StopOptions, req.RestartOptions)
		if pErr != nil {
			decisionErr = pErr
			return nil
		}

		// Target existence check (403).
		if resolveErr != nil {
			if errors.Is(resolveErr, docker.ErrTargetNotFound) {
				decisionErr = newForbidden(ReasonTargetMissing)
				return nil
			}
			decisionErr = newForbidden(ReasonDefaultDeny)
			return nil
		}

		// Precedence 3, 4, 5: Explicit DENY -> Explicit ALLOW -> Default Deny.
		policyID, selectorID, evalErr := evaluatePolicies(
			ctx,
			q,
			control,
			principal,
			req.EndpointID,
			req.Operation,
			resolvedTarget,
			normLog,
			normTimeout,
		)
		if evalErr != nil {
			attr.SelectorID = selectorID // the deciding selector, when one decided
			decisionErr = evalErr
			return nil
		}

		targetID, tErr := docker.ParseTargetIdentity(resolvedTarget.EndpointID, string(resolvedTarget.ContainerID))
		if tErr != nil {
			decisionErr = newForbidden(ReasonDefaultDeny)
			return nil
		}

		decision = Decision{
			Target:          targetID,
			ContainerName:   resolvedTarget.Name,
			Operation:       req.Operation,
			Principal:       principal,
			MatchedPolicyID: policyID,
			SelectorID:      selectorID,
			Generations:     currentGens,
			PolicyEpoch:     epoch,
			LogOptions:      normLog,
			TimeoutSeconds:  normTimeout,
			DecidedAt:       now,
			creds:           req.Principal,
			requireAAL2:     req.RequireAAL2,
			binding:         binding,
		}
		return nil
	})

	if readErr != nil {
		return Decision{}, newForbidden(ReasonDefaultDeny)
	}
	if decisionErr != nil {
		return Decision{}, attribute(decisionErr, attr)
	}

	// Final safety check so concurrent continuity loss during policy evaluation cannot allow.
	// The principal and selector are known by now, so these denials are attributed too.
	finalAttr := decision.Attribution()
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ctx.Err() != nil || epoch != a.policyEpoch {
		return Decision{}, attribute(newForbidden(ReasonDecisionStale), &finalAttr)
	}
	currentBackend, ok := a.backends[req.EndpointID]
	if !ok || currentBackend != backend || !backend.Ready() || backend.VerificationState() != docker.StateVerified {
		return Decision{}, attribute(newForbidden(ReasonSafetyUnverified), &finalAttr)
	}

	return decision, nil
}

func evaluatePolicies(
	ctx context.Context,
	q *store.Queries,
	control store.InstallationControl,
	principal VerifiedPrincipal,
	endpointID domain.EndpointID,
	op docker.Operation,
	target docker.ContainerSummary,
	normLog *docker.LogOptions,
	normTimeout *int,
) (PolicyID, domain.SelectorID, error) {
	rows, err := q.ListEndpointOperationPoliciesWithSelectors(ctx, store.ListEndpointOperationPoliciesWithSelectorsParams{
		EndpointID: endpointID,
		Operation:  string(op),
	})
	if err != nil {
		return "", "", newForbidden(ReasonDefaultDeny)
	}

	activeGroupSet := make(map[domain.GroupID]struct{}, len(principal.ActiveGroups))
	for _, g := range principal.ActiveGroups {
		activeGroupSet[g] = struct{}{}
	}
	denyGroupSet := make(map[domain.GroupID]struct{}, len(principal.DenyCandidateGroups))
	for _, g := range principal.DenyCandidateGroups {
		denyGroupSet[g] = struct{}{}
	}

	var matchedAllow *store.ListEndpointOperationPoliciesWithSelectorsRow
	sawCapExceeded := false
	var capSelector domain.SelectorID

	for i := range rows {
		row := &rows[i]

		// Validate policy row integrity: exactly one subject column must be non-null.
		subjCount := 0
		if row.UserID.Valid {
			subjCount++
		}
		if row.GroupID.Valid {
			subjCount++
		}
		if row.AgentID.Valid {
			subjCount++
		}
		if subjCount != 1 {
			return "", "", newForbidden(ReasonDefaultDeny)
		}
		if row.Effect != "ALLOW" && row.Effect != "DENY" {
			return "", "", newForbidden(ReasonDefaultDeny)
		}
		if row.PolicyState != "active" && row.PolicyState != "quarantined" && row.PolicyState != "disabled" {
			return "", "", newForbidden(ReasonDefaultDeny)
		}
		if row.PolicyState == "disabled" {
			continue
		}

		// Determine whether this rule applies to the current principal.
		applies := false
		if row.Effect == "DENY" {
			// Per RESTORE-03, active and quarantined DENY rules conservatively block
			// across direct and group memberships.
			switch principal.Kind {
			case PrincipalUser:
				if row.UserID.Valid && domain.UserID(row.UserID.String) == principal.UserID {
					applies = true
				} else if row.GroupID.Valid {
					_, applies = denyGroupSet[domain.GroupID(row.GroupID.String)]
				}
			case PrincipalAgent:
				if row.AgentID.Valid && domain.AgentID(row.AgentID.String) == principal.AgentID {
					applies = true
				} else if row.GroupID.Valid {
					_, applies = denyGroupSet[domain.GroupID(row.GroupID.String)]
				}
			}
		} else {
			// ALLOW rules grant authority ONLY when active and matching current AuthorityGeneration.
			if row.PolicyState != "active" || row.PolicyAuthorityGeneration <= 0 || row.PolicyAuthorityGeneration != control.AuthorityGeneration {
				continue
			}
			switch principal.Kind {
			case PrincipalUser:
				if row.UserID.Valid && domain.UserID(row.UserID.String) == principal.UserID {
					applies = true
				} else if row.GroupID.Valid {
					_, applies = activeGroupSet[domain.GroupID(row.GroupID.String)]
				}
			case PrincipalAgent:
				if row.AgentID.Valid && domain.AgentID(row.AgentID.String) == principal.AgentID {
					applies = true
				} else if row.GroupID.Valid {
					_, applies = activeGroupSet[domain.GroupID(row.GroupID.String)]
				}
			}
		}

		if !applies {
			continue
		}

		sel := store.ContainerSelector{
			ID:                row.SelectorID,
			EndpointID:        row.SelectorEndpointID,
			ContainerName:     row.ContainerName,
			NameIsGlob:        row.NameIsGlob,
			ComposeProject:    row.ComposeProject,
			ComposeService:    row.ComposeService,
			ImagePattern:      row.ImagePattern,
			PinnedContainerID: row.PinnedContainerID,
			PinnedImageDigest: row.PinnedImageDigest,
		}
		matched, mErr := MatchSelector(sel, target)
		if mErr != nil {
			return "", "", mErr
		}
		if !matched {
			continue
		}

		// Precedence 3: Explicit DENY overrides all direct and group ALLOWs. The
		// denying rule's selector is returned with the denial for usage attribution.
		if row.Effect == "DENY" {
			return "", domain.SelectorID(row.SelectorID), newForbidden(ReasonExplicitDeny)
		}

		// Precedence 4: Explicit ALLOW must satisfy operation parameter caps.
		if SatisfiesPolicyConstraints(op, normLog, normTimeout, row.LogTailMax, row.StopTimeoutMax) {
			if matchedAllow == nil {
				matchedAllow = row
			}
		} else {
			if !sawCapExceeded {
				capSelector = domain.SelectorID(row.SelectorID)
			}
			sawCapExceeded = true
		}
	}

	if matchedAllow != nil {
		return PolicyID(matchedAllow.PolicyID), domain.SelectorID(matchedAllow.SelectorID), nil
	}
	if sawCapExceeded {
		return "", capSelector, newForbidden(ReasonParameterCapExceeded)
	}
	return "", "", newForbidden(ReasonDefaultDeny)
}

// ValidateDecision re-verifies a previously issued Decision before dispatch or during
// an active streaming Lease. It resolves the target strictly by its immutable ContainerID
// (never re-resolving mutable names) and checks current safety, control, credential,
// group, selector, and policy parameter caps.
//
// A policy-epoch change observed only at publication (binding intact, context
// live, backend unchanged and safe) is not itself a denial: the evaluation is
// repeated on a fresh snapshot with the epoch re-captured, up to
// maxValidationAttempts. A real denial, a shared fault or retry exhaustion deny.
func (a *Authorizer) ValidateDecision(ctx context.Context, dec Decision) error {
	for attempt := 0; attempt < maxValidationAttempts; attempt++ {
		retry, err := a.validateDecisionOnce(ctx, dec)
		if !retry {
			return err
		}
	}
	a.cancelMatchingLeases(dec)
	return newForbidden(ReasonDecisionStale)
}

// maxValidationAttempts bounds epoch-only re-evaluation so continuous policy
// churn fails closed instead of livelocking.
const maxValidationAttempts = 16

// maxErrorTreeNodes bounds onlyContextCauses so a pathological or cyclic error
// graph is treated as "not pure" (shared) instead of walking unboundedly.
const maxErrorTreeNodes = 64

// onlyContextCauses reports whether err is NON-nil and every leaf of its entire
// error tree is context.Canceled or context.DeadlineExceeded. It walks both
// Unwrap() error and Unwrap() []error (errors.Join, multi-%w) with a node bound
// and never inspects error strings. Any independent leaf, an empty/unknown
// multi-wrapper or an exhausted bound is conservatively NOT pure, so the fault
// is handled as shared and affected peers are canceled.
func onlyContextCauses(err error) bool {
	if err == nil {
		return false
	}
	budget := maxErrorTreeNodes
	var pure func(error) bool
	pure = func(e error) bool {
		budget--
		if budget < 0 {
			return false
		}
		if e == context.Canceled || e == context.DeadlineExceeded {
			return true
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			real := 0
			for _, c := range u.Unwrap() {
				if c == nil {
					continue // a nil child carries no fault
				}
				real++
				if !pure(c) {
					return false
				}
			}
			return real > 0
		case interface{ Unwrap() error }:
			inner := u.Unwrap()
			return inner != nil && pure(inner)
		default:
			return false
		}
	}
	return pure(err)
}

// backendSafe reports whether backend is ready and self/peer verified.
func backendSafe(backend docker.DockerBackend) bool {
	return backend != nil && backend.Ready() && backend.VerificationState() == docker.StateVerified
}

// validateDecisionOnce performs one evaluation. retry=true means only the
// policy epoch moved during evaluation and the caller should re-evaluate.
func (a *Authorizer) validateDecisionOnce(ctx context.Context, dec Decision) (retry bool, _ error) {
	if ctx.Err() != nil {
		a.cancelMatchingLeases(dec)
		return false, newForbidden(ReasonDecisionStale)
	}
	if _, err := docker.ParseTargetIdentity(dec.Target.EndpointID, string(dec.Target.ContainerID)); err != nil {
		a.cancelMatchingLeases(dec)
		return false, newForbidden(ReasonDecisionStale)
	}
	if err := docker.ValidateOperation(dec.Operation); err != nil {
		a.cancelMatchingLeases(dec)
		return false, newForbidden(ReasonDecisionStale)
	}

	a.mu.RLock()
	backend, ok := a.backends[dec.Target.EndpointID]
	epoch := a.policyEpoch
	bound := a.validBindingLocked(dec)
	a.mu.RUnlock()
	if !bound {
		return false, newForbidden(ReasonDecisionStale)
	}
	if !ok || !backendSafe(backend) {
		a.cancelLeases(dec, false)
		return false, newForbidden(ReasonSafetyUnverified)
	}

	// Resolve target strictly by immutable 64-hex ContainerID.
	currentTarget, err := backend.ResolveTarget(ctx, string(dec.Target.ContainerID))
	if err != nil {
		// A co-observed shared fault (protected/unverified/missing target, a
		// backend that is no longer safe, or ANY other independent fault in the
		// error tree such as a joined generic metadata failure) is never masked by
		// this caller's own cancellation: only a pure cancellation (every leaf of
		// the error tree is a context cancellation/deadline cause) with a still
		// verified backend is local to the caller (P1.18.4 P111-L2).
		protected := errors.Is(err, docker.ErrProtectedTarget)
		unverified := errors.Is(err, docker.ErrUnverified) || !backendSafe(backend)
		shared := protected || unverified || errors.Is(err, docker.ErrTargetNotFound)
		a.cancelLeases(dec, ctx.Err() != nil && !shared && onlyContextCauses(err))
		if protected {
			return false, newForbidden(ReasonSelfProtected)
		}
		if unverified {
			return false, newForbidden(ReasonSafetyUnverified)
		}
		return false, newForbidden(ReasonDecisionStale)
	}
	if docker.HasProtectedNamespaceLabel(currentTarget.Labels) {
		a.cancelLeases(dec, false)
		return false, newForbidden(ReasonSelfProtected)
	}

	now := a.clock()
	var validateErr error
	if now.Before(dec.DecidedAt) {
		a.cancelMatchingLeases(dec)
		return false, newForbidden(ReasonDecisionStale)
	}

	readErr := a.repo.Read(ctx, func(q *store.Queries) error {
		control, err := q.GetInstallationControl(ctx)
		if err != nil {
			return err
		}
		if !activeInstallationControl(control) {
			validateErr = newForbidden(ReasonRestoreQuarantined)
			return nil
		}
		currentGens := store.Generations{
			Credential: control.CredentialGeneration,
			Session:    control.SessionGeneration,
			Authority:  control.AuthorityGeneration,
			Restore:    control.RestoreGeneration,
		}
		if currentGens != dec.Generations {
			validateErr = newForbidden(ReasonDecisionStale)
			return nil
		}

		principal, vErr := a.verifier.VerifyPrincipal(ctx, q, control, dec.creds, now)
		if vErr != nil {
			validateErr = newForbidden(ReasonDecisionStale)
			return nil
		}
		if dec.requireAAL2 && (principal.Kind != PrincipalUser || principal.AchievedAssurance < 2) {
			validateErr = newForbidden(ReasonDecisionStale)
			return nil
		}

		ep, epErr := q.GetEndpoint(ctx, dec.Target.EndpointID)
		if epErr != nil || ep.State != "active" || ep.Slug != "local" || ep.Transport != "unix" || ep.AuthorityGeneration != control.AuthorityGeneration {
			validateErr = newForbidden(ReasonDecisionStale)
			return nil
		}

		_, _, evalErr := evaluatePolicies(
			ctx,
			q,
			control,
			principal,
			dec.Target.EndpointID,
			dec.Operation,
			currentTarget,
			dec.LogOptions,
			dec.TimeoutSeconds,
		)
		if evalErr != nil {
			validateErr = newForbidden(ReasonDecisionStale)
			return nil
		}
		return nil
	})

	// Shared state is classified before any local outcome so a shared fault
	// observed at publication is never masked by this caller's cancellation or
	// by an unrelated stale/read failure.
	a.mu.RLock()
	bound = a.validBindingLocked(dec)
	sameBackend := a.backends[dec.Target.EndpointID] == backend
	epochMoved := epoch != a.policyEpoch
	a.mu.RUnlock()
	if !backendSafe(backend) {
		a.cancelLeases(dec, false)
		return false, newForbidden(ReasonSafetyUnverified)
	}
	if readErr != nil {
		a.cancelMatchingLeases(dec)
		// Fail closed for the caller, but a storage fault is not a policy decision:
		// it is never attributed or accounted as a denial.
		return false, &DenialError{Base: ErrForbidden, Reason: ReasonDecisionStale, fault: true}
	}
	if validateErr != nil {
		a.cancelMatchingLeases(dec)
		return false, validateErr
	}
	if !bound || !sameBackend || ctx.Err() != nil {
		a.cancelMatchingLeases(dec)
		return false, newForbidden(ReasonDecisionStale)
	}
	if epochMoved {
		return true, nil
	}
	return false, nil
}

// AcquireLease authorizes req and registers a cancellable Lease for long-lived operations.
//
// Every 403 refusal after Authorize allowed the request (registration-time staleness,
// the revalidation under the registered lease, the final staleness check) is a refusal
// of a VERIFIED principal for a known decision, so it carries that decision's
// attribution exactly like Authorize's own late refusals (usage accounting, TD 9.1).
func (a *Authorizer) AcquireLease(ctx context.Context, req AuthorizeRequest) (*Lease, error) {
	dec, err := a.Authorize(ctx, req)
	if err != nil {
		return nil, err
	}
	attr := dec.Attribution()

	leaseCtx, cancel := context.WithCancel(ctx)
	id := a.nextLeaseID.Add(1)
	lease := &Lease{
		Decision:   dec,
		id:         id,
		authorizer: a,
		ctx:        leaseCtx,
		cancel:     cancel,
	}

	a.mu.Lock()
	if ctx.Err() != nil || dec.PolicyEpoch != a.policyEpoch || !a.validBindingLocked(dec) {
		a.mu.Unlock()
		cancel()
		return nil, attribute(newForbidden(ReasonDecisionStale), &attr)
	}
	a.leases[id] = lease
	a.mu.Unlock()

	// Revalidate once after registration so any concurrent policy/safety change
	// between Authorize and map insertion immediately cancels the lease.
	if err := lease.Revalidate(ctx); err != nil {
		lease.Release()
		return nil, attribute(err, &attr)
	}

	a.mu.RLock()
	// The lease is already registered, so any later policy notification
	// revalidates it itself; an epoch-only move is not a denial here.
	stale := leaseCtx.Err() != nil || !a.validBindingLocked(dec)
	a.mu.RUnlock()
	if stale {
		lease.Release()
		return nil, attribute(newForbidden(ReasonDecisionStale), &attr)
	}
	return lease, nil
}

// NotifyPolicyChange advances the policy epoch and revalidates all active Leases,
// immediately canceling any Lease whose authorization is no longer valid (TD §3.4).
//
// ctx is the notification's OWN bound, not a request context. No-op and
// unrelated notifications preserve healthy leases only while ctx is live: a
// notification whose context has already ended (an un-detached request context
// or an expired bound) still advances the epoch but every revalidation then
// fails closed and cancels the lease. Direct callers must therefore detach
// request cancellation and keep a finite bound (context.WithoutCancel +
// context.WithTimeout); internal/ops.Service.NotifyAuthorityChange is the
// supported bridge. This never skips epoch/revocation work.
func (a *Authorizer) NotifyPolicyChange(ctx context.Context) error {
	// Serialize notifications. If ctx ends first we still advance the epoch and
	// revalidate under the ended context, which fails closed by canceling the
	// affected leases (never leaves a possibly revoked lease live).
	select {
	case a.notifySem <- struct{}{}:
		defer func() { <-a.notifySem }()
	case <-ctx.Done():
	}
	a.mu.Lock()
	a.policyEpoch++
	snapshot := make([]*Lease, 0, len(a.leases))
	for _, l := range a.leases {
		snapshot = append(snapshot, l)
	}
	a.mu.Unlock()

	for _, l := range snapshot {
		_ = l.Revalidate(ctx)
	}
	return nil
}

// InvalidateAll unconditionally cancels and removes all active Leases.
func (a *Authorizer) InvalidateAll() {
	a.mu.Lock()
	a.policyEpoch++
	a.invalidationRevision++
	snapshot := make([]*Lease, 0, len(a.leases))
	for _, l := range a.leases {
		snapshot = append(snapshot, l)
	}
	a.leases = make(map[uint64]*Lease)
	a.mu.Unlock()

	for _, l := range snapshot {
		l.Release()
	}
}

// InvalidateSelfProtection drops the self/peer safety proof of EVERY registered backend and cancels every active
// Lease. From this moment no operation reaches a backend (safety_unverified) until that backend's own VerifySelf
// succeeds again. It is the hook a restore uses (security-contracts.md S2.2.1/S2.2.6, RESTORE-06): an authenticated
// archive proves nothing about the Docker daemon, the peers around Mandatary or Mandatary's own identity, so after
// a restore and when its endpoint becomes effective again the proof has to be rebuilt independently, never inherited.
// The composition root passes it to auth.Admin.WithSafetyReset.
func (a *Authorizer) InvalidateSelfProtection() {
	a.mu.RLock()
	backends := make([]docker.DockerBackend, 0, len(a.backends))
	for _, b := range a.backends {
		backends = append(backends, b)
	}
	a.mu.RUnlock()
	for _, b := range backends {
		b.InvalidateSafety()
	}
	a.InvalidateAll()
}

// ActiveLeaseCount returns the number of currently active Leases.
func (a *Authorizer) ActiveLeaseCount() int {
	a.mu.RLock()
	n := len(a.leases)
	a.mu.RUnlock()
	return n
}

// ListEndpointContainers returns the endpoint's currently extant containers exactly as the evaluator can see
// them: the backend never lists Mandatary itself or any peer, so neither can appear (SELF-04, SELF-08). It
// is a read-only view for policy administration (the rule editor's inventory and preview); it grants
// nothing and requires the same proof of self-identity that every operation does. A missing, closed or
// UNVERIFIED backend fails closed with ReasonSafetyUnverified.
func (a *Authorizer) ListEndpointContainers(ctx context.Context, endpointID domain.EndpointID) ([]docker.ContainerSummary, error) {
	if _, err := domain.ParseEndpointID(string(endpointID)); err != nil {
		return nil, newForbidden(ReasonEndpointInactive)
	}
	backend, ok := a.getBackend(endpointID)
	if !ok || backend == nil || !backend.Ready() || backend.VerificationState() != docker.StateVerified {
		return nil, newForbidden(ReasonSafetyUnverified)
	}
	containers, err := backend.ListContainers(ctx)
	if err != nil {
		if errors.Is(err, docker.ErrUnverified) {
			return nil, newForbidden(ReasonSafetyUnverified)
		}
		return nil, newForbidden(ReasonDefaultDeny)
	}
	visible := make([]docker.ContainerSummary, 0, len(containers))
	for _, c := range containers {
		if docker.HasProtectedNamespaceLabel(c.Labels) {
			continue // defence in depth: a backend that listed one must still not expose it
		}
		visible = append(visible, c)
	}
	return visible, nil
}

// InspectEndpointPolicyTargets evaluates all stored policies on endpointID against
// the endpoint's currently extant non-protected containers so deleted targets remain
// visible as TargetMissing ("Inactive / Target Missing") rather than vanishing (TD §7.2).
func (a *Authorizer) InspectEndpointPolicyTargets(ctx context.Context, endpointID domain.EndpointID) ([]PolicyTargetStatus, error) {
	if _, err := domain.ParseEndpointID(string(endpointID)); err != nil {
		return nil, newForbidden(ReasonEndpointInactive)
	}
	backend, ok := a.getBackend(endpointID)
	if !ok || backend == nil || !backend.Ready() || backend.VerificationState() != docker.StateVerified {
		return nil, newForbidden(ReasonSafetyUnverified)
	}

	containers, err := backend.ListContainers(ctx)
	if err != nil {
		if errors.Is(err, docker.ErrUnverified) {
			return nil, newForbidden(ReasonSafetyUnverified)
		}
		return nil, newForbidden(ReasonDefaultDeny)
	}

	var statuses []PolicyTargetStatus
	var inspectErr error

	readErr := a.repo.Read(ctx, func(q *store.Queries) error {
		rows, qErr := q.ListPoliciesWithSelectorsForEndpoint(ctx, endpointID)
		if qErr != nil {
			return qErr
		}
		statuses = make([]PolicyTargetStatus, 0, len(rows))
		for _, r := range rows {
			sel := store.ContainerSelector{
				ID:                r.SelectorID,
				EndpointID:        r.SelectorEndpointID,
				ContainerName:     r.ContainerName,
				NameIsGlob:        r.NameIsGlob,
				ComposeProject:    r.ComposeProject,
				ComposeService:    r.ComposeService,
				ImagePattern:      r.ImagePattern,
				PinnedContainerID: r.PinnedContainerID,
				PinnedImageDigest: r.PinnedImageDigest,
			}
			var matchedIDs []docker.ContainerID
			for _, c := range containers {
				m, mErr := MatchSelector(sel, c)
				if mErr != nil {
					inspectErr = mErr
					return nil
				}
				if m {
					matchedIDs = append(matchedIDs, c.ContainerID)
				}
			}
			statuses = append(statuses, PolicyTargetStatus{
				PolicyID:            PolicyID(r.PolicyID),
				SelectorID:          domain.SelectorID(r.SelectorID),
				ContainerName:       r.ContainerName,
				TargetMissing:       len(matchedIDs) == 0,
				MatchedContainerIDs: matchedIDs,
			})
		}
		return nil
	})
	if readErr != nil {
		return nil, newForbidden(ReasonDefaultDeny)
	}
	if inspectErr != nil {
		return nil, inspectErr
	}
	return statuses, nil
}

// Close cancels all active Leases.
func (a *Authorizer) Close() error {
	a.InvalidateAll()
	return nil
}
