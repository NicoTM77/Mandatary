package authz

import (
	"errors"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
)

// Attribution is the secret-free who/what of an authorizer outcome: the tuple of
// TD 9.1 (user, agent, endpoint, selector, operation) and nothing else. It holds only
// identifiers, never a credential, token, session secret, container name or any
// Docker payload, and it is never part of an error's text or any formatted output.
//
// UserID is the acting human, or the owning user of an agent (empty for a
// group-owned agent: the owner group is not a user and is never turned into one).
// AgentID is empty for a human principal. SelectorID is the selector of the policy
// that decided the outcome; it is empty when no policy selector matched (a default
// deny, a missing target, a rejected parameter set).
type Attribution struct {
	UserID     domain.UserID
	AgentID    domain.AgentID
	EndpointID domain.EndpointID
	SelectorID domain.SelectorID
	Operation  docker.Operation
}

// Event turns the attribution into the usage event of the given outcome.
func (a Attribution) Event(outcome domain.UsageOutcome) domain.UsageEvent {
	return domain.UsageEvent{UserID: a.UserID, AgentID: a.AgentID, EndpointID: a.EndpointID, SelectorID: a.SelectorID, Operation: string(a.Operation), Outcome: outcome}
}

func principalAttribution(p VerifiedPrincipal) Attribution {
	switch p.Kind {
	case PrincipalUser:
		return Attribution{UserID: p.UserID}
	case PrincipalAgent:
		return Attribution{UserID: p.OwnerUserID, AgentID: p.AgentID}
	}
	return Attribution{}
}

// Attribution reports who and what the decision authorized. It is the attribution of
// an ALLOWED outcome: the deciding selector is the matched allow policy's.
func (d Decision) Attribution() Attribution {
	a := principalAttribution(d.Principal)
	a.EndpointID = d.Target.EndpointID
	a.SelectorID = d.SelectorID
	a.Operation = d.Operation
	return a
}

// AttributionOf returns the attribution of a policy denial (403) of a VERIFIED
// principal. It exists only after authentication succeeded: self-protection, safety,
// quarantine and endpoint-state refusals that precede it, every 401 and every
// storage fault carry none, so nobody is ever attributed on unverified input.
func AttributionOf(err error) (Attribution, bool) {
	var de *DenialError
	if errors.As(err, &de) && de != nil && de.attr != nil {
		return *de.attr, true
	}
	return Attribution{}, false
}

// attribute attaches a to a 403 denial. Anything else (nil attribution, a 401, a
// non-denial) is returned unchanged.
func attribute(err error, a *Attribution) error {
	var de *DenialError
	if a == nil || !errors.As(err, &de) || de == nil || de.Base != ErrForbidden {
		return err
	}
	cp := *a
	return &DenialError{Base: de.Base, Reason: de.Reason, attr: &cp}
}
