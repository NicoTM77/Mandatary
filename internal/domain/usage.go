package domain

// UsageOutcome is the closed set of the three usage counters of TD 9.1. There is no
// fourth aggregate: an attempt that produced no authorization decision and no backend
// evidence is simply not counted (see docs/usage-accounting.md).
type UsageOutcome string

const (
	// UsageAllowed: authorized AND the backend executed the operation successfully.
	UsageAllowed UsageOutcome = "allowed"
	// UsageDenied: an authenticated principal was refused by the authorizer (a 403),
	// or its authorization ended before the backend could finish.
	UsageDenied UsageOutcome = "denied"
	// UsageError: authorized, but the backend execution failed or did not finish.
	UsageError UsageOutcome = "error"
)

// Valid reports whether o is one of the three counters.
func (o UsageOutcome) Valid() bool {
	return o == UsageAllowed || o == UsageDenied || o == UsageError
}

// UsageEvent is one accounted outcome. It is the attribution tuple of TD 9.1 plus
// the outcome, and nothing else: no request, response, log, credential, address or
// Docker payload is ever part of it.
//
// UserID is the acting human, or the owning user of an agent; it is empty for an
// agent owned by a group. AgentID is empty for a human principal. At least one of
// them is set. SelectorID is the selector of the policy that decided the outcome;
// it is empty only for a Denied outcome that matched no selector (a default deny,
// a missing target, a rejected parameter set). Operation is one of the six
// permission keys.
type UsageEvent struct {
	UserID     UserID
	AgentID    AgentID
	EndpointID EndpointID
	SelectorID SelectorID
	Operation  string
	Outcome    UsageOutcome
}
