package authz

import (
	"context"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Authenticate is the credential-validity gate (TD §3.3 step 2) evaluated ALONE: it
// runs the same installation-control and credential verification that Authorize
// applies, against the same trusted storage and clock, and contacts no backend.
// It decides nothing about targets, policy or operations.
//
// P1.14 adapters call it before Service.Execute so an unauthenticated caller is
// refused (401) before any target resolution can happen. Without it, the approved
// precedence (self-protection before authentication) lets an unauthenticated caller
// distinguish protected names from other names (C1 O1). Authorize remains the sole
// authority and verifies again on every dispatch; a nil result here is never an
// authorization.
//
// Outcomes match Authorize: 403 restore_quarantined while the installation is in
// restore quarantine (for every caller, as Authorize does), 401 for every
// credential that is absent, ambiguous, unknown, expired, revoked, rotated out,
// quarantined or stale, and a fail-closed 403 default_deny when storage cannot be
// read or ctx has ended.
func (a *Authorizer) Authenticate(ctx context.Context, creds PrincipalCredentials) error {
	if ctx == nil || ctx.Err() != nil {
		return newForbidden(ReasonDefaultDeny)
	}
	now := a.clock()
	var decisionErr error
	if err := a.repo.Read(ctx, func(q *store.Queries) error {
		control, err := q.GetInstallationControl(ctx)
		if err != nil {
			return err
		}
		if !activeInstallationControl(control) {
			decisionErr = newForbidden(ReasonRestoreQuarantined)
			return nil
		}
		_, decisionErr = a.verifier.VerifyPrincipal(ctx, q, control, creds, now)
		return nil
	}); err != nil {
		return newForbidden(ReasonDefaultDeny)
	}
	return decisionErr
}
