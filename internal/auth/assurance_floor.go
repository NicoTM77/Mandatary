package auth

import (
	"context"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Retirement provenance (migration 00010). A revoked second factor lowers an
// account's required assurance only when its recorded reason proves the removal
// was authorised. The three values and NULL are the whole vocabulary.
const (
	// retireProtective: compromise-report or retry-ceiling invalidation. Reached
	// with password-only evidence, so it can never lower the floor.
	retireProtective = "protective"
	// retireAuthorized: removal that already passed the fresh maximum-account-
	// assurance gate (freshSession). Allows an optional-MFA account to return to AAL1.
	retireAuthorized = "authorized_removal"
	// retireRecovered: settled by an approved restricted recovery that bound a
	// replacement factor (password + saved code + new factor proof).
	retireRecovered = "recovery_replacement"
)

// A factor is ambiguous - and therefore still counted - when its provenance is
// NULL (every revocation before the migration) or protective.
func deliberatelyRetired(a store.Authenticator) bool {
	return a.State == "revoked" && a.RevokedAt.Valid && a.RetirementReason.Valid &&
		(a.RetirementReason.String == retireAuthorized || a.RetirementReason.String == retireRecovered)
}

// isSecondFactor is the one place that names which kinds can raise the floor.
func isSecondFactor(a store.Authenticator) bool { return a.Kind == "totp" || a.Kind == "webauthn" }

// assuranceFloor is the single required-assurance computation shared by login
// issuance, the session verifier, the sensitive-write gate, step-up and the
// lifecycle freshSession check. It answers "what assurance MUST this account
// present for a maximum-available sensitive write", never "what can it present
// right now":
//
//   - administrators and any non-optional MFA policy always require 2;
//   - otherwise 2 as soon as the account has EVER bound a second factor of the
//     current credential generation, unless every such factor was deliberately
//     retired (authorised removal or approved recovery replacement).
//
// Live, disabled, retry-exhausted, expired, quarantined, protectively
// invalidated and pre-migration (NULL provenance) factors all keep it at 2, so
// an unavailable factor can never be mistaken for permission to downgrade.
func assuranceFloor(c store.InstallationControl, u store.User, admin bool, all []store.Authenticator) int64 {
	if admin || u.MfaRequirement != "optional" {
		return 2
	}
	for _, a := range all {
		if isSecondFactor(a) && a.BoundAt.Valid && a.CredentialGeneration == c.CredentialGeneration && !deliberatelyRetired(a) {
			return 2
		}
	}
	return 1
}

// isAdministrator reports whether the user holds any non-disabled administrative role.
func isAdministrator(ctx context.Context, q *store.Queries, userID string) (bool, error) {
	roles, err := q.ListUserAdministrativeRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.State != "disabled" {
			return true, nil
		}
	}
	return false, nil
}
