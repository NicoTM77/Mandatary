package auth

import (
	"context"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// completeRestoreRecovery is the commit of the host-authorized restore-administrator recovery (security-contracts.md S2.2.5,
// RESTORE-08). In ONE transaction it enrolls the new recovery administrator and ends the restore quarantine.
//
// What it does: activates the NEW account staged by this ceremony (fresh password, freshly proven second factor, at least
// one freshly proven notification address) with exactly one super_admin role at the CURRENT generations, ends quarantine
// and queues a binding notice. It issues NO session: the administrator signs in through the ordinary AAL2 path.
//
// What it must never do: activate, revive or re-bind any restored account, role, factor, saved code, address or session;
// approve any manifest entry or any imported authority (every restored record stays quarantined until it is named and
// approved with ReapproveRestored by that administrator after a normal login); lower or reset a control generation. The
// restore transition already rotated all four, so the staged account is stamped with the rotated values and nothing from
// a backup can match them.
func (s *Setup) completeRestoreRecovery(ctx context.Context, q *store.Queries, sess store.SetupSession, totp store.Authenticator, now int64) (CompleteResult, []string, error) {
	if !sess.StagedUserID.Valid || sess.StagedVerifier == nil || totp.UserID != sess.StagedUserID.String {
		return CompleteResult{}, nil, errSetupLogical
	}
	user, err := q.GetUser(ctx, sess.StagedUserID.String)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if user.State != "quarantined" || user.MfaRequirement != "required" {
		return CompleteResult{}, nil, errSetupLogical
	}
	confirmed, err := q.ListConfirmedStagedAddresses(ctx, user.ID)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if len(confirmed) == 0 {
		return CompleteResult{}, nil, errSetupLogical // no end of quarantine without a confirmed destination (N1)
	}
	// Quarantine must still be the restore's. Anything else (already ended, never begun, a fresh installation) refuses.
	if err = restoreRecoveryEligible(ctx, q); err != nil {
		return CompleteResult{}, nil, err
	}
	if n, err := q.EndRestoreQuarantine(ctx); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	control, err := q.GetInstallationControl(ctx)
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if control.RestoreQuarantined != 0 {
		return CompleteResult{}, nil, errSetupLogical
	}
	// A restore whose import failed leaves the previous administrator role at a stale generation instead of
	// quarantined; retire it so exactly one administrator can ever be active. After a completed import this changes nothing.
	if err = q.BackupQuarantineRoles(ctx); err != nil {
		return CompleteResult{}, nil, err
	}
	if n, err := q.ActivateRecoveryAdmin(ctx, store.ActivateRecoveryAdminParams{CredentialGeneration: control.CredentialGeneration, AuthorityGeneration: control.AuthorityGeneration, ID: user.ID}); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	passwordID, err := s.randomHex()
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if err = q.CreateRecoveryAdminVerifier(ctx, store.CreateRecoveryAdminVerifierParams{ID: passwordID, UserID: user.ID, CredentialGeneration: control.CredentialGeneration, CreatedAt: now,
		BoundAt: nullableInt(now), ChangedAt: nullableInt(now), VerifierHash: sess.StagedVerifier, PasswordCodepoints: sess.StagedPasswordCodepoints, PasswordFormat: sess.StagedPasswordFormat}); err != nil {
		return CompleteResult{}, nil, err
	}
	if n, err := q.ActivateProvenTOTP(ctx, store.ActivateProvenTOTPParams{Generation: control.CredentialGeneration, Now: nullableInt(now), ID: totp.ID}); err != nil {
		return CompleteResult{}, nil, err
	} else if n != 1 {
		return CompleteResult{}, nil, errSetupLogical
	}
	roleID, err := s.randomHex()
	if err != nil {
		return CompleteResult{}, nil, err
	}
	if err = q.CreateRecoveryAdminRole(ctx, store.CreateRecoveryAdminRoleParams{ID: roleID, UserID: user.ID, AuthorityGeneration: control.AuthorityGeneration}); err != nil {
		return CompleteResult{}, nil, err
	}
	for _, a := range confirmed {
		if n, err := q.ActivateConfirmedAddress(ctx, store.ActivateConfirmedAddressParams{Now: nullableInt(now), Generation: control.AuthorityGeneration, ID: a.ID, UserID: user.ID}); err != nil {
			return CompleteResult{}, nil, err
		} else if n != 1 {
			return CompleteResult{}, nil, errSetupLogical
		}
	}
	if err = q.RevokeUnconfirmedAddresses(ctx, store.RevokeUnconfirmedAddressesParams{Now: nullableInt(now), UserID: user.ID}); err != nil {
		return CompleteResult{}, nil, err
	}
	// The binding notice is durable in this transaction or the quarantine does not end (NOTIFY-DELIVERY).
	if err = s.l.enqueue(ctx, q, control, user.ID, "authenticator_bound", now); err != nil {
		return CompleteResult{}, nil, errSetupLogical
	}
	// A restore into a fresh instance never ran the first-administrator setup; it can never run now. It is a no-op when
	// setup was already completed (MarkSetupCompleted only ever sets the timestamp once).
	if _, err = q.MarkSetupCompleted(ctx, nullableInt(now)); err != nil {
		return CompleteResult{}, nil, err
	}
	if err = endSession(ctx, q, sess, now, "completed"); err != nil {
		return CompleteResult{}, nil, err
	}
	removals, err := revokePurpose(ctx, q, PurposeRestoreRecovery, now, "setup_completed")
	if err != nil {
		return CompleteResult{}, nil, err
	}
	return CompleteResult{Purpose: PurposeRestoreRecovery, Username: user.Username}, removals, nil
}
