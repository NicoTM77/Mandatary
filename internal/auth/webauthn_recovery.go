package auth

import (
	"context"
	"database/sql"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// webBindingAuthority is ceremony binding data, never a session or achieved AAL.
// Ordinary and recovery callers enter through separate public methods and must
// match the same immutable authority kind/id again at serialized commit.
type webBindingAuthority struct {
	control           store.InstallationControl
	user              store.User
	session, recovery string
	expires           int64
}

func (w *WebAuthnService) registrationAuthority(ctx context.Context, q *store.Queries, secret []byte, now int64, recovered bool) (webBindingAuthority, error) {
	if !recovered {
		c, u, s, e := freshSession(ctx, q, secret, now)
		return webBindingAuthority{control: c, user: u, session: s.ID, expires: s.ExpiresAt}, e
	}
	c, u, cap, e := recoveryAuthorityFor(ctx, q, secret, now, "webauthn")
	if e != nil || cap.ReplacementAuthenticatorID.Valid {
		return webBindingAuthority{}, ErrDenied
	}
	return webBindingAuthority{control: c, user: u, recovery: cap.ID, expires: cap.ExpiresAt}, nil
}

// BeginRecoveredRegistration accepts only the existing password+saved-code
// restricted capability. It cannot create a session, modify policy or select a
// TOTP fallback under WebAuthn-only policy.
func (w *WebAuthnService) BeginRecoveredRegistration(ctx context.Context, secret []byte, resident bool) (RegistrationOptions, error) {
	return w.beginRegistration(ctx, secret, resident, true)
}

func (w *WebAuthnService) FinishRecoveredRegistration(ctx context.Context, secret []byte, id string, response []byte) error {
	return w.finishRegistration(ctx, secret, id, response, true)
}

func (w *WebAuthnService) completeRecoveredBinding(ctx context.Context, q *store.Queries, c store.InstallationControl, user, capability, id string, now int64) error {
	n, e := q.SelectRecoveryReplacement(ctx, store.SelectRecoveryReplacementParams{ID: capability, AuthenticatorID: sql.NullString{String: id, Valid: true}})
	if e != nil || n != 1 {
		return ErrDenied
	}
	all, e := q.ListUserAuthenticators(ctx, user)
	if e != nil {
		return e
	}
	for _, a := range all {
		if a.Kind == "webauthn" && a.ID != id && !a.RevokedAt.Valid {
			if _, e := q.RevokeWebAuthn(ctx, store.RevokeWebAuthnParams{ID: a.ID, Now: nullable(now)}); e != nil {
				return e
			}
		}
	}
	n, e = q.FinishRecoveryCapability(ctx, store.FinishRecoveryCapabilityParams{ID: capability, AuthenticatorID: sql.NullString{String: id, Valid: true}})
	if e != nil || n != 1 {
		return ErrDenied
	}
	if e := w.lifecycle.enqueue(ctx, q, c, user, "authenticator_replaced", now); e != nil {
		return e
	}
	return w.lifecycle.enqueue(ctx, q, c, user, "recovery_completed", now)
}
