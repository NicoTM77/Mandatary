package auth

import (
	"context"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Revoke is an owned-key, fresh maximum-assurance removal. It never downgrades
// policy. Protective notices cannot delay/reverse revocation or session denial.
func (w *WebAuthnService) Revoke(ctx context.Context, session []byte, id string) error {
	l := w.lifecycle
	if ctx.Err() != nil {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	authorize := func(q *store.Queries) (store.InstallationControl, store.User, error) {
		now := l.now().Unix()
		c, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return c, u, e
		}
		a, e := q.GetAuthenticator(ctx, id)
		if e != nil {
			return c, u, authorityReadError(e)
		}
		if a.UserID != u.ID || a.Kind != "webauthn" || a.CredentialGeneration != c.CredentialGeneration || a.RevokedAt.Valid || now < a.CreatedAt {
			return c, u, ErrDenied
		}
		all, e := q.ListUserAuthenticators(ctx, u.ID)
		if e != nil {
			return c, u, e
		}
		remaining := false
		for _, f := range all {
			if f.ID == id || !liveFactor(c, f, now) {
				continue
			}
			if f.Kind == "webauthn" || (f.Kind == "totp" && u.MfaRequirement != "webauthn") {
				remaining = true
			}
		}
		if u.MfaRequirement != "optional" && !remaining {
			return c, u, ErrDenied
		}
		return c, u, nil
	}
	authorized := false
	e := l.repo.Read(ctx, func(q *store.Queries) error { _, _, e := authorize(q); authorized = e == nil; return e })
	if e != nil {
		if authorized {
			l.repo.FailClosed()
		}
		return ErrDenied
	}
	logicalDenial := false
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		c, u, e := authorize(q)
		if e != nil {
			// No transition has started. Normal expiry/concurrent invalidation
			// denies authority without declaring healthy storage uncertain.
			logicalDenial = e == ErrDenied
			return e
		}
		now := l.now().Unix()
		n, e := q.RevokeWebAuthn(ctx, store.RevokeWebAuthnParams{ID: id, Now: nullable(now)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: u.ID, Now: nullable(now)}); e != nil {
			return e
		}
		return l.protectiveIntent(ctx, q, c, u.ID, "authenticator_removed", now)
	}, nil)
	if e != nil {
		if authorized && !logicalDenial {
			l.repo.FailClosed()
		}
		return ErrDenied
	}
	if e = l.expandProtectiveIntents(ctx); e != nil {
		l.repo.FailClosed()
		return ErrDenied
	}
	return nil
}
