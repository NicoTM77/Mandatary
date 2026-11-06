package auth

import (
	"context"
	"time"

	"github.com/NicoTM77/Mandatary/internal/auth/nfc17"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// ReportTOTPCompromise is the approved narrow single-bound-factor protective
// path. It invalidates the named TOTP and sessions, records independent notice
// intent, but issues NO replacement, recovery capability, ordinary session or
// assurance. Removal/binding administration still requires maximum fresh AAL.
func (l *Lifecycle) ReportTOTPCompromise(ctx context.Context, name string, password []byte, id, ip string) error {
	if ctx.Err() != nil || !l.gate.allow(ip, l.now()) {
		return ErrDenied
	}
	proof, e := l.passwords.Prove(ctx, name, password, ip)
	if e != nil {
		return ErrDenied
	}
	select {
	case passwordWork <- struct{}{}:
		defer func() { <-passwordWork }()
	default:
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	authorized := false
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		c, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		u, e := q.GetUser(ctx, proof.UserID)
		if e != nil {
			return ErrDenied
		}
		passwordBinding, e := q.GetAuthenticator(ctx, proof.AuthenticatorID)
		if e != nil {
			return ErrDenied
		}
		now := l.now().Unix()
		if !activeBinding(c, u, passwordBinding, now) || (passwordBinding.NextAttemptAt.Valid && now < passwordBinding.NextAttemptAt.Int64) {
			return ErrDenied
		}
		raw, e := nfc17.Canonical(password)
		if e != nil {
			return ErrDenied
		}
		if !VerifyPassword(raw, passwordBinding.VerifierHash, passwordBinding.PasswordFormat.String) {
			return ErrDenied
		}
		target, e := q.GetAuthenticator(ctx, id)
		if e != nil || target.UserID != u.ID || target.Kind != "totp" || target.CredentialGeneration != c.CredentialGeneration || target.RevokedAt.Valid || now < target.CreatedAt {
			return ErrDenied
		}
		authorized = true
		n, e := q.RevokeTOTP(ctx, store.RevokeTOTPParams{ID: id, Now: nullable(now)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: u.ID, Now: nullable(now)}); e != nil {
			return e
		}
		return l.protectiveIntent(ctx, q, c, u.ID, "authenticator_suspended", now)
	}, nil)
	if e != nil {
		if authorized {
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
