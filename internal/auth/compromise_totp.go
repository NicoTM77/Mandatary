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
	return l.reportCompromise(ctx, name, password, id, ip, "totp")
}

// Both callers select a fixed, internal kind. Report authority is deliberately
// narrower than removal/replacement and may revoke the last required factor.
func (l *Lifecycle) reportCompromise(ctx context.Context, name string, password []byte, id, ip, kind string) error {
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
	// Establish narrow report authority in a coherent read snapshot before
	// attempting writer admission. A valid owned-target report must remain
	// fail-closed even when Control cannot enter its callback. This snapshot is
	// NOT replacement/session authority and is revalidated under the writer.
	var observedControl store.InstallationControl
	var observedUser store.User
	var observedPassword store.Authenticator
	authorized := false
	e = l.repo.Read(ctx, func(q *store.Queries) error {
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
		if e != nil || target.UserID != u.ID || target.Kind != kind || target.CredentialGeneration != c.CredentialGeneration || target.RevokedAt.Valid || now < target.CreatedAt {
			return ErrDenied
		}
		observedControl, observedUser, observedPassword = c, u, passwordBinding
		authorized = true
		return nil
	})
	if e != nil {
		if authorized {
			l.repo.FailClosed()
		}
		return ErrDenied
	}
	logicalDenial := false
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		c, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		if c != observedControl {
			logicalDenial = true
			return ErrDenied
		}
		u, e := q.GetUser(ctx, proof.UserID)
		if e != nil {
			logicalDenial = authorityReadError(e) == ErrDenied
			return e
		}
		if u != observedUser {
			logicalDenial = true
			return ErrDenied
		}
		binding, e := q.GetAuthenticator(ctx, proof.AuthenticatorID)
		now := l.now().Unix()
		if e != nil {
			logicalDenial = authorityReadError(e) == ErrDenied
			return e
		}
		if !samePassword(binding, observedPassword) || !activeBinding(c, u, binding, now) || (binding.NextAttemptAt.Valid && now < binding.NextAttemptAt.Int64) {
			logicalDenial = true
			return ErrDenied
		}
		target, e := q.GetAuthenticator(ctx, id)
		if e != nil {
			logicalDenial = authorityReadError(e) == ErrDenied
			return e
		}
		if target.UserID != u.ID || target.Kind != kind || target.CredentialGeneration != c.CredentialGeneration || target.RevokedAt.Valid || now < target.CreatedAt {
			logicalDenial = true
			return ErrDenied
		}
		var n int64
		if kind == "webauthn" {
			n, e = q.RevokeWebAuthn(ctx, store.RevokeWebAuthnParams{ID: id, Now: nullable(now)})
		} else {
			n, e = q.RevokeTOTP(ctx, store.RevokeTOTPParams{ID: id, Now: nullable(now)})
		}
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: u.ID, Now: nullable(now)}); e != nil {
			return e
		}
		return l.protectiveIntent(ctx, q, c, u.ID, "authenticator_suspended", now)
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
