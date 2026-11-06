package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// recoveryAuthority checks only reenrollment capability, never ordinary AAL2.
// The approved WebAuthn-only policy is deliberately NOT satisfiable by this
// TOTP continuation; its replacement ceremony belongs to P1.07/08 integration.
func recoveryAuthority(ctx context.Context, q *store.Queries, secret []byte, now int64) (store.InstallationControl, store.User, store.RecoveryCapability, error) {
	var c store.InstallationControl
	var u store.User
	var cap store.RecoveryCapability
	deny := func() (store.InstallationControl, store.User, store.RecoveryCapability, error) {
		return c, u, cap, ErrDenied
	}
	if len(secret) != 32 || now < 0 || now > 253402300799 {
		return deny()
	}
	var e error
	c, e = q.GetInstallationControl(ctx)
	if e != nil || !activeControl(c) {
		return deny()
	}
	hash := sha256.Sum256(secret)
	cap, e = q.GetRecoveryCapability(ctx, hash[:])
	if e != nil {
		return deny()
	}
	u, e = q.GetUser(ctx, cap.UserID)
	if e != nil {
		return deny()
	}
	if cap.State != "restricted" || cap.CredentialGeneration != c.CredentialGeneration || cap.SessionGeneration != c.SessionGeneration || now < cap.CreatedAt || now >= cap.ExpiresAt || u.State != "active" || u.Compromised != 0 || u.CredentialGeneration != c.CredentialGeneration || u.AuthorityGeneration != c.AuthorityGeneration || u.PasswordRevision != cap.PasswordRevision || u.MfaRequirement == "webauthn" {
		return deny()
	}
	return c, u, cap, nil
}
func (l *Lifecycle) BeginRecoveredTOTP(ctx context.Context, secret []byte, algorithm string) (Enrollment, error) {
	if algorithm != "SHA1" && algorithm != "SHA256" {
		return Enrollment{}, ErrDenied
	}
	id, e := randomID()
	if e != nil {
		return Enrollment{}, ErrDenied
	}
	seed := make([]byte, 32)
	if _, e = rand.Read(seed); e != nil {
		return Enrollment{}, ErrDenied
	}
	defer clear(seed)
	encrypted, e := l.repo.EncryptSecret("totp", id, seed)
	if e != nil {
		return Enrollment{}, ErrDenied
	}
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, cap, e := recoveryAuthority(ctx, q, secret, now)
		if e != nil || cap.ReplacementAuthenticatorID.Valid {
			return ErrDenied
		}
		if e = q.CreatePendingTOTP(ctx, store.CreatePendingTOTPParams{ID: id, UserID: u.ID, CredentialGeneration: c.CredentialGeneration, CreatedAt: now, EncryptedSecret: encrypted, TotpAlgorithm: sql.NullString{String: algorithm, Valid: true}}); e != nil {
			return e
		}
		n, e := q.SelectRecoveryReplacement(ctx, store.SelectRecoveryReplacementParams{ID: cap.ID, AuthenticatorID: sql.NullString{String: id, Valid: true}})
		if e != nil || n != 1 {
			return ErrDenied
		}
		return nil
	}, nil)
	if e != nil {
		return Enrollment{}, ErrDenied
	}
	return Enrollment{ID: id, secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)}, nil
}
func (l *Lifecycle) ConfirmRecoveredTOTP(ctx context.Context, secret []byte, id, code, ip string) error {
	if ctx.Err() != nil || !l.gate.allow(ip, l.now()) {
		return ErrDenied
	}
	observed, seed, err := l.loadTOTP(ctx, id)
	if err != nil {
		return ErrDenied
	}
	defer clear(seed)
	caller := ctx
	accepted := false
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, cap, e := recoveryAuthority(ctx, q, secret, now)
		if e != nil || cap.ReplacementAuthenticatorID.String != id {
			return nil
		}
		a, e := q.GetAuthenticator(ctx, id)
		if e != nil {
			return nil
		}
		if a.UserID != u.ID || a.Kind != "totp" || a.State != "pending" || a.CredentialGeneration != c.CredentialGeneration || a.FailedAttempts >= a.RetryCeiling || (a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64) || caller.Err() != nil {
			return nil
		}
		if !bytes.Equal(a.EncryptedSecret, observed.EncryptedSecret) || a.TotpAlgorithm != observed.TotpAlgorithm {
			return ErrDenied
		}
		step, ok := matchTOTP(seed, a.TotpAlgorithm.String, code, now)
		if !ok {
			_, e = q.RecordTOTPFailure(ctx, store.RecordTOTPFailureParams{ID: id, NextAttemptAt: nullable(now + passwordWait(a.FailedAttempts+1))})
			return e
		}
		if l.repo.FailedClosed() {
			return nil
		}
		n, e := q.ActivateTOTP(ctx, store.ActivateTOTPParams{ID: id, Now: nullable(now), Step: nullable(step)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		hash := sha256.Sum256([]byte(code))
		if e = q.RecordTOTPAcceptance(ctx, store.RecordTOTPAcceptanceParams{AuthenticatorID: id, Step: step, VerifierPeriod: now / 30, OutputHash: hash[:]}); e != nil {
			return e
		}
		old, e := q.ListUserAuthenticators(ctx, u.ID)
		if e != nil {
			return e
		}
		for _, f := range old {
			if f.Kind == "totp" && f.ID != id && !f.RevokedAt.Valid {
				if _, e = q.RevokeTOTP(ctx, store.RevokeTOTPParams{ID: f.ID, Now: nullable(now)}); e != nil {
					return e
				}
			}
		}
		n, e = q.FinishRecoveryCapability(ctx, store.FinishRecoveryCapabilityParams{ID: cap.ID, AuthenticatorID: sql.NullString{String: id, Valid: true}})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = l.enqueue(ctx, q, c, u.ID, "authenticator_replaced", now); e != nil {
			return e
		}
		if e = l.enqueue(ctx, q, c, u.ID, "recovery_completed", now); e != nil {
			return e
		}
		accepted = true
		return nil
	}, nil)
	if e != nil || !accepted {
		return ErrDenied
	}
	return nil
}
