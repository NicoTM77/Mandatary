package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"io"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/auth/nfc17"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// Recovery codes are recovery-only, not alternate ordinary MFA. Each carries
// 128 random secret bits plus a random nonsecret record ID; only SHA256 of the
// exact complete encoding is persisted. Nothing re-displays a stored verifier.
type RecoveryCodes struct{ codes []string }

func (RecoveryCodes) String() string          { return "[REDACTED]" }
func (RecoveryCodes) GoString() string        { return "[REDACTED]" }
func (r *RecoveryCodes) ExportOnce() []string { out := r.codes; r.codes = nil; return out }

// RecoveryResult is the export-once outcome of Recover. The raw capability and the replacement
// code are secrets; the capability's identifier, expiry and whether the TOTP method is permitted
// are NON-secret metadata captured in the SAME successful transaction that consumed the saved
// code, so the caller never needs a second storage read before it reveals the replacement code
// (P1.18.4 P116-L6: that second read was the one avoidable window in which a consumed code and
// a replacement could be lost together).
type RecoveryResult struct {
	capability  []byte
	replacement RecoveryCodes
	meta        RecoveryCapabilityMeta
}

// RecoveryCapabilityMeta is the non-secret description of a freshly issued recovery capability.
type RecoveryCapabilityMeta struct {
	ID        string
	ExpiresAt int64
	// TOTP reports whether TOTP re-enrolment is permitted (false for a WebAuthn-only account).
	// WebAuthn availability is deployment configuration and is applied by the HTTP layer.
	TOTP bool
}

// Meta returns the non-secret capability metadata. It stays valid after ExportOnce.
func (r *RecoveryResult) Meta() RecoveryCapabilityMeta { return r.meta }

func (RecoveryResult) String() string   { return "[REDACTED]" }
func (RecoveryResult) GoString() string { return "[REDACTED]" }
func (r *RecoveryResult) ExportOnce() ([]byte, []string) {
	cap := r.capability
	r.capability = nil
	return cap, r.replacement.ExportOnce()
}

// recoveryCapabilitySeconds is the lifetime of a recovery capability (ten minutes).
const recoveryCapabilitySeconds = 600

func newRecoveryCode() (string, string, error) {
	id, e := randomID()
	if e != nil {
		return "", "", e
	}
	secret := make([]byte, 16)
	if _, e = io.ReadFull(rand.Reader, secret); e != nil {
		return "", "", ErrDenied
	}
	defer clear(secret)
	return id, id + "." + hex.EncodeToString(secret), nil
}
func persistRecoveryCode(ctx context.Context, q *store.Queries, id, user, batch, code string, generation, now int64) error {
	hash := sha256.Sum256([]byte(code))
	return q.CreateRecoveryCode(ctx, store.CreateRecoveryCodeParams{ID: id, UserID: user, CredentialGeneration: generation, CreatedAt: now, BoundAt: nullable(now), VerifierHash: hash[:], RecoveryBatchID: sql.NullString{String: batch, Valid: true}})
}

func (l *Lifecycle) IssueRecoveryCodes(ctx context.Context, session []byte) (RecoveryCodes, error) {
	result := RecoveryCodes{}
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, s, e := freshSession(ctx, q, session, now)
		if e != nil || s.AchievedAssurance != 2 {
			return ErrDenied
		}
		factors, e := q.ListUserAuthenticators(ctx, u.ID)
		if e != nil {
			return e
		}
		event := "recovery_codes_issued"
		for _, a := range factors {
			if a.Kind == "recovery_code" {
				event = "recovery_codes_replaced"
			}
		}
		if e = q.RevokeRecoveryBatches(ctx, u.ID); e != nil {
			return e
		}
		if e = q.RevokeRecoveryCodes(ctx, store.RevokeRecoveryCodesParams{UserID: u.ID, Now: nullable(now)}); e != nil {
			return e
		}
		if e = q.RevokeRecoveryCapabilities(ctx, u.ID); e != nil {
			return e
		}
		batch, e := randomID()
		if e != nil {
			return e
		}
		if e = q.CreateRecoveryBatch(ctx, store.CreateRecoveryBatchParams{ID: batch, UserID: u.ID, CredentialGeneration: c.CredentialGeneration, CreatedAt: now}); e != nil {
			return e
		}
		for i := 0; i < 10; i++ {
			id, code, e := newRecoveryCode()
			if e != nil {
				return e
			}
			if e = persistRecoveryCode(ctx, q, id, u.ID, batch, code, c.CredentialGeneration, now); e != nil {
				return e
			}
			result.codes = append(result.codes, code)
		}
		return l.enqueue(ctx, q, c, u.ID, event, now)
	}, nil)
	if e != nil {
		return RecoveryCodes{}, ErrDenied
	}
	return result, nil
}

// Recover requires a still-bound password plus ONE saved code. Its result is
// exclusively a ten-minute reenrollment capability and one replacement saved
// code (E08), never a normal session or a new factor usable for ordinary login.
// Lost response: consumption is not rolled back; use another saved code or an
// independent authenticator/explicit host recovery. There is no redisplay/reuse.
func (l *Lifecycle) Recover(ctx context.Context, name string, password []byte, code, ip string) (RecoveryResult, error) {
	if ctx.Err() != nil || len(code) > 128 || !l.gate.allow(ip, l.now()) {
		return RecoveryResult{}, ErrDenied
	}
	// Reuse the same durable password throttle and safe unknown/wrong behavior.
	proof, e := l.passwords.Prove(ctx, name, password, ip)
	if e != nil {
		return RecoveryResult{}, ErrDenied
	}
	select {
	case passwordWork <- struct{}{}:
		defer func() { <-passwordWork }()
	default:
		return RecoveryResult{}, ErrDenied
	}
	caller := ctx
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var result RecoveryResult
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		u, e := q.GetUser(ctx, proof.UserID)
		if e != nil {
			return nil
		}
		a, e := q.GetAuthenticator(ctx, proof.AuthenticatorID)
		if e != nil {
			return nil
		}
		if !activeBinding(c, u, a, now) || (a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64) || caller.Err() != nil {
			return nil
		}
		// Revalidate the still-bound password IN this atomic code-consumption
		// transaction. No stale public Proof value can authorize recovery.
		canonical, e := nfc17.Canonical(password)
		if e != nil {
			return nil
		}
		if !VerifyPassword(canonical, a.VerifierHash, a.PasswordFormat.String) {
			_, e = q.RecordProofFailure(ctx, store.RecordProofFailureParams{ID: a.ID, ObservedFailures: a.FailedAttempts, NextAttemptAt: nullable(now + passwordWait(a.FailedAttempts+1))})
			return e
		}
		batch, e := q.GetActiveRecoveryBatch(ctx, u.ID)
		if e != nil {
			return nil
		}
		if batch.CredentialGeneration != c.CredentialGeneration || now < batch.CreatedAt || now < batch.NextAttemptAt || batch.Failures >= 100 {
			return nil
		}
		parts := strings.Split(code, ".")
		var saved store.Authenticator
		valid := len(parts) == 2 && len(parts[0]) == 64 && len(parts[1]) == 32
		if valid {
			_, e = hex.DecodeString(parts[1])
			valid = e == nil
		}
		if valid {
			saved, e = q.GetAuthenticator(ctx, parts[0])
			valid = e == nil && saved.UserID == u.ID && saved.Kind == "recovery_code" && saved.RecoveryBatchID.String == batch.ID && liveFactor(c, saved, now)
		}
		hash := sha256.Sum256([]byte(code))
		valid = valid && subtle.ConstantTimeCompare(hash[:], saved.VerifierHash) == 1
		if !valid {
			count, writeErr := q.RecoveryFailure(ctx, store.RecoveryFailureParams{ID: batch.ID, NextAttemptAt: now + passwordWait(batch.Failures+1)})
			if writeErr != nil || count != 1 {
				l.repo.FailClosed()
				return ErrDenied
			}
			// The current issued batch is read and charged under the same
			// serialized control transaction. Only its actual ceiling crossing
			// invalidates saved codes; notice failure must not undo disablement.
			if batch.Failures+1 >= 100 {
				return l.protectiveIntent(ctx, q, c, u.ID, "authenticator_suspended", now)
			}
			return nil
		}
		if l.repo.FailedClosed() {
			return nil
		}
		n, e := q.ConsumeRecoveryCode(ctx, store.ConsumeRecoveryCodeParams{ID: saved.ID, Now: nullable(now)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		replacementID, replacement, e := newRecoveryCode()
		if e != nil {
			return e
		}
		if e = persistRecoveryCode(ctx, q, replacementID, u.ID, batch.ID, replacement, c.CredentialGeneration, now); e != nil {
			return e
		}
		if e = q.RevokeRecoveryCapabilities(ctx, u.ID); e != nil {
			return e
		}
		if e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: u.ID, Now: nullable(now)}); e != nil {
			return e
		}
		id, e := randomID()
		if e != nil {
			return e
		}
		cap := make([]byte, 32)
		if _, e = io.ReadFull(rand.Reader, cap); e != nil {
			return ErrDenied
		}
		digest := sha256.Sum256(cap)
		if e = q.CreateRecoveryCapability(ctx, store.CreateRecoveryCapabilityParams{ID: id, UserID: u.ID, SecretHash: digest[:], CredentialGeneration: c.CredentialGeneration, SessionGeneration: c.SessionGeneration, PasswordRevision: u.PasswordRevision, CreatedAt: now, ExpiresAt: now + recoveryCapabilitySeconds}); e != nil {
			return e
		}
		if e = l.enqueue(ctx, q, c, u.ID, "recovery_codes_replaced", now); e != nil {
			return e
		}
		result = RecoveryResult{capability: cap, replacement: RecoveryCodes{codes: []string{replacement}}, meta: RecoveryCapabilityMeta{ID: id, ExpiresAt: now + recoveryCapabilitySeconds, TOTP: u.MfaRequirement != "webauthn"}}
		return nil
	}, nil)
	if e != nil || len(result.capability) == 0 {
		return RecoveryResult{}, ErrDenied
	}
	return result, nil
}
