package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
)

// AssertionOptions is a protected ceremony payload, not a login/session.
type AssertionOptions struct {
	ID      string
	Options *protocol.CredentialAssertion
}

func (AssertionOptions) String() string   { return "[REDACTED]" }
func (AssertionOptions) GoString() string { return "[REDACTED]" }

// assertionSession accepts an opaque server-persisted ceremony/session binding.
// It grants no normal authority; P1.08 owns preauth issuance and completed-session
// creation, step-up and factor-evidence binding. Client assurance is never input.
func assertionSession(ctx context.Context, q *store.Queries, secret []byte, now int64) (c store.InstallationControl, u store.User, s store.Session, e error) {
	deny := func() (store.InstallationControl, store.User, store.Session, error) { return c, u, s, ErrDenied }
	if len(secret) < 32 || len(secret) > 256 || now < 0 || now > 253402300799 {
		return deny()
	}
	c, e = q.GetInstallationControl(ctx)
	if e != nil || !activeControl(c) {
		return deny()
	}
	hash := sha256.Sum256(secret)
	s, e = q.GetSessionByHash(ctx, hash[:])
	if e != nil {
		return deny()
	}
	u, e = q.GetUser(ctx, s.UserID)
	if e != nil || u.State != "active" || u.Compromised != 0 || u.CredentialGeneration != c.CredentialGeneration || u.AuthorityGeneration != c.AuthorityGeneration {
		return deny()
	}
	if (s.Purpose != "preauth" && s.Purpose != "normal") || s.State != "active" || s.RevokedAt.Valid || s.CredentialGeneration != c.CredentialGeneration || s.SessionGeneration != c.SessionGeneration || now < s.CreatedAt || now >= s.ExpiresAt || s.LastActivityAt > now || now-s.LastActivityAt >= s.IdleTimeoutSeconds {
		return deny()
	}
	return c, u, s, nil
}

// A nil allowlist offers only live keys for Begin. A pending ceremony loads its
// exact ownership inventory, including inactive keys, without widening its
// allowlist or decrypting unrelated retired keys. Ownership is not eligibility:
// Finish rechecks the selected key under Control before any proof work.
func (w *WebAuthnService) webUser(ctx context.Context, session []byte, allowed [][]byte) (webUser, map[string]store.Authenticator, map[string]store.WebauthnCredential, error) {
	l := w.lifecycle
	user := webUser{}
	factors := map[string]store.Authenticator{}
	records := map[string]store.WebauthnCredential{}
	e := l.repo.Read(ctx, func(q *store.Queries) error {
		c, u, _, e := assertionSession(ctx, q, session, l.now().Unix())
		if e != nil {
			return e
		}
		user.user = u
		user.handle, e = q.GetWebAuthnHandle(ctx, u.ID)
		if e != nil {
			return e
		}
		all, e := q.ListUserAuthenticators(ctx, u.ID)
		if e != nil {
			return e
		}
		for _, a := range all {
			if a.Kind != "webauthn" || a.CredentialGeneration != c.CredentialGeneration {
				continue
			}
			if allowed == nil {
				if !liveFactor(c, a, l.now().Unix()) {
					continue
				}
			} else {
				listed := false
				for _, id := range allowed {
					listed = listed || bytes.Equal(id, a.ExternalCredentialID)
				}
				if !listed {
					continue
				}
			}
			r, e := q.GetWebAuthnKeyRecord(ctx, a.ID)
			if e != nil {
				return e
			}
			factors[a.ID] = a
			records[a.ID] = r
		}
		return nil
	})
	if e != nil {
		return user, factors, records, ErrDenied
	}
	for id, r := range records {
		plain, e := l.repo.DecryptSecret("webauthn-credential", id, r.Envelope)
		if e != nil {
			return user, factors, records, ErrDenied
		}
		var data webCredential
		e = json.Unmarshal(plain, &data)
		clear(plain)
		a := factors[id]
		c := data.Credential
		if e != nil || data.User != user.user.ID || data.RPID != w.verifier.Config.RPID || !bytes.Equal(a.ExternalCredentialID, c.ID) || !bytes.Equal(a.PublicKey, c.PublicKey) || a.SignCount != nullable(int64(c.Authenticator.SignCount)) || a.BackupEligible != flagInt(c.Flags.BackupEligible) || a.BackupState != flagInt(c.Flags.BackupState) || !c.Flags.UserVerified {
			return user, factors, records, ErrDenied
		}
		user.credentials = append(user.credentials, c)
	}
	return user, factors, records, nil
}

func (w *WebAuthnService) BeginAssertion(ctx context.Context, session []byte) (AssertionOptions, error) {
	if ctx.Err() != nil || !admitWebAuthn() {
		return AssertionOptions{}, ErrDenied
	}
	defer func() { <-webAuthnWork }()
	l := w.lifecycle
	user, _, _, e := w.webUser(ctx, session, nil)
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	options, data, e := w.verifier.BeginLogin(user)
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	id, e := randomID()
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	var c store.InstallationControl
	var s store.Session
	e = l.repo.Read(ctx, func(q *store.Queries) error {
		var u store.User
		var e error
		c, u, s, e = assertionSession(ctx, q, session, l.now().Unix())
		if e != nil || u.ID != user.user.ID {
			return ErrDenied
		}
		return nil
	})
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	now := l.now().Unix()
	expires := now + 300
	if s.ExpiresAt < expires {
		expires = s.ExpiresAt
	}
	record := webChallenge{Data: *data, User: user.user.ID, Session: s.ID, Purpose: "webauthn_assertion", RPID: w.verifier.Config.RPID, Origins: w.verifier.Config.RPOrigins, Generation: c.CredentialGeneration, SessionGeneration: c.SessionGeneration, Issued: now, Expires: expires}
	plain, e := json.Marshal(record)
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	defer clear(plain)
	envelope, e := l.repo.EncryptSecret("webauthn-challenge", id, plain)
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	hash := sha256.Sum256([]byte(data.Challenge))
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		cc, u, ss, e := assertionSession(ctx, q, session, l.now().Unix())
		if e != nil || cc.CredentialGeneration != c.CredentialGeneration || cc.SessionGeneration != c.SessionGeneration || u.ID != record.User || ss.ID != s.ID || l.now().Unix() >= expires {
			return ErrDenied
		}
		if e = q.PruneWebAuthnChallenges(ctx, now); e != nil {
			return e
		}
		n, e := q.CountWebAuthnChallenges(ctx, store.CountWebAuthnChallengesParams{UserID: u.ID, Now: now})
		if e != nil || n >= 16 {
			return ErrDenied
		}
		if e = q.CreateWebAuthnChallenge(ctx, store.CreateWebAuthnChallengeParams{ID: id, UserID: u.ID, SessionID: sql.NullString{String: s.ID, Valid: true}, Purpose: record.Purpose, ChallengeHash: hash[:], IssuedAt: now, ExpiresAt: expires, CredentialGeneration: c.CredentialGeneration}); e != nil {
			return e
		}
		return q.PutWebAuthnChallenge(ctx, store.PutWebAuthnChallengeParams{ChallengeID: id, Envelope: envelope})
	}, nil)
	if e != nil {
		return AssertionOptions{}, ErrDenied
	}
	return AssertionOptions{ID: id, Options: options}, nil
}

// FinishAssertion returns an observation, not AAL2/session authority. This
// deliberately supports only UP+UV ceremonies; possession-only/U2F fallback is
// not selected. A valid UV signature proves the protocol's possession+activation
// signals, not device-internal erasure/biometric/sync-provider conformance.
func (w *WebAuthnService) FinishAssertion(ctx context.Context, session []byte, id string, response []byte, ip string) (FactorProof, error) {
	l := w.lifecycle
	if ctx.Err() != nil || len(response) > 32768 || !l.gate.allow(ip, l.now()) || !admitWebAuthn() {
		return FactorProof{}, ErrDenied
	}
	defer func() { <-webAuthnWork }()
	observed, record, e := w.loadChallenge(ctx, id)
	if e != nil || record.Purpose != "webauthn_assertion" || observed.ConsumedAt.Valid || l.now().Unix() < record.Issued || l.now().Unix() >= record.Expires {
		return FactorProof{}, ErrDenied
	}
	parsed, e := protocol.ParseCredentialRequestResponseBytes(response)
	if e != nil {
		return FactorProof{}, ErrDenied
	}
	if len(record.Data.AllowedCredentialIDs) == 0 {
		return FactorProof{}, ErrDenied
	}
	user, factors, records, e := w.webUser(ctx, session, record.Data.AllowedCredentialIDs)
	if e != nil || user.user.ID != record.User {
		return FactorProof{}, ErrDenied
	}
	var selected store.Authenticator
	for _, a := range factors {
		if bytes.Equal(a.ExternalCredentialID, parsed.RawID) {
			selected = a
			break
		}
	}
	now := l.now().Unix()
	if selected.ID == "" || (selected.NextAttemptAt.Valid && now < selected.NextAttemptAt.Int64) {
		return FactorProof{}, ErrDenied
	}
	// Prepare only an UNTRUSTED candidate envelope outside Control, avoiding
	// recursive Repository lifecycle locking. Use the pinned library's own state
	// update helpers, not a second counter policy. Nothing is persisted until the
	// real verifier runs under the shared control lock and its entire output is
	// byte-identical to this candidate. Library drift therefore fails closed.
	var candidate []byte
	for _, c := range user.credentials {
		if !bytes.Equal(c.ID, parsed.RawID) {
			continue
		}
		c.Authenticator.UpdateCounter(parsed.Response.AuthenticatorData.Counter)
		if record.Data.AuthorizeUVInitialization {
			c.Flags = c.Flags.UpdateWithUVInitialization(parsed.Response.AuthenticatorData.Flags)
		} else {
			c.Flags = c.Flags.Update(parsed.Response.AuthenticatorData.Flags)
		}
		candidate, e = json.Marshal(webCredential{User: user.user.ID, RPID: record.RPID, Credential: c})
		if e != nil {
			return FactorProof{}, ErrDenied
		}
		break
	}
	if len(candidate) == 0 {
		return FactorProof{}, ErrDenied
	}
	defer clear(candidate)
	envelope, e := l.repo.EncryptSecret("webauthn-credential", selected.ID, candidate)
	if e != nil {
		return FactorProof{}, ErrDenied
	}
	caller := ctx
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	result := FactorProof{}
	e = l.repo.Control(ctx, func(q *store.Queries) (err error) {
		evaluated := false
		defer func() {
			// Any rollback after real proof work loses the admitted attempt's
			// consumption/accounting. Stop acceptance BEFORE releasing Control,
			// including statement failures preceding the failure-charge update.
			if evaluated && err != nil {
				l.repo.FailClosed()
			}
		}()
		now := l.now().Unix()
		c, u, s, e := assertionSession(ctx, q, session, now)
		if e != nil || u.ID != record.User || s.ID != record.Session || c.CredentialGeneration != record.Generation || c.SessionGeneration != record.SessionGeneration || caller.Err() != nil {
			return ErrDenied
		}
		row, e := q.GetWebAuthnChallenge(ctx, id)
		if e != nil || row.ConsumedAt.Valid || now < row.IssuedAt || now >= row.ExpiresAt || !bytes.Equal(row.Envelope, observed.Envelope) {
			return ErrDenied
		}
		a, e := q.GetAuthenticator(ctx, selected.ID)
		if e != nil || !liveFactor(c, a, now) || a.UserID != u.ID || a.Kind != "webauthn" || a.FailedAttempts != selected.FailedAttempts || a.NextAttemptAt != selected.NextAttemptAt || (a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64) || !bytes.Equal(a.PublicKey, selected.PublicKey) || !bytes.Equal(a.ExternalCredentialID, selected.ExternalCredentialID) || a.SignCount != selected.SignCount || a.BackupEligible != selected.BackupEligible || a.BackupState != selected.BackupState {
			return ErrDenied
		}
		r, e := q.GetWebAuthnKeyRecord(ctx, a.ID)
		if e != nil || !bytes.Equal(r.Envelope, records[a.ID].Envelope) {
			return ErrDenied
		}
		// All evaluated proofs share the same cross-process admission/ceiling
		// transaction. Concurrent or exhausted stale snapshots deny BEFORE crypto,
		// not after speculative signature work that could exceed/undercharge100.
		evaluated = true
		credential, verifyErr := w.verifyLogin(user, record.Data, parsed)
		valid := verifyErr == nil && parsed.Response.AuthenticatorData.Flags.HasUserVerified() && parsed.Response.AuthenticatorData.Flags.HasUserPresent()
		if valid && credential.Authenticator.CloneWarning && !credential.Flags.BackupEligible {
			valid = false
		}
		n, e := q.ConsumeWebAuthnChallenge(ctx, store.ConsumeWebAuthnChallengeParams{ID: id, Now: nullable(now)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if !valid {
			n, e = q.RecordWebAuthnFailure(ctx, store.RecordWebAuthnFailureParams{ID: a.ID, Now: nullable(now), NextAttemptAt: nullable(now + passwordWait(a.FailedAttempts+1))})
			if e != nil || n != 1 {
				l.repo.FailClosed()
				return ErrDenied
			}
			if a.FailedAttempts+1 >= a.RetryCeiling {
				return l.protectiveIntent(ctx, q, c, u.ID, "authenticator_suspended", now)
			}
			return nil
		}
		afterProof := l.now().Unix()
		// Consumption is tied to the admitted attempt's pre-proof instant, but
		// no successful observation may outlive its challenge/session/key or
		// caller. Already evaluated invalid proofs above still charge durably.
		if afterProof < now || afterProof >= record.Expires || afterProof >= s.ExpiresAt || afterProof-s.LastActivityAt >= s.IdleTimeoutSeconds || !liveFactor(c, a, afterProof) || caller.Err() != nil {
			return nil
		}
		if l.repo.FailedClosed() {
			return ErrDenied
		}
		verified, e := json.Marshal(webCredential{User: u.ID, RPID: record.RPID, Credential: *credential})
		if e != nil {
			return ErrDenied
		}
		matches := bytes.Equal(verified, candidate)
		clear(verified)
		if !matches {
			return ErrDenied
		}
		n, e = q.UpdateWebAuthnKeyRecord(ctx, store.UpdateWebAuthnKeyRecordParams{AuthenticatorID: a.ID, Envelope: envelope})
		if e != nil || n != 1 {
			return ErrDenied
		}
		n, e = q.AdvanceWebAuthn(ctx, store.AdvanceWebAuthnParams{ID: a.ID, Now: nullable(now), SignCount: nullable(int64(credential.Authenticator.SignCount)), BackupState: flagInt(credential.Flags.BackupState)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		result = FactorProof{UserID: u.ID, AuthenticatorID: a.ID}
		return nil
	}, nil)
	if e != nil || result.UserID == "" {
		return FactorProof{}, ErrDenied
	}
	return result, nil
}
