package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"

	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

type webUser struct {
	user        store.User
	handle      []byte
	credentials []wa.Credential
}

func (u webUser) WebAuthnID() []byte                   { return u.handle }
func (u webUser) WebAuthnName() string                 { return u.user.Username }
func (u webUser) WebAuthnDisplayName() string          { return u.user.Username }
func (u webUser) WebAuthnCredentials() []wa.Credential { return u.credentials }

// RegistrationOptions must only be exported in a protected, no-store ceremony.
// Formatting is redacted; direct JSON is the intentional browser wire encoding.
type RegistrationOptions struct {
	ID      string
	Options *protocol.CredentialCreation
}

func (RegistrationOptions) String() string   { return "[REDACTED]" }
func (RegistrationOptions) GoString() string { return "[REDACTED]" }

type webChallenge struct {
	Data                                           wa.SessionData
	User, Session, Purpose, RPID                   string
	Recovery                                       string
	Origins                                        []string
	Generation, SessionGeneration, Issued, Expires int64
}
type webCredential struct {
	User, RPID string
	Credential wa.Credential
}

var webAlgorithms = []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}

func (w *WebAuthnService) BeginRegistration(ctx context.Context, session []byte, resident bool) (RegistrationOptions, error) {
	return w.beginRegistration(ctx, session, resident, false)
}

func (w *WebAuthnService) beginRegistration(ctx context.Context, session []byte, resident, recovered bool) (RegistrationOptions, error) {
	if ctx.Err() != nil || !admitWebAuthn() {
		return RegistrationOptions{}, ErrDenied
	}
	defer func() { <-webAuthnWork }()
	l := w.lifecycle
	var c store.InstallationControl
	var u store.User
	var authority webBindingAuthority
	var handle []byte
	var exclude []protocol.CredentialDescriptor
	e := l.repo.Read(ctx, func(q *store.Queries) error {
		var e error
		authority, e = w.registrationAuthority(ctx, q, session, l.now().Unix(), recovered)
		c, u = authority.control, authority.user
		if e != nil {
			return e
		}
		all, e := q.ListUserAuthenticators(ctx, u.ID)
		if e != nil {
			return e
		}
		for _, a := range all {
			if a.Kind == "webauthn" && a.BoundAt.Valid && !a.RevokedAt.Valid && a.CredentialGeneration == c.CredentialGeneration {
				exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: a.ExternalCredentialID})
			}
		}
		if !recovered && len(exclude) >= 16 {
			return ErrDenied
		}
		handle, e = q.GetWebAuthnHandle(ctx, u.ID)
		if e == sql.ErrNoRows {
			return nil
		}
		return e
	})
	if e != nil {
		return RegistrationOptions{}, ErrDenied
	}
	if len(handle) == 0 {
		handle = make([]byte, 32)
		if _, e = io.ReadFull(rand.Reader, handle); e != nil {
			return RegistrationOptions{}, ErrDenied
		}
	}
	user := webUser{user: u, handle: handle}
	options, data, e := w.verifier.BeginRegistration(user, wa.WithCredentialParameters(webAlgorithms), wa.WithExclusions(exclude), func(o *protocol.PublicKeyCredentialCreationOptions) error {
		o.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
		if resident {
			o.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementRequired
		}
		return nil
	})
	if e != nil {
		return RegistrationOptions{}, ErrDenied
	}
	id, e := randomID()
	if e != nil {
		return RegistrationOptions{}, ErrDenied
	}
	now := l.now().Unix()
	expires := now + 300
	if expires > authority.expires {
		expires = authority.expires
	}
	record := webChallenge{Data: *data, User: u.ID, Session: authority.session, Recovery: authority.recovery, Purpose: "webauthn_binding", RPID: w.verifier.Config.RPID, Origins: w.verifier.Config.RPOrigins, Generation: c.CredentialGeneration, SessionGeneration: c.SessionGeneration, Issued: now, Expires: expires}
	plain, e := json.Marshal(record)
	if e != nil {
		return RegistrationOptions{}, ErrDenied
	}
	defer clear(plain)
	envelope, e := l.repo.EncryptSecret("webauthn-challenge", id, plain)
	if e != nil {
		return RegistrationOptions{}, ErrDenied
	}
	hash := sha256.Sum256([]byte(data.Challenge))
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		current, e := w.registrationAuthority(ctx, q, session, l.now().Unix(), recovered)
		if e != nil || current.control.CredentialGeneration != c.CredentialGeneration || current.control.SessionGeneration != c.SessionGeneration || current.user.ID != u.ID || current.session != authority.session || current.recovery != authority.recovery || l.now().Unix() >= expires {
			return ErrDenied
		}
		if e = q.PruneWebAuthnChallenges(ctx, now); e != nil {
			return e
		}
		n, e := q.CountWebAuthnChallenges(ctx, store.CountWebAuthnChallengesParams{UserID: u.ID, Now: now})
		if e != nil || n >= 16 {
			return ErrDenied
		}
		if e = q.PutWebAuthnHandle(ctx, store.PutWebAuthnHandleParams{UserID: u.ID, Handle: handle}); e != nil {
			return e
		}
		h, e := q.GetWebAuthnHandle(ctx, u.ID)
		if e != nil || !bytes.Equal(h, handle) {
			return ErrDenied
		}
		if e = q.CreateWebAuthnChallenge(ctx, store.CreateWebAuthnChallengeParams{ID: id, UserID: u.ID, SessionID: sql.NullString{String: authority.session, Valid: authority.session != ""}, Purpose: record.Purpose, ChallengeHash: hash[:], IssuedAt: now, ExpiresAt: expires, CredentialGeneration: c.CredentialGeneration}); e != nil {
			return e
		}
		return q.PutWebAuthnChallenge(ctx, store.PutWebAuthnChallengeParams{ChallengeID: id, Envelope: envelope})
	}, nil)
	if e != nil {
		return RegistrationOptions{}, ErrDenied
	}
	return RegistrationOptions{ID: id, Options: options}, nil
}

func (w *WebAuthnService) loadChallenge(ctx context.Context, id string) (store.GetWebAuthnChallengeRow, webChallenge, error) {
	l := w.lifecycle
	var row store.GetWebAuthnChallengeRow
	var record webChallenge
	if len(id) != 64 {
		return row, record, ErrDenied
	}
	e := l.repo.Read(ctx, func(q *store.Queries) error { var e error; row, e = q.GetWebAuthnChallenge(ctx, id); return e })
	if e != nil {
		return row, record, ErrDenied
	}
	plain, e := l.repo.DecryptSecret("webauthn-challenge", id, row.Envelope)
	if e != nil {
		return row, record, ErrDenied
	}
	defer clear(plain)
	if json.Unmarshal(plain, &record) != nil {
		return row, record, ErrDenied
	}
	hash := sha256.Sum256([]byte(record.Data.Challenge))
	if record.User != row.UserID || record.Session != row.SessionID.String || record.Purpose != row.Purpose || record.Generation != row.CredentialGeneration || record.Issued != row.IssuedAt || record.Expires != row.ExpiresAt || !bytes.Equal(hash[:], row.ChallengeHash) || record.RPID != w.verifier.Config.RPID || !equalStrings(record.Origins, w.verifier.Config.RPOrigins) {
		return row, record, ErrDenied
	}
	return row, record, nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func flagInt(v bool) sql.NullInt64 {
	if v {
		return nullable(1)
	}
	return nullable(0)
}

func (w *WebAuthnService) FinishRegistration(ctx context.Context, session []byte, id string, response []byte) error {
	return w.finishRegistration(ctx, session, id, response, false)
}

func (w *WebAuthnService) finishRegistration(ctx context.Context, session []byte, id string, response []byte, recovered bool) error {
	if ctx.Err() != nil || len(response) > 32768 || !admitWebAuthn() {
		return ErrDenied
	}
	defer func() { <-webAuthnWork }()
	l := w.lifecycle
	observed, record, e := w.loadChallenge(ctx, id)
	if e != nil || record.Purpose != "webauthn_binding" || (record.Recovery != "") != recovered || observed.ConsumedAt.Valid || l.now().Unix() < record.Issued || l.now().Unix() >= record.Expires {
		return ErrDenied
	}
	// Reject terminal/unowned ceremonies before parsing attacker-controlled
	// attestation/certificates; the serialized commit rechecks all live state.
	e = l.repo.Read(ctx, func(q *store.Queries) error {
		a, e := w.registrationAuthority(ctx, q, session, l.now().Unix(), recovered)
		if e != nil || a.user.ID != record.User || a.session != record.Session || a.recovery != record.Recovery || a.control.CredentialGeneration != record.Generation || a.control.SessionGeneration != record.SessionGeneration {
			return ErrDenied
		}
		return nil
	})
	if e != nil {
		return ErrDenied
	}
	parsed, e := protocol.ParseCredentialCreationResponseBytes(response)
	if e != nil {
		return ErrDenied
	}
	user := webUser{user: store.User{ID: record.User}, handle: record.Data.UserID}
	credential, e := w.verifier.CreateCredential(user, record.Data, parsed)
	if e != nil {
		return ErrDenied
	}
	if len(credential.ID) == 0 || len(credential.ID) > 1024 || !credential.Flags.UserVerified || !credential.Flags.UserPresent {
		return ErrDenied
	}
	// A 'none' attestation validates the advertised algorithm but carries no
	// signature that would otherwise force key parsing. Validate the actual
	// COSE key shape/curve/point as well; an alg label alone is not ES256.
	publicKey, e := webauthncose.ParsePublicKey(credential.PublicKey)
	ec, ok := publicKey.(webauthncose.EC2PublicKeyData)
	if e != nil || !ok || ec.Algorithm != int64(webauthncose.AlgES256) || ec.Curve != int64(webauthncose.P256) {
		return ErrDenied
	}
	plain, e := json.Marshal(webCredential{User: record.User, RPID: record.RPID, Credential: *credential})
	if e != nil {
		return ErrDenied
	}
	defer clear(plain)
	envelope, e := l.repo.EncryptSecret("webauthn-credential", id, plain)
	if e != nil {
		return ErrDenied
	}
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		authority, e := w.registrationAuthority(ctx, q, session, now, recovered)
		c, u := authority.control, authority.user
		if e != nil || u.ID != record.User || authority.session != record.Session || authority.recovery != record.Recovery || c.CredentialGeneration != record.Generation || c.SessionGeneration != record.SessionGeneration {
			return ErrDenied
		}
		if !recovered {
			all, e := q.ListUserAuthenticators(ctx, u.ID)
			if e != nil {
				return e
			}
			count := 0
			for _, a := range all {
				if a.Kind == "webauthn" && a.BoundAt.Valid && !a.RevokedAt.Valid && a.CredentialGeneration == c.CredentialGeneration {
					count++
				}
			}
			if count >= 16 {
				return ErrDenied
			}
		}
		row, e := q.GetWebAuthnChallenge(ctx, id)
		if e != nil || row.ConsumedAt.Valid || now < row.IssuedAt || now >= row.ExpiresAt || !bytes.Equal(row.Envelope, observed.Envelope) {
			return ErrDenied
		}
		n, e := q.ConsumeWebAuthnChallenge(ctx, store.ConsumeWebAuthnChallengeParams{ID: id, Now: nullable(now)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = q.CreateWebAuthnAuthenticator(ctx, store.CreateWebAuthnAuthenticatorParams{ID: id, UserID: u.ID, CredentialGeneration: c.CredentialGeneration, CreatedAt: now, BoundAt: nullable(now), ChangedAt: nullable(now), PublicKey: credential.PublicKey, ExternalCredentialID: credential.ID, SignCount: nullable(int64(credential.Authenticator.SignCount)), BackupEligible: flagInt(credential.Flags.BackupEligible), BackupState: flagInt(credential.Flags.BackupState)}); e != nil {
			return e
		}
		if e = q.PutWebAuthnKeyRecord(ctx, store.PutWebAuthnKeyRecordParams{AuthenticatorID: id, Label: "Security key", Envelope: envelope}); e != nil {
			return e
		}
		if recovered {
			return w.completeRecoveredBinding(ctx, q, c, u.ID, authority.recovery, id, now)
		}
		return l.enqueue(ctx, q, c, u.ID, "authenticator_bound", now)
	}, nil)
	if e != nil {
		return ErrDenied
	}
	return nil
}
