package store

import (
	"bytes"
	"context"
	"crypto/rand"
)

const keyCheckText = "Mandatary repository master-key binding v1"

// Called only under the shared lock and a verified FULL writer. Initialization
// is allowed only on creation/upgrade into this schema, never on a missing
// control record in an already initialized repository.
func (r *Repository) bindKey(ctx context.Context, key *MasterKey, initialize bool) error {
	q := New(r.writer)
	if initialize {
		installation := make([]byte, 32)
		if _, err := rand.Read(installation); err != nil {
			return ErrKey
		}
		c, err := newRecordCipher(key, installation)
		if err != nil {
			return ErrKey
		}
		check, err := c.Seal("key-check", "installation", []byte(keyCheckText))
		if err != nil {
			return ErrKey
		}
		if err := q.InitializeRepositoryMetadata(ctx, InitializeRepositoryMetadataParams{InstallationID: installation, KeyCheck: check}); err != nil {
			return ErrKey
		}
	}
	metadata, err := q.GetRepositoryMetadata(ctx)
	if err != nil {
		return ErrKey
	}
	c, err := newRecordCipher(key, metadata.InstallationID)
	if err != nil {
		return ErrKey
	}
	check, err := c.Open("key-check", "installation", metadata.KeyCheck)
	if err != nil || !bytes.Equal(check, []byte(keyCheckText)) {
		return ErrKey
	}
	r.cipher = c
	return nil
}

// EncryptSecret/DecryptSecret bind pending TOTP material to its authenticator ID.
// Only the owning lifecycle verifier should access plaintext. They confer no
// proof-of-possession, session assurance or permission; no public route exists.
func (r *Repository) EncryptSecret(purpose, id string, plain []byte) ([]byte, error) {
	r.lifecycle.RLock()
	defer r.lifecycle.RUnlock()
	if r.closed || r.poisoned.Load() || (purpose != "totp" && purpose != "smtp") {
		return nil, ErrSecret
	}
	return r.cipher.Seal(purpose, id, plain)
}
func (r *Repository) DecryptSecret(purpose, id string, envelope []byte) ([]byte, error) {
	r.lifecycle.RLock()
	defer r.lifecycle.RUnlock()
	if r.closed || r.poisoned.Load() || (purpose != "totp" && purpose != "smtp") {
		return nil, ErrSecret
	}
	return r.cipher.Open(purpose, id, envelope)
}

// SMTP storage is deliberately NOT SMTP configuration, a dispatcher or an
// authorization service. Calls must later sit behind the approved assurance gate.
func (r *Repository) PutSMTPSecret(ctx context.Context, id string, plain []byte) error {
	envelope, err := r.EncryptSecret("smtp", id, plain)
	if err != nil {
		return ErrSecret
	}
	return r.Write(ctx, func(q *Queries) error { return q.PutSMTPRecord(ctx, PutSMTPRecordParams{ID: id, Ciphertext: envelope}) })
}
func (r *Repository) SMTPSecret(ctx context.Context, id string) ([]byte, error) {
	var envelope []byte
	err := r.Read(ctx, func(q *Queries) error { var err error; envelope, err = q.GetSMTPRecord(ctx, id); return err })
	if err != nil {
		return nil, ErrSecret
	}
	return r.DecryptSecret("smtp", id, envelope)
}
