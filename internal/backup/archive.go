package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// Archive format v1. Every field below is signed. The importer decodes ONLY into these types with
// unknown fields refused, so an archive cannot carry a state, a generation, a quarantine flag,
// a recovery control or any other local control value: there is no field to put it in, and an extra
// one is a malformed archive, not an ignored one (RESTORE-11).
const (
	Format         = "mandatary-logical-backup"
	ArchiveVersion = 1
	// MaxArchiveBytes bounds every archive before any parsing work.
	MaxArchiveBytes = 16 << 20

	integrityInfo = "mandatary/backup/integrity/v1"
	secretsInfo   = "mandatary/backup/secrets/v1"
	saltBytes     = 32
)

// Mode selects what an archive carries.
type Mode string

const (
	// ModeFull carries the cleartext scope plus the master-key-bound envelope of credential
	// material, for restore under the SAME master key. Import is still not activation.
	ModeFull Mode = "full"
	// ModeClean carries the cleartext scope only (credentials and MFA stripped at export) so it can
	// move to an installation with a NEW master key.
	ModeClean Mode = "clean"
)

// Provenance reports what the integrity tag proved to THIS installation.
type Provenance string

const (
	// ProvenanceAuthenticated: the tag verified under this installation's master key.
	ProvenanceAuthenticated Provenance = "authenticated"
	// ProvenanceUnauthenticated: only a clean archive can be this; the content digest matched but
	// the tag cannot be checked without the exporting key. It is corruption detection, nothing more.
	ProvenanceUnauthenticated Provenance = "unauthenticated"
)

// Archive is the signed document.
type Archive struct {
	Format                string  `json:"format"`
	SchemaVersion         int     `json:"schema_version"`
	DatabaseSchemaVersion int64   `json:"database_schema_version"`
	MandataryVersion      string  `json:"mandatary_version"`
	CreatedAt             string  `json:"created_at"` // informational only; never used for expiry or freshness
	BackupID              string  `json:"backup_id"`
	Mode                  Mode    `json:"mode"`
	HMACSalt              string  `json:"hmac_salt"`
	Scope                 Scope   `json:"scope"`
	Secrets               *Sealed `json:"secrets"`
	ContentDigest         string  `json:"content_digest"`
	IntegrityHMAC         string  `json:"integrity_hmac"`
}

// Sealed is the AES-256-GCM envelope of the credential material (full mode only).
type Sealed struct {
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// secretPayload is what Sealed contains. Every credential-specific value lives here, never in the
// cleartext scope: password verifiers, TOTP seeds, public keys, credential identifiers, hashes of
// agent tokens and WebAuthn records.
type secretPayload struct {
	Authenticators   map[string]authenticatorSecret `json:"authenticators"`
	AgentCredentials map[string][]byte              `json:"agent_credentials"`
	WebauthnUsers    map[string][]byte              `json:"webauthn_users"`
	WebauthnRecords  map[string][]byte              `json:"webauthn_records"`
}

type authenticatorSecret struct {
	CreatedAt            int64   `json:"created_at"`
	BoundAt              *int64  `json:"bound_at"`
	ExpiresAt            *int64  `json:"expires_at"`
	VerifierHash         []byte  `json:"verifier_hash"`
	TOTPSeed             []byte  `json:"totp_seed"`
	PublicKey            []byte  `json:"public_key"`
	ExternalCredentialID []byte  `json:"external_credential_id"`
	PasswordCodepoints   *int64  `json:"password_codepoints"`
	PasswordFormat       *string `json:"password_format"`
	MaxAssurance         int64   `json:"max_assurance"`
	PhishingResistant    *int64  `json:"phishing_resistant"`
	RetryCeiling         int64   `json:"retry_ceiling"`
	LastAcceptedTOTPStep *int64  `json:"last_accepted_totp_step"`
	SignCount            *int64  `json:"sign_count"`
	BackupEligible       *int64  `json:"backup_eligible"`
	BackupState          *int64  `json:"backup_state"`
	UserVerified         *int64  `json:"user_verified"`
	TOTPAlgorithm        *string `json:"totp_algorithm"`
}

// canonical is the exact byte string the digest and the tag cover: the document with both
// integrity fields blanked, in Go's deterministic struct-field order. The importer verifies the
// re-encoding of what it DECODED and imports from that decoded value only, so no byte that was
// not signed can influence an import.
func (a Archive) canonical() ([]byte, error) {
	a.ContentDigest, a.IntegrityHMAC = "", ""
	return json.Marshal(a)
}

func digestOf(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func tagOf(key, canonical []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("mandatary-backup-integrity-v1\x00"))
	_, _ = mac.Write(canonical)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func equalB64(a, b string) bool {
	x, e1 := base64.StdEncoding.Strict().DecodeString(a)
	y, e2 := base64.StdEncoding.Strict().DecodeString(b)
	return e1 == nil && e2 == nil && len(x) == len(y) && subtle.ConstantTimeCompare(x, y) == 1
}

func randomBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, ErrUnavailable
	}
	return b, nil
}

func secretsAAD(a Archive) []byte {
	return []byte("mandatary-backup-secrets-v1\x00" + a.BackupID + "\x00" + string(a.Mode))
}

func sealPayload(a Archive, key []byte, nonce []byte, p secretPayload) ([]byte, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, ErrUnavailable
	}
	return aead.Seal(nil, nonce, plain, secretsAAD(a)), nil
}

func openPayload(a Archive, key []byte) (secretPayload, error) {
	var zero secretPayload
	if a.Secrets == nil {
		return zero, ErrMalformed
	}
	nonce, e1 := base64.StdEncoding.Strict().DecodeString(a.Secrets.Nonce)
	ct, e2 := base64.StdEncoding.Strict().DecodeString(a.Secrets.Ciphertext)
	block, e3 := aes.NewCipher(key)
	if e1 != nil || e2 != nil || e3 != nil {
		return zero, ErrMalformed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() || len(ct) < aead.Overhead() || len(ct) > MaxArchiveBytes {
		return zero, ErrMalformed
	}
	plain, err := aead.Open(nil, nonce, ct, secretsAAD(a))
	if err != nil {
		return zero, ErrIntegrity
	}
	defer clear(plain)
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	var p secretPayload
	if dec.Decode(&p) != nil {
		return zero, ErrMalformed
	}
	var extra json.RawMessage
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return zero, ErrMalformed
	}
	return p, nil
}

// decodeStrict reads exactly one JSON object with no unknown field and no trailing data.
func decodeStrict(raw []byte, dst any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' || len(raw) > MaxArchiveBytes {
		return ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return ErrMalformed
	}
	var extra json.RawMessage
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return ErrMalformed
	}
	return nil
}

func newRandomReader() io.Reader { return rand.Reader }
