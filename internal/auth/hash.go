package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Immutable canonicalization semantics, independent of algorithm/work factors.
const PasswordProfile = "mdt-pwd-u17-nfc-cn-v1" // #nosec G101 -- public immutable format identifier, not a credential.
const phcPrefix = "$argon2id$v=19$m=65536,t=3,p=4$"

func HashPassword(canonical []byte) ([]byte, error) { return hashPassword(canonical, rand.Reader) }
func hashPassword(canonical []byte, entropy io.Reader) ([]byte, error) {
	if len(canonical) == 0 || len(canonical) > 8192 {
		return nil, ErrPassword
	}
	var salt [16]byte
	if _, e := io.ReadFull(entropy, salt[:]); e != nil {
		return nil, ErrPassword
	}
	key := argon2.IDKey(canonical, salt[:], 3, 64*1024, 4, 32)
	return []byte(phcPrefix + base64.RawStdEncoding.EncodeToString(salt[:]) + "$" + base64.RawStdEncoding.EncodeToString(key)), nil
}
func parseVerifier(encoded []byte, profile string) ([]byte, []byte, bool) {
	if profile != PasswordProfile || len(encoded) != len(phcPrefix)+22+1+43 || !bytes.HasPrefix(encoded, []byte(phcPrefix)) {
		return nil, nil, false
	}
	parts := strings.Split(string(encoded[len(phcPrefix):]), "$")
	if len(parts) != 2 {
		return nil, nil, false
	}
	salt, e := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if e != nil || len(salt) != 16 {
		return nil, nil, false
	}
	key, e := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(key) != 32 {
		return nil, nil, false
	}
	return salt, key, true
}

// VerifyPassword verifies already canonical bytes ONLY under the explicitly
// stored supported profile. No current establishment minimum/list is applied.
// Callers bound concurrency before invoking this expensive operation.
func VerifyPassword(canonical, encoded []byte, profile string) bool {
	salt, key, ok := parseVerifier(encoded, profile)
	if !ok || len(canonical) > 8192 {
		return false
	}
	got := argon2.IDKey(canonical, salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(got, key) == 1
}
