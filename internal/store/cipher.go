package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

var ErrSecret = errors.New("secret unavailable or invalid")

const envelopeVersion = 1
const saltSize = 32
const maxSecretSize = 64 * 1024

// Each envelope has a fresh 256-bit salt and 96-bit GCM nonce from crypto/rand.
// HKDF-SHA256 derives a 256-bit per-record/per-write key. Length-framed AAD binds
// version, installation, purpose and record identity; moving ciphertext denies.
// This is at-rest encryption, not authenticator verification or authority.
type recordCipher struct {
	key          *MasterKey
	installation []byte
	random       io.Reader
}

func newRecordCipher(key *MasterKey, installation []byte) (*recordCipher, error) {
	if key == nil || len(installation) != 32 {
		return nil, ErrKey
	}
	return &recordCipher{key: key, installation: append([]byte(nil), installation...), random: rand.Reader}, nil
}
func (c *recordCipher) aad(purpose, id string) ([]byte, error) {
	if (purpose != "smtp" && purpose != "totp" && purpose != "key-check" && purpose != "webauthn-challenge" && purpose != "webauthn-credential") || len(id) == 0 || len(id) > 256 {
		return nil, ErrSecret
	}
	data := append([]byte("mandatary/secret/v1"), c.installation...)
	for _, s := range []string{purpose, id} {
		data = binary.BigEndian.AppendUint64(data, uint64(len(s)))
		data = append(data, s...)
	}
	return data, nil
}
func (c *recordCipher) aead(salt, aad []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, c.key.value[:], salt, string(aad), 32)
	if err != nil {
		return nil, ErrSecret
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrSecret
	}
	return cipher.NewGCM(block)
}
func (c *recordCipher) Seal(purpose, id string, plain []byte) ([]byte, error) {
	aad, err := c.aad(purpose, id)
	if err != nil || len(plain) > maxSecretSize {
		return nil, ErrSecret
	}
	header := make([]byte, 1+saltSize+12)
	header[0] = envelopeVersion
	if _, err := io.ReadFull(c.random, header[1:]); err != nil {
		return nil, ErrSecret
	}
	aead, err := c.aead(header[1:1+saltSize], aad)
	if err != nil {
		return nil, ErrSecret
	}
	return aead.Seal(header, header[1+saltSize:], plain, aad), nil
}
func (c *recordCipher) Open(purpose, id string, envelope []byte) ([]byte, error) {
	aad, err := c.aad(purpose, id)
	if err != nil || len(envelope) < 1+saltSize+12+16 || len(envelope) > 1+saltSize+12+16+maxSecretSize || envelope[0] != envelopeVersion {
		return nil, ErrSecret
	}
	aead, err := c.aead(envelope[1:1+saltSize], aad)
	if err != nil {
		return nil, ErrSecret
	}
	plain, err := aead.Open(nil, envelope[1+saltSize:1+saltSize+12], envelope[1+saltSize+12:], aad)
	if err != nil {
		return nil, ErrSecret
	}
	return plain, nil
}
