// Package domain defines identifiers shared by storage and later services.
// These types do not authenticate a caller or confer authority.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// EndpointID is a canonical, non-nil UUID, not a mutable display name or slug.
type EndpointID string

type UserID string
type GroupID string
type AgentID string
type SelectorID string

const LocalEndpointSlug = "local"

// ParseEndpointID rejects noncanonical input rather than silently normalizing it.
func ParseEndpointID(value string) (EndpointID, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", errors.New("invalid endpoint UUID")
	}
	nonzero := false
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("invalid endpoint UUID")
		}
		if c != '0' {
			nonzero = true
		}
	}
	if !nonzero {
		return "", errors.New("nil endpoint UUID")
	}
	return EndpointID(value), nil
}

// NewEndpointID generates a random UUIDv4 using the OS-backed CSPRNG.
func NewEndpointID() (EndpointID, error) {
	id, err := NewUUID(rand.Reader)
	if err != nil {
		return "", errors.New("generate endpoint UUID")
	}
	return EndpointID(id), nil
}

// NewUUID reads 16 bytes from source and formats a canonical lowercase UUIDv4.
// Production callers pass crypto/rand.Reader; a failing source yields an error
// and never a predictable fallback value.
func NewUUID(source io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(source, b[:]); err != nil {
		return "", errors.New("generate UUID")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
