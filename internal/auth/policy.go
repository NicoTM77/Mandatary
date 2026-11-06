package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"
	"github.com/NicoTM77/Mandatary/internal/auth/nfc17"
	"sort"
	"unicode/utf8"
)

//go:embed blocklist.bin
var blockedDigests string

var ErrBlocked = errors.New("password is common, expected or compromised; choose a different uncommon passphrase, not a trivial variation")

type Policy struct {
	MinimumPasswordOnly, MinimumMFA int
	hibp                            *HIBP
}

func DefaultPolicy() Policy { return Policy{MinimumPasswordOnly: 15, MinimumMFA: 8} }

// WithHIBP explicitly opts into external five-hex-prefix disclosure. Offline
// screening is always mandatory; unavailability retains that offline floor.
func (p Policy) WithHIBP() Policy { p.hibp = NewHIBP(); return p }
func (p Policy) Validate(ctx context.Context, raw []byte, compulsoryMFA bool, contextValues []string) ([]byte, error) {
	if p.MinimumPasswordOnly < 15 || p.MinimumPasswordOnly > 128 || p.MinimumMFA < 8 || p.MinimumMFA > 128 {
		return nil, ErrPassword
	}
	b, e := nfc17.Canonical(raw)
	if e != nil {
		return nil, ErrPassword
	}
	n := utf8.RuneCount(b)
	min := p.MinimumPasswordOnly
	if compulsoryMFA {
		min = p.MinimumMFA
	}
	if n < min || n > 128 {
		return nil, ErrPassword
	}
	if blocked(b) {
		return nil, ErrBlocked
	}
	values := append([]string{"mandatary", "docker"}, contextValues...)
	for _, v := range values {
		for _, suffix := range []string{"", "1", "123", "123!", "!", "password"} {
			candidate, e := nfc17.Canonical([]byte(v + suffix))
			if e == nil && bytes.Equal(b, candidate) {
				return nil, ErrBlocked
			}
		}
	}
	if p.hibp != nil {
		found, _ := p.hibp.Check(ctx, b)
		if found {
			return nil, ErrBlocked
		}
	}
	return b, nil
}
func blocked(b []byte) bool {
	// SHA256 here is exact blocklist membership, NOT a password verifier.
	h := sha256.Sum256(b)
	key := string(h[:])
	n := len(blockedDigests) / 32
	i := sort.Search(n, func(i int) bool { return blockedDigests[i*32:(i+1)*32] >= key })
	return i < n && blockedDigests[i*32:(i+1)*32] == key
}
