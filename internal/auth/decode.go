// Package auth implements internal password proof and policy, not public
// authentication routes, session issuance, recovery authority or MFA.
package auth

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

var ErrPassword = errors.New("password does not meet the selected policy; choose a longer uncommon password")

const MaxPasswordWireBytes = 32768

// DecodePasswordJSON accepts an original JSON string TOKEN, before any lossy
// unmarshalling. Envelope/unknown-field/transport checks belong to the adapter.
// The independent wire bound admits all escapes of eligible raw512 scalars.
func DecodePasswordJSON(raw []byte) ([]byte, error) {
	if len(raw) > MaxPasswordWireBytes || !utf8.Valid(raw) {
		return nil, ErrPassword
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return nil, ErrPassword
		}
		if raw[i] != 'u' {
			continue
		}
		n, ok := hex4(raw, i+1)
		if !ok {
			return nil, ErrPassword
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return nil, ErrPassword
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return nil, ErrPassword
			}
			low, ok := hex4(raw, i+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return nil, ErrPassword
			}
			i += 6
		}
	}
	var s *string
	if json.Unmarshal(raw, &s) != nil || s == nil || len(*s) > 4096 {
		return nil, ErrPassword
	}
	return []byte(*s), nil
}
func hex4(b []byte, i int) (uint16, bool) {
	if i < 0 || i > len(b)-4 {
		return 0, false
	}
	var n uint16
	for _, v := range b[i : i+4] {
		n <<= 4
		switch {
		case v >= '0' && v <= '9':
			n += uint16(v - '0')
		case v >= 'a' && v <= 'f':
			n += uint16(v - 'a' + 10)
		case v >= 'A' && v <= 'F':
			n += uint16(v - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}
