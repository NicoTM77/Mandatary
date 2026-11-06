package auth

import (
	"crypto/subtle"
	"encoding/base32"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// matchTOTP applies the approved TOTP algorithm at exact integer counters using
// the selected library's RFC4226 primitive. Its TOTP float conversion and input
// trimming are deliberately not authority. Output is possession evidence only.
// The owning transaction MUST also enforce durable replay, retry and user state.
func matchTOTP(seed []byte, algorithm, code string, now int64) (int64, bool) {
	if now < 0 || now > 253402300799 || len(code) != 6 {
		return 0, false
	}
	for _, c := range []byte(code) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	var a otp.Algorithm
	switch algorithm {
	case "SHA1":
		if len(seed) < 20 || len(seed) > 64 {
			return 0, false
		}
		a = otp.AlgorithmSHA1
	case "SHA256":
		if len(seed) < 32 || len(seed) > 64 {
			return 0, false
		}
		a = otp.AlgorithmSHA256
	default:
		return 0, false
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	current := now / 30
	var matched int64
	found := false
	for _, step := range []int64{current - 1, current, current + 1} {
		if step < 0 {
			continue
		}
		expected, e := hotp.GenerateCodeCustom(secret, uint64(step), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: a})
		if e != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			matched = step
			found = true
		}
	}
	return matched, found
}
