package auth

import (
	"encoding/base32"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"testing"
	"time"
)

func publicSHA256Code(t *testing.T, seed []byte, counter uint64) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed), counter, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA256})
	if err != nil {
		t.Fatal("public vector generation failed")
	}
	return code
}

// Public RFC6238 SHA256 seed has equal six-digit outputs at counters398541/2.
// The same value stays continuously valid from verifier period398540 to398543.
func TestTOTPCollisionCannotExtendOutputReplay(t *testing.T) {
	l, db, _ := lifecycleFixture(t)
	seed := []byte("12345678901234567890123456789012")
	encrypted, err := l.repo.EncryptSecret("totp", "public-vector", seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,encrypted_secret,totp_algorithm,max_assurance) VALUES('public-vector','u','totp','active',1,1,1,?,'SHA256',1)`, encrypted); err != nil {
		t.Fatal(err)
	}
	code := publicSHA256Code(t, seed, 398541)
	if publicSHA256Code(t, seed, 398542) != code {
		t.Fatal("public collision vector changed")
	}
	now := time.Unix(398540*30, 0)
	l.now = func() time.Time { return now }
	if _, err = l.VerifyTOTP(t.Context(), "u", "public-vector", code, "192.0.2.1"); err != nil {
		t.Fatal("first public vector denied")
	}
	now = time.Unix(398543*30, 0)
	if _, err = l.VerifyTOTP(t.Context(), "u", "public-vector", code, "192.0.2.2"); err != ErrDenied {
		t.Fatal("adjacent collision extended accepted output replay")
	}
}
