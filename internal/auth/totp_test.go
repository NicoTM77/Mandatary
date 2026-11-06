package auth

import (
	"encoding/base32"
	"testing"
)

func TestTOTPParametersAndWindow(t *testing.T) {
	// RFC6238 AppendixB 8-digit vectors truncated to the selected six digits.
	for _, v := range []struct{ algorithm, seed, code string }{
		{"SHA1", "12345678901234567890", "287082"},
		{"SHA256", "12345678901234567890123456789012", "119246"},
	} {
		t.Run(v.algorithm, func(t *testing.T) {
			for _, now := range []int64{30, 59, 60, 89} {
				step, ok := matchTOTP([]byte(v.seed), v.algorithm, v.code, now)
				if !ok || step != 1 {
					t.Fatal("RFC vector/window rejected")
				}
			}
			for _, now := range []int64{-1, 90, 1 << 62} {
				if _, ok := matchTOTP([]byte(v.seed), v.algorithm, v.code, now); ok {
					t.Fatal("outside bounded window accepted")
				}
			}
			for _, bad := range []string{"", v.code + " ", " " + v.code, "00000", "1234567", "１２３４５６"} {
				if _, ok := matchTOTP([]byte(v.seed), v.algorithm, bad, 59); ok {
					t.Fatal("malformed proof accepted")
				}
			}
		})
	}
	if _, ok := matchTOTP([]byte("short"), "SHA1", "123456", 59); ok {
		t.Fatal("weak seed accepted")
	}
	if _, ok := matchTOTP([]byte(base32.StdEncoding.EncodeToString([]byte("public synthetic seed material!!"))), "MD5", "123456", 59); ok {
		t.Fatal("unapproved algorithm accepted")
	}
}
