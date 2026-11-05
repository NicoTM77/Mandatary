package auth

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestArgonVerifier(t *testing.T) {
	p := []byte("synthetic long test passphrase")
	a, e := HashPassword(p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := HashPassword(p)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(a, b) {
		t.Fatal("salt reused")
	}
	if !VerifyPassword(p, a, PasswordProfile) || VerifyPassword(append(p, 'x'), a, PasswordProfile) || VerifyPassword(p, a, "unknown-historical-profile") {
		t.Fatal("proof/profile binding")
	}
	for _, s := range []string{"", strings.Repeat("x", 10000), string(a) + "$x", strings.Replace(string(a), "m=65536", "m=999999999", 1), strings.Replace(string(a), "t=3", "t=1", 1)} {
		if VerifyPassword(p, []byte(s), PasswordProfile) {
			t.Fatal("unsafe format accepted")
		}
	}
	if _, e := hashPassword(p, failingReader{}); e == nil {
		t.Fatal("entropy failure accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
