package auth

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/NicoTM77/Mandatary/internal/auth/nfc17"
)

// This digest covers accepts/denials, canonical bytes/counts, membership and
// fixed-salt Argon2 output. CI uses the same golden under both locked compilers.
func TestCrossToolchainPasswordContract(t *testing.T) {
	h := sha256.New()
	for _, raw := range []string{"synthetic cafe\u0301 phrase", "synthetic café phrase", strings.Repeat("x", 13) + "\U000105d2\u0307", "q" + strings.Repeat("\u0301", 127), "q" + strings.Repeat("\u0301", 31) + "\u0323", "q\u0323" + strings.Repeat("\u0301", 31), strings.Repeat("\uE000", 15), "\u0378", "\ufdd0", "\ufffd", "Case and spaces ", "case and spaces ", "Ａ compatibility", string([]byte{0xff}), "password1"} {
		b, e := nfc17.Canonical([]byte(raw))
		if e != nil {
			_, _ = fmt.Fprintln(h, "denied") // hash.Hash writes cannot fail.
			continue
		}
		v, e := hashPassword(b, bytes.NewReader([]byte("0123456789abcdef")))
		if e != nil {
			t.Fatal(e)
		}
		_, _ = fmt.Fprintf(h, "%x:%d:%t:%s\n", b, utf8.RuneCount(b), blocked(b), v) // hash.Hash writes cannot fail.
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	t.Logf("cross-toolchain password contract=%s", got)
	if got != "5a6f879f4932ce02ccd32b6e5a2b756fdfbbac9c060cc4ed6070d57492cd25f7" {
		t.Fatal("immutable cross-toolchain password semantics changed")
	}
}
func FuzzStrictPasswordJSON(f *testing.F) {
	for _, s := range []string{`"\ud800"`, `"\ud83d\ude00"`, `"\ufffd"`, `null`, `"x" "y"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, e := DecodePasswordJSON(b)
		if e != nil {
			if out != nil {
				t.Fatal("partial secret")
			}
			return
		}
		if !utf8.Valid(out) || len(out) > 4096 {
			t.Fatal("invalid decoded password")
		}
	})
}
func FuzzVerifierParsing(f *testing.F) {
	for _, s := range []string{"", phcPrefix, "$argon2id$v=19$m=999999999,t=3,p=4$"} {
		f.Add([]byte(s), PasswordProfile)
	}
	f.Fuzz(func(t *testing.T, b []byte, p string) {
		salt, key, ok := parseVerifier(b, p)
		if ok && (len(salt) != 16 || len(key) != 32 || p != PasswordProfile) {
			t.Fatal("unsafe parser success")
		}
	})
}
