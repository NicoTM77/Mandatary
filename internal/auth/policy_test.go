package auth

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPasswordPolicyBoundaries(t *testing.T) {
	p := DefaultPolicy()
	for _, mfa := range []bool{false, true} {
		for _, n := range []int{7, 8, 14, 15, 63, 64, 127, 128, 129} {
			s := strings.Repeat("😀", n)
			out, e := p.Validate(context.Background(), []byte(s), mfa, nil)
			want := n <= 128 && (n >= 15 || mfa && n >= 8)
			if (e == nil) != want {
				t.Fatalf("boundary n=%d mfa=%v", n, mfa)
			}
			if want && utf8.RuneCount(out) != n {
				t.Fatal("codepoint count changed")
			}
		}
	}
	for _, s := range []string{strings.Repeat("x", 13) + "\U000105D2\u0307", "a\u0378" + strings.Repeat("x", 20), string([]byte{0xff}) + strings.Repeat("a", 20)} {
		if _, e := p.Validate(context.Background(), []byte(s), false, nil); e == nil {
			t.Fatal("short normalized/unassigned/malformed admitted")
		}
	}
	for _, s := range []string{" an uncommon docker phrase ", strings.Repeat("lowercase", 3), strings.Repeat("\uE000", 15), strings.Repeat("\ufffd", 15)} {
		if _, e := p.Validate(context.Background(), []byte(s), false, nil); e != nil {
			t.Fatal("composition/substring/repertoire restriction")
		}
	}
}
func TestWholePasswordBlocklist(t *testing.T) {
	p := DefaultPolicy()
	for _, s := range []string{"password", "password1", "mandatary", "docker123", "syntheticuser123"} {
		if _, e := p.Validate(context.Background(), []byte(s), true, []string{"syntheticuser"}); e == nil {
			t.Fatal("full forbidden value accepted")
		}
	}
	if _, e := p.Validate(context.Background(), []byte("long password1 phrase containing docker"), false, nil); e != nil {
		t.Fatal("substring false positive")
	}
	a, e := p.Validate(context.Background(), []byte("synthetic cafe\u0301 phrase"), false, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.Validate(context.Background(), []byte("synthetic café phrase"), false, nil)
	if e != nil || string(a) != string(b) {
		t.Fatal("canonical policy drift")
	}
}
