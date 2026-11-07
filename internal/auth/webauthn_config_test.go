package auth

import "testing"

func TestWebAuthnRequiresExplicitVerifierName(t *testing.T) {
	l, _, _ := lifecycleFixture(t)
	for _, c := range []WebAuthnSettings{
		{}, {RPID: "com", Origins: []string{"https://com"}},
		{RPID: "example.invalid", Origins: []string{"http://example.invalid"}},
		{RPID: "example.invalid", Origins: []string{"https://example.invalid.evil.invalid"}},
		{RPID: "example.invalid", Origins: []string{"https://example.invalid/path"}},
		{RPID: "example.invalid", Origins: []string{"https://user@example.invalid"}},
		{RPID: "example.invalid", Origins: []string{"https://example.invalid?x=y"}},
		{RPID: "EXAMPLE.invalid", Origins: []string{"https://example.invalid"}},
	} {
		if _, err := NewWebAuthn(l, c); err != ErrDenied {
			t.Fatal("unsafe verifier configuration accepted")
		}
	}
	if _, err := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid", "https://admin.example.invalid:8443"}}); err != nil {
		t.Fatal("valid explicit verifier denied", err)
	}
}
