package config

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestPublicOriginValidation(t *testing.T) {
	for _, c := range []struct {
		origin string
		ok     bool
	}{
		{"https://mandatary.example.invalid", true},
		{"https://mandatary.example.invalid:8443", true},
		{"http://mandatary.example.invalid", false},
		{"https://mandatary.example.invalid/", false},
		{"https://mandatary.example.invalid/setup", false},
		{"https://mandatary.example.invalid?x=1", false},
		{"https://mandatary.example.invalid#x", false},
		{"https://user:pw@mandatary.example.invalid", false},
		{"https://mandatary.example.invalid ", false},
		{"https://mandatary.example.invalid\r\nX: y", false},
		{"https://", false},
		{"mandatary.example.invalid", false},
		{"https://" + string(make([]byte, 300)), false},
	} {
		c2, err := Load(env(map[string]string{"MANDATARY_PUBLIC_ORIGIN": c.origin}))
		if (err == nil) != c.ok {
			t.Fatalf("%q: ok=%v err=%v", c.origin, c.ok, err)
		}
		if err != nil && err.Error() != "invalid MANDATARY_PUBLIC_ORIGIN" {
			t.Fatalf("validation error echoed input: %v", err)
		}
		if c.ok && c2.PublicOrigin != c.origin {
			t.Fatal("origin not retained")
		}
	}
}

func TestNoticeSettingsAreAllOrNothing(t *testing.T) {
	full := map[string]string{
		"MANDATARY_PUBLIC_ORIGIN": "https://mandatary.example.invalid", "MANDATARY_SMTP_RELAY": "smtp.example.invalid:465",
		"MANDATARY_SMTP_TLS": "implicit", "MANDATARY_SMTP_SENDER": "notices@example.invalid", "MANDATARY_NOTICE_CONTACT": "security@example.invalid",
	}
	if _, err := Load(env(full)); err != nil {
		t.Fatal(err)
	}
	for k := range full {
		if k == "MANDATARY_PUBLIC_ORIGIN" {
			continue
		}
		partial := map[string]string{}
		for kk, v := range full {
			if kk != k {
				partial[kk] = v
			}
		}
		if _, err := Load(env(partial)); err == nil {
			t.Fatalf("partial notice configuration without %s was accepted", k)
		}
	}
	noOrigin := map[string]string{}
	for k, v := range full {
		if k != "MANDATARY_PUBLIC_ORIGIN" {
			noOrigin[k] = v
		}
	}
	if _, err := Load(env(noOrigin)); err == nil {
		t.Fatal("mail without a trusted origin was accepted")
	}
	bad := map[string]string{}
	for k, v := range full {
		bad[k] = v
	}
	bad["MANDATARY_SMTP_TLS"] = "plain"
	if _, err := Load(env(bad)); err == nil {
		t.Fatal("cleartext SMTP accepted")
	}
	bad["MANDATARY_SMTP_TLS"] = "implicit"
	bad["MANDATARY_SMTP_SENDER"] = "a@example.invalid\r\nBcc: x@example.invalid"
	if _, err := Load(env(bad)); err == nil {
		t.Fatal("header injection in sender accepted")
	}
}
