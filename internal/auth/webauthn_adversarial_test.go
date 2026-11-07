package auth

import (
	"encoding/base64"
	"encoding/json"
	"github.com/fxamacker/cbor/v2"
	"testing"
	"time"
)

func alterResponse(t *testing.T, b []byte, fn func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("synthetic response invalid")
	}
	fn(m)
	return jsonBytes(t, m)
}
func alterClient(t *testing.T, m map[string]any, fn func(map[string]any)) {
	t.Helper()
	r := m["response"].(map[string]any)
	b, e := base64.RawURLEncoding.DecodeString(r["clientDataJSON"].(string))
	if e != nil {
		t.Fatal(e)
	}
	var data map[string]any
	if json.Unmarshal(b, &data) != nil {
		t.Fatal("bad synthetic client data")
	}
	fn(data)
	r["clientDataJSON"] = b64(jsonBytes(t, data))
}
func TestWebAuthnAssertionAdversarialMatrix(t *testing.T) {
	for _, name := range []string{"origin", "scheme", "port", "type", "challenge", "cross-origin", "top-origin", "signature", "rp-hash", "missing-uv", "missing-up", "backup-invalid", "changed-be", "user-handle", "credential-id", "expired", "clock-rollback", "quarantine", "generation", "revoked-factor", "revoked-session", "recovery-session", "setup-session", "public-key-tamper", "envelope-tamper"} {
		t.Run(name, func(t *testing.T) {
			w, db, session, key, id := webFixture(t)
			c, e := w.BeginAssertion(t.Context(), session)
			if e != nil {
				t.Fatal(e)
			}
			response := key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
			query := ""
			switch name {
			case "origin":
				response = key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid.evil.invalid", 5, 1)
			case "scheme":
				response = key.assert(t, c.Options.Response.Challenge.String(), "http://example.invalid", 5, 1)
			case "port":
				response = key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid:8443", 5, 1)
			case "challenge":
				response = key.assert(t, "different-challenge-with-more-than-thirty-two-bytes", "https://example.invalid", 5, 1)
			case "missing-uv":
				response = key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 1, 1)
			case "missing-up":
				response = key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 4, 1)
			case "backup-invalid":
				response = key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 21, 1)
			case "changed-be":
				response = key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 13, 1)
			case "type", "cross-origin", "top-origin":
				response = alterResponse(t, response, func(m map[string]any) {
					alterClient(t, m, func(d map[string]any) {
						switch name {
						case "type":
							d["type"] = "webauthn.create"
						case "cross-origin":
							d["crossOrigin"] = true
						case "top-origin":
							d["topOrigin"] = "https://evil.invalid"
						}
					})
				})
			case "signature":
				response = alterResponse(t, response, func(m map[string]any) { r := m["response"].(map[string]any); r["signature"] = b64(make([]byte, 72)) })
			case "rp-hash":
				response = alterResponse(t, response, func(m map[string]any) {
					r := m["response"].(map[string]any)
					b, _ := base64.RawURLEncoding.DecodeString(r["authenticatorData"].(string))
					b[0] ^= 1
					r["authenticatorData"] = b64(b)
				})
			case "user-handle":
				response = alterResponse(t, response, func(m map[string]any) { m["response"].(map[string]any)["userHandle"] = b64([]byte("wrong-owner")) })
			case "credential-id":
				response = alterResponse(t, response, func(m map[string]any) { m["id"] = b64([]byte("unknown")); m["rawId"] = m["id"] })
			case "expired":
				at := w.lifecycle.now().Add(300 * time.Second)
				w.lifecycle.now = func() time.Time { return at }
			case "clock-rollback":
				at := w.lifecycle.now().Add(-time.Second)
				w.lifecycle.now = func() time.Time { return at }
			case "quarantine":
				query = `UPDATE installation_control SET restore_quarantined=1`
			case "generation":
				query = `UPDATE installation_control SET credential_generation=2`
			case "revoked-factor":
				query = `UPDATE authenticators SET state='revoked',revoked_at=2000000010 WHERE kind='webauthn'`
			case "revoked-session":
				query = `UPDATE sessions SET state='revoked',revoked_at=2000000010`
			case "recovery-session":
				query = `UPDATE sessions SET purpose='recovery',achieved_assurance=0,methods=16`
			case "setup-session":
				query = `UPDATE sessions SET purpose='setup',achieved_assurance=0,methods=0`
			case "public-key-tamper":
				query = `UPDATE authenticators SET public_key=x'010203' WHERE kind='webauthn'`
			case "envelope-tamper":
				query = `UPDATE webauthn_credentials SET envelope=x'010203'`
			}
			if query != "" {
				if _, e = db.Exec(query); e != nil {
					t.Fatal(e)
				}
			}
			if name != "signature" {
				response = key.resign(t, response)
			}
			if p, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.6"); e != ErrDenied || p.AuthenticatorID != "" {
				t.Fatal("adversarial assertion accepted", id)
			}
		})
	}
}
func TestWebAuthnRegistrationAdversarialMatrix(t *testing.T) {
	for _, name := range []string{"origin", "missing-up", "missing-uv", "backup-invalid", "expired", "wrong-session", "quarantine", "outbox-failure", "malformed-attestation", "unsupported-algorithm", "algorithm-curve-mismatch", "off-curve"} {
		t.Run(name, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			w, e := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
			if e != nil {
				t.Fatal(e)
			}
			c, e := w.BeginRegistration(t.Context(), session, false)
			if e != nil {
				t.Fatal(e)
			}
			key := newVirtualKey(t)
			flags := byte(5)
			origin := "https://example.invalid"
			switch name {
			case "origin":
				origin = "https://evil.invalid"
			case "missing-up":
				flags = 4
			case "missing-uv":
				flags = 1
			case "backup-invalid":
				flags = 21
			case "expired":
				at := l.now().Add(300 * time.Second)
				l.now = func() time.Time { return at }
			case "wrong-session":
				session = []byte("wrong synthetic session with enough entropy length")
			case "quarantine":
				if _, e = db.Exec(`UPDATE installation_control SET restore_quarantined=1`); e != nil {
					t.Fatal(e)
				}
			case "outbox-failure":
				if _, e = db.Exec(`CREATE TRIGGER reject_web_notice BEFORE INSERT ON security_notice_outbox BEGIN SELECT RAISE(ABORT,'synthetic'); END`); e != nil {
					t.Fatal(e)
				}
			}
			response := key.create(t, c.Options.Response.Challenge.String(), origin, flags)
			if name == "malformed-attestation" {
				response = alterResponse(t, response, func(m map[string]any) { m["response"].(map[string]any)["attestationObject"] = b64([]byte{0}) })
			}
			if name == "unsupported-algorithm" || name == "algorithm-curve-mismatch" || name == "off-curve" {
				response = alterResponse(t, response, func(m map[string]any) {
					r := m["response"].(map[string]any)
					b, _ := base64.RawURLEncoding.DecodeString(r["attestationObject"].(string))
					var a map[string]any
					if cbor.Unmarshal(b, &a) != nil {
						t.Fatal("bad fixture")
					}
					data := a["authData"].([]byte)
					offset := 55 + len(key.id)
					var pub map[int]any
					if cbor.Unmarshal(data[offset:], &pub) != nil {
						t.Fatal("bad fixture key")
					}
					switch name {
					case "unsupported-algorithm":
						pub[3] = -8
					case "algorithm-curve-mismatch":
						pub[-1] = 2
					case "off-curve":
						pub[-2] = make([]byte, 32)
						pub[-3] = make([]byte, 32)
					}
					encoded, e := cbor.Marshal(pub)
					if e != nil {
						t.Fatal(e)
					}
					a["authData"] = append(data[:offset], encoded...)
					b, e = cbor.Marshal(a)
					if e != nil {
						t.Fatal(e)
					}
					r["attestationObject"] = b64(b)
				})
			}
			if e = w.FinishRegistration(t.Context(), session, c.ID, response); e != ErrDenied {
				t.Fatal("invalid binding accepted")
			}
			var n int
			if e = db.QueryRow(`SELECT count(*) FROM authenticators WHERE kind='webauthn'`).Scan(&n); e != nil || n != 0 {
				t.Fatal("failed binding left active credential")
			}
		})
	}
}
