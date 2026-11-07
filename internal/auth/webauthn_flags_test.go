package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Re-sign mutated client/authenticator data so negative cases isolate their
// named protocol checks, rather than also failing an unrelated signature check.
func (v virtualKey) resign(t *testing.T, response []byte) []byte {
	t.Helper()
	return alterResponse(t, response, func(m map[string]any) {
		r := m["response"].(map[string]any)
		client, e := base64.RawURLEncoding.DecodeString(r["clientDataJSON"].(string))
		if e != nil {
			t.Fatal(e)
		}
		data, e := base64.RawURLEncoding.DecodeString(r["authenticatorData"].(string))
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(client)
		digest := sha256.Sum256(append(data, h[:]...))
		signature, e := ecdsa.SignASN1(rand.Reader, v.key, digest[:])
		if e != nil {
			t.Fatal(e)
		}
		r["signature"] = b64(signature)
	})
}

func TestWebAuthnBackupFlagsAndCounterPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		flags    byte
		counts   []uint32
		accepted []bool
	}{
		{"zero-device", 5, []uint32{0, 0, 1, 1, 0}, []bool{true, true, true, false, false}},
		{"synced", 13, []uint32{0, 4, 2, 4, 5}, []bool{true, true, true, true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			w, e := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
			if e != nil {
				t.Fatal(e)
			}
			c, e := w.BeginRegistration(t.Context(), session, true)
			if e != nil {
				t.Fatal(e)
			}
			key := newVirtualKey(t)
			if e = w.FinishRegistration(t.Context(), session, c.ID, key.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", tc.flags)); e != nil {
				t.Fatal(e)
			}
			var max uint32
			for i, count := range tc.counts {
				a, e := w.BeginAssertion(t.Context(), session)
				if e != nil {
					t.Fatal(e)
				}
				flags := tc.flags
				if tc.name == "synced" && i%2 == 1 {
					flags |= 16
				}
				_, e = w.FinishAssertion(t.Context(), session, a.ID, key.assert(t, a.Options.Response.Challenge.String(), "https://example.invalid", flags, count), "192.0.2.40")
				if (e == nil) != tc.accepted[i] {
					t.Fatalf("counter step %d accepted=%t expected=%t", i, e == nil, tc.accepted[i])
				}
				if tc.accepted[i] && count > max {
					max = count
				}
				var saved, bs int64
				if e := db.QueryRow(`SELECT sign_count,backup_state FROM authenticators WHERE id=?`, c.ID).Scan(&saved, &bs); e != nil || saved != int64(max) {
					t.Fatal("counter maximum lost", e)
				}
				if tc.accepted[i] && bs != int64((flags>>4)&1) {
					t.Fatal("backup state not persisted")
				}
			}
			w.lifecycle = reopenLifecycle(t, l, db)
			if _, e := w.BeginAssertion(t.Context(), session); e != nil {
				t.Fatal("restart lost association/flags", e)
			}
		})
	}
}

func TestWebAuthnPackedAttestationSignature(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid-self", false: "bad-self-signature"}[valid], func(t *testing.T) {
			l, _, session := lifecycleFixture(t)
			w, e := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
			if e != nil {
				t.Fatal(e)
			}
			c, e := w.BeginRegistration(t.Context(), session, false)
			if e != nil {
				t.Fatal(e)
			}
			key := newVirtualKey(t)
			response := alterResponse(t, key.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5), func(m map[string]any) {
				r := m["response"].(map[string]any)
				raw, e := base64.RawURLEncoding.DecodeString(r["attestationObject"].(string))
				if e != nil {
					t.Fatal(e)
				}
				var att map[string]any
				if e := cbor.Unmarshal(raw, &att); e != nil {
					t.Fatal(e)
				}
				client, e := base64.RawURLEncoding.DecodeString(r["clientDataJSON"].(string))
				if e != nil {
					t.Fatal(e)
				}
				h := sha256.Sum256(client)
				digest := sha256.Sum256(append(att["authData"].([]byte), h[:]...))
				if !valid {
					digest[0] ^= 1
				}
				sig, e := ecdsa.SignASN1(rand.Reader, key.key, digest[:])
				if e != nil {
					t.Fatal(e)
				}
				att["fmt"] = "packed"
				att["attStmt"] = map[string]any{"alg": -7, "sig": sig}
				raw, e = cbor.Marshal(att)
				if e != nil {
					t.Fatal(e)
				}
				r["attestationObject"] = b64(raw)
			})
			e = w.FinishRegistration(t.Context(), session, c.ID, response)
			if (e == nil) != valid {
				t.Fatal("packed signature policy mismatch", e)
			}
		})
	}
}
