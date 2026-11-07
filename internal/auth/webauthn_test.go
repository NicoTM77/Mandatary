package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/NicoTM77/Mandatary/internal/store"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Test-only CTAP-shaped authenticator. Every assertion uses a real generated
// P-256 private key. This is RP protocol evidence, not hardware/biometric proof.
type virtualKey struct {
	key *ecdsa.PrivateKey
	id  []byte
}

func newVirtualKey(t *testing.T) virtualKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	id := make([]byte, 32)
	if _, e = rand.Read(id); e != nil {
		t.Fatal(e)
	}
	return virtualKey{k, id}
}
func (v virtualKey) create(t *testing.T, challenge string, origin string, flags byte) []byte {
	t.Helper()
	client := jsonBytes(t, map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	pub, e := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: v.key.X.FillBytes(make([]byte, 32)), -3: v.key.Y.FillBytes(make([]byte, 32))})
	if e != nil {
		t.Fatal(e)
	}
	rp := sha256.Sum256([]byte("example.invalid"))
	data := append([]byte{}, rp[:]...)
	data = append(data, flags|0x40, 0, 0, 0, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(v.id)))
	data = append(data, v.id...)
	data = append(data, pub...)
	att, e := cbor.Marshal(map[string]any{"fmt": "none", "authData": data, "attStmt": map[string]any{}})
	if e != nil {
		t.Fatal(e)
	}
	return jsonBytes(t, map[string]any{"id": b64(v.id), "rawId": b64(v.id), "type": "public-key", "response": map[string]any{"clientDataJSON": b64(client), "attestationObject": b64(att), "transports": []string{"usb"}}, "clientExtensionResults": map[string]any{}})
}

func (v virtualKey) assert(t *testing.T, challenge, origin string, flags byte, count uint32) []byte {
	t.Helper()
	client := jsonBytes(t, map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte("example.invalid"))
	data := append([]byte{}, rp[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, count)
	h := sha256.Sum256(client)
	signed := append(append([]byte{}, data...), h[:]...)
	digest := sha256.Sum256(signed)
	signature, e := ecdsa.SignASN1(rand.Reader, v.key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	return jsonBytes(t, map[string]any{"id": b64(v.id), "rawId": b64(v.id), "type": "public-key", "response": map[string]any{"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(signature)}, "clientExtensionResults": map[string]any{}})
}
func webFixture(t *testing.T) (*WebAuthnService, *sql.DB, []byte, virtualKey, string) {
	t.Helper()
	l, db, session := lifecycleFixture(t)
	w, e := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
	if e != nil {
		t.Fatal(e)
	}
	c, e := w.BeginRegistration(t.Context(), session, false)
	if e != nil {
		t.Fatal(e)
	}
	v := newVirtualKey(t)
	if e = w.FinishRegistration(t.Context(), session, c.ID, v.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
		t.Fatal(e)
	}
	return w, db, session, v, c.ID
}
func TestWebAuthnAssertionProvesUVAndRejectsReplay(t *testing.T) {
	w, _, session, v, authID := webFixture(t)
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	response := v.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
	proof, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.1")
	if e != nil || proof.UserID != "u" || proof.AuthenticatorID != authID {
		t.Fatal("signed UV assertion denied", e)
	}
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.2"); e != ErrDenied {
		t.Fatal("assertion replay accepted")
	}
	// A mere enrollment-time UV property cannot replace current signed UV.
	c, e = w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, v.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 1, 2), "192.0.2.3"); e != ErrDenied {
		t.Fatal("UV downgrade accepted")
	}
	var a store.Authenticator
	if e = w.lifecycle.repo.Read(t.Context(), func(q *store.Queries) error { var e error; a, e = q.GetAuthenticator(t.Context(), authID); return e }); e != nil || a.SignCount.Int64 != 1 {
		t.Fatal("rejected proof advanced counter")
	}
}

func TestWebAuthnBindingRequiresFreshSessionAndProof(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	w, e := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
	if e != nil {
		t.Fatal(e)
	}
	c, e := w.BeginRegistration(t.Context(), session, false)
	if e != nil {
		t.Fatal(e)
	}
	var count int
	if e = db.QueryRow(`SELECT count(*) FROM authenticators WHERE kind='webauthn' AND state='active'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("binding active before proof")
	}
	v := newVirtualKey(t)
	if e = w.FinishRegistration(t.Context(), session, c.ID, v.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
		t.Fatal("valid binding denied", e)
	}
	if e = w.FinishRegistration(t.Context(), session, c.ID, v.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != ErrDenied {
		t.Fatal("binding replay accepted")
	}
	if e = db.QueryRow(`SELECT count(*) FROM authenticators WHERE kind='webauthn' AND state='active'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("proven binding not committed")
	}
	if e = db.QueryRow(`SELECT count(*) FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id WHERE e.event_type='authenticator_bound' AND o.dispatch_state='ready'`).Scan(&count); e != nil || count != 2 {
		t.Fatal("binding fanout missing")
	}
	if _, e = w.BeginRegistration(t.Context(), session, false); e != ErrDenied {
		t.Fatal("weak session added second factor")
	}
}
