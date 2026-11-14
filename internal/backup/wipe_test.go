package backup

import (
	"bytes"
	"errors"
	"testing"
)

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Review L1 (P1.18 round 1): the re-sealed credential material that a restore prepares is cleared when the restore
// returns, as far as Go allows. Go cannot promise that a copy made by the runtime or a GC move is gone; the point is that
// nothing this package still holds keeps a secret alive after the call.
func TestSealedMaterialIsZeroedWhenItIsCleared(t *testing.T) {
	m := &sealedMaterial{totp: map[string][]byte{"a": bytes.Repeat([]byte{0xAB}, 48)}, webauthn: map[string][]byte{"b": bytes.Repeat([]byte{0xCD}, 64)}}
	totp, webauthn := m.totp["a"], m.webauthn["b"]
	m.clear()
	if !allZero(totp) || !allZero(webauthn) {
		t.Fatal("the sealed credential envelopes were not zeroed")
	}
}

// The plaintext a full archive carries (TOTP seeds, credential records, token hashes) is zeroed by Wipe, and a wiped archive
// can no longer be restored: a caller that is done with an archive cannot accidentally restore blanked credentials.
func TestWipeZeroesTheOpenedArchiveSecretsAndRefusesAnyFurtherRestore(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	raw := src.export(ModeFull)

	v, err := src.svc.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	var seeds [][]byte
	for _, a := range v.payload.Authenticators {
		if len(a.TOTPSeed) > 0 {
			seeds = append(seeds, a.TOTPSeed)
		}
	}
	if len(seeds) == 0 {
		t.Fatal("the fixture archive carries no TOTP seed: the test would prove nothing")
	}
	var tokenHashes [][]byte
	for _, h := range v.payload.AgentCredentials {
		tokenHashes = append(tokenHashes, h)
	}
	v.Wipe()
	for _, s := range seeds {
		if !allZero(s) {
			t.Fatal("a TOTP seed survived Wipe")
		}
	}
	for _, h := range tokenHashes {
		if !allZero(h) {
			t.Fatal("an agent token hash survived Wipe")
		}
	}
	dst := newEnv(t, keyHexA)
	before := dst.snapshot()
	if _, err = dst.svc.Restore(t.Context(), v, RestoreOptions{Initiator: InitiatorHost, Authorize: allow}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("restoring a wiped archive: %v", err)
	}
	dst.sameExceptControl(before)
	if c := dst.controls(); c.RestoreGeneration != 0 {
		t.Fatalf("a refused restore entered quarantine: %+v", c)
	}
	v.Wipe() // idempotent
}
