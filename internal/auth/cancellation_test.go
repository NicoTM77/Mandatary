package auth

import (
	"context"
	"testing"
)

func TestCallerDisconnectCannotEraseFailureOrPoisonService(t *testing.T) {
	s, _, db := serviceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.verify = func(p, v []byte, profile string) bool {
		matched := VerifyPassword(p, v, profile)
		cancel()
		return matched
	}
	if _, e := s.Prove(ctx, "synthetic-user", []byte("wrong public synthetic proof"), "192.0.2.1"); e != ErrDenied {
		t.Fatal(e)
	}
	if scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 1 {
		t.Fatal("disconnect erased actual failed proof")
	}
	s.verify = VerifyPassword
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != nil {
		t.Fatal("untrusted disconnect poisoned service", e)
	}
}
