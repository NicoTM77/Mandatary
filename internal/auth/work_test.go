package auth

import (
	"testing"
	"time"
)

func TestPasswordComparableVerifierWork(t *testing.T) {
	for _, state := range []string{"wrong", "unknown", "compromised", "inactive", "malformed", "wait"} {
		t.Run(state, func(t *testing.T) {
			s, _, db := serviceFixture(t)
			s.now = func() time.Time { return time.Unix(2000000000, 0) }
			name := "synthetic-user"
			switch state {
			case "unknown":
				name = "unknown-user"
			case "compromised":
				execFixture(t, db, `UPDATE users SET compromised=1 WHERE id='u'`)
			case "inactive":
				execFixture(t, db, `UPDATE users SET state='disabled' WHERE id='u'`)
			case "malformed":
				execFixture(t, db, `UPDATE authenticators SET password_format='unknown' WHERE id='pwd'`)
			case "wait":
				execFixture(t, db, `UPDATE authenticators SET failed_attempts=5,next_attempt_at=2000000001 WHERE id='pwd'`)
			}
			calls := 0
			s.verify = func(p, v []byte, profile string) bool {
				calls++
				if _, _, ok := parseVerifier(v, profile); !ok {
					t.Error("non-comparable verifier")
				}
				return VerifyPassword(p, v, profile)
			}
			if _, e := s.Prove(t.Context(), name, []byte("incorrect synthetic public proof"), "192.0.2.1"); e != ErrDenied {
				t.Fatal("unsafe error", e)
			}
			want := 1
			if state == "wait" {
				want = 0
			}
			if calls != want {
				t.Fatalf("verifier calls=%d want=%d", calls, want)
			}
		})
	}
}
func TestPasswordProofExpiryAfterKDFDenies(t *testing.T) {
	s, _, db := serviceFixture(t)
	now := time.Unix(2000000000, 0)
	s.now = func() time.Time { return now }
	execFixture(t, db, `UPDATE authenticators SET expires_at=2000000001,failed_attempts=2 WHERE id='pwd'`)
	s.verify = func(p, v []byte, profile string) bool {
		matched := VerifyPassword(p, v, profile)
		now = now.Add(time.Second)
		return matched
	}
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1"); e != ErrDenied {
		t.Fatal("expired in-flight proof accepted")
	}
	if scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 2 {
		t.Fatal("expired proof reset retry state")
	}
}
