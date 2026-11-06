package auth

import "testing"

// Keep the real Argon verification and shared-lock admission timeout: an
// authorized report that cannot persist must terminate the in-flight proof too.
func TestProtectiveFailureDuringPasswordProofDeniesInFlight(t *testing.T) {
	for _, matched := range []bool{true, false} {
		t.Run(map[bool]string{true: "correct", false: "incorrect"}[matched], func(t *testing.T) {
			s, _, db := serviceFixture(t)
			execFixture(t, db, `UPDATE authenticators SET failed_attempts=2 WHERE id='pwd'`)
			s.verify = func(p, v []byte, profile string) bool {
				matched := VerifyPassword(p, v, profile)
				done := make(chan error, 1)
				go func() { done <- s.MarkCompromised(t.Context(), "u") }()
				if err := <-done; err != ErrDenied {
					t.Errorf("expected protective report admission failure: %v", err)
				}
				return matched
			}
			raw := []byte("a unique synthetic public phrase")
			if !matched {
				raw = []byte("incorrect synthetic public phrase")
			}
			proof, err := s.Prove(t.Context(), "synthetic-user", raw, "192.0.2.1")
			if scalarFixture(t, db, `SELECT compromised FROM users WHERE id='u'`) != 0 {
				t.Fatal("precondition: timed-out report persisted")
			}
			if err != ErrDenied || proof != (Proof{}) {
				t.Fatal("in-flight proof acknowledged after protective failure")
			}
			if !matched && scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 3 {
				t.Fatal("terminal poison erased an actual failed-proof charge")
			}
			if matched && scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 2 {
				t.Fatal("unacknowledged proof reset prior failures")
			}
		})
	}
}
