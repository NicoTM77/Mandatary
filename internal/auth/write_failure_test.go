package auth

import "testing"

func TestFailedProtectiveOrRetryWriteStopsAcceptance(t *testing.T) {
	for _, op := range []string{"compromise", "proof"} {
		t.Run(op, func(t *testing.T) {
			s, _, db := serviceFixture(t)
			table := "users"
			if op == "proof" {
				table = "authenticators"
			}
			execFixture(t, db, `CREATE TRIGGER fail_write BEFORE UPDATE ON `+table+` BEGIN SELECT RAISE(ABORT,'public synthetic failure'); END`)
			if op == "compromise" {
				if e := s.MarkCompromised(t.Context(), "u"); e != ErrDenied {
					t.Fatal(e)
				}
			} else {
				if _, e := s.Prove(t.Context(), "synthetic-user", []byte("wrong synthetic public proof"), "192.0.2.1"); e != ErrDenied {
					t.Fatal(e)
				}
			}
			execFixture(t, db, `DROP TRIGGER fail_write`)
			if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != ErrDenied {
				t.Fatal("failed security-control write did not stop subsequent acceptance")
			}
		})
	}
}
