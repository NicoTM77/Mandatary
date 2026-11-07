package auth

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnEvaluatedProofStatementFailureStopsAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name, trigger string
		valid         bool
	}{
		{"consume_bad", `BEFORE UPDATE OF consumed_at ON auth_challenges`, false},
		{"charge_bad", `BEFORE UPDATE OF failed_attempts ON authenticators`, false},
		{"consume_good", `BEFORE UPDATE OF consumed_at ON auth_challenges`, true},
		{"envelope_good", `BEFORE UPDATE OF envelope ON webauthn_credentials`, true},
		{"advance_good", `BEFORE UPDATE OF sign_count ON authenticators`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, db, session, key, id := webFixture(t)
			execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id=?`, id)
			c, e := w.BeginAssertion(t.Context(), session)
			if e != nil {
				t.Fatal(e)
			}
			signer := key
			if !tc.valid {
				signer = newVirtualKey(t)
				signer.id = key.id
			}
			response := signer.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
			calls := 0
			original := w.verifyLogin
			w.verifyLogin = func(u wa.User, s wa.SessionData, p *protocol.ParsedCredentialAssertionData) (*wa.Credential, error) {
				calls++
				return original(u, s, p)
			}
			execFixture(t, db, `CREATE TRIGGER proof_statement_fault `+tc.trigger+` BEGIN SELECT RAISE(ABORT,'synthetic proof statement failure'); END`)
			for i := 0; i < 3; i++ {
				proof, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.230")
				if e != ErrDenied || proof.UserID != "" {
					t.Fatal("uncertain proof acknowledged", e)
				}
			}
			var failed int
			var consumed any
			if e = db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id=?`, id).Scan(&failed); e != nil {
				t.Fatal(e)
			}
			if e = db.QueryRow(`SELECT consumed_at FROM auth_challenges WHERE id=?`, c.ID).Scan(&consumed); e != nil {
				t.Fatal(e)
			}
			t.Logf("real_verifier_calls=%d failed_attempts=%d consumed=%v fail_closed=%v", calls, failed, consumed, w.lifecycle.repo.FailedClosed())
			if calls != 1 || !w.lifecycle.repo.FailedClosed() || failed != 99 || consumed != nil {
				t.Fatal("rolled-back evaluated proof permitted further verification")
			}
		})
	}
}
