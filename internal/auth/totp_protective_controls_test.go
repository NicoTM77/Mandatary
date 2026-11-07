package auth

import (
	"testing"
	"time"
)

func TestInvalidTOTPReportsDoNotPoisonAcceptance(t *testing.T) {
	for _, invalid := range []string{"password", "owner", "missing", "kind", "revoked", "generation"} {
		t.Run(invalid, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e := queueBindingNotice(t, l, session)
			id := e.ID
			password := []byte("a unique synthetic public phrase")
			switch invalid {
			case "password":
				password = []byte("incorrect synthetic public phrase")
			case "owner":
				execFixture(t, db, `INSERT INTO users(id,username,state,credential_generation,authority_generation) VALUES('other','synthetic-other','active',1,1)`)
				execFixture(t, db, `UPDATE authenticators SET user_id='other' WHERE kind='totp'`)
			case "missing":
				id = "known-absent"
			case "kind":
				id = "pwd"
			case "revoked":
				execFixture(t, db, `UPDATE authenticators SET state='revoked',revoked_at=2000000010 WHERE kind='totp'`)
			case "generation":
				execFixture(t, db, `UPDATE authenticators SET credential_generation=2 WHERE kind='totp'`)
			}
			if err := l.ReportTOTPCompromise(t.Context(), "synthetic-user", password, id, "192.0.2.2"); err != ErrDenied {
				t.Fatal("invalid report accepted")
			}
			if l.repo.FailedClosed() {
				t.Fatal("invalid report poisoned unrelated acceptance")
			}
			if _, err := l.passwords.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.3"); err != nil {
				t.Fatal("invalid report disabled independent password", err)
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM protective_notice_intents`).Scan(&count); err != nil || count != 0 {
				t.Fatal("invalid report generated protective intent", err)
			}
		})
	}
}

func TestInvalidTOTPRemovalDoesNotPoisonAcceptance(t *testing.T) {
	for _, invalid := range []string{"weak", "expired", "missing", "last-required"} {
		t.Run(invalid, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e := queueBindingNotice(t, l, session)
			execFixture(t, db, `UPDATE sessions SET achieved_assurance=2,methods=3`)
			if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
				t.Fatal(err)
			}
			id := e.ID
			switch invalid {
			case "weak":
				session = []byte("unrecognized synthetic session with no authority")
			case "expired":
				at := l.now().Add(901 * time.Second)
				l.now = func() time.Time { return at }
			case "missing":
				id = "known-absent"
			case "last-required":
				execFixture(t, db, `UPDATE users SET mfa_requirement='required' WHERE id='u'`)
			}
			if err := l.RevokeTOTP(t.Context(), session, id); err != ErrDenied {
				t.Fatal("invalid removal accepted")
			}
			if l.repo.FailedClosed() {
				t.Fatal("invalid removal poisoned acceptance")
			}
		})
	}
}
