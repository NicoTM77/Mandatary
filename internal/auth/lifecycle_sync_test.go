package auth

import (
	"testing"
	"time"
)

// Reuses the test-only real SQLite WAL xSync interposer, not a mock repository.
func TestLifecycleSQLiteSyncFailureNeverAcknowledges(t *testing.T) {
	for _, operation := range []string{"bind", "verify", "wrong-proof", "remove", "report", "issue", "recover", "rebind", "dispatch"} {
		t.Run(operation, func(t *testing.T) {
			probe := installAuthSyncProbe(t)
			l, db, session := lifecycleFixture(t)
			e, err := l.BeginTOTP(t.Context(), session, "SHA256")
			if err != nil {
				t.Fatal(err)
			}
			if operation != "bind" {
				if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
					t.Fatal(err)
				}
			}
			var code string
			var cap []byte
			if operation == "recover" || operation == "rebind" {
				batch, err := l.IssueRecoveryCodes(t.Context(), session)
				if err != nil {
					t.Fatal(err)
				}
				code = batch.ExportOnce()[0]
				if operation == "rebind" {
					r, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), code, "192.0.2.2")
					if err != nil {
						t.Fatal(err)
					}
					cap, _ = r.ExportOnce()
					e, err = l.BeginRecoveredTOTP(t.Context(), cap, "SHA256")
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if operation == "verify" || operation == "wrong-proof" {
				at := l.now().Add(30 * time.Second)
				l.now = func() time.Time { return at }
			}
			probe.mu.Lock()
			probe.fail = true
			probe.mu.Unlock()
			switch operation {
			case "bind":
				err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.3")
			case "verify":
				_, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, l.now()), "192.0.2.3")
			case "wrong-proof":
				_, err = l.VerifyTOTP(t.Context(), "u", e.ID, "abcdef", "192.0.2.3")
			case "remove":
				err = l.RevokeTOTP(t.Context(), session, e.ID)
			case "report":
				err = l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.3")
			case "issue":
				_, err = l.IssueRecoveryCodes(t.Context(), session)
			case "recover":
				_, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), code, "192.0.2.3")
			case "rebind":
				err = l.ConfirmRecoveredTOTP(t.Context(), cap, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.3")
			case "dispatch":
				_, err = l.DispatchNotices(t.Context(), 1)
			}
			probe.mu.Lock()
			failed := probe.failed
			probe.fail = false
			probe.mu.Unlock()
			if err != ErrDenied || failed == 0 || !l.repo.FailedClosed() {
				t.Fatal("actual failed SQLite sync was not fail-closed", operation, failed)
			}
			if _, err = l.BeginTOTP(t.Context(), session, "SHA256"); err != ErrDenied {
				t.Fatal("uncertain handle accepted later lifecycle operation")
			}
		})
	}
}
