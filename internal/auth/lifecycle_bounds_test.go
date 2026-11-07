package auth

import (
	"github.com/NicoTM77/Mandatary/internal/store"
	"strings"
	"testing"
)

func TestOversizedTOTPProofRejectedBeforeEvaluation(t *testing.T) {
	for _, mode := range []string{"pending", "active"} {
		t.Run(mode, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e, err := l.BeginTOTP(t.Context(), session, "SHA256")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "active" {
				if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
					t.Fatal(err)
				}
				_, err = l.VerifyTOTP(t.Context(), "u", e.ID, strings.Repeat("a", 1024), "192.0.2.2")
			} else {
				err = l.ConfirmTOTP(t.Context(), session, e.ID, strings.Repeat("a", 1024), "192.0.2.2")
			}
			if err != ErrDenied {
				t.Fatal("oversized proof accepted")
			}
			var failures int
			if err = db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id=?`, e.ID).Scan(&failures); err != nil || failures != 0 {
				t.Fatal("oversized transport input evaluated/charged")
			}
		})
	}
}
func TestOversizedRecoveryRejectedBeforeEvaluation(t *testing.T) {
	l, _, session := provenTOTP(t)
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), strings.Repeat("a", 1024), "192.0.2.2"); err != ErrDenied {
		t.Fatal("oversized recovery proof accepted")
	}
	if err = l.repo.Read(t.Context(), func(q *store.Queries) error {
		b, err := q.GetActiveRecoveryBatch(t.Context(), "u")
		if err != nil {
			return err
		}
		if b.Failures != 0 {
			t.Fatal("oversized input charged to recovery factor")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recovery, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.3")
	if err != nil {
		t.Fatal(err)
	}
	cap, _ := recovery.ExportOnce()
	e, err := l.BeginRecoveredTOTP(t.Context(), cap, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmRecoveredTOTP(t.Context(), cap, e.ID, strings.Repeat("a", 1024), "192.0.2.4"); err != ErrDenied {
		t.Fatal("oversized replacement proof accepted")
	}
	if err = l.repo.Read(t.Context(), func(q *store.Queries) error {
		a, err := q.GetAuthenticator(t.Context(), e.ID)
		if err != nil {
			return err
		}
		if a.FailedAttempts != 0 {
			t.Fatal("oversized replacement input charged")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
