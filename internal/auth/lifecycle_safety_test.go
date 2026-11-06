package auth

import (
	"github.com/NicoTM77/Mandatary/internal/store"
	"testing"
	"time"
)

func provenTOTP(t *testing.T) (*Lifecycle, Enrollment, []byte) {
	t.Helper()
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	return l, e, session
}

func TestTOTPExhaustionDoesNotDisableRecovery(t *testing.T) {
	l, e, session := provenTOTP(t)
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	now := l.now()
	l.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		now = now.Add(65 * time.Second)
		if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, "abcdef", "192.0.2.2"); err != ErrDenied {
			t.Fatal("wrong OTP accepted")
		}
	}
	if err := l.repo.Read(t.Context(), func(q *store.Queries) error {
		factor, err := q.GetAuthenticator(t.Context(), e.ID)
		if err != nil {
			return err
		}
		if factor.State != "disabled" || !factor.ChangedAt.Valid || factor.ChangedAt.Int64 != now.Unix() {
			t.Fatal("retry disablement lifecycle date not recorded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, now), "192.0.2.3"); err != ErrDenied {
		t.Fatal("exhausted factor revived")
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.4"); err != nil {
		t.Fatal("unaffected recovery disabled", err)
	}
}

func TestFailedRecoveryBudgetWriteStopsFurtherAcceptance(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	if _, err = db.Exec(`CREATE TRIGGER reject_budget BEFORE UPDATE OF failures ON recovery_batches BEGIN SELECT RAISE(ABORT,'synthetic recovery write failure'); END`); err != nil {
		t.Fatal(err)
	}
	wrong := codes[0][:len(codes[0])-1] + "0"
	if wrong == codes[0] {
		wrong = codes[0][:len(codes[0])-1] + "1"
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), wrong, "192.0.2.2"); err != ErrDenied {
		t.Fatal("failed budget acknowledged")
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.3"); err != ErrDenied {
		t.Fatal("uncertain recovery budget allowed acceptance")
	}
}

func TestFailedTOTPRetryWriteStopsFurtherAcceptance(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`CREATE TRIGGER reject_retry BEFORE UPDATE OF failed_attempts ON authenticators BEGIN SELECT RAISE(ABORT,'synthetic retry write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.VerifyTOTP(t.Context(), "u", e.ID, "abcdef", "192.0.2.2"); err != ErrDenied {
		t.Fatal("failed retry write acknowledged")
	}
	now := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return now }
	if _, err := l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, now), "192.0.2.3"); err != ErrDenied {
		t.Fatal("uncertain retry control allowed later proof")
	}
}

func TestPasswordOnlyCompromiseReportCannotReplaceFactor(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE users SET mfa_requirement='required' WHERE id='u'`); err != nil {
		t.Fatal(err)
	}
	if err := l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.BeginTOTP(t.Context(), session, "SHA256"); err != ErrDenied {
		t.Fatal("report yielded replacement authority")
	}
	now := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return now }
	if _, err := l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, now), "192.0.2.3"); err != ErrDenied {
		t.Fatal("reported authenticator accepted")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM recovery_capabilities`).Scan(&count); err != nil || count != 0 {
		t.Fatal("report minted recovery capability")
	}
}

func TestProtectiveRevocationSurvivesOutboxFailure(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_notice BEFORE INSERT ON security_notice_outbox BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = l.RevokeTOTP(t.Context(), session, e.ID); err != ErrDenied {
		t.Fatal("failed outbox was acknowledged")
	}
	var state string
	if err = db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("protective revoke rolled back with outbox")
	}
	if !l.repo.FailedClosed() {
		t.Fatal("unrecorded protective notice did not degrade acceptance")
	}
}
