package auth

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
	"golang.org/x/sys/unix"
)

func TestTOTPReportAdmissionFailureStopsAcceptance(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	enrollment := queueBindingNotice(t, l, session)
	var filename string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&filename); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(filename), "control.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	calls := 0
	waiting := make(chan struct{})
	held := make(chan error, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	l.passwords.now = func() time.Time {
		calls++
		if calls == 4 {
			go func() {
				close(waiting)
				err := unix.Flock(int(lock.Fd()), unix.LOCK_EX)
				held <- err
				<-release
				_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
				close(done)
			}()
			<-waiting
			// The proof owns the lock here. Queue the blocking OS waiter before its
			// unlock; unlike the service's nonblocking retry it receives that handoff.
			time.Sleep(100 * time.Millisecond)
		}
		return l.now()
	}
	err = l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), enrollment.ID, "192.0.2.2")
	close(release)
	if calls < 4 {
		t.Fatal("real password proof did not finish")
	}
	if lockErr := <-held; lockErr != nil {
		t.Fatal(lockErr)
	}
	<-done
	var state string
	if e := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, enrollment.ID).Scan(&state); e != nil {
		t.Fatal(e)
	}
	if state != "active" || err != ErrDenied {
		t.Fatal("did not intercept real revocation admission", state, err)
	}
	at := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return at }
	_, verifyErr := l.VerifyTOTP(t.Context(), "u", enrollment.ID, enrollmentCode(t, enrollment, at), "192.0.2.3")
	if verifyErr != ErrDenied || !l.repo.FailedClosed() {
		t.Fatal("failed protective report left affected acceptance available")
	}
}

func TestTOTPRemovalAdmissionFailureStopsAcceptance(t *testing.T) {
	l, e, session := provenTOTP(t)
	// Hold the actual shared lock in an already-running operation. Removal must
	// establish narrow session/target authority without requiring writer admission.
	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.repo.Control(t.Context(), func(_ *store.Queries) error { close(held); <-release; return nil }, nil)
	}()
	<-held
	err := l.RevokeTOTP(t.Context(), session, e.ID)
	close(release)
	inflight := <-done
	if err != ErrDenied || !l.repo.FailedClosed() || inflight != store.ErrStorage {
		t.Fatal("protective removal did not terminate affected and in-flight acceptance", err, inflight)
	}
}

func TestTOTPRemovalAdmissionFailureDeniesInFlightProof(t *testing.T) {
	l, enrollment, session := provenTOTP(t)
	at := l.now().Add(30 * time.Second)
	code := enrollmentCode(t, enrollment, at)
	held, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	l.now = func() time.Time {
		if calls.Add(1) == 2 { // VerifyTOTP's serialized state check, after admission.
			close(held)
			<-release
		}
		return at
	}
	type outcome struct {
		proof FactorProof
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		p, e := l.VerifyTOTP(t.Context(), "u", enrollment.ID, code, "192.0.2.3")
		done <- outcome{p, e}
	}()
	<-held
	err := l.RevokeTOTP(t.Context(), session, enrollment.ID)
	close(release)
	got := <-done
	if err != ErrDenied || got.err != ErrDenied || got.proof != (FactorProof{}) || !l.repo.FailedClosed() {
		t.Fatal("in-flight real proof acknowledged after removal admission failure", err, got.err)
	}
}
