package auth

import (
	"testing"
	"time"
)

// A verification takes the verifier period at the moment it verifies, not the period in which the
// client computed its output. A code of the previous 30 s step that is verified in period P spends P:
// no further acceptance is possible in P (even for the code of P's own step) and the next one is
// possible in P+1. The P1.20 release harness relies on this rule when it decides how long to wait
// before signing in again (tests/release/stackdeploy.py Admin.login, test_release.py AdminLoginPeriod).
func TestTOTPPreviousStepCodeSpendsTheVerifierPeriod(t *testing.T) {
	l, _, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	verifier := time.Unix(2000000070, 0) // the first second of a verifier period
	l.now = func() time.Time { return verifier }
	// The client computed its code just before the boundary, in the previous step; the service verifies it in the new period.
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, verifier.Add(-time.Second)), "192.0.2.2"); err != nil {
		t.Fatal("a code of the previous step was refused inside the window", err)
	}
	// A second sign-in in the same verifier period is refused, whichever step its code is for.
	l.now = func() time.Time { return verifier.Add(5 * time.Second) }
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, l.now()), "192.0.2.3"); err != ErrDenied {
		t.Fatal("a second acceptance in the same verifier period", err)
	}
	// It is possible again in the next period.
	l.now = func() time.Time { return verifier.Add(31 * time.Second) }
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, l.now()), "192.0.2.4"); err != nil {
		t.Fatal("the next verifier period was refused", err)
	}
}
