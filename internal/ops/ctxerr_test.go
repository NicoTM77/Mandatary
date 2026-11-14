package ops_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// firedDeadline is a dispatch bound whose expiry the test fires deterministically AND
// reports the way a real timer does: Err() is context.DeadlineExceeded (not Canceled).
type firedDeadline struct {
	context.Context
	fired atomic.Bool
}

func (c *firedDeadline) Err() error {
	if c.fired.Load() {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}

// P1.18.4 P113-L2: caller-vs-open-timeout outcomes of the shared service, pinned for
// the adapter mapping (internal/api Classify: context.Canceled -> canceled/499,
// context.DeadlineExceeded -> timeout/504, never forbidden/denied).
//
// Intentional service precedence, kept as is:
//   - Logs open: a fired dispatch deadline is a backend fault that the service evidences,
//     so it returns context.DeadlineExceeded EVEN IF the caller has also left;
//   - one-shot call: a vanished caller yields its OWN context error (context.Canceled),
//     while a caller that is still present gets context.DeadlineExceeded.
//
// In every row: exactly one accounted event (error, never denied, no double counting),
// no result, no lease leak, the backend safety proof untouched, and the error is the
// bare context sentinel (no cause text, no credential).
func TestCallerGoneAndDispatchDeadlineKeepDistinctCancelAndTimeoutOutcomes(t *testing.T) {
	cases := []struct {
		op         docker.Operation
		callerGone bool
		want       error
	}{
		{docker.OpLogs, false, context.DeadlineExceeded},
		{docker.OpLogs, true, context.DeadlineExceeded},
		{docker.OpInspectStatus, false, context.DeadlineExceeded},
		{docker.OpInspectStatus, true, context.Canceled},
		{docker.OpStop, false, context.DeadlineExceeded},
		{docker.OpStop, true, context.Canceled},
	}
	for _, tc := range cases {
		name := string(tc.op) + "/caller-present"
		if tc.callerGone {
			name = string(tc.op) + "/caller-gone"
		}
		t.Run(name, func(t *testing.T) {
			u := &usageSpy{}
			var (
				mu     sync.Mutex
				bound  *firedDeadline
				cancel context.CancelFunc
			)
			e := newEnv(t, withUsage(u), func(c *envConfig) {
				c.withTimeout = func(*env) func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
					return func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
						inner, cn := context.WithCancel(parent)
						b := &firedDeadline{Context: inner}
						mu.Lock()
						bound, cancel = b, cn
						mu.Unlock()
						return b, cn
					}
				}
			})
			entered := make(chan context.Context, 1)
			e.spy.beforeOperation = func(_ string, ctx context.Context) {
				entered <- ctx
				<-ctx.Done() // a hung daemon: returns only when its context ends
			}
			reqCtx, leave := context.WithCancel(t.Context())
			defer leave()
			done := make(chan outcome, 1)
			go func() {
				res, err := e.svc.Execute(reqCtx, midCallRequest(tc.op))
				done <- outcome{res, err}
			}()
			backendCtx := <-entered
			if tc.callerGone {
				leave()
				settle()
			}
			if err := backendCtx.Err(); err != nil {
				t.Fatalf("the backend context ended before the deadline fired (%v)", err)
			}
			mu.Lock()
			bound.fired.Store(true)
			cancel()
			mu.Unlock()
			o := <-done
			if o.res.Logs != nil {
				_ = o.res.Logs.Close()
			}
			if o.err != tc.want { // identity: the bare sentinel, never a wrapped cause
				t.Fatalf("Execute = %v, want exactly %v", o.err, tc.want)
			}
			if isDenial(o.err) || errors.Is(o.err, ops.ErrStreamRevoked) {
				t.Fatalf("a context outcome must never look like a denial: %v", o.err)
			}
			if o.res.Logs != nil || o.res.Status != nil || o.res.Config != nil {
				t.Fatal("a result was returned for a call whose deadline fired")
			}
			wantEvents(t, u, botEvt(tc.op, domain.UsageError))
			if n := e.svc.UsageFailures(); n != 0 {
				t.Fatalf("%d accounting failures", n)
			}
			if n := e.az.ActiveLeaseCount(); n != 0 {
				t.Fatalf("active leases = %d, want 0", n)
			}
			if !e.mock.Ready() || e.mock.VerificationState() != docker.StateVerified {
				t.Fatalf("backend safety proof lost (state=%v)", e.mock.VerificationState())
			}
		})
	}
}
