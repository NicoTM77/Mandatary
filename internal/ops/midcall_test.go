package ops_test

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// settle yields the scheduler so any goroutine a regression would have started in
// reaction to a cancellation (context.AfterFunc) has run. It only strengthens
// detection of a regression: nothing passes because it is long enough, and the
// positive controls in this file pin the cancellation paths that MUST still work.
func settle() {
	for i := 0; i < 500; i++ {
		runtime.Gosched()
	}
}

// midCallRequest is a well-formed request for op; logs opens a follow stream.
func midCallRequest(op docker.Operation) ops.Request {
	if op == docker.OpLogs {
		return followReq(botCreds())
	}
	return req(botCreds(), "edge-proxy", op)
}

type outcome struct {
	res ops.Result
	err error
}

// P113-CANCEL-06 (reviewer RP-04 regression, F3): once admitted, a caller that
// leaves while the backend's operational call (or the Logs open call) is in flight
// must NOT cancel that call's context: the SDK adapter reads a canceled operational
// context as a fault and would invalidate the endpoint's global safety proof. For
// every one of the six keys: the backend context stays live, the call finishes, its
// result is withheld and the caller's own context error is returned, no lease leaks
// and the same principal's sibling stream is untouched. The control without a
// departing caller completes normally.
func TestCallerLeavingMidBackendCallNeverCancelsTheBackendContext(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, leaves := range []bool{false, true} {
			name := string(op) + "/control"
			if leaves {
				name = string(op) + "/caller-leaves"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				sibling, _ := openFollow(t, e, botCreds())
				before := len(e.spy.operationalCalls())

				var opened *probeStream
				e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { opened = newProbe(inner); return opened }
				entered := make(chan context.Context, 1)
				release := make(chan struct{})
				e.spy.beforeOperation = func(_ string, ctx context.Context) {
					entered <- ctx
					<-release
				}
				reqCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan outcome, 1)
				go func() {
					res, err := e.svc.Execute(reqCtx, midCallRequest(op))
					done <- outcome{res, err}
				}()
				backendCtx := <-entered
				if leaves {
					cancel()
					settle()
				}
				if err := backendCtx.Err(); err != nil {
					t.Fatalf("caller leaving mid-call canceled the backend operational context (%v)", err)
				}
				if n := e.az.ActiveLeaseCount(); n != 2 {
					t.Fatalf("active leases mid-call = %d, want the sibling's and the in-flight call's", n)
				}
				close(release)
				o := <-done
				if o.res.Logs != nil {
					defer func() { _ = o.res.Logs.Close() }()
				}
				if got := len(e.spy.operationalCalls()) - before; got != 1 {
					t.Fatalf("operational attempts = %d, want exactly the one in flight", got)
				}
				if !e.mock.Ready() || e.mock.VerificationState() != docker.StateVerified {
					t.Fatalf("backend safety proof lost (state=%v)", e.mock.VerificationState())
				}
				select {
				case <-sibling.Done():
					t.Fatal("a departing caller canceled the principal's sibling stream")
				default:
				}

				if !leaves {
					if o.err != nil || !isAllowedOutcome(o.res, op) {
						t.Fatalf("control Execute = %v (%+v)", o.err, o.res)
					}
					return
				}
				if !errors.Is(o.err, context.Canceled) || isDenial(o.err) {
					t.Fatalf("Execute = %v, want the caller's own context.Canceled", o.err)
				}
				if o.res.Logs != nil || o.res.Status != nil || o.res.Config != nil {
					t.Fatal("a departed caller's result was not withheld")
				}
				if op == docker.OpLogs {
					if opened == nil {
						t.Fatal("the Logs open call never produced a stream")
					}
					waitDone(t, opened.closed, "withheld backend stream closed")
				}
				if n := e.az.ActiveLeaseCount(); n != 1 {
					t.Fatalf("active leases after = %d, want only the sibling's", n)
				}
				e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "sibling alive\n"})
				if f, nerr := sibling.Next(t.Context()); nerr != nil || string(f.Payload) != "sibling alive\n" {
					t.Fatalf("sibling Next = %q, %v", f.Payload, nerr)
				}
			})
		}
	}
}

// P113-CANCEL-07 (adverse control): the caller leaving does not shield a call from
// a REAL revocation: authority ending mid-call still cancels the backend context,
// whether or not the caller also left, and the result is withheld.
func TestRevocationStillCancelsAMidCallBackendContextWhenCallerAlsoLeft(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, alsoLeaves := range []bool{false, true} {
			name := string(op)
			if alsoLeaves {
				name += "/caller-also-left"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				entered := make(chan context.Context, 1)
				release := make(chan struct{})
				e.spy.beforeOperation = func(_ string, ctx context.Context) {
					entered <- ctx
					<-release
				}
				reqCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan outcome, 1)
				go func() {
					res, err := e.svc.Execute(reqCtx, midCallRequest(op))
					done <- outcome{res, err}
				}()
				backendCtx := <-entered
				if alsoLeaves {
					cancel()
				}
				revokeCredential(e)
				if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
					t.Fatal(err)
				}
				waitDone(t, backendCtx.Done(), "revocation cancels the in-flight backend context")
				close(release)
				o := <-done
				if o.res.Logs != nil {
					defer func() { _ = o.res.Logs.Close() }()
					t.Fatal("a stream was handed out after its authorization was revoked")
				}
				if o.res.Status != nil || o.res.Config != nil {
					t.Fatal("data was returned after its authorization was revoked")
				}
				if n := e.az.ActiveLeaseCount(); n != 0 {
					t.Fatalf("leaked %d leases", n)
				}
			})
		}
	}
}
