package ops_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// P113-OPEN-01 (reviewer RP-06 regression, F4): the Logs open call is bounded by the
// dispatch deadline exactly like a one-shot call. With the caller gone (or not) and
// a hung daemon, the deadline firing ends the open deterministically (no sleeps, no
// wall-clock): Execute returns the context error, no stream is handed out, no lease
// leaks and the backend safety proof is untouched. The inspect control proves the
// same bound for a one-shot call.
func TestHungOpenIsBoundedByTheDispatchDeadline(t *testing.T) {
	for _, op := range []docker.Operation{docker.OpInspectStatus, docker.OpLogs} {
		for _, callerLeaves := range []bool{false, true} {
			name := string(op) + "/caller-present"
			if callerLeaves {
				name = string(op) + "/caller-gone"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t, recordDeadlines())
				entered := make(chan context.Context, 1)
				e.spy.beforeOperation = func(_ string, ctx context.Context) {
					entered <- ctx
					<-ctx.Done() // a hung daemon: returns only when its context ends
				}
				reqCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan outcome, 1)
				go func() {
					res, err := e.svc.Execute(reqCtx, midCallRequest(op))
					done <- outcome{res, err}
				}()
				backendCtx := <-entered
				if callerLeaves {
					cancel()
					settle()
				}
				if err := backendCtx.Err(); err != nil {
					t.Fatalf("the backend context ended before any deadline fired (%v)", err)
				}
				dl := e.deadlines()
				if len(dl) != 1 || dl[0] != ops.DefaultOperationTimeout {
					t.Fatalf("dispatch deadlines = %v, want exactly [%v]", dl, ops.DefaultOperationTimeout)
				}
				e.fireDeadline(0)
				o := <-done
				if o.res.Logs != nil {
					_ = o.res.Logs.Close()
				}
				if !errors.Is(o.err, context.Canceled) || isDenial(o.err) {
					t.Fatalf("Execute = %v, want the context error of the fired deadline (not a denial)", o.err)
				}
				if o.res.Logs != nil || o.res.Status != nil || o.res.Config != nil {
					t.Fatal("a result was returned for a call whose deadline fired")
				}
				if backendCtx.Err() == nil {
					t.Fatal("the deadline did not end the hung backend call")
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
}

// P113-OPEN-02: a stream that finishes opening only AFTER its deadline fired (a
// transport that ignores its context) is closed and never handed out.
func TestStreamOpenedAfterItsDeadlineIsClosedNotHandedOut(t *testing.T) {
	e := newEnv(t, recordDeadlines())
	e.spy.ignoreCtx = true // the daemon completes the open although its context ended
	var opened *probeStream
	e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { opened = newProbe(inner); return opened }
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	e.spy.beforeOperation = func(_ string, ctx context.Context) {
		entered <- ctx
		<-release // ignores its context
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := e.svc.Execute(t.Context(), followReq(botCreds()))
		done <- outcome{res, err}
	}()
	backendCtx := <-entered
	e.fireDeadline(0)
	<-backendCtx.Done() // the deadline released the lease the open runs under
	close(release)
	o := <-done
	if o.res.Logs != nil {
		_ = o.res.Logs.Close()
		t.Fatal("a stream that opened after its deadline was handed out")
	}
	if !errors.Is(o.err, context.Canceled) || isDenial(o.err) {
		t.Fatalf("Execute = %v, want the deadline's context error", o.err)
	}
	if opened == nil {
		t.Fatal("the Logs open call never produced a stream")
	}
	waitDone(t, opened.closed, "late backend stream closed")
	if n := e.az.ActiveLeaseCount(); n != 0 {
		t.Fatalf("active leases = %d, want 0", n)
	}
}

// P113-OPEN-03 (control): the deadline bounds only the OPEN. A handed-off stream
// survives the deadline context being fired afterwards and keeps delivering frames.
func TestHandedOffStreamSurvivesTheOpenDeadline(t *testing.T) {
	e := newEnv(t, recordDeadlines())
	stream, _ := openFollow(t, e, botCreds())
	if dl := e.deadlines(); len(dl) != 1 || dl[0] != ops.DefaultOperationTimeout {
		t.Fatalf("dispatch deadlines = %v, want exactly [%v]", dl, ops.DefaultOperationTimeout)
	}
	e.fireDeadline(0)
	settle()
	select {
	case <-stream.Done():
		t.Fatal("the open deadline ended a handed-off stream")
	default:
	}
	if n := e.az.ActiveLeaseCount(); n != 1 {
		t.Fatalf("active leases = %d, want the stream's", n)
	}
	e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "after deadline\n"})
	if f, err := stream.Next(t.Context()); err != nil || string(f.Payload) != "after deadline\n" {
		t.Fatalf("Next = %q, %v", f.Payload, err)
	}
}
