package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// P1.20 R2: every loss and restoration of the safety proof is reported with a closed reason, step and cause.
// These tests pin the diagnostics only; they assert nothing about when a proof SHOULD be dropped.

type transitionRecorder struct {
	mu  sync.Mutex
	got []Transition
}

func (r *transitionRecorder) observe(tr Transition) {
	r.mu.Lock()
	r.got = append(r.got, tr)
	r.mu.Unlock()
}

func (r *transitionRecorder) all() []Transition {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Transition(nil), r.got...)
}

func observedAdapter(t *testing.T) (*SDKAdapter, *fakeDaemonTransport, *transitionRecorder) {
	t.Helper()
	rec := &transitionRecorder{}
	cfg := reviewerProof()
	cfg.Observer = rec.observe
	a, tr := reviewerAdapter(t, cfg)
	tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Name: "ordinary"})
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rec.all(); len(got) != 0 {
		t.Fatalf("the first verification is not a loss of proof, yet %d transitions were reported: %+v", len(got), got)
	}
	return a, tr, rec
}

func onlyDrop(t *testing.T, rec *transitionRecorder) Transition {
	t.Helper()
	got := rec.all()
	if len(got) != 1 || got[0].Verified {
		t.Fatalf("want exactly one drop, got %+v", got)
	}
	return got[0]
}

func TestProofDropIsReportedWithReasonStepAndCause(t *testing.T) {
	target := func(a *SDKAdapter) TargetIdentity {
		return TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
	}
	cases := []struct {
		name    string
		arrange func(a *SDKAdapter, tr *fakeDaemonTransport)
		act     func(a *SDKAdapter) error
		reason  DropReason
		step    DropStep
		cause   DropCause
	}{
		{
			name:    "inventory read fails during a request's continuity check",
			arrange: func(_ *SDKAdapter, tr *fakeDaemonTransport) { tr.mu.Lock(); tr.failList = errSynthetic; tr.mu.Unlock() },
			act:     func(a *SDKAdapter) error { _, err := a.InspectStatus(context.Background(), target(a)); return err },
			reason:  DropDaemonUnreachable, step: StepInventory, cause: CauseTransport,
		},
		{
			name: "target inspect fails after continuity held",
			arrange: func(_ *SDKAdapter, tr *fakeDaemonTransport) {
				tr.mu.Lock()
				tr.failInspect = errSynthetic
				tr.mu.Unlock()
			},
			act: func(a *SDKAdapter) error { _, err := a.InspectStatus(context.Background(), target(a)); return err },
			// the self inspect of the continuity check is the first inspect to fail
			reason: DropDaemonUnreachable, step: StepInspectSelf, cause: CauseTransport,
		},
		{
			name: "daemon identity changes",
			arrange: func(_ *SDKAdapter, tr *fakeDaemonTransport) {
				tr.mu.Lock()
				tr.daemonID = "another-daemon"
				tr.mu.Unlock()
			},
			act:    func(a *SDKAdapter) error { _, err := a.InspectStatus(context.Background(), target(a)); return err },
			reason: DropIdentity, step: StepContinuity, cause: CauseNone,
		},
		{
			name:    "an operational call fails after dispatch",
			arrange: func(_ *SDKAdapter, tr *fakeDaemonTransport) { tr.mu.Lock(); tr.failOp = errSynthetic; tr.mu.Unlock() },
			act:     func(a *SDKAdapter) error { return a.Start(context.Background(), target(a)) },
			reason:  DropOperationFault, step: StepOperation, cause: CauseTransport,
		},
		{
			name:    "the process drops the proof on purpose",
			arrange: func(*SDKAdapter, *fakeDaemonTransport) {},
			act:     func(a *SDKAdapter) error { a.InvalidateSafety(); return nil },
			reason:  DropExternal, step: StepNone, cause: CauseNone,
		},
		{
			name:    "the adapter is closed",
			arrange: func(*SDKAdapter, *fakeDaemonTransport) {},
			act:     func(a *SDKAdapter) error { return a.Close() },
			reason:  DropClosed, step: StepNone, cause: CauseNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, tr, rec := observedAdapter(t)
			tc.arrange(a, tr)
			_ = tc.act(a)
			d := onlyDrop(t, rec).Drop
			if d.Reason != tc.reason || d.Step != tc.step || d.Cause != tc.cause {
				t.Fatalf("drop = %+v, want reason=%s step=%s cause=%s", d, tc.reason, tc.step, tc.cause)
			}
			if a.Ready() {
				t.Fatal("a reported drop must leave the proof dropped")
			}
		})
	}
}

// A deadline and a cancellation are different causes, and both are reported before any behavior question is asked.
func TestProofDropTellsDeadlineFromCancellation(t *testing.T) {
	slow := func(a *SDKAdapter, tr *fakeDaemonTransport) {
		tr.mu.Lock()
		tr.delay = func(req *http.Request) { <-req.Context().Done() }
		tr.mu.Unlock()
	}
	t.Run("deadline", func(t *testing.T) {
		a, tr, rec := observedAdapter(t)
		slow(a, tr)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		_, _ = a.InspectStatus(ctx, TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID})
		d := onlyDrop(t, rec).Drop
		if d.Reason != DropDaemonUnreachable || d.Cause != CauseDeadline || d.Step != StepInfo {
			t.Fatalf("drop = %+v", d)
		}
		if d.Elapsed < 20*time.Millisecond {
			t.Fatalf("elapsed %v does not reflect the failing step", d.Elapsed)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		a, tr, rec := observedAdapter(t)
		slow(a, tr)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		_, _ = a.InspectStatus(ctx, TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID})
		d := onlyDrop(t, rec).Drop
		if d.Reason != DropDaemonUnreachable || d.Cause != CauseCanceled {
			t.Fatalf("drop = %+v", d)
		}
	})
}

func TestProofRestorationReportsOutageAndOnlyAfterADrop(t *testing.T) {
	a, tr, rec := observedAdapter(t)
	tr.mu.Lock()
	tr.failList = errSynthetic
	tr.mu.Unlock()
	_, _ = a.ListContainers(context.Background())
	// further failures while already unverified are not new transitions
	_, _ = a.ListContainers(context.Background())
	_ = a.Start(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID})
	if got := rec.all(); len(got) != 1 {
		t.Fatalf("repeated refusals of an already dropped proof must not be reported again: %+v", got)
	}
	tr.mu.Lock()
	tr.failList = nil
	tr.mu.Unlock()
	time.Sleep(15 * time.Millisecond)
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := rec.all()
	if len(got) != 2 || !got[1].Verified || got[1].Outage < 10*time.Millisecond {
		t.Fatalf("want drop then restoration with the outage, got %+v", got)
	}
	// a fresh verification while a proof is held is itself a (deliberate) drop, then a restoration
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	got = rec.all()
	if len(got) != 4 || got[2].Verified || got[2].Drop.Reason != DropReverify || !got[3].Verified {
		t.Fatalf("want reverify drop then restoration, got %+v", got)
	}
}

func TestTransitionObserverCannotChangeADecision(t *testing.T) {
	rec := &transitionRecorder{}
	cfg := reviewerProof()
	cfg.Observer = func(tr Transition) {
		rec.observe(tr)
		panic("observer fault") // a faulty observer must not turn a refusal into anything else
	}
	a, tr := reviewerAdapter(t, cfg)
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	tr.failList = errSynthetic
	tr.mu.Unlock()
	if _, err := a.ListContainers(context.Background()); err == nil {
		t.Fatal("the refusal must survive a faulty observer")
	}
	if a.Ready() || len(rec.all()) != 1 {
		t.Fatal("the proof must be dropped (and reported once) even when the observer faults")
	}
}

func TestClassifyCauseNamesTheTransportFailureWithoutReadingItsText(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "unix", Err: &os.SyscallError{Syscall: "connect", Err: syscall.EAGAIN}}
	read := &net.OpError{Op: "read", Net: "unix", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}
	for _, tc := range []struct {
		name string
		err  error
		want DropCause
	}{
		{"nil", nil, CauseNone},
		{"deadline", fmt.Errorf("Get: %w", context.DeadlineExceeded), CauseDeadline},
		{"canceled", &url.Error{Op: "Get", Err: context.Canceled}, CauseCanceled},
		{"eof", &url.Error{Op: "Get", Err: io.EOF}, CauseEOF},
		{"unexpected eof", io.ErrUnexpectedEOF, CauseEOF},
		{"reset", &url.Error{Op: "Get", Err: read}, CauseConnReset},
		{"dial would block", &url.Error{Op: "Get", Err: dial}, CauseDial},
		{"dial refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, CauseDial},
		{"net timeout", &url.Error{Op: "Get", Err: timeoutErr{}}, CauseNetTimeout},
		{"other transport", &url.Error{Op: "Get", Err: errors.New("anything")}, CauseTransport},
		{"daemon error", errors.New("Error response from daemon"), CauseDaemonError},
	} {
		if got := classifyCause(tc.err); got != tc.want {
			t.Errorf("%s: classifyCause = %q, want %q", tc.name, got, tc.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
