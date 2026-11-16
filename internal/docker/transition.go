package docker

import (
	"context"
	"errors"
	"net"
	"time"
)

// Safety-proof transition diagnostics (P1.20, R2).
//
// Losing the endpoint-wide safety proof (VERIFIED -> UNVERIFIED) refuses every legitimate call until a
// fresh VerifySelf succeeds. An operator must be able to tell THAT it happened, WHY and for how long, so every
// such transition and its recovery is reported to an optional observer. The report is secret-free by
// construction: it carries only members of the closed vocabularies below, durations and counts. It never
// carries an error text, a path, a container or daemon ID, a label, a token or a request payload, and it
// changes no decision: the observer cannot veto, delay or alter a transition.

// DropReason is the closed set of reasons a proof is dropped.
type DropReason string

const (
	// DropDaemonUnreachable: a daemon read (ping, info, inventory, inspect) failed or ran out of time.
	DropDaemonUnreachable DropReason = "daemon_unreachable"
	// DropCheckDeadline: the stream watchdog's own continuity-check deadline fired.
	DropCheckDeadline DropReason = "check_deadline"
	// DropIdentity: the daemon or the own-container identity, the inventory or the labels no longer match.
	DropIdentity DropReason = "identity"
	// DropUnsupportedAPI: the daemon API is below the supported minimum.
	DropUnsupportedAPI DropReason = "unsupported_api"
	// DropOperationFault: a dispatched operational call failed with an uncertain (non-logical) error.
	DropOperationFault DropReason = "operation_fault"
	// DropStreamFault: the body of a log stream failed.
	DropStreamFault DropReason = "stream_fault"
	// DropReverify: a fresh verification started while a proof was held.
	DropReverify DropReason = "reverify"
	// DropExternal: dropped on purpose by the process (restore, endpoint reapproval, configuration change).
	DropExternal DropReason = "external"
	// DropClosed: the monitor was closed.
	DropClosed DropReason = "closed"
)

// DropStep is the closed set of steps that were running when the proof was dropped.
type DropStep string

const (
	StepPing          DropStep = "ping"
	StepInfo          DropStep = "info"
	StepInventory     DropStep = "inventory"
	StepInspectSelf   DropStep = "inspect_self"
	StepInspectTarget DropStep = "inspect_target"
	StepVerify        DropStep = "verify"
	StepContinuity    DropStep = "continuity"
	StepOperation     DropStep = "operation"
	StepStream        DropStep = "stream"
	StepNone          DropStep = "none"
)

// DropCause is the closed classification of the error that ended a step.
type DropCause string

const (
	CauseDeadline    DropCause = "deadline"
	CauseCanceled    DropCause = "canceled"
	CauseTransport   DropCause = "transport"
	CauseDaemonError DropCause = "daemon_error"
	CauseNone        DropCause = "none"
)

// Drop describes why a proof was dropped. Elapsed is how long the failing step ran (zero when unknown).
type Drop struct {
	Reason  DropReason
	Step    DropStep
	Cause   DropCause
	Elapsed time.Duration
}

// Transition is one observable change of the proof. Verified reports the NEW state. A drop carries its Drop,
// the number of daemon calls in flight and of active streams at that moment. A restoration carries how long
// the proof was missing.
type Transition struct {
	Verified bool
	Drop     Drop
	Inflight int64
	Streams  int
	Outage   time.Duration
}

// TransitionObserver receives every transition after the monitor's lock is released. It must not block.
type TransitionObserver func(Transition)

// classifyCause maps an error to its closed cause class without reading the error text.
func classifyCause(err error) DropCause {
	var netErr net.Error
	switch {
	case err == nil:
		return CauseNone
	case errors.Is(err, context.DeadlineExceeded):
		return CauseDeadline
	case errors.Is(err, context.Canceled):
		return CauseCanceled
	case errors.As(err, &netErr):
		return CauseTransport
	case errors.Is(err, ErrBackendFailed):
		return CauseTransport
	default:
		return CauseDaemonError
	}
}

// dropFor builds the Drop of a failed daemon read. A deadline set by our own stream watchdog is told apart
// from the caller's and from the daemon's.
func dropFor(ctx context.Context, step DropStep, started time.Time, err error) Drop {
	d := Drop{Reason: DropDaemonUnreachable, Step: step, Cause: classifyCause(err)}
	if !started.IsZero() {
		d.Elapsed = time.Since(started)
	}
	if ctx != nil && ctx.Err() != nil && context.Cause(ctx) == errStreamCheckDeadline {
		d.Reason, d.Cause = DropCheckDeadline, CauseDeadline
	}
	return d
}

// SetObserver installs the transition observer (nil removes it).
func (m *SafetyMonitor) SetObserver(o TransitionObserver) {
	m.mu.Lock()
	m.observer = o
	m.mu.Unlock()
}

// InflightCalls is the number of daemon calls currently running.
func (m *SafetyMonitor) InflightCalls() int64 { return m.inflight.Load() }

// trackCall counts one daemon call as in flight until the returned function runs.
func (m *SafetyMonitor) trackCall() func() {
	m.inflight.Add(1)
	return func() { m.inflight.Add(-1) }
}

// dropLocked revokes the proof (the single place that does) and returns the transition to report, or nil when
// there was no proof to lose. The caller must release the lock and then pass the result to notify.
func (m *SafetyMonitor) dropLocked(d Drop) *Transition {
	var tr *Transition
	if m.state == StateVerified {
		tr = &Transition{Drop: d, Inflight: m.inflight.Load(), Streams: len(m.activeStreams)}
		m.droppedAt = time.Now()
	}
	m.invalidateLocked()
	return tr
}

// drop revokes the proof and reports the transition.
func (m *SafetyMonitor) drop(d Drop) {
	m.mu.Lock()
	tr := m.dropLocked(d)
	m.mu.Unlock()
	m.notify(tr)
}

func (m *SafetyMonitor) dropIdentity() {
	m.drop(Drop{Reason: DropIdentity, Step: StepVerify, Cause: CauseNone})
}

// restoredLocked returns the restoration transition when a proof that was dropped is published again.
func (m *SafetyMonitor) restoredLocked() *Transition {
	if m.droppedAt.IsZero() {
		return nil
	}
	tr := &Transition{Verified: true, Outage: time.Since(m.droppedAt)}
	m.droppedAt = time.Time{}
	return tr
}

func (m *SafetyMonitor) notify(tr *Transition) {
	if tr == nil {
		return
	}
	m.mu.RLock()
	o := m.observer
	m.mu.RUnlock()
	if o != nil {
		// Diagnostics must never change a decision: a faulty observer cannot unwind the refusal that caused the report.
		defer func() { _ = recover() }()
		o(*tr)
	}
}
