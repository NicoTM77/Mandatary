package docker

import (
	"context"
	"errors"
	"time"
)

// Bounded continuity freshness (P1.20, R2).
//
// Every read admission used to repeat the same continuity check (daemon /info ID, inspect of the own container,
// the all-state inventory) three times per call, and every live stream repeated it before and after each delivery
// and once a second, so a handful of clients put dozens of identical reads in flight on one daemon, and one
// failed read dropped the endpoint-wide proof for everybody. One successful check may now cover other callers for
// a short, fixed time. Nothing else is cached: no authorization decision, policy, credential, session, lease, name
// mapping or target inspect. The design and its rationale are in docs/docker-backend.md ("Bounded continuity
// freshness").
//
//   - The snapshot is bound to the safety epoch and lives under SafetyMonitor.mu, the lock that also revokes the
//     proof, so publication and invalidation cannot interleave: any drop clears it, and a refresh that started in
//     an older epoch can never publish.
//   - Its age runs on the monotonic clock from the START of the refresh (before the first read), so a slow refresh
//     counts against it. It covers a caller while 0 <= age < TTL; at exactly TTL it is expired. An expired or
//     failed check is never used as a fallback.
//   - At most one refresh runs at a time, performed by the caller that found none, on that caller's own context
//     and with that caller's own error classification. The refresh is therefore byte-for-byte the check a single
//     caller makes today. Other callers wait for it and are served only by a refresh that started after they
//     arrived, or that is still fresh when it ends; otherwise one of them leads the next. Nobody waits for more
//     than two refreshes, and the daemon sees one check per refresh, however many callers are waiting.
//   - A waiter reads nothing, so its own cancellation or deadline is local. Only a deadline this process set
//     itself (ErrSafetyCheckDeadline: the stream watchdog, the readiness heartbeat) revokes, as the watchdog
//     always has. A leader keeps today's rule: an independent fault revokes before it returns, even when its own
//     cancellation coincides; a pure stream-consumer abort is local and the next caller leads a new refresh.
//   - There is no background refresh and no event or timer that can extend freshness. The only way to a fresh
//     snapshot is a completed, successful check of the current epoch.
//
// ContinuityTTL 0 (the default) bypasses all of this: each caller makes its own check, as before.

// MaxContinuityTTL is the longest continuity freshness SDKOptions.ContinuityTTL accepts.
const MaxContinuityTTL = time.Second

// continuityRefreshCeiling bounds one refresh, so a hung daemon cannot hold the single flight indefinitely. It is
// the verification timeout the product already applies to a whole VerifySelf. A variable only so a test can lower it.
var continuityRefreshCeiling = 15 * time.Second

// sdkOptionsTestHook lets a test of this package adjust the options of every adapter it builds (the twin run in
// continuity_twin_test.go). Nothing outside a _test file ever sets it.
var sdkOptionsTestHook func(*SDKOptions)

type contMode int

const (
	// modeRead may be covered by a check that is still fresh.
	modeRead contMode = iota
	// modeFresh (start, stop, restart) needs a check that started after the call began.
	modeFresh
)

type contKind int

const (
	kindAdmission contKind = iota
	kindStream
)

type contOutcome int

const (
	// The zero value means the refresh has not ended; a waiter reads the outcome only after done is closed.
	// outcomeOK: the check succeeded and the proof of its epoch still held.
	outcomeOK contOutcome = iota + 1
	// outcomeLocalAbort: the leader's own pure stream-consumer abort; the proof was not touched.
	outcomeLocalAbort
	// outcomeFault: the proof was revoked (by this check or concurrently).
	outcomeFault
)

// contFlight is the refresh in progress. outcome is written once, before done is closed.
type contFlight struct {
	seq     uint64
	start   time.Time
	epoch   uint64
	done    chan struct{}
	outcome contOutcome
}

func (m *SafetyMonitor) configureContinuity(ttl time.Duration, clock func() time.Time) {
	if clock == nil {
		clock = time.Now // never strip the monotonic reading
	}
	m.mu.Lock()
	m.ttl, m.clock = ttl, clock
	m.mu.Unlock()
}

// continuityWaiters is the number of callers waiting for a refresh someone else leads (diagnostics and tests).
func (m *SafetyMonitor) continuityWaiters() int64 { return m.contWaiters.Load() }

// continuitySnapshot reports whether a current-epoch check is held and when it started.
func (m *SafetyMonitor) continuitySnapshot() (bool, time.Time, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.contValid && m.contEpoch == m.epoch, m.contStart, m.contEpoch
}

// coveredLocked reports whether the snapshot may answer a caller that arrived when the last refresh had rank
// arrivalSeq: a check that started after the caller arrived always may; an older one only for a read, and only
// while it is younger than the TTL (a negative age, a clock that went backwards, never counts).
func (m *SafetyMonitor) coveredLocked(now time.Time, arrivalSeq uint64, mode contMode) bool {
	if !m.contValid || m.contEpoch != m.epoch || m.state != StateVerified || m.closed {
		return false
	}
	if m.contSeq > arrivalSeq {
		return true
	}
	if mode != modeRead {
		return false
	}
	age := now.Sub(m.contStart)
	return age >= 0 && age < m.ttl
}

// publishContinuityLocked makes a successful refresh the snapshot, if it belongs to the current epoch and does not
// move the snapshot backwards.
func (m *SafetyMonitor) publishContinuityLocked(fl *contFlight) {
	if m.closed || m.state != StateVerified || fl.epoch != m.epoch {
		return
	}
	if m.contValid && m.contEpoch == fl.epoch && (fl.seq <= m.contSeq || fl.start.Before(m.contStart)) {
		return
	}
	m.contValid, m.contStart, m.contEpoch, m.contSeq = true, fl.start, fl.epoch, fl.seq
}

// ensureContinuity returns nil once a successful continuity check covers the caller; every other outcome is
// the caller's refusal. See the package comment above for the rules.
func (a *SDKAdapter) ensureContinuity(ctx context.Context, mode contMode, kind contKind) error {
	m := a.safety
	if m.ttl == 0 {
		return a.refreshContinuity(ctx, kind)
	}
	var arrivalSeq uint64
	arrived := false
	for {
		m.mu.Lock()
		if m.closed || m.state != StateVerified || m.selfID == "" {
			m.mu.Unlock()
			return ErrUnverified
		}
		if !arrived {
			arrivalSeq, arrived = m.flightSeq, true
		}
		now := m.clock()
		if m.coveredLocked(now, arrivalSeq, mode) {
			m.mu.Unlock()
			return nil
		}
		if fl := m.flight; fl != nil && fl.epoch == m.epoch {
			m.mu.Unlock()
			if err := a.awaitRefresh(ctx, fl); err != nil {
				return err
			}
			continue
		}
		m.flightSeq++
		fl := &contFlight{seq: m.flightSeq, start: now, epoch: m.epoch, done: make(chan struct{})}
		m.flight = fl
		m.mu.Unlock()
		return a.leadRefresh(ctx, kind, fl)
	}
}

// awaitRefresh waits for the refresh someone else leads. It returns nil when the caller must look again, and
// ErrUnverified when the proof is gone.
func (a *SDKAdapter) awaitRefresh(ctx context.Context, fl *contFlight) error {
	m := a.safety
	m.contWaiters.Add(1)
	defer m.contWaiters.Add(-1)
	select {
	case <-fl.done:
		if fl.outcome == outcomeFault {
			return ErrUnverified
		}
		return nil
	case <-ctx.Done():
		// A waiter observed no daemon evidence. Its own cancellation or deadline is local; a deadline this
		// process set on the check itself is not, exactly as for the check's own I/O.
		if errors.Is(context.Cause(ctx), ErrSafetyCheckDeadline) {
			m.drop(Drop{Reason: DropCheckDeadline, Step: StepContinuity, Cause: CauseDeadline})
			return ErrUnverified
		}
		return SanitizeError(ctx.Err())
	}
}

// leadRefresh performs the check on the leader's own context and classification, then publishes its result under
// the lock that also revokes the proof.
func (a *SDKAdapter) leadRefresh(ctx context.Context, kind contKind, fl *contFlight) error {
	m := a.safety
	lctx, cancel := context.WithTimeoutCause(ctx, continuityRefreshCeiling, ErrSafetyCheckDeadline)
	err := a.refreshContinuity(lctx, kind)
	cancel()

	m.mu.Lock()
	if m.flight == fl {
		m.flight = nil
	}
	still := !m.closed && m.state == StateVerified && m.epoch == fl.epoch
	switch {
	case err == nil && still:
		m.publishContinuityLocked(fl)
		fl.outcome = outcomeOK
	case err != nil && still:
		fl.outcome = outcomeLocalAbort
	default:
		fl.outcome = outcomeFault
	}
	close(fl.done)
	m.mu.Unlock()

	if err == nil && !still {
		return ErrUnverified
	}
	return err
}

// refreshContinuity is the continuity check itself, with the classification of the caller's kind.
func (a *SDKAdapter) refreshContinuity(ctx context.Context, kind contKind) error {
	if kind == kindStream {
		return a.verifyStreamContinuity(ctx)
	}
	return a.verifySelfContinuity(ctx)
}
