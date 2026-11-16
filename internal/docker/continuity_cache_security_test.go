package docker

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// P1.20 R2, security side of the bounded continuity cache. A cancellation of one caller is local; an independent
// fault still revokes before that caller is answered; invalidation, identity change and every other safety
// transition beat any snapshot; a refresh never publishes into another epoch.

func (e *cacheEnv) openFollowStream() (LogStream, context.CancelFunc) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := e.a.Logs(ctx, e.target(), LogOptions{Stdout: true, Follow: true})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { cancel(); _ = s.Close() })
	return s, cancel
}

func (e *cacheEnv) requireRevoked(what string, peer context.Context) {
	e.t.Helper()
	if e.a.Ready() {
		e.t.Errorf("%s: the proof was not revoked", what)
	}
	if peer != nil && peer.Err() == nil {
		e.t.Errorf("%s: an unrelated active stream was not cancelled", what)
	}
	before := e.a.Counters().TotalOperational()
	if err := e.a.Start(context.Background(), e.target()); !errors.Is(err, ErrUnverified) || e.a.Counters().TotalOperational() != before {
		e.t.Errorf("%s: an operation was admitted (err=%v)", what, err)
	}
}

func (e *cacheEnv) requireHealthy(what string, peer context.Context) {
	e.t.Helper()
	if !e.a.Ready() {
		e.t.Errorf("%s: a local event revoked the proof", what)
	}
	if peer != nil && peer.Err() != nil {
		e.t.Errorf("%s: a local event cancelled an unrelated stream", what)
	}
	if got := e.rec.all(); len(got) != 0 {
		e.t.Errorf("%s: transitions reported: %+v", what, got)
	}
}

// 5. A refresh that is in flight when ANY invalidation happens publishes nothing; its waiters fail closed; only a
// fresh VerifySelf restores, and the next check is a real one.
func TestContinuityInvalidationDuringRefresh(t *testing.T) {
	invalidators := map[string]func(e *cacheEnv){
		"InvalidateSafety": func(e *cacheEnv) { e.a.InvalidateSafety() },
		"SetConfig":        func(e *cacheEnv) { e.a.safety.SetConfig(e.cfg) },
		"Close":            func(e *cacheEnv) { e.a.safety.Close() },
		"VerifySelf": func(e *cacheEnv) {
			if err := e.a.VerifySelf(context.Background()); err != nil {
				t.Error(err)
			}
		},
		"operation-fault": func(e *cacheEnv) { _ = e.a.safety.operationErrorAt(StepOperation, errSynthetic) },
		"stream-fault":    func(e *cacheEnv) { _ = e.a.safety.operationErrorAt(StepStream, errSynthetic) },
	}
	for _, stage := range []string{"info", "inspect-self", "list"} {
		for name, invalidate := range invalidators {
			t.Run(stage+"/"+name, func(t *testing.T) {
				e := newCacheEnv(t, ttl, nil)
				g := newGate(stage)
				e.m.setHook(g.hook)
				leader := startAsync(func() error { return e.resolve(context.Background()) })
				g.waitEntered(t)
				waiters := startResolvers(e, 2)
				e.waitWaiters(2)
				invalidate(e)
				g.open()
				for i, err := range append([]error{recvErr(t, leader)}, collect(t, waiters)...) {
					if !errors.Is(err, ErrUnverified) {
						t.Errorf("caller %d got %v, want ErrUnverified", i, err)
					}
				}
				if v, _, _ := e.a.safety.continuitySnapshot(); v {
					t.Fatal("a refresh interrupted by an invalidation published a snapshot")
				}
				if got := e.a.Counters().TotalOperational(); got != 0 {
					t.Fatalf("%d operational calls were dispatched", got)
				}
				if name != "VerifySelf" {
					if e.a.Ready() {
						t.Fatal("the proof survived the invalidation")
					}
					if name == "Close" {
						return
					}
					if err := e.resolve(context.Background()); !errors.Is(err, ErrUnverified) {
						t.Fatalf("an unverified endpoint admitted a call: %v", err)
					}
					if err := e.a.VerifySelf(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				e.m.take()
				e.mustResolve() // only a real check follows
				if got := e.m.take(); got["info"] != 1 || got["inspect-self"] != 1 {
					t.Fatalf("the next call did not perform a real check: %v", got)
				}
			})
		}
	}
}

// Defense in depth: besides the epoch binding, every revocation clears the snapshot itself, so no later change of
// the epoch rules could ever revive one.
func TestContinuityEveryRevocationClearsTheSnapshotItself(t *testing.T) {
	revokers := map[string]func(e *cacheEnv){
		"InvalidateSafety": func(e *cacheEnv) { e.a.InvalidateSafety() },
		"SetConfig":        func(e *cacheEnv) { e.a.safety.SetConfig(e.cfg) },
		"Close":            func(e *cacheEnv) { e.a.safety.Close() },
		"VerifySelf":       func(e *cacheEnv) { _ = e.a.VerifySelf(context.Background()) },
		"operation-fault":  func(e *cacheEnv) { _ = e.a.safety.operationErrorAt(StepOperation, errSynthetic) },
		"stream-fault":     func(e *cacheEnv) { _ = e.a.safety.operationErrorAt(StepStream, errSynthetic) },
		"mismatch": func(e *cacheEnv) {
			e.fake.mu.Lock()
			e.fake.daemonID = "another-daemon"
			e.fake.mu.Unlock()
			e.clock.advance(ttl)
			_ = e.resolve(context.Background())
		},
	}
	for name, revoke := range revokers {
		t.Run(name, func(t *testing.T) {
			e := newCacheEnv(t, ttl, nil)
			e.mustResolve()
			if v, _, _ := e.a.safety.continuitySnapshot(); !v {
				t.Fatal("no snapshot to revoke")
			}
			revoke(e)
			e.a.safety.mu.Lock()
			held := e.a.safety.contValid
			e.a.safety.mu.Unlock()
			if held {
				t.Fatal("the snapshot itself survived the revocation")
			}
		})
	}
}

// 7. The leading stream's own cancellation is local: no revocation, no stream loss; a waiter takes over.
func TestContinuityLeaderStreamPureCancelIsLocal(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	peer, unregister, err := e.a.safety.RegisterStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	s, _ := e.openFollowStream()
	e.clock.advance(ttl) // the check before the delivery is a real one
	e.m.take()
	g := newGate("info")
	e.m.setHook(g.hook)
	nextCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leader := startAsync(func() error { _, err := s.Next(nextCtx); return err })
	g.waitEntered(t)
	waiters := startResolvers(e, 3)
	e.waitWaiters(3)
	cancel()
	if err := recvErr(t, leader); err == nil {
		t.Fatal("the canceled read succeeded")
	}
	for i, err := range collect(t, waiters) {
		if err != nil {
			t.Errorf("waiter %d was not admitted by the next refresh: %v", i, err)
		}
	}
	e.requireHealthy("leader stream cancel", peer)
	if got := e.m.take(); got["info"] != 2 {
		t.Errorf("the abandoned refresh and one new one expected, /info reads: %d", got["info"])
	}
}

// 8. An independent fault coinciding with the leader's own cancellation revokes BEFORE the leader is answered;
// its waiters fail closed and nothing is dispatched.
func TestContinuityLeaderFaultWithCancelRevokesBeforeReturn(t *testing.T) {
	for _, fault := range []struct {
		name string
		err  error
	}{{"independent", io.ErrUnexpectedEOF}, {"joined", errors.Join(io.ErrUnexpectedEOF, context.Canceled)}} {
		for _, stage := range []string{"info", "inspect-self", "list"} {
			t.Run(fault.name+"/"+stage, func(t *testing.T) {
				e := newCacheEnv(t, ttl, nil)
				peer, unregister, err := e.a.safety.RegisterStream(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer unregister()
				s, _ := e.openFollowStream()
				e.clock.advance(ttl)
				base := e.a.Counters().TotalOperational()
				g := newGate(stage)
				g.fault = fault.err
				e.m.setHook(g.hook)
				nextCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				leader := startAsync(func() error {
					_, err := s.Next(nextCtx)
					// revoked before the canceled call returned, not afterwards
					if e.a.Ready() || peer.Err() == nil {
						t.Error("the proof or an unrelated stream was still alive when the leader returned")
					}
					return err
				})
				g.waitEntered(t)
				waiters := startResolvers(e, 2)
				e.waitWaiters(2)
				cancel()
				if err := recvErr(t, leader); err == nil {
					t.Fatal("the faulted read succeeded")
				}
				for i, err := range collect(t, waiters) {
					if !errors.Is(err, ErrUnverified) {
						t.Errorf("waiter %d: %v, want ErrUnverified", i, err)
					}
				}
				e.requireRevoked("leader fault with cancel", peer)
				if got := e.a.Counters().TotalOperational(); got != base {
					t.Errorf("operational calls after the fault: %d, want %d", got, base)
				}
			})
		}
	}
}

// 9. A waiter's own pure cancellation is local, for admissions and for streams; the leader still publishes.
func TestContinuityWaiterPureCancelIsLocal(t *testing.T) {
	for _, via := range []string{"admission", "stream"} {
		t.Run(via, func(t *testing.T) {
			e := newCacheEnv(t, ttl, nil)
			peer, unregister, err := e.a.safety.RegisterStream(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer unregister()
			var s LogStream
			if via == "stream" {
				s, _ = e.openFollowStream()
				e.clock.advance(ttl)
			}
			g := newGate("info")
			e.m.setHook(g.hook)
			leader := startAsync(func() error { return e.resolve(context.Background()) })
			g.waitEntered(t)
			wctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waiter := startAsync(func() error {
				if via == "stream" {
					_, err := s.Next(wctx)
					return err
				}
				return e.resolve(wctx)
			})
			e.waitWaiters(1)
			cancel()
			err = recvErr(t, waiter)
			if err == nil || errors.Is(err, ErrBackendFailed) {
				t.Fatalf("the waiter returned %v, want a cancellation", err)
			}
			if via == "admission" && !errors.Is(err, context.Canceled) {
				t.Fatalf("the waiter returned %v, want context.Canceled", err)
			}
			e.requireHealthy("waiter cancel", peer)
			g.open()
			if err := recvErr(t, leader); err != nil {
				t.Fatalf("the healthy leader was affected: %v", err)
			}
			if v, _, _ := e.a.safety.continuitySnapshot(); !v {
				t.Fatal("the healthy leader did not publish")
			}
		})
	}
}

// 10. A waiter whose deadline is OUR safety deadline revokes, exactly as the watchdog does; a caller's own
// deadline does not.
func TestContinuityWaiterInternalDeadlineRevokes(t *testing.T) {
	t.Run("internal deadline", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		peer, unregister, _ := e.a.safety.RegisterStream(context.Background())
		defer unregister()
		g := newGate("info")
		e.m.setHook(g.hook)
		leader := startAsync(func() error { return e.resolve(context.Background()) })
		g.waitEntered(t)
		wctx, cancel := context.WithTimeoutCause(context.Background(), 30*time.Millisecond, ErrSafetyCheckDeadline)
		defer cancel()
		err := e.resolve(wctx)
		if !errors.Is(err, ErrUnverified) {
			t.Fatalf("got %v, want ErrUnverified", err)
		}
		d := onlyDrop(t, e.rec).Drop
		if d.Reason != DropCheckDeadline || d.Step != StepContinuity || d.Cause != CauseDeadline {
			t.Fatalf("drop = %+v, want check_deadline/continuity/deadline", d)
		}
		e.requireRevoked("waiter safety deadline", peer)
		g.open()
		if err := recvErr(t, leader); !errors.Is(err, ErrUnverified) {
			t.Fatalf("the leader of a revoked epoch returned %v", err)
		}
	})
	t.Run("caller deadline", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		g := newGate("info")
		e.m.setHook(g.hook)
		leader := startAsync(func() error { return e.resolve(context.Background()) })
		g.waitEntered(t)
		wctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if err := e.resolve(wctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want the caller's own deadline", err)
		}
		e.requireHealthy("waiter caller deadline", nil)
		g.open()
		if err := recvErr(t, leader); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("one cause for every internal deadline", func(t *testing.T) {
		if !errors.Is(errStreamCheckDeadline, ErrSafetyCheckDeadline) {
			t.Fatal("the stream watchdog must use the exported safety-check cause")
		}
	})
}

// A hung daemon cannot hold the single flight: the refresh has its own ceiling, which revokes like any other of
// our deadlines, and every waiter fails closed.
func TestContinuityRefreshCeilingBoundsAHungDaemon(t *testing.T) {
	old := continuityRefreshCeiling
	continuityRefreshCeiling = 100 * time.Millisecond
	defer func() { continuityRefreshCeiling = old }()
	e := newCacheEnv(t, ttl, nil)
	peer, unregister, _ := e.a.safety.RegisterStream(context.Background())
	defer unregister()
	g := newGate("info") // never released
	e.m.setHook(g.hook)
	leader := startAsync(func() error { return e.resolve(context.Background()) })
	g.waitEntered(t)
	waiters := startResolvers(e, 2)
	e.waitWaiters(2)
	for i, err := range append([]error{recvErr(t, leader)}, collect(t, waiters)...) {
		if !errors.Is(err, ErrUnverified) {
			t.Errorf("caller %d got %v, want ErrUnverified", i, err)
		}
	}
	d := onlyDrop(t, e.rec).Drop
	if d.Reason != DropCheckDeadline || d.Step != StepInfo || d.Cause != CauseDeadline {
		t.Fatalf("drop = %+v, want check_deadline/info/deadline", d)
	}
	e.requireRevoked("hung refresh", peer)
}

// 11. An admission that performs the check itself still drops the proof when its own client cancels or times out
// (the pinned admission semantics), at TTL 1 s too.
func TestContinuityAdmissionLeaderCancelStillDrops(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			e := newCacheEnv(t, ttl, nil)
			g := newGate("info")
			e.m.setHook(g.hook)
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
			}
			defer cancel()
			call := startAsync(func() error { return e.resolve(ctx) })
			g.waitEntered(t)
			if mode == "cancel" {
				cancel()
			}
			if err := recvErr(t, call); !errors.Is(err, ErrUnverified) {
				t.Fatalf("got %v, want ErrUnverified", err)
			}
			d := onlyDrop(t, e.rec).Drop
			wantCause := CauseCanceled
			if mode == "deadline" {
				wantCause = CauseDeadline
			}
			if d.Reason != DropDaemonUnreachable || d.Step != StepInfo || d.Cause != wantCause {
				t.Fatalf("drop = %+v", d)
			}
			e.requireRevoked("admission leader "+mode, nil)
		})
	}
}

// 12. A mutation needs a check that started after the call began, whatever snapshot exists; concurrent mutations
// share a check only if it started after each of them arrived.
func TestContinuityMutationsNeedAFreshCheck(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"start", "stop", "restart"} {
		t.Run(op, func(t *testing.T) {
			e := newCacheEnv(t, ttl, nil)
			e.mustResolve() // a fresh snapshot exists
			e.m.take()
			var err error
			switch op {
			case "start":
				err = e.a.Start(ctx, e.target())
			case "stop":
				err = e.a.Stop(ctx, e.target(), StopOptions{})
			default:
				err = e.a.Restart(ctx, e.target(), RestartOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := e.m.take(); got["info"] != 1 || got["inspect-self"] != 1 || got["inspect"] != 1 || got[op] != 1 {
				t.Errorf("%s with a fresh snapshot: %v, want its own continuity check", op, got)
			}
		})
	}
	t.Run("concurrent mutations", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		g := newGate("info")
		e.m.setHook(g.hook)
		first := startAsync(func() error { return e.a.Start(ctx, e.target()) })
		g.waitEntered(t)
		rest := make([]<-chan error, 4)
		for i := range rest {
			rest[i] = startAsync(func() error { return e.a.Start(ctx, e.target()) })
		}
		e.waitWaiters(4)
		g.open()
		for i, err := range append([]error{recvErr(t, first)}, collect(t, rest)...) {
			if err != nil {
				t.Errorf("start %d: %v", i, err)
			}
		}
		// the first start's check began before the others arrived and cannot cover them; one later check covers all four
		if got := e.m.take(); got["info"] != 2 {
			t.Errorf("/info reads = %d, want 2 (%v)", got["info"], got)
		}
	})
}

// 13. A daemon swap that keeps the own container is detected within the bound for reads, at once for mutations.
func TestContinuityDaemonIDChangeBound(t *testing.T) {
	swap := func(e *cacheEnv) {
		e.fake.mu.Lock()
		e.fake.daemonID = "another-daemon"
		e.fake.mu.Unlock()
	}
	t.Run("read within the bound is admitted, a mutation is refused", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve()
		swap(e)
		e.clock.advance(ttl / 2)
		if err := e.resolve(context.Background()); err != nil {
			t.Fatalf("a read inside the documented bound was refused: %v", err)
		}
		before := e.a.Counters().TotalOperational()
		if err := e.a.Start(context.Background(), e.target()); !errors.Is(err, ErrUnverified) || e.a.Counters().TotalOperational() != before {
			t.Fatalf("a mutation after a daemon swap: %v", err)
		}
		if e.a.Ready() {
			t.Fatal("the proof survived the daemon swap")
		}
	})
	t.Run("at the bound reads are refused and streams cancelled", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		peer, unregister, _ := e.a.safety.RegisterStream(context.Background())
		defer unregister()
		e.mustResolve()
		swap(e)
		e.clock.advance(ttl)
		if err := e.resolve(context.Background()); !errors.Is(err, ErrUnverified) {
			t.Fatalf("a read at the bound was admitted: %v", err)
		}
		e.requireRevoked("daemon swap at the bound", peer)
		if d := onlyDrop(t, e.rec).Drop; d.Reason != DropIdentity || d.Step != StepContinuity {
			t.Fatalf("drop = %+v", d)
		}
	})
}

// 14. Name reuse and container recreation within the bound: resolution always reads a fresh list.
func TestContinuityNameReuseAndRecreationWithinTheBound(t *testing.T) {
	t.Run("a protected replacement takes over the name", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve()
		e.fake.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Name: "old"})
		e.fake.putContainer(fakeDaemonContainer{ID: string(testApp2ID), Name: "ordinary", Labels: map[string]string{"io.mandatary.role": "peer"}})
		e.clock.advance(ttl / 4) // still inside the bound
		if err := e.resolve(context.Background()); !errors.Is(err, ErrProtectedTarget) {
			t.Fatalf("the replacement was resolved by its name: %v", err)
		}
		if got, err := e.a.ResolveTarget(context.Background(), "old"); err != nil || got.ContainerID != testApp1ID {
			t.Fatalf("the renamed container: %v, %v", got.ContainerID, err)
		}
		e.m.take()
		if err := e.a.Start(context.Background(), TargetIdentity{EndpointID: e.a.EndpointID(), ContainerID: testApp2ID}); !errors.Is(err, ErrProtectedTarget) {
			t.Fatalf("a protected peer was dispatched: %v", err)
		}
		got := e.m.take()
		if got["start"] != 0 || got["logs"] != 0 || e.a.Counters().TotalOperational() != 0 {
			t.Fatalf("an operational request reached the replacement: %v", got)
		}
	})
	t.Run("the own container is recreated with a new ID", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve()
		e.fake.mu.Lock()
		delete(e.fake.containers, string(testSelfID))
		e.fake.mu.Unlock()
		e.fake.putContainer(fakeDaemonContainer{ID: string(testPeerID), Name: "self", Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}})
		if err := e.resolve(context.Background()); !errors.Is(err, ErrUnverified) {
			t.Fatalf("a recreated self was accepted within the bound: %v", err)
		}
		e.requireRevoked("self recreation", nil)
	})
}

// 15. A new reserved-namespace peer is refused at resolution and at dispatch from the first call on.
func TestContinuityNewProtectedPeerWithinTheBound(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	e.mustResolve()
	e.fake.putContainer(fakeDaemonContainer{ID: string(testApp2ID), Name: "second", Labels: map[string]string{"io.mandatary.agent": "x"}})
	// dispatch before anything has marked it: the fresh target inspect finds the reserved label
	if _, err := e.a.InspectStatus(context.Background(), TargetIdentity{EndpointID: e.a.EndpointID(), ContainerID: testApp2ID}); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("dispatch: %v", err)
	}
	if e.a.Counters().OperationalInspects != 0 {
		t.Fatal("a protected peer was inspected operationally")
	}
	if _, err := e.a.ResolveTarget(context.Background(), "second"); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("resolve: %v", err)
	}
	items, err := e.a.ListContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.ContainerID == testApp2ID {
			t.Fatal("a protected peer was listed")
		}
	}
}

// 16. A second container claiming the deployment binding is caught by the next resolution's own list.
func TestContinuityBindingOverlapWithinTheBound(t *testing.T) {
	e := newCacheEnv(t, ttl, func(cfg *SelfIdentityConfig) { cfg.InstanceUUID = testSelfUUID })
	e.mustResolve()
	e.fake.putContainer(fakeDaemonContainer{ID: string(testApp2ID), Name: "second", Labels: map[string]string{SelfInstanceUUIDLabelKey: testSelfUUID}})
	if err := e.resolve(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("an overlapping binding was accepted: %v", err)
	}
	e.requireRevoked("binding overlap", nil)
	// removing the overlap does not resurrect the proof
	e.fake.mu.Lock()
	delete(e.fake.containers, string(testApp2ID))
	e.fake.mu.Unlock()
	if err := e.resolve(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("removing the overlap restored authority: %v", err)
	}
}

// 17. Active streams: deliveries inside the bound cost no continuity read; invalidation takes effect at once and
// buffered bytes are not served; after the bound the watcher refreshes.
func TestContinuityActiveStreams(t *testing.T) {
	t.Run("deliveries inside the bound", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		s, _ := e.openFollowStream()
		e.m.take()
		for i := 0; i < 3; i++ {
			e.follow <- encodeMultiplexedFrame(1, []byte("x"))
			if _, err := s.Next(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if got := e.m.take(); got["info"] != 0 || got["inspect-self"] != 0 || got["list"] != 0 {
			t.Fatalf("deliveries inside the bound read the daemon: %v", got)
		}
	})
	t.Run("invalidation stops delivery at once", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		s, _ := e.openFollowStream()
		e.follow <- encodeMultiplexedFrame(1, []byte("buffered"))
		e.a.InvalidateSafety()
		if f, err := s.Next(context.Background()); err == nil || len(f.Payload) != 0 {
			t.Fatalf("Next after invalidation: %q, %v", f.Payload, err)
		}
		buf := []byte("zzzzzzzz")
		if n, err := s.Read(buf); err == nil || n != 0 || string(buf) != "zzzzzzzz" {
			t.Fatalf("Read after invalidation: %d, %v", n, err)
		}
	})
	t.Run("the watcher refreshes after the bound", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		_, _ = e.openFollowStream()
		e.m.take()
		e.clock.advance(ttl)
		deadline := time.Now().Add(4 * time.Second)
		for e.m.count("info") == 0 {
			if time.Now().After(deadline) {
				t.Fatal("the idle watcher never refreshed an expired check")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !e.a.Ready() {
			t.Fatal("a healthy refresh lost the proof")
		}
	})
}

// 18. Restore and rebind drop the proof whatever is cached; only a fresh VerifySelf restores.
func TestContinuityRestoreAndRebind(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	peer, unregister, _ := e.a.safety.RegisterStream(context.Background())
	defer unregister()
	e.mustResolve()
	e.a.InvalidateSafety() // what InvalidateSelfProtection does at restore and endpoint reapproval
	if err := e.resolve(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("a fresh snapshot outlived the invalidation: %v", err)
	}
	e.requireRevoked("restore", peer)
	if err := e.a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.m.take()
	e.mustResolve()
	if got := e.m.take(); got["info"] != 1 {
		t.Fatalf("the check before the invalidation served the new proof: %v", got)
	}
}
