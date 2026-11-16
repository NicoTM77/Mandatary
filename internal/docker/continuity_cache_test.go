package docker

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// P1.20 R2: bounded continuity caching. One successful continuity check (daemon ID, own container, all-state
// inventory) may cover later READ admissions and stream deliveries for less than ContinuityTTL; nothing else is
// cached. These tests pin freshness, sharing and read counts with a fake clock and controlled latency; the
// cancellation, fault, invalidation and identity requirements are in continuity_cache_security_test.go.

const ttl = time.Second

func wantReads(t *testing.T, got map[string]int, want map[string]int) {
	t.Helper()
	for _, k := range []string{"info", "inspect-self", "inspect", "list", "logs", "start", "stop", "restart"} {
		if got[k] != want[k] {
			t.Errorf("reads of kind %q = %d, want %d (all: %v)", k, got[k], want[k], got)
		}
	}
}

// 1. A snapshot is valid for 0 <= age < TTL and expired at exactly TTL.
func TestContinuityExpiryBoundary(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	e.mustResolve() // refresh at t0: 1 info, 1 self inspect, 1 continuity list + the resolution's own list
	wantReads(t, e.m.take(), map[string]int{"info": 1, "inspect-self": 1, "list": 2})

	e.clock.advance(ttl - time.Nanosecond)
	e.mustResolve() // inside the bound: no continuity read at all; the list of the resolution is always fresh
	wantReads(t, e.m.take(), map[string]int{"list": 1})

	e.clock.advance(time.Nanosecond) // age == TTL
	e.mustResolve()
	wantReads(t, e.m.take(), map[string]int{"info": 1, "inspect-self": 1, "list": 2})

	// a clock that stepped backwards never makes a snapshot younger
	e.clock.advance(-10 * time.Second)
	e.mustResolve()
	wantReads(t, e.m.take(), map[string]int{"info": 1, "inspect-self": 1, "list": 2})
}

// 2. The refresh duration counts against freshness: age is measured from the START of the refresh.
func TestContinuityRefreshDurationCountsAgainstFreshness(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	e.m.setHook(func(kind string, r *http.Request) error {
		if kind == "info" && e.m.count("info") == 1 {
			e.clock.advance(ttl) // the refresh itself takes a full TTL
		}
		return nil
	})
	e.mustResolve() // the leader is served whatever its refresh cost
	e.m.take()
	e.m.setHook(nil)
	// the snapshot started a TTL ago, so the next caller needs a refresh of its own
	e.mustResolve()
	wantReads(t, e.m.take(), map[string]int{"info": 1, "inspect-self": 1, "list": 2})
}

// A caller that was already waiting when a refresh STARTED is served by it, however long it took; a caller that
// arrived while it ran is served only if it is still fresh at its end.
func TestContinuityWaiterServedByRefreshStartedAfterArrival(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	g1 := newGate("info")
	e.m.setHook(g1.hook)
	leader := startAsync(func() error { return e.resolve(context.Background()) })
	g1.waitEntered(t)
	e.clock.advance(2 * ttl) // the first refresh is slower than the TTL
	w := startResolvers(e, 2)
	e.waitWaiters(2)
	e.m.setHook(func(kind string, r *http.Request) error {
		if kind == "info" {
			e.clock.advance(ttl) // and so is the second
		}
		return nil
	})
	g1.open()
	if err := recvErr(t, leader); err != nil {
		t.Fatal(err)
	}
	for i, err := range collect(t, w) {
		if err != nil {
			t.Errorf("waiter %d: %v", i, err)
		}
	}
	// two refreshes in total: the slow one and exactly one that started after the waiters arrived
	if got := e.m.take(); got["info"] != 2 {
		t.Errorf("info reads = %d, want 2 (%v)", got["info"], got)
	}
}

// 3. 50 concurrent stale admissions share exactly one continuity check.
func TestContinuityConcurrentStaleAdmissionsShareOneCheck(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	g := newGate("info")
	e.m.setHook(g.hook)
	const n = 50
	results := make(chan []error, 1)
	go func() { results <- concurrently(n, func(int) error { return e.resolve(context.Background()) }) }()
	g.waitEntered(t)
	e.waitWaiters(10)
	g.open()
	for i, err := range <-results {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	wantReads(t, e.m.take(), map[string]int{"info": 1, "inspect-self": 1, "list": 1 + n})
}

// 4. A refresh slower than the TTL does not multiply reads: callers that arrive during it are served by the next
// one, which started after they arrived, and there are at most two refreshes in total.
func TestContinuitySaturationAtMostTwoRefreshes(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	g := newGate("info")
	e.m.setHook(g.hook)
	first := startAsync(func() error { return e.resolve(context.Background()) })
	g.waitEntered(t)
	e.clock.advance(3 * ttl)
	rest := startResolvers(e, 20)
	e.waitWaiters(20)
	g.open()
	if err := recvErr(t, first); err != nil {
		t.Fatal(err)
	}
	for i, err := range collect(t, rest) {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if got := e.m.take(); got["info"] != 2 || got["inspect-self"] != 2 {
		t.Errorf("two refreshes expected, reads: %v", got)
	}
}

// 6. Publication never moves the snapshot's start backwards and never crosses an epoch.
func TestContinuityPublicationNeverRegressesOrCrossesEpochs(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	m := e.a.safety
	t0 := e.clock.Now()
	m.mu.Lock()
	epoch := m.epoch
	m.mu.Unlock()
	publish := func(seq uint64, start time.Time, ep uint64) {
		m.mu.Lock()
		m.publishContinuityLocked(&contFlight{seq: seq, start: start, epoch: ep})
		m.mu.Unlock()
	}
	publish(2, t0.Add(100*time.Millisecond), epoch)
	publish(1, t0, epoch) // an older refresh that finished late
	if v, start, _ := m.continuitySnapshot(); !v || !start.Equal(t0.Add(100*time.Millisecond)) {
		t.Fatalf("older refresh moved the snapshot: valid=%v start=%v", v, start)
	}
	publish(9, t0.Add(time.Hour), epoch+1) // another epoch's refresh is never published
	if _, start, _ := m.continuitySnapshot(); !start.Equal(t0.Add(100 * time.Millisecond)) {
		t.Fatalf("a refresh of another epoch was published: %v", start)
	}
}

// A refresh of epoch N finishing after the proof was re-established as N+1 publishes nothing and its callers fail.
func TestContinuityLateRefreshOfAnOlderEpochIsDiscarded(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	g := newGate("info")
	e.m.setHook(g.hook)
	old := startAsync(func() error { return e.resolve(context.Background()) })
	g.waitEntered(t)
	if err := e.a.VerifySelf(context.Background()); err != nil { // epoch N+1 holds a proof again
		t.Fatal(err)
	}
	e.clock.advance(100 * time.Millisecond)
	e.mustResolve() // leads the refresh of epoch N+1 while the old one is still held
	_, newStart, _ := e.a.safety.continuitySnapshot()
	g.open()
	if err := recvErr(t, old); !errors.Is(err, ErrUnverified) {
		t.Fatalf("the refresh of the old epoch returned %v, want ErrUnverified", err)
	}
	if v, start, _ := e.a.safety.continuitySnapshot(); !v || !start.Equal(newStart) {
		t.Fatalf("the late refresh replaced the snapshot of the current epoch (valid=%v)", v)
	}
}

// 20. Options.
func TestContinuityOptionsAreValidated(t *testing.T) {
	for _, c := range []struct {
		ttl time.Duration
		ok  bool
	}{{-1, false}, {0, true}, {time.Nanosecond, true}, {time.Second, true}, {time.Second + time.Nanosecond, false}, {2 * time.Second, false}} {
		_, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Transport: newFakeDaemonTransport(), ContinuityTTL: c.ttl})
		if c.ok != (err == nil) || (!c.ok && !errors.Is(err, ErrInvalidConfig)) {
			t.Errorf("ContinuityTTL %v: err = %v, accepted should be %v", c.ttl, err, c.ok)
		}
	}
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Transport: newFakeDaemonTransport()})
	if err != nil {
		t.Fatal(err)
	}
	if a.safety.clock == nil {
		t.Error("a nil Clock must default to time.Now")
	}
	if MaxContinuityTTL != time.Second {
		t.Errorf("MaxContinuityTTL = %v, want 1 s", MaxContinuityTTL)
	}
}

// 22. Read counts with a fresh snapshot (the TTL-0 counts stay pinned by daemon_reads_test.go).
func TestContinuityReadCountsWithAFreshSnapshot(t *testing.T) {
	ctx := context.Background()
	t.Run("status call", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve() // seeds the snapshot
		e.m.take()
		e.mustResolve()
		if _, err := e.a.InspectStatus(ctx, e.target()); err != nil {
			t.Fatal(err)
		}
		got := e.m.take() // 2 lists + 1 target inspect, no /info at all
		wantReads(t, got, map[string]int{"list": 1, "inspect": 1})
		if total := got["info"] + got["inspect-self"] + got["inspect"] + got["list"]; total != 2 {
			t.Errorf("a status call with a fresh snapshot reads %d times, want 2 (1 list + 1 target inspect)", total)
		}
	})
	t.Run("admitted status call as the authorizer makes it", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve()
		e.m.take()
		e.mustResolve() // admission
		e.mustResolve() // lease revalidation
		if _, err := e.a.InspectStatus(ctx, e.target()); err != nil {
			t.Fatal(err)
		}
		got := e.m.take()
		if total := got["info"] + got["inspect-self"] + got["inspect"] + got["list"]; total != 3 || got["info"] != 0 {
			t.Errorf("an admitted status call reads %v, want 2 lists + 1 target inspect and no /info", got)
		}
	})
	t.Run("mutation", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve()
		e.m.take()
		e.mustResolve()
		e.mustResolve()
		if err := e.a.Start(ctx, e.target()); err != nil {
			t.Fatal(err)
		}
		got := e.m.take() // its own continuity check (3) + target inspect (1) + the 2 resolution lists
		if total := got["info"] + got["inspect-self"] + got["inspect"] + got["list"]; total != 6 || got["info"] != 1 {
			t.Errorf("a mutation reads %v, want 6 reads with exactly one /info", got)
		}
	})
	t.Run("tail logs", func(t *testing.T) {
		e := newCacheEnv(t, ttl, nil)
		e.mustResolve()
		e.m.take()
		e.mustResolve()
		e.mustResolve()
		s, err := e.a.Logs(ctx, e.target(), LogOptions{Stdout: true, Tail: 3})
		if err != nil {
			t.Fatal(err)
		}
		frames := 0
		for {
			if _, err := s.Next(ctx); err != nil {
				break
			}
			frames++
		}
		_ = s.Close()
		got := e.m.take()
		if frames != 1 || got["info"] != 0 || got["inspect-self"] != 0 || got["logs"] != 1 || got["list"] != 2 || got["inspect"] != 1 {
			t.Errorf("tail logs: frames=%d reads=%v, want 3 metadata reads, 0 /info and 0 continuity reads per frame", frames, got)
		}
	})
}

// 22b. Five idle follow streams cost one shared check per second, not one each.
func TestContinuityIdleFollowStreamsShareTheCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("real time")
	}
	ctx := context.Background()
	e := newCacheEnv(t, ttl, nil)
	e.a.safety.clock = time.Now // real time: the watchers tick for real
	for i := 0; i < 5; i++ {
		s, err := e.a.Logs(ctx, e.target(), LogOptions{Stdout: true, Follow: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
	}
	e.m.take()
	time.Sleep(3500 * time.Millisecond)
	got := e.m.take()
	// 5 streams x 3 ticks would be 15 /info reads without sharing (the pinned TTL-0 behaviour); sharing makes it about one per second
	if got["info"] < 2 || got["info"] > 5 {
		t.Errorf("five idle follow streams over 3.5 s read /info %d times, want 2..5 (%v)", got["info"], got)
	}
	if got["inspect-self"] != got["info"] {
		t.Errorf("one self inspect per shared check expected: %v", got)
	}
}

// 21. No goroutine is left behind by many refresh, share and cancel cycles.
func TestContinuityDoesNotLeakGoroutines(t *testing.T) {
	e := newCacheEnv(t, ttl, nil)
	e.m.setHook(func(kind string, r *http.Request) error {
		select {
		case <-time.After(50 * time.Microsecond):
		case <-r.Context().Done():
			return r.Context().Err()
		}
		return nil
	})
	settle := func() int {
		time.Sleep(50 * time.Millisecond)
		return goroutines()
	}
	before := settle()
	for i := 0; i < 1000; i++ {
		e.clock.advance(ttl)
		cctx, cancel := context.WithCancel(context.Background())
		stop := time.AfterFunc(time.Duration(i%3)*20*time.Microsecond, cancel)
		errs := concurrently(4, func(j int) error {
			c := context.Background()
			if j == 0 {
				c = cctx
			}
			// a stream-kind check: its own cancellation is local and never revokes the proof
			return e.a.ensureContinuity(c, modeRead, kindStream)
		})
		stop.Stop()
		cancel()
		for _, err := range errs[1:] {
			if err != nil {
				t.Fatalf("cycle %d: %v", i, err)
			}
		}
		if !e.a.Ready() {
			t.Fatalf("cycle %d: the proof was lost", i)
		}
	}
	if after := settle(); after > before+3 {
		t.Fatalf("goroutines: %d before, %d after 1000 cycles", before, after)
	}
}
