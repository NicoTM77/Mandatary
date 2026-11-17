package docker

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Helpers of the bounded-continuity tests (P1.20 R2): a fake monotonic clock, a daemon transport that counts the
// reads by kind and lets a test hold, fail or slow one of them, and an adapter builder. Nothing here changes an
// existing test; every file that uses them is new.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// meterTransport forwards to the fake daemon, counts each request by kind and runs an optional hook before it.
type meterTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	n    map[string]int
	hook func(kind string, r *http.Request) error
}

func newMeterTransport(base http.RoundTripper) *meterTransport {
	return &meterTransport{base: base, n: map[string]int{}}
}

// requestKind names a daemon request: info, list, inspect-self, inspect (any other container), logs, start, stop,
// restart or other.
func requestKind(r *http.Request) string {
	p := r.URL.Path
	if i := strings.Index(p, "/containers/"); i >= 0 {
		rest := strings.Split(strings.TrimPrefix(p[i:], "/containers/"), "/")
		switch {
		case rest[0] == "json":
			return "list"
		case len(rest) == 2 && rest[1] == "json":
			if rest[0] == string(testSelfID) {
				return "inspect-self"
			}
			return "inspect"
		case len(rest) == 2:
			return rest[1]
		}
	}
	switch {
	case strings.HasSuffix(p, "/info"):
		return "info"
	case strings.HasSuffix(p, "/_ping"):
		return "ping"
	}
	return "other"
}

func (m *meterTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	kind := requestKind(r)
	m.mu.Lock()
	m.n[kind]++
	hook := m.hook
	m.mu.Unlock()
	if hook != nil {
		if err := hook(kind, r); err != nil {
			return nil, err
		}
	}
	return m.base.RoundTrip(r)
}

func (m *meterTransport) setHook(h func(kind string, r *http.Request) error) {
	m.mu.Lock()
	m.hook = h
	m.mu.Unlock()
}

// take returns the counts since the previous take.
func (m *meterTransport) take() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.n
	m.n = map[string]int{}
	return out
}

func (m *meterTransport) count(kind string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n[kind]
}

// gate holds the FIRST request of one kind until released (or until its own context ends, when it answers with
// fault, or with the context's error when there is none). Later requests of the kind pass.
type gate struct {
	kind    string
	entered chan struct{}
	release chan struct{}
	fault   error
	once    sync.Once
	onEnter func()
}

func newGate(kind string) *gate {
	return &gate{kind: kind, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gate) hook(kind string, r *http.Request) error {
	if kind != g.kind {
		return nil
	}
	first := false
	g.once.Do(func() { first = true })
	if !first {
		return nil
	}
	if g.onEnter != nil {
		g.onEnter()
	}
	close(g.entered)
	select {
	case <-g.release:
		return nil
	case <-r.Context().Done():
		if g.fault != nil {
			return g.fault
		}
		return r.Context().Err()
	}
}

func (g *gate) open() {
	select {
	case <-g.release:
	default:
		close(g.release)
	}
}

func (g *gate) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the %s request was never made", g.kind)
	}
}

// cacheEnv is one adapter over a metered fake daemon with a fake clock.
type cacheEnv struct {
	t     *testing.T
	a     *SDKAdapter
	fake  *fakeDaemonTransport
	m     *meterTransport
	clock *fakeClock
	rec   *transitionRecorder
	cfg   SelfIdentityConfig
	// follow feeds the live log stream of the ordinary container.
	follow chan []byte
}

func newCacheEnv(t *testing.T, ttl time.Duration, mod func(cfg *SelfIdentityConfig)) *cacheEnv {
	t.Helper()
	e := &cacheEnv{t: t, fake: newFakeDaemonTransport(), clock: newFakeClock(), rec: &transitionRecorder{}}
	e.fake.putContainer(fakeDaemonContainer{ID: string(testSelfID), Name: "self", Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}})
	e.follow = make(chan []byte, 16)
	e.fake.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Name: "ordinary", Logs: encodeMultiplexedFrame(1, []byte("l1\n")), FollowCh: e.follow})
	e.fake.putContainer(fakeDaemonContainer{ID: string(testApp2ID), Name: "second"})
	e.m = newMeterTransport(e.fake)
	e.cfg = reviewerProof()
	e.cfg.Observer = e.rec.observe
	if mod != nil {
		mod(&e.cfg)
	}
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Transport: e.m, Identity: e.cfg, ContinuityTTL: ttl, Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.a = a
	t.Cleanup(func() { _ = a.Close() })
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.rec.all(); len(got) != 0 {
		t.Fatalf("setup reported transitions: %+v", got)
	}
	e.m.take()
	return e
}

func (e *cacheEnv) target() TargetIdentity {
	return TargetIdentity{EndpointID: e.a.EndpointID(), ContainerID: testApp1ID}
}

func (e *cacheEnv) resolve(ctx context.Context) error {
	_, err := e.a.ResolveTarget(ctx, "ordinary")
	return err
}

func (e *cacheEnv) mustResolve() {
	e.t.Helper()
	if err := e.resolve(context.Background()); err != nil {
		e.t.Fatalf("resolve: %v", err)
	}
}

// waitWaiters blocks until at least n callers wait for a refresh that somebody else leads.
func (e *cacheEnv) waitWaiters(n int64) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.a.safety.continuityWaiters() < n {
		if time.Now().After(deadline) {
			e.t.Fatalf("only %d of %d callers are waiting for the refresh", e.a.safety.continuityWaiters(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// concurrently runs fn n times in parallel and returns the errors in order.
func concurrently(n int, fn func(i int) error) []error {
	out := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = fn(i)
		}()
	}
	wg.Wait()
	return out
}

// startResolvers starts n ResolveTarget calls and returns their result channels.
func startResolvers(e *cacheEnv, n int) []<-chan error {
	out := make([]<-chan error, n)
	for i := range out {
		out[i] = startAsync(func() error { return e.resolve(context.Background()) })
	}
	return out
}

func collect(t *testing.T, chans []<-chan error) []error {
	t.Helper()
	out := make([]error, len(chans))
	for i, ch := range chans {
		out[i] = recvErr(t, ch)
	}
	return out
}

func goroutines() int { return runtime.NumGoroutine() }

func startAsync(fn func() error) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	return ch
}

func recvErr(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("call did not return")
		return nil
	}
}

// expiringClock reads a time that is 2 s later on every call, so a continuity check is always expired when the
// next caller looks at it. It is how the whole existing suite is replayed at a 1 s TTL (twin_test.go).
type expiringClock struct{ n atomic.Int64 }

func (c *expiringClock) Now() time.Time {
	return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC).Add(time.Duration(c.n.Add(1)) * 2 * time.Second)
}
