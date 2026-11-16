package docker

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// P1.20 R2: how many reads of the Docker daemon one admitted call and one live log stream cause. The numbers are
// the product's current behavior, pinned so that a change to them is a visible decision (the load a workload puts
// on the daemon is the sum of these reads, and every read that fails drops the endpoint-wide safety proof).

// readCounter counts the daemon reads of a fake daemon by kind.
type readCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func newReadCounter(tr *fakeDaemonTransport) *readCounter {
	rc := &readCounter{n: map[string]int{}}
	tr.mu.Lock()
	tr.delay = func(req *http.Request) {
		kind := "other"
		switch p := req.URL.Path; {
		case strings.HasSuffix(p, "/info"):
			kind = "info"
		case strings.HasSuffix(p, "/containers/json"):
			kind = "list"
		case strings.HasSuffix(p, "/json"):
			kind = "inspect"
		case strings.HasSuffix(p, "/logs"):
			kind = "logs"
		}
		rc.mu.Lock()
		rc.n[kind]++
		rc.mu.Unlock()
	}
	tr.mu.Unlock()
	return rc
}

func (rc *readCounter) take() map[string]int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := rc.n
	rc.n = map[string]int{}
	return out
}

func TestDaemonReadsOfOneAdmittedCall(t *testing.T) {
	a, tr, _ := observedAdapter(t)
	rc := newReadCounter(tr)
	ctx := context.Background()
	target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
	// The authorizer resolves the target at admission, resolves it again when it revalidates the freshly
	// registered lease, and the operation then verifies it a last time before it is dispatched.
	if _, err := a.ResolveTarget(ctx, string(testApp1ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResolveTarget(ctx, string(testApp1ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.InspectStatus(ctx, target); err != nil {
		t.Fatal(err)
	}
	got := rc.take()
	want := map[string]int{"info": 3, "inspect": 4, "list": 5}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("reads of kind %q per admitted call = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	if total := got["info"] + got["inspect"] + got["list"]; total != 12 {
		t.Errorf("one admitted status call reads the daemon %d times, want 12", total)
	}
}

func TestDaemonReadsOfOneLiveLogStreamPerSecond(t *testing.T) {
	a, tr, _ := observedAdapter(t)
	tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Name: "ordinary", FollowCh: make(chan []byte, 8)})
	ctx := context.Background()
	target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
	s, err := a.Logs(ctx, target, LogOptions{Stdout: true, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	rc := newReadCounter(tr)
	// the safety watchdog verifies continuity once a second while the stream is open, whatever the stream does
	time.Sleep(3500 * time.Millisecond)
	got := rc.take()
	if got["info"] < 3 || got["info"] > 4 || got["list"] != got["info"] || got["inspect"] != got["info"] {
		t.Errorf("an idle follow stream must cost one continuity check (info+inspect+list) per second, got %v over 3.5 s", got)
	}
}

func TestDaemonReadsOfOneTailLogsCall(t *testing.T) {
	a, tr, _ := observedAdapter(t)
	three := append(append(encodeMultiplexedFrame(1, []byte("l1\n")), encodeMultiplexedFrame(1, []byte("l2\n"))...), encodeMultiplexedFrame(1, []byte("l3\n"))...)
	tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Name: "ordinary", Logs: three})
	ctx := context.Background()
	target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
	rc := newReadCounter(tr)
	if _, err := a.ResolveTarget(ctx, string(testApp1ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResolveTarget(ctx, string(testApp1ID)); err != nil {
		t.Fatal(err)
	}
	s, err := a.Logs(ctx, target, LogOptions{Stdout: true, Tail: 3})
	if err != nil {
		t.Fatal(err)
	}
	frames := 0
	for {
		_, err := s.Next(ctx)
		if err != nil {
			break
		}
		frames++
	}
	_ = s.Close()
	got := rc.take()
	t.Logf("tail=3 logs call: frames=%d reads=%v total=%d", frames, got, got["info"]+got["inspect"]+got["list"])
}
