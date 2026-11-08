package docker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type review380MetadataBarrier struct {
	base    http.RoundTripper
	path    string
	armed   atomic.Bool
	entered chan struct{}
	skip    atomic.Int32
	fault   error
}

func (b *review380MetadataBarrier) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, b.path) && b.armed.Load() && b.skip.Add(-1) < 0 && b.armed.CompareAndSwap(true, false) {
		close(b.entered)
		<-r.Context().Done()
		if b.fault != nil {
			return nil, b.fault
		}
		return nil, r.Context().Err()
	}
	return b.base.RoundTrip(r)
}

// Closing an ordinary stream (or canceling its Next) must not turn a locally
// aborted continuity query into global daemon failure. No daemon state changes.
func TestReview380LocalCancellationDuringContinuity(t *testing.T) {
	for _, stage := range []string{"/info", "/containers/" + string(testSelfID) + "/json", "/containers/json"} {
		for _, mode := range []string{"Close-Next", "Close-Read", "Cancel-Next", "Deadline-Next"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				base := newFakeDaemonTransport()
				base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
				base.putContainer(fakeDaemonContainer{ID: string(testApp1ID)})
				barrier := &review380MetadataBarrier{base: base, path: stage, entered: make(chan struct{})}
				a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: barrier})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = a.Close() }()
				if err = a.VerifySelf(ctx); err != nil {
					t.Fatal(err)
				}
				peer, unregister, err := a.safety.RegisterStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer unregister()
				target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
				s, err := a.Logs(ctx, target, LogOptions{Stdout: true, Follow: true})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.Close() }()
				nextCtx, cancel := context.WithCancel(ctx)
				if mode == "Deadline-Next" {
					cancel()
					nextCtx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				}
				defer cancel()
				barrier.armed.Store(true)
				done := make(chan error, 1)
				go func() {
					if mode == "Close-Read" {
						_, e := s.Read(make([]byte, 32))
						done <- e
					} else {
						_, e := s.Next(nextCtx)
						done <- e
					}
				}()
				select {
				case <-barrier.entered:
				case <-time.After(3 * time.Second):
					cancel()
					_ = s.Close()
					if e := <-done; e == nil {
						t.Error("aborted worker succeeded")
					}
					t.Fatal("did not enter continuity request")
				}
				if mode == "Cancel-Next" {
					cancel()
				} else if mode != "Deadline-Next" {
					_ = s.Close()
				}
				select {
				case e := <-done:
					if e == nil || e == io.EOF {
						t.Error("canceled read succeeded")
					}
				case <-time.After(3 * time.Second):
					cancel()
					_ = s.Close()
					if e := <-done; e == nil {
						t.Error("aborted worker succeeded")
					}
					t.Fatal("local cancel did not interrupt continuity request")
				}
				if !a.Ready() {
					t.Error("local cancellation of healthy continuity request invalidated global proof")
				}
				if peer.Err() != nil {
					t.Error("local cancellation killed unrelated healthy peer")
				}
				if e := a.Start(ctx, target); e != nil {
					t.Errorf("healthy operation now needs fresh VerifySelf: %v", e)
				}
			})
		}
	}
}

func TestReview380HealthyAndLiveFailureControls(t *testing.T) {
	for _, mode := range []string{"ordinary-close", "live-inspect-fault", "live-inventory-fault"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			a, tr := reviewerAdapter(t, reviewerProof())
			if e := a.VerifySelf(ctx); e != nil {
				t.Fatal(e)
			}
			peer, unregister, e := a.safety.RegisterStream(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer unregister()
			target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
			s, e := a.Logs(ctx, target, LogOptions{Stdout: true, Follow: true})
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = s.Close() }()
			if mode == "ordinary-close" {
				_ = s.Close()
				if !a.Ready() || peer.Err() != nil || a.Start(ctx, target) != nil {
					t.Error("healthy Close/control failed")
				}
				return
			}
			// No caller cancellation: an actual transport failure remains fail-closed.
			tr.mu.Lock()
			switch mode {
			case "live-inspect-fault":
				tr.failInspect = errors.New("synthetic live inspect failure")
			case "live-inventory-fault":
				tr.failList = errors.New("synthetic live inventory failure")
			}
			tr.mu.Unlock()
			if _, e = s.Next(ctx); e == nil {
				t.Error("live transport failure accepted")
			}
			if a.Ready() || peer.Err() == nil {
				t.Error("live transport failure did not revoke proof/peers")
			}
			before := a.Counters().TotalOperational()
			if e = a.Start(ctx, target); !errors.Is(e, ErrUnverified) || a.Counters().TotalOperational() != before {
				t.Error("live failure admitted operation")
			}
		})
	}
}
