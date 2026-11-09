package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// Exercise the same classifier after body I/O and from the idle watcher, not
// just the pre-read requests covered by the original independent reproducer.
func TestStreamMetadataCancellationBoundaries(t *testing.T) {
	for _, stage := range []string{"/info", "/containers/" + string(testSelfID) + "/json", "/containers/json"} {
		for _, mode := range []string{"post-close-next", "post-close-read", "post-cancel-next", "idle-close", "idle-watchdog", "watchdog", "independent-fault-with-cancel", "joined-fault-with-cancel", "explicit-invalidation"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				base := newFakeDaemonTransport()
				base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
				base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Logs: encodeMultiplexedFrame(1, []byte("ordinary log"))})
				barrier := &review380MetadataBarrier{base: base, path: stage, entered: make(chan struct{})}
				if mode == "independent-fault-with-cancel" {
					barrier.fault = io.ErrUnexpectedEOF
				}
				if mode == "joined-fault-with-cancel" {
					barrier.fault = errors.Join(io.ErrUnexpectedEOF, context.Canceled)
				}
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
				defer cancel()
				post := mode == "post-close-next" || mode == "post-close-read" || mode == "post-cancel-next"
				if post {
					barrier.skip.Store(1) // let the pre-read check complete
				}
				barrier.armed.Store(true)
				done := make(chan error, 1)
				if mode != "idle-close" && mode != "idle-watchdog" {
					go func() {
						if mode == "post-close-read" {
							p := bytes.Repeat([]byte{'x'}, 32)
							n, e := s.Read(p)
							if n != 0 || !bytes.Equal(p, bytes.Repeat([]byte{'x'}, 32)) {
								t.Error("canceled post-check exposed bytes or modified caller buffer")
							}
							done <- e
						} else {
							frame, e := s.Next(nextCtx)
							if len(frame.Payload) != 0 {
								t.Error("canceled check exposed payload")
							}
							done <- e
						}
					}()
				}
				select {
				case <-barrier.entered:
				case <-time.After(5 * time.Second):
					cancel()
					_ = s.Close()
					if mode != "idle-close" && mode != "idle-watchdog" {
						if e := <-done; e == nil {
							t.Error("aborted worker succeeded")
						}
					}
					t.Fatal("metadata request not entered")
				}
				switch mode {
				case "post-cancel-next", "independent-fault-with-cancel", "joined-fault-with-cancel":
					cancel()
				case "watchdog", "idle-watchdog": // no local abort: wait for the actual two-second deadline
				case "explicit-invalidation":
					a.InvalidateSafety()
				default:
					_ = s.Close()
				}
				if mode == "idle-close" || mode == "idle-watchdog" {
					// Join the watcher (and therefore its entered check) deterministically.
					// Close itself does not wait for that goroutine.
					select {
					case <-s.(*safetyLogStream).watchDone:
					case <-time.After(5 * time.Second):
						t.Fatal("idle watcher did not terminate")
					}
				} else {
					select {
					case e := <-done:
						if e == nil || errors.Is(e, io.EOF) {
							t.Error("aborted check succeeded")
						}
					case <-time.After(5 * time.Second):
						cancel()
						_ = s.Close()
						if e := <-done; e == nil {
							t.Error("aborted worker succeeded")
						}
						t.Fatal("metadata request did not terminate")
					}
				}
				mustRevoke := mode == "watchdog" || mode == "idle-watchdog" || mode == "independent-fault-with-cancel" || mode == "joined-fault-with-cancel" || mode == "explicit-invalidation"
				if mustRevoke {
					if a.Ready() || peer.Err() == nil {
						t.Error("genuine uncertainty did not revoke proof and peer")
					}
					before := a.Counters().TotalOperational()
					if e := a.Start(ctx, target); !errors.Is(e, ErrUnverified) || a.Counters().TotalOperational() != before {
						t.Error("operation admitted after uncertainty")
					}
				} else if !a.Ready() || peer.Err() != nil || a.Start(ctx, target) != nil {
					t.Error("local abort poisoned healthy proof, peer or admission")
				}
				if _, err = s.Next(ctx); err == nil {
					t.Error("aborted stream recovered")
				}
			})
		}
	}
}
