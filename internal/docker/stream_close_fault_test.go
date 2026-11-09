package docker

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

type closeFaultBody struct {
	entered      chan struct{}
	closed       chan struct{}
	closeRelease chan struct{}
	enterOnce    sync.Once
	closeOnce    sync.Once
}

func (b *closeFaultBody) Read([]byte) (int, error) {
	b.enterOnce.Do(func() { close(b.entered) })
	<-b.closed
	return 0, io.ErrClosedPipe
}
func (b *closeFaultBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	<-b.closeRelease
	return nil
}

// Hold Close after it interrupts Read, but before stream unregistration. This
// forces the canceled Next result to cross the guard while its parent is live.
func TestEnteredCloseFaultPreservesHealthyProof(t *testing.T) {
	for _, tty := range []bool{false, true} {
		for _, cancelNext := range []bool{false, true} {
			ctx := context.Background()
			body := &closeFaultBody{entered: make(chan struct{}), closed: make(chan struct{}), closeRelease: make(chan struct{})}
			base := newFakeDaemonTransport()
			base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
			base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Tty: tty})
			a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: body}})
			if err != nil {
				t.Fatal(err)
			}
			if err = a.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			peer, unregister, err := a.safety.RegisterStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
			s, err := a.Logs(ctx, target, LogOptions{Stdout: true, Follow: true})
			if err != nil {
				t.Fatal(err)
			}
			nextCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { _, e := s.Next(nextCtx); done <- e }()
			<-body.entered
			closeDone := make(chan struct{})
			if cancelNext {
				cancel()
				close(closeDone)
			} else {
				go func() { _ = s.Close(); close(closeDone) }()
			}
			select {
			case err = <-done:
				if err == nil {
					t.Error("closed entered read succeeded")
				}
			case <-time.After(time.Second):
				close(body.closeRelease)
				_ = body.Close()
				if err = <-done; err == nil {
					t.Error("terminated read succeeded")
				}
				t.Fatal("local close did not interrupt body I/O")
			}
			close(body.closeRelease)
			<-closeDone
			cancel()
			if !a.Ready() || peer.Err() != nil || a.Start(ctx, target) != nil {
				t.Errorf("local close/cancel mislabeled as daemon loss: tty=%v cancelNext=%v", tty, cancelNext)
			}
			_ = s.Close()
			unregister()
			_ = a.Close()
		}
	}
}
