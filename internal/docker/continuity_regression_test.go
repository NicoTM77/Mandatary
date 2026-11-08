package docker

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestActiveStreamsRecheckDeploymentOverlap(t *testing.T) {
	for _, which := range []string{"sdk", "mock"} {
		t.Run(which, func(t *testing.T) {
			ctx := context.Background()
			cfg := SelfIdentityConfig{InstanceUUID: testSelfUUID, EvidenceReader: func(context.Context) (ProcessEvidence, error) { return ProcessEvidence{PrivateCgroupNS: true}, nil }}
			var b DockerBackend
			var overlap, remove func()
			if which == "sdk" {
				a, tr := reviewerAdapter(t, cfg)
				b = a
				tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Logs: encodeMultiplexedFrame(1, []byte("ordinary buffered log\n"))})
				overlap = func() {
					tr.putContainer(fakeDaemonContainer{ID: string(testPeerID), Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}})
				}
				remove = func() { tr.mu.Lock(); delete(tr.containers, string(testPeerID)); tr.mu.Unlock() }
			} else {
				ep := mustEndpointID(t)
				cfg.EndpointID = ep
				m, err := NewMockBackend(MockOptions{EndpointID: ep, Identity: cfg, Containers: []MockContainerFixture{{ID: testSelfID, Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}}, {ID: testApp1ID, Logs: []MockLogLine{{Stream: LogStreamStdout, Line: "ordinary buffered log\n"}}}}})
				if err != nil {
					t.Fatal(err)
				}
				b = m
				overlap = func() {
					if err := m.UpsertContainer(MockContainerFixture{ID: testPeerID, Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}}); err != nil {
						t.Error(err)
					}
				}
				remove = func() { m.RemoveContainer(testPeerID) }
			}
			defer func() { _ = b.Close() }()
			if err := b.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			stream, err := b.Logs(ctx, TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID}, LogOptions{Stdout: true, Follow: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stream.Close() }()
			if n, err := stream.Read(make([]byte, 1)); n != 1 || err != nil {
				t.Fatal("first log byte failed")
			}
			overlap()
			if n, err := stream.Read(make([]byte, 20)); n != 0 || err == nil {
				t.Error("stream disclosed bytes after overlap")
			}
			if b.Ready() {
				t.Error("overlap left ready")
			}
			remove()
			if err := b.Start(ctx, TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID}); !errors.Is(err, ErrUnverified) {
				t.Error("proof resumed without resynchronization")
			}
			if err := b.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			if err := b.Start(ctx, TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID}); err != nil {
				t.Fatal("fresh proof did not restore ordinary dispatch")
			}
		})
	}
}

func TestIdleSDKStreamDetectsInventoryLoss(t *testing.T) {
	a, tr := reviewerAdapter(t, reviewerProof())
	tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), FollowCh: make(chan []byte)})
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream, err := a.Logs(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}, LogOptions{Stdout: true, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	tr.mu.Lock()
	tr.failList = errors.New("synthetic inventory loss")
	tr.mu.Unlock()
	// An idle stream must invalidate/cancel even with no consumer calls.
	// The fake pipe closes on the stream's context; awaiting it joins its writer.
	done := make(chan error, 1)
	go func() { _, err := stream.Next(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, io.EOF) {
			t.Error("inventory loss not denied")
		}
	case <-time.After(3 * time.Second):
		_ = stream.Close()
		if err := <-done; err == nil {
			t.Error("terminated read returned success")
		}
		t.Fatal("idle stream was not canceled")
	}
	if a.Ready() {
		t.Error("inventory loss left ready")
	}
}
