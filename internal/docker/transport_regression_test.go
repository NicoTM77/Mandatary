package docker

import (
	"context"
	"errors"
	"testing"
)

func TestSDKFailuresCancelStreamsAndRequireFreshProof(t *testing.T) {
	for _, op := range []string{"list", "resolve", "inspect", "start", "stop", "restart", "logs"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			a, tr := reviewerAdapter(t, reviewerProof())
			tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Logs: encodeMultiplexedFrame(1, []byte("ordinary payload\n"))})
			if err := a.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
			s, err := a.Logs(ctx, target, LogOptions{Stdout: true, Follow: true})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if n, err := s.Read(make([]byte, 1)); n != 1 || err != nil {
				t.Fatal("first byte failed")
			}
			tr.mu.Lock()
			switch op {
			case "list", "resolve":
				tr.failList = errors.New("synthetic disconnect")
			case "inspect":
				tr.failInspect = errors.New("synthetic disconnect")
			default:
				tr.failOp = errors.New("synthetic disconnect")
			}
			tr.mu.Unlock()
			switch op {
			case "list":
				_, err = a.ListContainers(ctx)
			case "resolve":
				_, err = a.ResolveTarget(ctx, "ordinary")
			case "inspect":
				_, err = a.InspectConfig(ctx, target)
			case "start":
				err = a.Start(ctx, target)
			case "stop":
				err = a.Stop(ctx, target, StopOptions{})
			case "restart":
				err = a.Restart(ctx, target, RestartOptions{})
			case "logs":
				_, err = a.Logs(ctx, target, LogOptions{Stdout: true})
			}
			if err == nil || a.Ready() {
				t.Fatal("disconnect did not invalidate")
			}
			tr.mu.Lock()
			tr.failList = nil
			tr.failInspect = nil
			tr.failOp = nil
			tr.mu.Unlock()
			if n, err := s.Read(make([]byte, 20)); n != 0 || err == nil {
				t.Error("revoked buffered bytes survived disconnect")
			}
			before := a.Counters().TotalOperational()
			if err = a.Start(ctx, target); !errors.Is(err, ErrUnverified) {
				t.Error("disconnect recovered without VerifySelf")
			}
			if a.Counters().TotalOperational() != before {
				t.Error("stale proof dispatched")
			}
			if err = a.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			if err = a.Start(ctx, target); err != nil {
				t.Fatal("fresh proof did not recover")
			}
		})
	}
}

func TestKnownMissingTargetDoesNotInvalidateHealthyDaemon(t *testing.T) {
	a, _ := reviewerAdapter(t, reviewerProof())
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := a.Start(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp2ID})
	if !errors.Is(err, ErrTargetNotFound) || !a.Ready() {
		t.Error("logical missing-target denial poisoned healthy proof")
	}
	if a.Counters().TotalOperational() != 0 {
		t.Error("missing target dispatched")
	}
}
