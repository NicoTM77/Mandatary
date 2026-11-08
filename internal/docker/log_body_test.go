package docker

import (
	"context"
	"errors"
	"testing"
)

func TestLogBodyFaultIsNotALogicalTargetDenial(t *testing.T) {
	// An error from a body Read is continuity loss, not a successful Docker
	// response describing a missing target/invalid argument. Never let a typed
	// transport error acquire the logical-request proof-preservation exception.
	for _, fault := range []error{ErrTargetNotFound, ErrInvalidParameter} {
		t.Run(fault.Error(), func(t *testing.T) {
			a, _ := reviewerAdapter(t, reviewerProof())
			ctx := context.Background()
			if err := a.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			peer, unregister, err := a.safety.RegisterStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer unregister()
			body := &sdkLogBody{ctx: ctx, reader: &review376Body{payload: []byte("ordinary log"), fault: fault}, onError: a.operationError}
			if n, err := body.Read(make([]byte, 32)); n != 0 || !errors.Is(err, ErrBackendFailed) {
				t.Error("body fault misclassified as logical denial")
			}
			if a.Ready() || peer.Err() == nil {
				t.Error("body fault preserved proof/peer stream")
			}
			if err := a.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			if n, err := body.Read(make([]byte, 32)); n != 0 || !errors.Is(err, ErrBackendFailed) {
				t.Error("fault latch disappeared after fresh proof")
			}
			if !a.Ready() {
				t.Error("rereading a latched old fault invalidated fresh proof")
			}
		})
	}
}
