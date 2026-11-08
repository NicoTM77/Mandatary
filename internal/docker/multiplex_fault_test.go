package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// Unlike review376Body, preserve any bytes not consumed by a short read. This
// exercises an exactly filled io.ReadFull request as well as bufio prefetch.
type terminalFaultBody struct {
	payload []byte
}

func (b *terminalFaultBody) Read(p []byte) (int, error) {
	n := copy(p, b.payload)
	b.payload = b.payload[n:]
	if len(b.payload) == 0 {
		return n, errors.New("synthetic terminal connection fault")
	}
	return n, nil
}
func (b *terminalFaultBody) Close() error { return nil }

func TestMultiplexFaultPrecedesFramingAndLimits(t *testing.T) {
	for _, mode := range []string{"exact-header", "exact-large-payload", "prefetched-frames", "oversize-header", "response-limit"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			wire := encodeMultiplexedFrame(1, []byte("ordinary log"))
			switch mode {
			case "exact-header":
				wire = encodeMultiplexedFrame(1, nil)
			case "exact-large-payload":
				wire = encodeMultiplexedFrame(1, bytes.Repeat([]byte{'x'}, MaxLogFrameBytes))
			case "prefetched-frames":
				wire = append(wire, wire...)
			case "oversize-header":
				wire = make([]byte, 8)
				wire[0] = 1
				binary.BigEndian.PutUint32(wire[4:], MaxLogFrameBytes+1)
			}
			base := newFakeDaemonTransport()
			base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
			base.putContainer(fakeDaemonContainer{ID: string(testApp1ID)})
			a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: &terminalFaultBody{payload: wire}}})
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
			s, err := a.Logs(ctx, target, LogOptions{Stdout: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			if mode == "response-limit" {
				s.(*safetyLogStream).inner.(*sdkLogStream).totalBytes = MaxLogResponseBytes
			}
			f, err := s.Next(ctx)
			if len(f.Payload) != 0 || !errors.Is(err, ErrBackendFailed) {
				t.Errorf("body fault masked by framing/limit: %v", err)
			}
			if a.Ready() || peer.Err() == nil {
				t.Error("observed body fault did not synchronously revoke proof/peers")
			}
			before := a.Counters().TotalOperational()
			if err = a.Start(ctx, target); !errors.Is(err, ErrUnverified) || a.Counters().TotalOperational() != before {
				t.Error("new dispatch admitted without fresh proof")
			}
		})
	}
}

func TestMultiplexCoReturnedHealthyEOF(t *testing.T) {
	// Complete frames co-returned with EOF are healthy, including an exactly
	// filled payload request and multiple prefetched frames. EOF is not a fault.
	for _, size := range []int{0, 12, MaxLogFrameBytes} {
		ctx := context.Background()
		payload := bytes.Repeat([]byte{'x'}, size)
		wire := encodeMultiplexedFrame(1, payload)
		s := newSDKLogStream(ctx, &eofPayloadBody{payload: wire}, nil, false, false, nil)
		f, err := s.Next(ctx)
		if err != nil || !bytes.Equal(f.Payload, payload) {
			t.Errorf("healthy frame denied/changed at size %d: %v", size, err)
		}
		if _, err = s.Next(ctx); !errors.Is(err, io.EOF) {
			t.Errorf("healthy EOF changed at size %d: %v", size, err)
		}
		_ = s.Close()
	}
}

type eofPayloadBody struct{ payload []byte }

func (b *eofPayloadBody) Read(p []byte) (int, error) {
	n := copy(p, b.payload)
	b.payload = b.payload[n:]
	if len(b.payload) == 0 {
		return n, io.EOF
	}
	return n, nil
}
func (b *eofPayloadBody) Close() error { return nil }
