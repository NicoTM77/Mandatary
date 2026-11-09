package docker

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The body produces one complete Docker multiplex frame and a co-returned
// connection fault. First independently demonstrate that the actual body read
// reports the fault; do not require a second consumer read to observe it.
func review378FaultBody(t *testing.T, source string, wire []byte) io.ReadCloser {
	t.Helper()
	if source == "synthetic" {
		return &review376Body{payload: wire, fault: errors.New("synthetic connection loss")}
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(
		strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"),
		&review376Body{payload: wire, fault: io.EOF})), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Body
}

func TestReview378MultiplexBodyFaultAtFirstDelivery(t *testing.T) {
	for _, source := range []string{"synthetic", "parsed-http"} {
		for _, api := range []string{"Next", "Read"} {
			t.Run(source+"/"+api, func(t *testing.T) {
				ctx := context.Background()
				wire := encodeMultiplexedFrame(1, []byte("ordinary log"))
				// Multiplex parser's bufio reader requests 32KiB. This source really
				// returns a complete frame plus non-EOF error on precisely that first read.
				timing := review378FaultBody(t, source, wire)
				n, observed := timing.Read(make([]byte, 32*1024))
				_ = timing.Close()
				if n != len(wire) || observed == nil || errors.Is(observed, io.EOF) {
					t.Fatalf("invalid adverse fixture: n=%d err=%v", n, observed)
				}
				t.Logf("direct first 32KiB body read: n=%d non-EOF-error=%v", n, observed)
				base := newFakeDaemonTransport()
				base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
				base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Tty: false})
				a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: review378FaultBody(t, source, wire)}})
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
				if api == "Next" {
					frame, e := s.Next(ctx)
					if e == nil || len(frame.Payload) != 0 {
						t.Error("complete multiplex frame was delivered despite co-returned connection fault")
					}
				} else {
					buf := bytes.Repeat([]byte{'?'}, 32)
					n, e := s.Read(buf)
					if n != 0 || e == nil || !bytes.Equal(buf, bytes.Repeat([]byte{'?'}, 32)) {
						t.Error("multiplex bytes delivered to caller despite observed connection fault")
					}
				}
				if a.Ready() {
					t.Error("observed multiplex body connection fault left proof VERIFIED at first delivery")
				}
				if peer.Err() == nil {
					t.Error("observed multiplex fault did not cancel peer stream")
				}
				before := a.Counters().TotalOperational()
				_ = a.Start(ctx, target)
				if a.Counters().TotalOperational() != before {
					t.Error("Start dispatched after observed multiplex body fault without fresh VerifySelf")
				}
				if err = a.VerifySelf(ctx); err != nil {
					t.Fatal(err)
				}
				if err = a.Start(ctx, target); err != nil {
					t.Fatal("fresh explicit proof did not recover")
				}
				if f, e := s.Next(ctx); e == nil || len(f.Payload) != 0 {
					t.Error("revoked old frame stream recovered after fresh proof")
				}
				if n, e := s.Read(make([]byte, 32)); e == nil || n != 0 {
					t.Error("revoked old byte stream recovered after fresh proof")
				}
			})
		}
	}
}

func TestReview378HealthyMultiplexEOFAndClose(t *testing.T) {
	for _, api := range []string{"Next", "Read"} {
		t.Run(api, func(t *testing.T) {
			ctx := context.Background()
			wire := encodeMultiplexedFrame(1, []byte("ordinary log"))
			base := newFakeDaemonTransport()
			base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
			base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Tty: false})
			a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: io.NopCloser(bytes.NewReader(wire))}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = a.Close() }()
			if err = a.VerifySelf(ctx); err != nil {
				t.Fatal(err)
			}
			target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
			s, err := a.Logs(ctx, target, LogOptions{Stdout: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			if api == "Next" {
				f, e := s.Next(ctx)
				if e != nil || string(f.Payload) != "ordinary log" {
					t.Fatal("healthy multiplex frame changed or denied")
				}
			} else {
				buf := make([]byte, 32)
				n, e := s.Read(buf)
				if e != nil || string(buf[:n]) != "ordinary log" {
					t.Fatal("healthy multiplex bytes changed or denied")
				}
			}
			if _, e := s.Next(ctx); !errors.Is(e, io.EOF) {
				t.Fatal("healthy multiplex EOF changed")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			if !a.Ready() || a.Start(ctx, target) != nil {
				t.Error("healthy EOF/local Close invalidated proof")
			}
		})
	}
}
