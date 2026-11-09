package docker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type review376Body struct {
	mu      sync.Mutex
	used    bool
	payload []byte
	fault   error
}

func (b *review376Body) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used {
		return 0, io.EOF
	}
	b.used = true
	return copy(p, b.payload), b.fault
}
func (b *review376Body) Close() error { return nil }

type review376Transport struct {
	base *fakeDaemonTransport
	body io.ReadCloser
}

func (tr *review376Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/logs") {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: tr.body, Request: r}, nil
	}
	return tr.base.RoundTrip(r)
}

// Derived from independent review run376 (attachment21). The parsed HTTP
// fixture is corrected to observe bytes+error on the first body Read (see
// TestParsedHTTPFaultTiming). First-delivery denial assertions are unchanged.
func TestReview376StreamFaultCannotKeepProof(t *testing.T) {
	for _, mode := range []string{"tty-zero-byte-error", "tty-bytes-and-error", "tty-truncated-http", "multiplex-error-after-frame"} {
		t.Run(mode, func(t *testing.T) {
			base := newFakeDaemonTransport()
			base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
			tty := mode != "multiplex-error-after-frame"
			base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Tty: tty})
			payload := []byte(nil)
			if mode == "tty-bytes-and-error" {
				payload = []byte("ordinary log")
			}
			if !tty {
				payload = encodeMultiplexedFrame(1, []byte("ordinary log"))
			}
			var b io.ReadCloser = &review376Body{payload: payload, fault: errors.New("synthetic read connection loss")}
			if mode == "tty-truncated-http" {
				b = truncatedHTTPBody(t)
			}
			a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: b}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = a.Close() }()
			if err = a.VerifySelf(context.Background()); err != nil {
				t.Fatal(err)
			}
			target := TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}
			s, err := a.Logs(context.Background(), target, LogOptions{Stdout: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			_, first := s.Next(context.Background())
			if tty && a.Ready() {
				t.Error("observed TTY body read error did not revoke proof at first delivery")
				before := a.Counters().TotalOperational()
				_ = a.Start(context.Background(), target)
				if a.Counters().TotalOperational() != before {
					t.Error("operation dispatched after observed TTY body fault before another stream read")
				}
			}
			if first == nil {
				_, _ = s.Next(context.Background())
			}
			if a.Ready() {
				t.Error("underlying read connection error left safety verified")
			}
			before := a.Counters().TotalOperational()
			_ = a.Start(context.Background(), target)
			if a.Counters().TotalOperational() != before {
				t.Error("new operation dispatched after read connection error without fresh verification")
			}
		})
	}
}

func TestReview376StreamLocalCloseControl(t *testing.T) {
	a, tr := reviewerAdapter(t, reviewerProof())
	tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Logs: encodeMultiplexedFrame(1, []byte("ordinary log"))})
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err := a.Logs(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}, LogOptions{Stdout: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if !a.Ready() {
		t.Error("healthy consumer close must not invalidate daemon proof")
	}
}
