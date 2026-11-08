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

func truncatedHTTPBody(t *testing.T) io.ReadCloser {
	t.Helper()
	// Separate headers/body to prevent header prefetch, and declare enough
	// remaining bytes for net/http's LimitedReader to bypass its bufio buffer.
	// Otherwise a small read can defer the body's EOF until a later call.
	wire := io.MultiReader(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"),
		&review376Body{payload: []byte("ordinary log"), fault: io.EOF})
	resp, err := http.ReadResponse(bufio.NewReader(wire), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Body
}

func TestParsedHTTPFaultTiming(t *testing.T) {
	// Prove the first-delivery fixture actually reports bytes+error. A single
	// strings.Reader instead lets ReadResponse prefetch bytes: its first body
	// read is healthy and only the second observes truncation.
	b := truncatedHTTPBody(t)
	defer func() { _ = b.Close() }()
	if n, err := b.Read(make([]byte, MaxLogFrameBytes)); n == 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("first read did not report bytes and truncation: n=%d err=%v", n, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nordinary log")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if n, err := resp.Body.Read(make([]byte, MaxLogFrameBytes)); n == 0 || err != nil {
		t.Fatalf("prefetched first read: n=%d err=%v", n, err)
	}
	if _, err := resp.Body.Read(make([]byte, MaxLogFrameBytes)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("prefetched second read: %v", err)
	}
}

func TestTTYFaultDeniesDeliveryCancelsPeersAndRequiresFreshProof(t *testing.T) {
	for _, source := range []string{"bytes-and-error", "parsed-http"} {
		for _, api := range []string{"Next", "Read"} {
			t.Run(source+"/"+api, func(t *testing.T) {
				ctx := context.Background()
				base := newFakeDaemonTransport()
				base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
				base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Tty: true})
				var body io.ReadCloser = &review376Body{payload: []byte("ordinary log"), fault: errors.New("synthetic read connection loss")}
				if source == "parsed-http" {
					body = truncatedHTTPBody(t)
				}
				a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: body}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = a.Close() }()
				if err = a.VerifySelf(ctx); err != nil {
					t.Fatal(err)
				}
				peerCtx, unregister, err := a.safety.RegisterStream(ctx)
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
					f, err := s.Next(ctx)
					if len(f.Payload) != 0 || !errors.Is(err, ErrBackendFailed) {
						t.Error("fault-bearing frame acknowledged")
					}
				} else {
					buf := bytes.Repeat([]byte{'?'}, 20)
					n, err := s.Read(buf)
					if n != 0 || !errors.Is(err, ErrBackendFailed) || !bytes.Equal(buf, bytes.Repeat([]byte{'?'}, 20)) {
						t.Error("fault-bearing bytes delivered to caller")
					}
				}
				if a.Ready() || peerCtx.Err() == nil {
					t.Error("observed fault did not synchronously invalidate proof and cancel peer")
				}
				before := a.Counters().TotalOperational()
				if err = a.Start(ctx, target); !errors.Is(err, ErrUnverified) || a.Counters().TotalOperational() != before {
					t.Error("operation admitted without fresh proof")
				}
				if err = a.VerifySelf(ctx); err != nil {
					t.Fatal(err)
				}
				if err = a.Start(ctx, target); err != nil {
					t.Fatal("fresh explicit proof did not recover")
				}
				if n, err := s.Read(make([]byte, 20)); n != 0 || err == nil {
					t.Error("old stream recovered after re-verification")
				}
			})
		}
	}
}

func TestTTYSmallRemainingReadCannotHideFault(t *testing.T) {
	for _, remaining := range []int64{0, 8, 100} {
		ctx := context.Background()
		s := newSDKLogStream(ctx, &review376Body{payload: []byte("ordinary log"), fault: errors.New("synthetic read connection loss")}, nil, true, false)
		s.totalBytes = MaxLogResponseBytes - remaining
		f, err := s.Next(ctx)
		_ = s.Close()
		if len(f.Payload) != 0 || !errors.Is(err, ErrBackendFailed) {
			t.Errorf("observed body fault hidden near response cap, remaining=%d err=%v", remaining, err)
		}
	}
}

func TestTTYBytesWithHealthyEOFRemainUsable(t *testing.T) {
	ctx := context.Background()
	base := newFakeDaemonTransport()
	base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
	base.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Tty: true})
	payload := []byte("ordinary\r\nfinal fragment")
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &review376Transport{base: base, body: &review376Body{payload: payload, fault: io.EOF}}})
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
	f, err := s.Next(ctx)
	if err != nil || !bytes.Equal(f.Payload, payload) {
		t.Fatal("healthy bytes with EOF changed or denied")
	}
	if _, err = s.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatal("healthy EOF not preserved")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if !a.Ready() || a.Start(ctx, target) != nil {
		t.Error("healthy EOF/local close invalidated daemon proof")
	}
}
