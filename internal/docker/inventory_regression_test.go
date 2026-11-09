package docker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type logBodyTransport struct {
	base *fakeDaemonTransport
	body io.ReadCloser
}

func (tr *logBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/logs") {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: tr.body, Request: req}, nil
	}
	return tr.base.RoundTrip(req)
}

func TestIdleEnteredLogReadCanceledByInventoryWatcher(t *testing.T) {
	base := newFakeDaemonTransport()
	base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
	base.putContainer(fakeDaemonContainer{ID: string(testApp1ID)})
	body := &reviewerBlockingBody{entered: make(chan struct{}), release: make(chan struct{})}
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: &logBodyTransport{base: base, body: body}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err = a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream, err := a.Logs(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}, LogOptions{Stdout: true, Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	done := make(chan error, 1)
	go func() { _, err := stream.Next(context.Background()); done <- err }()
	<-body.entered
	base.mu.Lock()
	base.failList = errors.New("synthetic inventory loss")
	base.mu.Unlock()
	select {
	case err := <-done:
		if err == nil {
			t.Error("revoked read returned success")
		}
	case <-time.After(4 * time.Second):
		_ = body.Close()
		if err := <-done; err == nil {
			t.Error("terminated read returned success")
		}
		t.Fatal("entered idle read survived inventory loss")
	}
	if a.Ready() {
		t.Error("inventory loss did not invalidate proof")
	}
}

func TestMalformedInventoryCannotEstablishProof(t *testing.T) {
	a, tr := reviewerAdapter(t, reviewerProof())
	tr.putContainer(fakeDaemonContainer{ID: "malformed", Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
	if err := a.VerifySelf(context.Background()); err == nil || a.Ready() {
		t.Error("incomplete identity inventory accepted")
	}
	if err := a.Start(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}); err == nil {
		t.Error("incomplete proof admitted operation")
	}
	if a.Counters().TotalOperational() != 0 {
		t.Error("incomplete proof dispatched")
	}
}
