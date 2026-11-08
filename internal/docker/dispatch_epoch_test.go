package docker

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type reverifyTargetTransport struct {
	base http.RoundTripper
	hook func()
	used atomic.Bool
}

func (tr *reverifyTargetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := tr.base.RoundTrip(req)
	if strings.HasSuffix(req.URL.Path, "/containers/"+string(testApp1ID)+"/json") && !tr.used.Swap(true) {
		tr.hook()
	}
	return resp, err
}

func TestTargetProofCannotCrossVerificationEpoch(t *testing.T) {
	base := newFakeDaemonTransport()
	base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
	base.putContainer(fakeDaemonContainer{ID: string(testApp1ID)})
	tr := &reverifyTargetTransport{base: base}
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err = a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr.hook = func() {
		a.InvalidateSafety()
		if err := a.VerifySelf(context.Background()); err != nil {
			t.Error(err)
		}
	}
	if err = a.Start(context.Background(), TargetIdentity{EndpointID: a.EndpointID(), ContainerID: testApp1ID}); err == nil {
		t.Error("target metadata from superseded proof admitted dispatch")
	}
	if a.Counters().TotalOperational() != 0 {
		t.Error("superseded target proof dispatched")
	}
}
