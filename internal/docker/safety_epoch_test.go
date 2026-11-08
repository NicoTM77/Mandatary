package docker

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestVerificationCannotOutliveSafetyChanges(t *testing.T) {
	for _, change := range []string{"config", "close", "newer-failed-verify"} {
		t.Run(change, func(t *testing.T) {
			ep := mustEndpointID(t)
			cfg, fixtures := DefaultMockFixtures(ep)
			entered, release := make(chan struct{}), make(chan struct{})
			cfg.EvidenceReader = func(context.Context) (ProcessEvidence, error) {
				close(entered)
				<-release
				return ProcessEvidence{ContainerID: string(MockSelfContainerID)}, nil
			}
			m, err := NewMockBackend(MockOptions{EndpointID: ep, Identity: cfg, Containers: fixtures})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Close() }()
			done := make(chan error, 1)
			go func() { done <- m.VerifySelf(context.Background()) }()
			<-entered
			switch change {
			case "config":
				m.SetIdentityConfig(SelfIdentityConfig{EndpointID: ep})
			case "close":
				_ = m.Close()
			case "newer-failed-verify":
				if err := m.safety.Verify(context.Background(), "", nil, nil); err == nil {
					t.Error("invalid newer proof accepted")
				}
			}
			close(release)
			if err := <-done; err == nil || m.Ready() {
				t.Error("old verification restored proof")
			}
			before := m.Counters().TotalOperational()
			if err := m.Start(context.Background(), TargetIdentity{EndpointID: ep, ContainerID: testApp1ID}); !errors.Is(err, ErrUnverified) {
				t.Error("dispatch admitted stale proof")
			}
			if m.Counters().TotalOperational() != before {
				t.Error("stale dispatch counted")
			}
		})
	}
}

type barrierTransport struct {
	base             http.RoundTripper
	entered, release chan struct{}
}

func (tr *barrierTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/containers/json") {
		close(tr.entered)
		<-tr.release
	}
	return tr.base.RoundTrip(req)
}
func TestSDKVerificationEpochStartsBeforeInventory(t *testing.T) {
	a, base := reviewerAdapter(t, reviewerProof())
	tr := &barrierTransport{base: base, entered: make(chan struct{}), release: make(chan struct{})}
	// Construct a new adapter with a barrier at the actual HTTP inventory boundary.
	b, err := NewSDKAdapter(SDKOptions{EndpointID: a.EndpointID(), Identity: reviewerProof(), Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	done := make(chan error, 1)
	go func() { done <- b.VerifySelf(context.Background()) }()
	<-tr.entered
	b.InvalidateSafety()
	close(tr.release)
	if err := <-done; err == nil || b.Ready() {
		t.Error("inventory work predating invalidation published proof")
	}
}
