package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

func reviewerAdapter(t *testing.T, cfg SelfIdentityConfig) (*SDKAdapter, *fakeDaemonTransport) {
	t.Helper()
	ep := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{ID: string(testSelfID), Name: "self", Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}})
	tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Name: "ordinary"})
	a, err := NewSDKAdapter(SDKOptions{EndpointID: ep, Transport: tr, Identity: cfg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, tr
}
func reviewerProof() SelfIdentityConfig {
	return SelfIdentityConfig{ExplicitContainerID: string(testSelfID), EvidenceReader: func(context.Context) (ProcessEvidence, error) {
		return ProcessEvidence{ContainerID: string(testSelfID)}, nil
	}}
}

func TestReviewerBareExplicitIDCannotProveNativeIdentity(t *testing.T) {
	cfg := SelfIdentityConfig{ExplicitContainerID: string(testSelfID), EvidenceReader: func(context.Context) (ProcessEvidence, error) { return ProcessEvidence{}, nil }}
	a, _ := reviewerAdapter(t, cfg)
	err := a.VerifySelf(context.Background())
	if err == nil || a.Ready() {
		t.Error("bare explicit ID accepted without process evidence or deployment binding")
	}
	_ = a.Start(context.Background(), TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID})
	if a.Counters().TotalOperational() != 0 {
		t.Error("operational SDK call occurred under unproven native identity")
	}
	cfg.EndpointID = mustEndpointID(t)
	m, err := NewMockBackend(MockOptions{EndpointID: cfg.EndpointID, Identity: cfg, Containers: []MockContainerFixture{{ID: testSelfID, Labels: map[string]string{SelfLabelKey: SelfLabelValue}}, {ID: testApp1ID}}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.VerifySelf(context.Background()); err == nil || m.Ready() {
		t.Error("mock has the same bare-ID bypass")
	}
}

func TestReviewerInvalidationCannotBeOverwrittenByStaleVerify(t *testing.T) {
	cfg := reviewerProof()
	cfg.EndpointID = mustEndpointID(t)
	m, err := NewSafetyMonitor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.Verify(context.Background(), "daemon", nil, func(id ContainerID) (SafetyCandidate, error) {
			close(entered)
			<-release
			return SafetyCandidate{ID: id, Labels: map[string]string{SelfLabelKey: SelfLabelValue}}, nil
		})
	}()
	<-entered
	m.Invalidate()
	close(release)
	err = <-done
	if err == nil || m.Ready() {
		t.Error("verification begun before invalidation republished VERIFIED after invalidation")
	}
}

func TestReviewerTransportFailureInvalidatesProof(t *testing.T) {
	for _, stage := range []string{"inventory", "target-inspect", "operation"} {
		t.Run(stage, func(t *testing.T) {
			a, tr := reviewerAdapter(t, reviewerProof())
			if err := a.VerifySelf(context.Background()); err != nil {
				t.Fatal(err)
			}
			tr.mu.Lock()
			switch stage {
			case "inventory":
				tr.failList = errors.New("synthetic connection loss")
			case "target-inspect":
				tr.failInspect = errors.New("synthetic connection loss")
			case "operation":
				tr.failOp = errors.New("synthetic connection loss")
			}
			tr.mu.Unlock()
			target := TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID}
			var err error
			if stage == "inventory" {
				_, err = a.ListContainers(context.Background())
			} else {
				err = a.Start(context.Background(), target)
			}
			if err == nil {
				t.Fatal("fixture did not inject failure")
			}
			if a.Ready() {
				t.Error("connection loss leaves safety VERIFIED")
			}
			tr.mu.Lock()
			tr.failList = nil
			tr.failInspect = nil
			tr.failOp = nil
			tr.mu.Unlock()
			before := a.Counters().TotalOperational()
			_ = a.Start(context.Background(), target)
			if a.Counters().TotalOperational() != before {
				t.Error("new operational SDK call allowed after connection loss without fresh VerifySelf")
			}
		})
	}
}

func TestReviewerUUIDOverlapAfterVerificationDenies(t *testing.T) {
	cfg := SelfIdentityConfig{InstanceUUID: testSelfUUID, EvidenceReader: func(context.Context) (ProcessEvidence, error) { return ProcessEvidence{PrivateCgroupNS: true}, nil }}
	a, tr := reviewerAdapter(t, cfg)
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr.putContainer(fakeDaemonContainer{ID: string(testPeerID), Name: "replacement", Labels: map[string]string{SelfLabelKey: SelfLabelValue, SelfInstanceUUIDLabelKey: testSelfUUID}})
	err := a.Start(context.Background(), TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID})
	if err == nil || a.Ready() || a.Counters().TotalOperational() != 0 {
		t.Error("new duplicate deployment binding was not revalidated before operational dispatch")
	}
}

type reviewerBlockingBody struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	signal  sync.Once
}

func (b *reviewerBlockingBody) Read([]byte) (int, error) {
	b.signal.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *reviewerBlockingBody) Close() error { b.once.Do(func() { close(b.release) }); return nil }

func TestReviewerCloseInterruptsPendingSDKRead(t *testing.T) {
	b := &reviewerBlockingBody{entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newSDKLogStream(ctx, b, cancel, false, true)
	readDone := make(chan struct{})
	go func() { _, _ = s.Next(context.Background()); close(readDone) }()
	<-b.entered
	closeDone := make(chan struct{})
	go func() { _ = s.Close(); close(closeDone) }()
	blocked := false
	select {
	case <-closeDone:
	case <-time.After(200 * time.Millisecond):
		blocked = true
	}
	// Release independently to join both workers even when product Close deadlocks.
	_ = b.Close()
	<-readDone
	<-closeDone
	if blocked {
		t.Error("Close cannot acquire mutex held by a blocked Next; active body is not closed")
	}
}

func TestReviewerNextContextInterruptsPendingSDKRead(t *testing.T) {
	b := &reviewerBlockingBody{entered: make(chan struct{}), release: make(chan struct{})}
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	s := newSDKLogStream(parent, b, stop, false, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Next(ctx); done <- err }()
	<-b.entered
	cancel()
	blocked := false
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		blocked = true
	}
	_ = b.Close()
	if blocked {
		<-done
	}
	_ = s.Close()
	if blocked {
		t.Error("Next context cancellation is ignored once underlying read begins")
	}
}

func TestReviewerReadDoesNotServeBufferedBytesAfterInvalidation(t *testing.T) {
	for _, which := range []string{"sdk", "mock"} {
		t.Run(which, func(t *testing.T) {
			var stream LogStream
			var invalidate func()
			if which == "sdk" {
				cfg := reviewerProof()
				cfg.EndpointID = mustEndpointID(t)
				m, _ := NewSafetyMonitor(cfg)
				_ = m.Verify(context.Background(), "daemon", nil, func(id ContainerID) (SafetyCandidate, error) {
					return SafetyCandidate{ID: id, Labels: map[string]string{SelfLabelKey: SelfLabelValue}}, nil
				})
				ctx, unregister, err := m.RegisterStream(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				stream = newSDKLogStream(ctx, io.NopCloser(bytes.NewReader(encodeMultiplexedFrame(1, []byte("synthetic log payload\n")))), unregister, false, true)
				invalidate = m.Invalidate
			} else {
				ep := mustEndpointID(t)
				cfg, fixtures := DefaultMockFixtures(ep)
				m, err := NewMockBackend(MockOptions{EndpointID: ep, Identity: cfg, Containers: fixtures})
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				if err = m.VerifySelf(context.Background()); err != nil {
					t.Fatal(err)
				}
				stream, err = m.Logs(context.Background(), TargetIdentity{EndpointID: ep, ContainerID: testApp1ID}, LogOptions{Stdout: true, Follow: true})
				if err != nil {
					t.Fatal(err)
				}
				invalidate = m.InvalidateSafety
			}
			defer stream.Close()
			buf := make([]byte, 1)
			if n, err := stream.Read(buf); n != 1 || err != nil {
				t.Fatalf("first read failed: n=%d err=%v", n, err)
			}
			invalidate()
			if n, err := stream.Read(make([]byte, 64)); n > 0 || err == nil {
				t.Error("buffered log bytes returned after safety invalidation")
			}
		})
	}
}

func TestReviewerTTYValid40KiBAndExactBytes(t *testing.T) {
	for _, text := range []string{strings.Repeat("a", 40*1024) + "\n", "progress\r\nlast-fragment"} {
		t.Run("raw", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := newSDKLogStream(ctx, io.NopCloser(strings.NewReader(text)), cancel, true, false)
			defer s.Close()
			got, err := io.ReadAll(s)
			if err != nil {
				t.Errorf("valid raw output below 64KiB rejected: %v", err)
			}
			if string(got) != text {
				t.Error("raw TTY output bytes altered or lost")
			}
		})
	}
}

func TestReviewerSecretArgumentAndEntropyProjection(t *testing.T) {
	ep := mustEndpointID(t)
	token := "0123456789abcdef0123456789abcdef"
	raw := container.InspectResponse{ID: string(testApp1ID), Config: &container.Config{Cmd: []string{"--password", "short-value"}, Env: []string{"VALUE=/" + token}}}
	got, err := SanitizeInspectConfig(ep, raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(got.Cmd, " "), "short-value") {
		t.Error("split secret flag value preserved")
	}
	if strings.Contains(strings.Join(got.Env, " "), token) {
		t.Error("high entropy env value bypasses redaction when prefixed by slash")
	}
	labels := FilterSafeLabels(map[string]string{"org.opencontainers.image.source": "https://x/" + token})
	if strings.Contains(labels["org.opencontainers.image.source"], token) {
		t.Error("high entropy URL path bypasses safe-label value redaction")
	}
}

type reviewerTransport struct {
	base       *fakeDaemonTransport
	failTarget bool
}

func (tr *reviewerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if tr.failTarget && strings.HasSuffix(req.URL.Path, "/containers/"+string(testApp1ID)+"/json") {
		return nil, errors.New("synthetic target connection failure")
	}
	return tr.base.RoundTrip(req)
}
func TestReviewerTargetMetadataFailureInvalidatesProof(t *testing.T) {
	base := newFakeDaemonTransport()
	base.putContainer(fakeDaemonContainer{ID: string(testSelfID), Labels: map[string]string{SelfLabelKey: SelfLabelValue}})
	base.putContainer(fakeDaemonContainer{ID: string(testApp1ID)})
	tr := &reviewerTransport{base: base}
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Identity: reviewerProof(), Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err = a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr.failTarget = true
	err = a.Start(context.Background(), TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID})
	if err == nil {
		t.Fatal("fixture did not fail target metadata read")
	}
	if a.Ready() {
		t.Error("target metadata connection failure preserves VERIFIED")
	}
	if a.Counters().TotalOperational() != 0 {
		t.Error("rejected target reached operation")
	}
}

func TestReviewerHealthyProofAndSanitizerControls(t *testing.T) {
	a, _ := reviewerAdapter(t, reviewerProof())
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background(), TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testApp1ID}); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background(), TargetIdentity{EndpointID: mustEndpointID(t), ContainerID: testSelfID}); !errors.Is(err, ErrProtectedTarget) {
		t.Fatal("self protection control failed")
	}
	if a.Counters().TotalOperational() != 1 {
		t.Fatal("control operation count mismatch")
	}
	if SanitizeEnvEntry("VALUE=0123456789abcdef0123456789abcdef") != "VALUE="+redactedValue {
		t.Error("bare entropy control failed")
	}
	if SanitizeEnvEntry("PATH=/usr/bin:/bin") != "PATH=/usr/bin:/bin" {
		t.Error("safe PATH control failed")
	}
	if SanitizeArgument("--password=short-value") != "--password="+redactedValue {
		t.Error("inline secret control failed")
	}
}
