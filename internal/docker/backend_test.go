package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

func TestOperationParameterBounds(t *testing.T) {
	approved := []Operation{
		OpLogs,
		OpInspectStatus,
		OpInspectConfig,
		OpStart,
		OpStop,
		OpRestart,
	}
	for _, op := range approved {
		if err := ValidateOperation(op); err != nil {
			t.Errorf("ValidateOperation(%q) unexpected error: %v", op, err)
		}
	}

	prohibited := []Operation{
		"",
		"container:exec",
		"container:attach",
		"container:create",
		"container:delete",
		"container:rm",
		"container:copy",
		"image:pull",
		"volume:create",
		"network:create",
		"swarm:init",
	}
	for _, op := range prohibited {
		if err := ValidateOperation(op); !errors.Is(err, ErrUnsupportedOperation) {
			t.Errorf("ValidateOperation(%q) = %v, want %v", op, err, ErrUnsupportedOperation)
		}
	}

	// LogOptions validation
	normLogs, err := ValidateLogOptions(LogOptions{Stdout: true})
	if err != nil {
		t.Fatalf("ValidateLogOptions default tail failed: %v", err)
	}
	if normLogs.Tail != DefaultLogTail {
		t.Errorf("default Tail = %d, want %d", normLogs.Tail, DefaultLogTail)
	}

	invalidLogCases := []struct {
		name string
		opts LogOptions
	}{
		{name: "neither stdout nor stderr", opts: LogOptions{Tail: 100}},
		{name: "tail_all true", opts: LogOptions{Stdout: true, TailAll: true}},
		{name: "negative tail", opts: LogOptions{Stdout: true, Tail: -1}},
		{name: "tail above 10000", opts: LogOptions{Stdout: true, Tail: MaxLogTail + 1}},
		{
			name: "until before since",
			opts: LogOptions{
				Stdout: true,
				Since:  time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC),
				Until:  time.Date(2026, 11, 8, 11, 0, 0, 0, time.UTC),
			},
		},
	}
	for _, tc := range invalidLogCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateLogOptions(tc.opts); !errors.Is(err, ErrInvalidParameter) {
				t.Fatalf("ValidateLogOptions(%+v) = %v, want %v", tc.opts, err, ErrInvalidParameter)
			}
		})
	}

	// Stop/Restart timeout validation
	defTimeout, err := ValidateStopTimeout(nil)
	if err != nil || defTimeout != DefaultStopTimeoutSeconds {
		t.Fatalf("ValidateStopTimeout(nil) = (%d, %v), want (%d, nil)", defTimeout, err, DefaultStopTimeoutSeconds)
	}
	for _, validSec := range []int{MinStopTimeoutSeconds, 10, MaxStopTimeoutSeconds} {
		v := validSec
		got, err := ValidateStopTimeout(&v)
		if err != nil || got != validSec {
			t.Errorf("ValidateStopTimeout(%d) = (%d, %v), want (%d, nil)", validSec, got, err, validSec)
		}
	}
	for _, invalidSec := range []int{-1, 0, MaxStopTimeoutSeconds + 1, 9999} {
		v := invalidSec
		if _, err := ValidateStopTimeout(&v); !errors.Is(err, ErrInvalidParameter) {
			t.Errorf("ValidateStopTimeout(%d) = %v, want %v", invalidSec, err, ErrInvalidParameter)
		}
	}
}

func TestEngineAPINegotiationAndMinimum144(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)

	rejectedVersions := []string{"", "1.24", "1.40", "1.43", "invalid"}
	for _, ver := range rejectedVersions {
		t.Run("reject_api_"+ver, func(t *testing.T) {
			tr := newFakeDaemonTransport()
			tr.apiVersion = ver
			tr.putContainer(fakeDaemonContainer{
				ID:     string(testSelfID),
				Name:   "mandatary",
				Labels: map[string]string{SelfLabelKey: SelfLabelValue},
			})

			adapter, err := NewSDKAdapter(SDKOptions{
				EndpointID: epID,
				Transport:  tr,
				Identity: SelfIdentityConfig{
					EndpointID:          epID,
					ExplicitContainerID: string(testSelfID),
					EvidenceReader: func(context.Context) (ProcessEvidence, error) {
						return ProcessEvidence{ContainerID: string(testSelfID)}, nil
					},
				},
			})
			if err != nil {
				t.Fatalf("NewSDKAdapter: %v", err)
			}
			if err := adapter.VerifySelf(ctx); !errors.Is(err, ErrUnsupportedAPIVersion) {
				t.Fatalf("VerifySelf with API version %q = %v, want %v", ver, err, ErrUnsupportedAPIVersion)
			}
			if adapter.Ready() {
				t.Fatalf("adapter must not be ready when API version %q is rejected", ver)
			}
			if got := adapter.Counters().TotalOperational(); got != 0 {
				t.Fatalf("TotalOperational() = %d, want 0", got)
			}
		})
	}

	acceptedVersions := []string{"1.44", "1.46", "1.56"}
	for _, ver := range acceptedVersions {
		t.Run("accept_api_"+ver, func(t *testing.T) {
			tr := newFakeDaemonTransport()
			tr.apiVersion = ver
			tr.putContainer(fakeDaemonContainer{
				ID:     string(testSelfID),
				Name:   "mandatary",
				Labels: map[string]string{SelfLabelKey: SelfLabelValue},
			})

			adapter, err := NewSDKAdapter(SDKOptions{
				EndpointID: epID,
				Transport:  tr,
				Identity: SelfIdentityConfig{
					EndpointID:          epID,
					ExplicitContainerID: string(testSelfID),
					EvidenceReader: func(context.Context) (ProcessEvidence, error) {
						return ProcessEvidence{ContainerID: string(testSelfID)}, nil
					},
				},
			})
			if err != nil {
				t.Fatalf("NewSDKAdapter: %v", err)
			}
			if err := adapter.VerifySelf(ctx); err != nil {
				t.Fatalf("VerifySelf with API version %q failed: %v", ver, err)
			}
			if adapter.NegotiatedAPIVersion() == "" {
				t.Fatalf("expected non-empty NegotiatedAPIVersion")
			}
		})
	}
}

func TestSDKAdapterAllowedOperationsAndBounds(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()

	var logBuf bytes.Buffer
	logBuf.Write(encodeMultiplexedFrame(1, []byte("stdout-line-1\n")))
	logBuf.Write(encodeMultiplexedFrame(2, []byte("stderr-line-1\n")))

	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:    string(testApp1ID),
		Name:  "payments-api",
		Image: "ghcr.io/example/payments:v1.2.3",
		Labels: map[string]string{
			"com.docker.compose.project": "commerce",
			"com.docker.compose.service": "payments",
		},
		Env:  []string{"PORT=9090", "API_SECRET=super-secret-canary"},
		Cmd:  []string{"/bin/payments", "--port=9090"},
		Logs: logBuf.Bytes(),
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	resolved, err := adapter.ResolveTarget(ctx, "payments-api")
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if resolved.ContainerID != testApp1ID || resolved.ComposeProject != "commerce" || resolved.ComposeService != "payments" {
		t.Fatalf("unexpected resolved summary: %+v", resolved)
	}

	target, err := ParseTargetIdentity(epID, string(resolved.ContainerID))
	if err != nil {
		t.Fatalf("ParseTargetIdentity: %v", err)
	}

	// Endpoint mismatch must fail closed with zero operational calls.
	otherEp, _ := domain.ParseEndpointID("99999999-2222-4333-8444-555555555555")
	if _, err := adapter.InspectStatus(ctx, TargetIdentity{EndpointID: otherEp, ContainerID: testApp1ID}); !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("InspectStatus endpoint mismatch = %v, want %v", err, ErrEndpointMismatch)
	}
	// Invalid parameter must fail closed before operational dispatch.
	badTimeout := 0
	if err := adapter.Stop(ctx, target, StopOptions{TimeoutSeconds: &badTimeout}); !errors.Is(err, ErrInvalidParameter) {
		t.Fatalf("Stop(timeout=0) = %v, want %v", err, ErrInvalidParameter)
	}
	if got := adapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("expected 0 operational calls after rejected pre-checks, got %d", got)
	}

	status, err := adapter.InspectStatus(ctx, target)
	if err != nil {
		t.Fatalf("InspectStatus: %v", err)
	}
	if status.Name != "payments-api" || !status.Running {
		t.Fatalf("unexpected InspectStatus: %+v", status)
	}

	cfg, err := adapter.InspectConfig(ctx, target)
	if err != nil {
		t.Fatalf("InspectConfig: %v", err)
	}
	if strings.Contains(strings.Join(cfg.Env, ","), "super-secret-canary") {
		t.Fatal("InspectConfig leaked secret env value")
	}

	stream, err := adapter.Logs(ctx, target, LogOptions{Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	f1, err := stream.Next(ctx)
	if err != nil || f1.Stream != LogStreamStdout || string(f1.Payload) != "stdout-line-1\n" {
		t.Fatalf("frame 1 = (%+v, %v)", f1, err)
	}
	f2, err := stream.Next(ctx)
	if err != nil || f2.Stream != LogStreamStderr || string(f2.Payload) != "stderr-line-1\n" {
		t.Fatalf("frame 2 = (%+v, %v)", f2, err)
	}
	if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after 2 frames, got %v", err)
	}
	_ = stream.Close()

	if err := adapter.Stop(ctx, target, StopOptions{}); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if tr.lastTimeout != "10" {
		t.Errorf("default Stop timeout query 't' = %q, want %q", tr.lastTimeout, "10")
	}
	if err := adapter.Start(ctx, target); err != nil {
		t.Fatalf("Start: %v", err)
	}
	customTimeout := 25
	if err := adapter.Restart(ctx, target, RestartOptions{TimeoutSeconds: &customTimeout}); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if tr.lastTimeout != "25" {
		t.Errorf("custom Restart timeout query 't' = %q, want %q", tr.lastTimeout, "25")
	}

	// Oversized log frame (> 64 KiB) must fail closed with ErrLogLimitExceeded.
	oversizedHeader := make([]byte, 8)
	oversizedHeader[0] = 1
	oversizedHeader[4] = 0
	oversizedHeader[5] = 2 // 128 KiB > 64 KiB
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp2ID),
		Name: "noisy-app",
		Logs: oversizedHeader,
	})
	noisyTarget := TargetIdentity{EndpointID: epID, ContainerID: testApp2ID}
	noisyStream, err := adapter.Logs(ctx, noisyTarget, LogOptions{Stdout: true})
	if err != nil {
		t.Fatalf("Logs(noisy): %v", err)
	}
	if _, err := noisyStream.Next(ctx); !errors.Is(err, ErrLogLimitExceeded) {
		t.Fatalf("oversized log frame Next() = %v, want %v", err, ErrLogLimitExceeded)
	}
	_ = noisyStream.Close()

	// Non-follow response cap (> 4 MiB across multiple 32 KiB frames) must fail closed.
	var bulkBuf bytes.Buffer
	chunk := bytes.Repeat([]byte("a"), 32*1024)
	for i := 0; i < 130; i++ { // 130 * 32 KiB > 4 MiB
		bulkBuf.Write(encodeMultiplexedFrame(1, chunk))
	}
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp2ID),
		Name: "noisy-app",
		Logs: bulkBuf.Bytes(),
	})
	bulkStream, err := adapter.Logs(ctx, noisyTarget, LogOptions{Stdout: true})
	if err != nil {
		t.Fatalf("Logs(bulk): %v", err)
	}
	var gotLimitErr bool
	for i := 0; i < 135; i++ {
		_, rErr := bulkStream.Next(ctx)
		if errors.Is(rErr, ErrLogLimitExceeded) {
			gotLimitErr = true
			break
		}
		if rErr != nil {
			t.Fatalf("unexpected error before response cap: %v", rErr)
		}
	}
	_ = bulkStream.Close()
	if !gotLimitErr {
		t.Fatal("expected ErrLogLimitExceeded when non-follow log stream exceeds 4 MiB")
	}

	// Systemerr stream frame (type 3) must fail closed with redacted ErrBackendFailed.
	sysErrFrame := encodeMultiplexedFrame(3, []byte("daemon systemerr with CANARY_SYSERR_SECRET"))
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp2ID),
		Name: "noisy-app",
		Logs: sysErrFrame,
	})
	sysErrStream, err := adapter.Logs(ctx, noisyTarget, LogOptions{Stdout: true, Stderr: true})
	if err != nil {
		t.Fatalf("Logs(syserr): %v", err)
	}
	_, sysErr := sysErrStream.Next(ctx)
	if !errors.Is(sysErr, ErrBackendFailed) {
		t.Fatalf("Systemerr frame Next() = %v, want %v", sysErr, ErrBackendFailed)
	}
	if strings.Contains(sysErr.Error(), "CANARY_SYSERR_SECRET") {
		t.Fatal("Systemerr error leaked raw frame payload")
	}
	_ = sysErrStream.Close()

	// TTY raw stream mode and io.ReadAll compatibility.
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp2ID),
		Name: "noisy-app",
		Tty:  true,
		Logs: []byte("tty-line-1\ntty-line-2\n"),
	})
	ttyStream, err := adapter.Logs(ctx, noisyTarget, LogOptions{Stdout: true})
	if err != nil {
		t.Fatalf("Logs(tty): %v", err)
	}
	ttyBytes, err := io.ReadAll(ttyStream)
	if err != nil {
		t.Fatalf("io.ReadAll(ttyStream): %v", err)
	}
	if string(ttyBytes) != "tty-line-1\ntty-line-2\n" {
		t.Fatalf("ttyStream ReadAll = %q, want %q", string(ttyBytes), "tty-line-1\ntty-line-2\n")
	}
	_ = ttyStream.Close()

	// Transport error during operational call must be sanitized without leaking socket/URL details.
	tr.mu.Lock()
	tr.failOp = errors.New("dial unix /var/run/docker.sock: secret CANARY_TRANSPORT_OP_ERR")
	tr.mu.Unlock()
	opErr := adapter.Start(ctx, target)
	if !errors.Is(opErr, ErrBackendFailed) {
		t.Fatalf("Start with transport failure = %v, want %v", opErr, ErrBackendFailed)
	}
	if strings.Contains(opErr.Error(), "CANARY_TRANSPORT_OP_ERR") || strings.Contains(opErr.Error(), "docker.sock") {
		t.Fatal("operational transport error leaked raw error text")
	}
	tr.mu.Lock()
	tr.failOp = nil
	tr.mu.Unlock()
}

func TestMockBackendFullLifecycleAndFaultInjection(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	idCfg, fixtures := DefaultMockFixtures(epID)

	mock, err := NewMockBackend(MockOptions{
		EndpointID: epID,
		Identity:   idCfg,
		Containers: fixtures,
	})
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	defer func() { _ = mock.Close() }()

	if err := mock.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	containers, err := mock.ListContainers(ctx)
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) < 3 {
		t.Fatalf("expected at least 3 non-protected sample containers, got %d", len(containers))
	}

	resolved, err := mock.ResolveTarget(ctx, containers[0].Name)
	if err != nil {
		t.Fatalf("ResolveTarget(%q): %v", containers[0].Name, err)
	}
	target := TargetIdentity{EndpointID: epID, ContainerID: resolved.ContainerID}

	if err := mock.Stop(ctx, target, StopOptions{}); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	st, err := mock.InspectStatus(ctx, target)
	if err != nil {
		t.Fatalf("InspectStatus after Stop: %v", err)
	}
	if st.Running || st.State != "exited" {
		t.Fatalf("expected stopped state after Stop, got %+v", st)
	}

	if err := mock.Start(ctx, target); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st, err = mock.InspectStatus(ctx, target)
	if err != nil || !st.Running || st.State != "running" {
		t.Fatalf("expected running state after Start, got (%+v, %v)", st, err)
	}

	if err := mock.Restart(ctx, target, RestartOptions{}); err != nil {
		t.Fatalf("Restart: %v", err)
	}

	cfg, err := mock.InspectConfig(ctx, target)
	if err != nil {
		t.Fatalf("InspectConfig: %v", err)
	}
	for _, env := range cfg.Env {
		if strings.Contains(env, "CANARY") || strings.Contains(env, "mdt_") {
			t.Fatalf("unredacted secret in mock InspectConfig env: %q", env)
		}
	}

	// Follow log stream and AppendLog
	logCtx, cancel := context.WithCancel(ctx)
	stream, err := mock.Logs(logCtx, target, LogOptions{Stdout: true, Stderr: true, Follow: true, Tail: 1})
	if err != nil {
		t.Fatalf("Logs follow: %v", err)
	}
	mock.AppendLog(target.ContainerID, MockLogLine{
		Timestamp: time.Now().UTC(),
		Stream:    LogStreamStdout,
		Line:      "followed-event-line\n",
	})
	var sawFollowed bool
	for i := 0; i < 4; i++ {
		frame, fErr := stream.Next(logCtx)
		if fErr != nil {
			t.Fatalf("stream.Next: %v", fErr)
		}
		if strings.Contains(string(frame.Payload), "followed-event-line") {
			sawFollowed = true
			break
		}
	}
	if !sawFollowed {
		t.Fatal("did not receive appended follow log line")
	}
	cancel()
	_ = stream.Close()

	// Fault injection
	mock.SetOperationFailure(OpRestart, ErrBackendUnavailable)
	if err := mock.Restart(ctx, target, RestartOptions{}); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Restart with fault injection = %v, want %v", err, ErrBackendUnavailable)
	}
	mock.SetOperationFailure(OpRestart, nil)

	// Event discontinuity simulation invalidates safety
	mock.SimulateEventDiscontinuity()
	if mock.Ready() || mock.VerificationState() != StateUnverified {
		t.Fatal("expected SimulateEventDiscontinuity to transition mock to UNVERIFIED")
	}
}
