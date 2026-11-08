package docker

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// SDKOptions configures the official moby/client SDK adapter.
// Transport is mandatory so the adapter never implicitly uses ambient environment
// variables or a default host socket.
type SDKOptions struct {
	EndpointID     domain.EndpointID
	Host           string
	Transport      http.RoundTripper
	ExpectedDaemon string
	Identity       SelfIdentityConfig
}

// OperationalCounters records SDK call counts separated between internal safety
// metadata reads and operational container calls.
type OperationalCounters struct {
	SafetyListCalls     int64
	SafetyInspectCalls  int64
	OperationalInspects int64
	OperationalLogs     int64
	OperationalStarts   int64
	OperationalStops    int64
	OperationalRestarts int64
}

func (c OperationalCounters) TotalOperational() int64 {
	return c.OperationalInspects + c.OperationalLogs + c.OperationalStarts + c.OperationalStops + c.OperationalRestarts
}

// SDKAdapter implements DockerBackend using the official github.com/moby/moby/client SDK.
type SDKAdapter struct {
	endpointID           domain.EndpointID
	expectedDaemon       string
	cli                  *client.Client
	safety               *SafetyMonitor
	mu                   sync.RWMutex
	negotiatedAPIVersion string

	safetyListCalls     atomic.Int64
	safetyInspectCalls  atomic.Int64
	operationalInspects atomic.Int64
	operationalLogs     atomic.Int64
	operationalStarts   atomic.Int64
	operationalStops    atomic.Int64
	operationalRestarts atomic.Int64
}

var _ DockerBackend = (*SDKAdapter)(nil)

func NewSDKAdapter(opts SDKOptions) (*SDKAdapter, error) {
	epID, err := domain.ParseEndpointID(string(opts.EndpointID))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if opts.Transport == nil {
		return nil, ErrInvalidConfig
	}
	idCfg := opts.Identity
	if idCfg.EndpointID == "" {
		idCfg.EndpointID = epID
	} else if idCfg.EndpointID != epID {
		return nil, ErrInvalidConfig
	}

	safety, err := NewSafetyMonitor(idCfg)
	if err != nil {
		return nil, err
	}

	host := strings.TrimSpace(opts.Host)
	if host == "" {
		host = "http://docker.example.internal"
	}

	httpClient := &http.Client{
		Transport: opts.Transport,
	}

	cli, err := client.New(
		client.WithHost(host),
		client.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, ErrInvalidConfig
	}

	return &SDKAdapter{
		endpointID:     epID,
		expectedDaemon: strings.TrimSpace(opts.ExpectedDaemon),
		cli:            cli,
		safety:         safety,
	}, nil
}

func (a *SDKAdapter) EndpointID() domain.EndpointID {
	return a.endpointID
}

func (a *SDKAdapter) Ready() bool {
	return a.safety.Ready()
}

func (a *SDKAdapter) VerificationState() VerificationState {
	return a.safety.State()
}

func (a *SDKAdapter) InvalidateSafety() {
	a.safety.Invalidate()
}

func (a *SDKAdapter) Counters() OperationalCounters {
	return OperationalCounters{
		SafetyListCalls:     a.safetyListCalls.Load(),
		SafetyInspectCalls:  a.safetyInspectCalls.Load(),
		OperationalInspects: a.operationalInspects.Load(),
		OperationalLogs:     a.operationalLogs.Load(),
		OperationalStarts:   a.operationalStarts.Load(),
		OperationalStops:    a.operationalStops.Load(),
		OperationalRestarts: a.operationalRestarts.Load(),
	}
}

func (a *SDKAdapter) NegotiatedAPIVersion() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.negotiatedAPIVersion
}

func (a *SDKAdapter) Close() error {
	a.safety.Close()
	if a.cli != nil {
		_ = a.cli.Close()
	}
	return nil
}

func compareAPIVersion(v1, v2 string) (int, error) {
	maj1, min1, err := parseMajorMinor(v1)
	if err != nil {
		return 0, err
	}
	maj2, min2, err := parseMajorMinor(v2)
	if err != nil {
		return 0, err
	}
	if maj1 != maj2 {
		return cmp.Compare(maj1, maj2), nil
	}
	return cmp.Compare(min1, min2), nil
}

func parseMajorMinor(v string) (int, int, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(v), "v")
	majStr, minStr, ok := strings.Cut(trimmed, ".")
	if !ok || majStr == "" || minStr == "" {
		return 0, 0, ErrUnsupportedAPIVersion
	}
	maj, err := strconv.Atoi(majStr)
	if err != nil || maj < 0 {
		return 0, 0, ErrUnsupportedAPIVersion
	}
	min, err := strconv.Atoi(minStr)
	if err != nil || min < 0 {
		return 0, 0, ErrUnsupportedAPIVersion
	}
	return maj, min, nil
}

func (a *SDKAdapter) VerifySelf(ctx context.Context) error {
	epoch := a.safety.beginVerification()
	pingRes, err := a.cli.Ping(ctx, client.PingOptions{
		NegotiateAPIVersion: true,
		ForceNegotiate:      true,
	})
	if strings.TrimSpace(pingRes.APIVersion) != "" {
		if c, vErr := compareAPIVersion(pingRes.APIVersion, MinEngineAPIVersion); vErr != nil || c < 0 {
			a.safety.Invalidate()
			return ErrUnsupportedAPIVersion
		}
	}
	if err != nil {
		a.safety.Invalidate()
		return SanitizeError(err)
	}

	if strings.TrimSpace(pingRes.APIVersion) == "" {
		a.safety.Invalidate()
		return ErrUnsupportedAPIVersion
	}
	negotiated := a.cli.ClientVersion()
	if c, vErr := compareAPIVersion(negotiated, MinEngineAPIVersion); vErr != nil || c < 0 {
		a.safety.Invalidate()
		return ErrUnsupportedAPIVersion
	}

	infoRes, err := a.cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		a.safety.Invalidate()
		return SanitizeError(err)
	}
	daemonID := strings.TrimSpace(infoRes.Info.ID)
	if daemonID == "" || (a.expectedDaemon != "" && daemonID != a.expectedDaemon) {
		a.safety.Invalidate()
		return ErrUnverified
	}

	listItems, err := a.safetyListContainers(ctx)
	if err != nil {
		a.safety.Invalidate()
		return err
	}

	candidates := make([]SafetyCandidate, 0, len(listItems))
	for _, item := range listItems {
		cid, cErr := ParseContainerID(item.ID)
		if cErr != nil {
			a.safety.Invalidate()
			return ErrUnverified
		}
		candidates = append(candidates, SafetyCandidate{
			ID:     cid,
			Labels: item.Labels,
		})
	}

	err = a.safety.verifyAt(ctx, epoch, daemonID, candidates, func(cid ContainerID) (SafetyCandidate, error) {
		raw, iErr := a.safetyInspectContainer(ctx, cid)
		if iErr != nil {
			return SafetyCandidate{}, iErr
		}
		var startedAt string
		if raw.State != nil {
			startedAt = raw.State.StartedAt
		}
		var labels map[string]string
		if raw.Config != nil {
			labels = raw.Config.Labels
		}
		parsedID, pErr := ParseContainerID(raw.ID)
		if pErr != nil {
			return SafetyCandidate{}, pErr
		}
		return SafetyCandidate{
			ID:        parsedID,
			Created:   raw.Created,
			StartedAt: startedAt,
			Labels:    labels,
		}, nil
	})
	if err != nil {
		a.safety.Invalidate()
		return ErrUnverified
	}

	a.mu.Lock()
	a.negotiatedAPIVersion = negotiated
	a.mu.Unlock()
	return nil
}

func (a *SDKAdapter) safetyListContainers(ctx context.Context) ([]container.Summary, error) {
	a.safetyListCalls.Add(1)
	res, err := a.cli.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		a.safety.Invalidate()
		return nil, SanitizeError(err)
	}
	return res.Items, nil
}

func (a *SDKAdapter) safetyInspectContainer(ctx context.Context, cid ContainerID) (container.InspectResponse, error) {
	a.safetyInspectCalls.Add(1)
	res, err := a.cli.ContainerInspect(ctx, string(cid), client.ContainerInspectOptions{})
	if err != nil {
		return container.InspectResponse{}, a.operationError(err)
	}
	return res.Container, nil
}

func (a *SDKAdapter) verifySelfContinuity(ctx context.Context) error {
	epoch := a.safety.currentEpoch()
	selfID, ok := a.safety.SelfContainerID()
	if !ok {
		return ErrUnverified
	}
	infoRes, err := a.cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		a.safety.Invalidate()
		return ErrUnverified
	}
	rawSelf, err := a.safetyInspectContainer(ctx, selfID)
	if err != nil {
		a.safety.Invalidate()
		return ErrUnverified
	}
	var startedAt string
	if rawSelf.State != nil {
		startedAt = rawSelf.State.StartedAt
	}
	var labels map[string]string
	if rawSelf.Config != nil {
		labels = rawSelf.Config.Labels
	}
	parsedID, err := ParseContainerID(rawSelf.ID)
	if err != nil {
		a.safety.Invalidate()
		return ErrUnverified
	}
	if err := a.safety.VerifyContinuity(strings.TrimSpace(infoRes.Info.ID), SafetyCandidate{
		ID:        parsedID,
		Created:   rawSelf.Created,
		StartedAt: startedAt,
		Labels:    labels,
	}); err != nil {
		return err
	}
	items, err := a.safetyListContainers(ctx)
	if err != nil {
		return err
	}
	candidates := make([]SafetyCandidate, 0, len(items))
	for _, item := range items {
		candidates = append(candidates, SafetyCandidate{ID: ContainerID(item.ID), Labels: item.Labels})
	}
	if err := a.safety.VerifyInventory(candidates); err != nil {
		return err
	}
	return a.safety.requireEpoch(epoch)
}

func (a *SDKAdapter) verifyTargetForOperation(ctx context.Context, target TargetIdentity) (container.InspectResponse, error) {
	epoch := a.safety.currentEpoch()
	if !a.safety.Ready() {
		return container.InspectResponse{}, ErrUnverified
	}
	if target.EndpointID != a.endpointID {
		return container.InspectResponse{}, ErrEndpointMismatch
	}
	cid, err := ParseContainerID(string(target.ContainerID))
	if err != nil {
		return container.InspectResponse{}, ErrInvalidTarget
	}
	if a.safety.IsProtected(cid) {
		return container.InspectResponse{}, ErrProtectedTarget
	}

	if err := a.verifySelfContinuity(ctx); err != nil {
		return container.InspectResponse{}, err
	}

	rawTarget, err := a.safetyInspectContainer(ctx, cid)
	if err != nil {
		return container.InspectResponse{}, err
	}
	var targetLabels map[string]string
	if rawTarget.Config != nil {
		targetLabels = rawTarget.Config.Labels
	}
	if HasProtectedNamespaceLabel(targetLabels) || a.safety.IsProtected(cid) {
		a.safety.MarkProtected(cid)
		return container.InspectResponse{}, ErrProtectedTarget
	}
	if err := a.safety.requireEpoch(epoch); err != nil {
		return container.InspectResponse{}, err
	}
	return rawTarget, nil
}

func (a *SDKAdapter) ListContainers(ctx context.Context) ([]ContainerSummary, error) {
	if !a.safety.Ready() {
		return nil, ErrUnverified
	}
	if err := a.verifySelfContinuity(ctx); err != nil {
		return nil, err
	}
	items, err := a.safetyListContainers(ctx)
	if err != nil {
		return nil, err
	}
	var out []ContainerSummary
	for _, item := range items {
		cid, cErr := ParseContainerID(item.ID)
		if cErr != nil {
			continue
		}
		if HasProtectedNamespaceLabel(item.Labels) || a.safety.IsProtected(cid) {
			a.safety.MarkProtected(cid)
			continue
		}
		summary, sErr := SanitizeContainerSummary(a.endpointID, item)
		if sErr != nil {
			continue
		}
		out = append(out, summary)
	}
	slices.SortFunc(out, func(x, y ContainerSummary) int {
		if c := cmp.Compare(x.Name, y.Name); c != 0 {
			return c
		}
		return cmp.Compare(string(x.ContainerID), string(y.ContainerID))
	})
	return out, nil
}

func (a *SDKAdapter) ResolveTarget(ctx context.Context, nameOrID string) (ContainerSummary, error) {
	if !a.safety.Ready() {
		return ContainerSummary{}, ErrUnverified
	}
	cleaned := normalizeContainerName(nameOrID)
	if cleaned == "" {
		return ContainerSummary{}, ErrInvalidTarget
	}
	if cid, err := ParseContainerID(cleaned); err == nil && a.safety.IsProtected(cid) {
		return ContainerSummary{}, ErrProtectedTarget
	}
	if err := a.verifySelfContinuity(ctx); err != nil {
		return ContainerSummary{}, err
	}

	items, err := a.safetyListContainers(ctx)
	if err != nil {
		return ContainerSummary{}, err
	}

	for _, item := range items {
		cid, cErr := ParseContainerID(item.ID)
		if cErr != nil {
			continue
		}
		matches := string(cid) == cleaned
		if !matches {
			for _, n := range item.Names {
				if normalizeContainerName(n) == cleaned {
					matches = true
					break
				}
			}
		}
		if !matches {
			continue
		}
		if HasProtectedNamespaceLabel(item.Labels) || a.safety.IsProtected(cid) {
			a.safety.MarkProtected(cid)
			return ContainerSummary{}, ErrProtectedTarget
		}
		return SanitizeContainerSummary(a.endpointID, item)
	}

	return ContainerSummary{}, ErrTargetNotFound
}

func (a *SDKAdapter) InspectStatus(ctx context.Context, target TargetIdentity) (InspectStatus, error) {
	raw, err := a.verifyTargetForOperation(ctx, target)
	if err != nil {
		return InspectStatus{}, err
	}
	a.operationalInspects.Add(1)
	return SanitizeInspectStatus(a.endpointID, raw)
}

func (a *SDKAdapter) InspectConfig(ctx context.Context, target TargetIdentity) (InspectConfig, error) {
	raw, err := a.verifyTargetForOperation(ctx, target)
	if err != nil {
		return InspectConfig{}, err
	}
	a.operationalInspects.Add(1)
	return SanitizeInspectConfig(a.endpointID, raw)
}

func (a *SDKAdapter) Logs(ctx context.Context, target TargetIdentity, opts LogOptions) (LogStream, error) {
	normOpts, err := ValidateLogOptions(opts)
	if err != nil {
		return nil, err
	}
	raw, err := a.verifyTargetForOperation(ctx, target)
	if err != nil {
		return nil, err
	}

	streamCtx, unregister, err := a.safety.RegisterStream(ctx)
	if err != nil {
		return nil, err
	}

	sdkOpts := client.ContainerLogsOptions{
		ShowStdout: normOpts.Stdout,
		ShowStderr: normOpts.Stderr,
		Timestamps: normOpts.Timestamps,
		Follow:     normOpts.Follow,
		Tail:       strconv.Itoa(normOpts.Tail),
	}
	if !normOpts.Since.IsZero() {
		sdkOpts.Since = normOpts.Since.UTC().Format(time.RFC3339Nano)
	}
	if !normOpts.Until.IsZero() {
		sdkOpts.Until = normOpts.Until.UTC().Format(time.RFC3339Nano)
	}

	a.operationalLogs.Add(1)
	rc, err := a.cli.ContainerLogs(streamCtx, string(target.ContainerID), sdkOpts)
	if err != nil {
		unregister()
		return nil, a.operationError(err)
	}

	var isTTY bool
	if raw.Config != nil {
		isTTY = raw.Config.Tty
	}

	stream := newSDKLogStream(streamCtx, rc, unregister, isTTY, normOpts.Follow)
	return guardLogStream(streamCtx, stream, a.verifySelfContinuity, a.operationError), nil
}

func (a *SDKAdapter) Start(ctx context.Context, target TargetIdentity) error {
	if _, err := a.verifyTargetForOperation(ctx, target); err != nil {
		return err
	}
	a.operationalStarts.Add(1)
	_, err := a.cli.ContainerStart(ctx, string(target.ContainerID), client.ContainerStartOptions{})
	return a.operationError(err)
}

// operationError never lets uncertain I/O preserve a cached safety proof.
func (a *SDKAdapter) operationError(err error) error {
	return a.safety.operationError(err)
}

func (a *SDKAdapter) Stop(ctx context.Context, target TargetIdentity, opts StopOptions) error {
	timeoutSec, err := ValidateStopTimeout(opts.TimeoutSeconds)
	if err != nil {
		return err
	}
	if _, err := a.verifyTargetForOperation(ctx, target); err != nil {
		return err
	}
	a.operationalStops.Add(1)
	_, err = a.cli.ContainerStop(ctx, string(target.ContainerID), client.ContainerStopOptions{
		Timeout: &timeoutSec,
	})
	return a.operationError(err)
}

func (a *SDKAdapter) Restart(ctx context.Context, target TargetIdentity, opts RestartOptions) error {
	timeoutSec, err := ValidateStopTimeout(opts.TimeoutSeconds)
	if err != nil {
		return err
	}
	if _, err := a.verifyTargetForOperation(ctx, target); err != nil {
		return err
	}
	a.operationalRestarts.Add(1)
	_, err = a.cli.ContainerRestart(ctx, string(target.ContainerID), client.ContainerRestartOptions{
		Timeout: &timeoutSec,
	})
	return a.operationError(err)
}

type sdkLogStream struct {
	ctx        context.Context
	rc         io.ReadCloser
	reader     *bufio.Reader
	unregister func()
	tty        bool
	follow     bool
	mu         sync.Mutex
	readMu     sync.Mutex
	closeOnce  sync.Once
	cancel     context.CancelFunc
	totalBytes int64
	readBuf    []byte
	closed     atomic.Bool
}

func newSDKLogStream(ctx context.Context, rc io.ReadCloser, unregister func(), tty, follow bool) *sdkLogStream {
	ctx, cancel := context.WithCancel(ctx)
	s := &sdkLogStream{
		ctx:        ctx,
		cancel:     cancel,
		rc:         rc,
		reader:     bufio.NewReaderSize(rc, 32*1024),
		unregister: unregister,
		tty:        tty,
		follow:     follow,
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s
}

func (s *sdkLogStream) Next(ctx context.Context) (LogFrame, error) {
	// Closing the body must interrupt I/O independently of the parser lock.
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return LogFrame{}, SanitizeError(ctx.Err())
	case <-s.ctx.Done():
		_ = s.Close()
		return LogFrame{}, ErrUnverified
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		if s.ctx.Err() != nil {
			return LogFrame{}, ErrUnverified
		}
		return LogFrame{}, io.EOF
	}

	var frame LogFrame
	var err error
	if s.tty {
		frame, err = s.nextTTYFrameLocked()
	} else {
		frame, err = s.nextMultiplexedFrameLocked()
	}
	if errors.Is(err, ErrLogLimitExceeded) || errors.Is(err, ErrBackendFailed) {
		return LogFrame{}, err
	}
	if ctx.Err() != nil {
		_ = s.Close()
		return LogFrame{}, SanitizeError(ctx.Err())
	}
	if s.ctx.Err() != nil || s.closed.Load() {
		return LogFrame{}, ErrUnverified
	}
	return frame, err
}

func (s *sdkLogStream) nextTTYFrameLocked() (LogFrame, error) {
	// TTY output has no Docker framing or guaranteed newline. Read bounded raw
	// chunks, never ReadLine (which strips CRLF and invents final newlines).
	size := MaxLogFrameBytes
	if !s.follow {
		size = int(min(int64(size), MaxLogResponseBytes-s.totalBytes+1))
	}
	payload := make([]byte, size)
	// Do not add a buffering layer here: bufio can defer an observed body
	// error when the remaining response allowance makes this a small read.
	n, err := s.rc.Read(payload)
	if err != nil && !errors.Is(err, io.EOF) {
		// A read may report both data and connection loss. Do not acknowledge
		// that data (or mask the fault with a limit error) before invalidation.
		return LogFrame{}, SanitizeError(err)
	}
	if !s.follow && s.totalBytes+int64(n) > MaxLogResponseBytes {
		_ = s.Close()
		return LogFrame{}, ErrLogLimitExceeded
	}
	if n == 0 && errors.Is(err, io.EOF) {
		return LogFrame{}, io.EOF
	}
	s.totalBytes += int64(n)
	return LogFrame{Stream: LogStreamStdout, Payload: payload[:n]}, nil
}

func (s *sdkLogStream) nextMultiplexedFrameLocked() (LogFrame, error) {
	var hdr [8]byte
	_, err := io.ReadFull(s.reader, hdr[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			if s.ctx.Err() != nil {
				return LogFrame{}, ErrUnverified
			}
			return LogFrame{}, io.EOF
		}
		if s.ctx.Err() != nil {
			return LogFrame{}, ErrUnverified
		}
		return LogFrame{}, SanitizeError(err)
	}

	var streamType LogStreamType
	switch hdr[0] {
	case 1:
		streamType = LogStreamStdout
	case 2:
		streamType = LogStreamStderr
	default:
		_ = s.Close()
		return LogFrame{}, ErrBackendFailed
	}

	frameSize := binary.BigEndian.Uint32(hdr[4:8])
	if frameSize > MaxLogFrameBytes {
		_ = s.Close()
		return LogFrame{}, ErrLogLimitExceeded
	}
	if !s.follow && s.totalBytes+int64(frameSize) > MaxLogResponseBytes {
		_ = s.Close()
		return LogFrame{}, ErrLogLimitExceeded
	}

	payload := make([]byte, int(frameSize))
	if _, err := io.ReadFull(s.reader, payload); err != nil {
		if s.ctx.Err() != nil {
			return LogFrame{}, ErrUnverified
		}
		return LogFrame{}, SanitizeError(err)
	}
	s.totalBytes += int64(frameSize)

	return LogFrame{
		Stream:  streamType,
		Payload: payload,
	}, nil
}

func (s *sdkLogStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.ctx.Err() != nil || s.closed.Load() {
		s.readBuf = nil
		return 0, ErrUnverified
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.readBuf) == 0 {
		frame, err := s.Next(s.ctx)
		if err != nil {
			return 0, err
		}
		s.readBuf = frame.Payload
	}
	if s.ctx.Err() != nil || s.closed.Load() {
		s.readBuf = nil
		return 0, ErrUnverified
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *sdkLogStream) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.cancel()
		if s.rc != nil {
			_ = s.rc.Close()
		}
		if s.unregister != nil {
			s.unregister()
		}
	})
	return nil
}
