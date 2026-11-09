package docker

import (
	"cmp"
	"context"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

const (
	MockSelfContainerID ContainerID = "1111111111111111111111111111111111111111111111111111111111111111"
	MockPeerContainerID ContainerID = "2222222222222222222222222222222222222222222222222222222222222222"
	MockSelfUUID                    = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	mockDefaultDaemonID             = "mock-daemon-00000001"
)

// MockContainerFixture defines a synthetic container in the in-memory mock backend.
type MockContainerFixture struct {
	ID            ContainerID
	Name          string
	Image         string
	ImageDigest   string
	State         string
	Status        string
	ExitCode      int
	HealthStatus  string
	FailingStreak int
	Created       string
	StartedAt     string
	FinishedAt    string
	Ports         []PortMapping
	Labels        map[string]string
	User          string
	WorkingDir    string
	Entrypoint    []string
	Cmd           []string
	Env           []string
	Mounts        []MountSummary
	Network       NetworkSummary
	Resources     ResourceLimits
	Logs          []MockLogLine
}

// MockLogLine is a single timestamped log line in the mock backend.
type MockLogLine struct {
	Timestamp time.Time
	Stream    LogStreamType
	Line      string
}

// MockOptions configures the container-free in-memory mock backend.
type MockOptions struct {
	EndpointID domain.EndpointID
	Identity   SelfIdentityConfig
	Containers []MockContainerFixture
}

// DefaultMockFixtures returns a realistic set of sample containers across states,
// including a synthetic Mandatary self container and a stopped peer container.
func DefaultMockFixtures(endpointID domain.EndpointID) (SelfIdentityConfig, []MockContainerFixture) {
	baseTime := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)

	idCfg := SelfIdentityConfig{
		EndpointID:          endpointID,
		ExplicitContainerID: string(MockSelfContainerID),
		InstanceUUID:        MockSelfUUID,
		EvidenceReader: func(context.Context) (ProcessEvidence, error) {
			return ProcessEvidence{ContainerID: string(MockSelfContainerID)}, nil
		},
	}

	fixtures := []MockContainerFixture{
		{
			ID:           MockSelfContainerID,
			Name:         "mandatary-self",
			Image:        "ghcr.io/nicotm77/mandatary:dev",
			ImageDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			State:        "running",
			Status:       "Up 2 hours (healthy)",
			HealthStatus: "healthy",
			Created:      baseTime.Format(time.RFC3339),
			StartedAt:    baseTime.Add(time.Second).Format(time.RFC3339),
			Labels: map[string]string{
				SelfLabelKey:             SelfLabelValue,
				SelfInstanceUUIDLabelKey: MockSelfUUID,
			},
			Env: []string{
				"MANDATARY_LISTEN_ADDR=127.0.0.1:8080",
				"MANDATARY_SECRET_KEY=CANARY_MOCK_SELF_SECRET",
			},
		},
		{
			ID:           MockPeerContainerID,
			Name:         "mandatary-peer-stopped",
			Image:        "ghcr.io/nicotm77/mandatary:dev",
			State:        "exited",
			Status:       "Exited (0) 3 hours ago",
			HealthStatus: "none",
			Created:      baseTime.Add(-4 * time.Hour).Format(time.RFC3339),
			StartedAt:    baseTime.Add(-4 * time.Hour).Format(time.RFC3339),
			FinishedAt:   baseTime.Add(-3 * time.Hour).Format(time.RFC3339),
			Labels: map[string]string{
				SelfLabelKey: SelfLabelValue,
			},
		},
		{
			ID:           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Name:         "edge-proxy",
			Image:        "nginx:1.27-alpine",
			ImageDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			State:        "running",
			Status:       "Up 2 hours (healthy)",
			HealthStatus: "healthy",
			Created:      baseTime.Format(time.RFC3339),
			StartedAt:    baseTime.Add(5 * time.Second).Format(time.RFC3339),
			Ports: []PortMapping{
				{ContainerPort: 80, Protocol: "tcp", HostIP: "127.0.0.1", HostPort: 8080},
			},
			Labels: map[string]string{
				"com.docker.compose.project":       "platform",
				"com.docker.compose.service":       "edge-proxy",
				"org.opencontainers.image.version": "1.27.2",
			},
			User:       "nginx",
			WorkingDir: "/etc/nginx",
			Entrypoint: []string{"/docker-entrypoint.sh"},
			Cmd:        []string{"nginx", "-g", "daemon off;"},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"NGINX_HOST=localhost",
				"UPSTREAM_API_SECRET=CANARY_MOCK_PROXY_SECRET",
				"MCP_TOKEN=mdt_mock_token_value_1234567890",
			},
			Network: NetworkSummary{
				NetworkMode: "bridge",
				Ports: []PortMapping{
					{ContainerPort: 80, Protocol: "tcp", HostIP: "127.0.0.1", HostPort: 8080},
				},
			},
			Resources: ResourceLimits{
				MemoryBytes:    268435456,
				NanoCPUs:       1000000000,
				ReadonlyRootfs: true,
			},
			Logs: []MockLogLine{
				{Timestamp: baseTime.Add(10 * time.Second), Stream: LogStreamStdout, Line: "nginx worker process started\n"},
				{Timestamp: baseTime.Add(20 * time.Second), Stream: LogStreamStderr, Line: "notice: configuration loaded\n"},
			},
		},
		{
			ID:            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Name:          "billing-worker",
			Image:         "ghcr.io/example/billing:v1.4.0",
			State:         "running",
			Status:        "Up 45 minutes (unhealthy)",
			HealthStatus:  "unhealthy",
			FailingStreak: 2,
			Created:       baseTime.Format(time.RFC3339),
			StartedAt:     baseTime.Add(15 * time.Minute).Format(time.RFC3339),
			Labels: map[string]string{
				"com.docker.compose.project": "platform",
				"com.docker.compose.service": "billing-worker",
			},
			Env: []string{
				"APP_ENV=staging",
				"DATABASE_PASSWORD=CANARY_MOCK_DB_PASSWORD",
			},
			Logs: []MockLogLine{
				{Timestamp: baseTime.Add(16 * time.Minute), Stream: LogStreamStdout, Line: "billing queue consumer connected\n"},
			},
		},
		{
			ID:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Name:         "batch-migrator",
			Image:        "ghcr.io/example/migrator:v1.4.0",
			State:        "exited",
			Status:       "Exited (0) 30 minutes ago",
			ExitCode:     0,
			HealthStatus: "none",
			Created:      baseTime.Format(time.RFC3339),
			StartedAt:    baseTime.Add(1 * time.Minute).Format(time.RFC3339),
			FinishedAt:   baseTime.Add(2 * time.Minute).Format(time.RFC3339),
			Labels: map[string]string{
				"com.docker.compose.project": "platform",
				"com.docker.compose.service": "batch-migrator",
			},
		},
		{
			ID:           "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Name:         "cache-redis",
			Image:        "redis:7.4-alpine",
			State:        "paused",
			Status:       "Up 1 hour (Paused)",
			HealthStatus: "healthy",
			Created:      baseTime.Format(time.RFC3339),
			StartedAt:    baseTime.Add(2 * time.Minute).Format(time.RFC3339),
			Labels: map[string]string{
				"com.docker.compose.project": "platform",
				"com.docker.compose.service": "cache-redis",
			},
		},
	}

	return idCfg, fixtures
}

// MockBackend is a deterministic, concurrency-safe in-memory DockerBackend that
// structurally cannot open any network or Unix socket.
type MockBackend struct {
	endpointID domain.EndpointID
	safety     *SafetyMonitor

	mu          sync.RWMutex
	daemonID    string
	containers  map[ContainerID]*MockContainerFixture
	opFailures  map[Operation]error
	subscribers map[ContainerID]map[uint64]chan MockLogLine
	nextSubID   uint64

	safetyListCalls     atomic.Int64
	safetyInspectCalls  atomic.Int64
	operationalInspects atomic.Int64
	operationalLogs     atomic.Int64
	operationalStarts   atomic.Int64
	operationalStops    atomic.Int64
	operationalRestarts atomic.Int64
}

var _ DockerBackend = (*MockBackend)(nil)

func NewMockBackend(opts MockOptions) (*MockBackend, error) {
	epID, err := domain.ParseEndpointID(string(opts.EndpointID))
	if err != nil {
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

	m := &MockBackend{
		endpointID:  epID,
		safety:      safety,
		daemonID:    mockDefaultDaemonID,
		containers:  make(map[ContainerID]*MockContainerFixture),
		opFailures:  make(map[Operation]error),
		subscribers: make(map[ContainerID]map[uint64]chan MockLogLine),
	}

	for _, c := range opts.Containers {
		if err := m.UpsertContainer(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func cloneFixture(c MockContainerFixture) *MockContainerFixture {
	cp := c
	cp.Name = normalizeContainerName(c.Name)
	if cp.Created == "" {
		cp.Created = "2026-11-08T09:00:00Z"
	}
	if cp.StartedAt == "" {
		cp.StartedAt = "2026-11-08T09:00:01Z"
	}
	if cp.State == "" {
		cp.State = "running"
	}
	if cp.HealthStatus == "" {
		cp.HealthStatus = "none"
	}
	cp.Ports = slices.Clone(c.Ports)
	cp.Labels = maps.Clone(c.Labels)
	cp.Entrypoint = slices.Clone(c.Entrypoint)
	cp.Cmd = slices.Clone(c.Cmd)
	cp.Env = slices.Clone(c.Env)
	cp.Mounts = slices.Clone(c.Mounts)
	cp.Network.Ports = slices.Clone(c.Network.Ports)
	cp.Network.Networks = slices.Clone(c.Network.Networks)
	cp.Resources.Ulimits = slices.Clone(c.Resources.Ulimits)
	cp.Logs = slices.Clone(c.Logs)
	return &cp
}

func (m *MockBackend) EndpointID() domain.EndpointID {
	return m.endpointID
}

func (m *MockBackend) Ready() bool {
	return m.safety.Ready()
}

func (m *MockBackend) VerificationState() VerificationState {
	return m.safety.State()
}

func (m *MockBackend) InvalidateSafety() {
	m.safety.Invalidate()
}

func (m *MockBackend) Counters() OperationalCounters {
	return OperationalCounters{
		SafetyListCalls:     m.safetyListCalls.Load(),
		SafetyInspectCalls:  m.safetyInspectCalls.Load(),
		OperationalInspects: m.operationalInspects.Load(),
		OperationalLogs:     m.operationalLogs.Load(),
		OperationalStarts:   m.operationalStarts.Load(),
		OperationalStops:    m.operationalStops.Load(),
		OperationalRestarts: m.operationalRestarts.Load(),
	}
}

func (m *MockBackend) Close() error {
	m.safety.Close()
	return nil
}

func (m *MockBackend) UpsertContainer(c MockContainerFixture) error {
	cid, err := ParseContainerID(string(c.ID))
	if err != nil {
		return err
	}
	c.ID = cid
	m.mu.Lock()
	m.containers[cid] = cloneFixture(c)
	m.mu.Unlock()
	return nil
}

func (m *MockBackend) RemoveContainer(id ContainerID) {
	m.mu.Lock()
	delete(m.containers, id)
	m.mu.Unlock()
}

func (m *MockBackend) AppendLog(id ContainerID, line MockLogLine) {
	m.mu.Lock()
	if c, ok := m.containers[id]; ok {
		c.Logs = append(c.Logs, line)
	}
	var subs []chan MockLogLine
	for _, ch := range m.subscribers[id] {
		subs = append(subs, ch)
	}
	m.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- line:
		default:
		}
	}
}

func (m *MockBackend) SetIdentityConfig(cfg SelfIdentityConfig) {
	m.safety.SetConfig(cfg)
}

func (m *MockBackend) SetOperationFailure(op Operation, err error) {
	m.mu.Lock()
	if err == nil {
		delete(m.opFailures, op)
	} else {
		m.opFailures[op] = err
	}
	m.mu.Unlock()
}

func (m *MockBackend) SimulateEventDiscontinuity() {
	m.safety.Invalidate()
}

func (m *MockBackend) VerifySelf(ctx context.Context) error {
	epoch := m.safety.beginVerification()
	m.safetyListCalls.Add(1)
	m.mu.RLock()
	daemonID := m.daemonID
	candidates := make([]SafetyCandidate, 0, len(m.containers))
	for _, c := range m.containers {
		candidates = append(candidates, SafetyCandidate{
			ID:        c.ID,
			Created:   c.Created,
			StartedAt: c.StartedAt,
			Labels:    maps.Clone(c.Labels),
		})
	}
	m.mu.RUnlock()

	return m.safety.verifyAt(ctx, epoch, daemonID, candidates, func(cid ContainerID) (SafetyCandidate, error) {
		m.safetyInspectCalls.Add(1)
		m.mu.RLock()
		defer m.mu.RUnlock()
		c, ok := m.containers[cid]
		if !ok {
			return SafetyCandidate{}, ErrTargetNotFound
		}
		return SafetyCandidate{
			ID:        c.ID,
			Created:   c.Created,
			StartedAt: c.StartedAt,
			Labels:    maps.Clone(c.Labels),
		}, nil
	})
}

func (m *MockBackend) verifySelfContinuity() error {
	epoch := m.safety.currentEpoch()
	selfID, ok := m.safety.SelfContainerID()
	if !ok {
		return ErrUnverified
	}
	m.safetyInspectCalls.Add(1)
	m.mu.RLock()
	daemonID := m.daemonID
	c, exists := m.containers[selfID]
	var cand SafetyCandidate
	if exists {
		cand = SafetyCandidate{
			ID:        c.ID,
			Created:   c.Created,
			StartedAt: c.StartedAt,
			Labels:    maps.Clone(c.Labels),
		}
	}
	all := make([]SafetyCandidate, 0, len(m.containers))
	for _, c := range m.containers {
		all = append(all, SafetyCandidate{ID: c.ID, Labels: maps.Clone(c.Labels)})
	}
	m.mu.RUnlock()
	if !exists {
		m.safety.Invalidate()
		return ErrUnverified
	}
	if err := m.safety.VerifyContinuity(daemonID, cand); err != nil {
		return err
	}
	if err := m.safety.VerifyInventory(all); err != nil {
		return err
	}
	return m.safety.requireEpoch(epoch)
}

func (m *MockBackend) verifyTargetForOperation(op Operation, target TargetIdentity) (*MockContainerFixture, error) {
	epoch := m.safety.currentEpoch()
	if err := ValidateOperation(op); err != nil {
		return nil, err
	}
	if !m.safety.Ready() {
		return nil, ErrUnverified
	}
	if target.EndpointID != m.endpointID {
		return nil, ErrEndpointMismatch
	}
	cid, err := ParseContainerID(string(target.ContainerID))
	if err != nil {
		return nil, ErrInvalidTarget
	}
	if m.safety.IsProtected(cid) {
		return nil, ErrProtectedTarget
	}
	if err := m.verifySelfContinuity(); err != nil {
		return nil, err
	}

	m.safetyInspectCalls.Add(1)
	m.mu.RLock()
	failErr := m.opFailures[op]
	c, ok := m.containers[cid]
	var cloned *MockContainerFixture
	if ok {
		cloned = cloneFixture(*c)
	}
	m.mu.RUnlock()

	if !ok {
		return nil, ErrTargetNotFound
	}
	if HasProtectedNamespaceLabel(cloned.Labels) || m.safety.IsProtected(cid) {
		m.safety.MarkProtected(cid)
		return nil, ErrProtectedTarget
	}
	if failErr != nil {
		return nil, m.safety.operationError(failErr)
	}
	if err := m.safety.requireEpoch(epoch); err != nil {
		return nil, err
	}
	return cloned, nil
}

func (m *MockBackend) summaryFromFixture(c *MockContainerFixture) ContainerSummary {
	safeLabels := FilterSafeLabels(c.Labels)
	var composeProject, composeService string
	if safeLabels != nil {
		composeProject = safeLabels["com.docker.compose.project"]
		composeService = safeLabels["com.docker.compose.service"]
	}
	return ContainerSummary{
		EndpointID:     m.endpointID,
		ContainerID:    c.ID,
		Name:           c.Name,
		State:          c.State,
		Status:         c.Status,
		Image:          c.Image,
		ImageDigest:    c.ImageDigest,
		ComposeProject: composeProject,
		ComposeService: composeService,
		Labels:         safeLabels,
	}
}

func (m *MockBackend) ListContainers(ctx context.Context) ([]ContainerSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, SanitizeError(err)
	}
	if !m.safety.Ready() {
		return nil, ErrUnverified
	}
	if err := m.verifySelfContinuity(); err != nil {
		return nil, err
	}

	m.safetyListCalls.Add(1)
	m.mu.RLock()
	var list []*MockContainerFixture
	for _, c := range m.containers {
		list = append(list, cloneFixture(*c))
	}
	m.mu.RUnlock()

	var out []ContainerSummary
	for _, c := range list {
		if HasProtectedNamespaceLabel(c.Labels) || m.safety.IsProtected(c.ID) {
			m.safety.MarkProtected(c.ID)
			continue
		}
		out = append(out, m.summaryFromFixture(c))
	}
	slices.SortFunc(out, func(a, b ContainerSummary) int {
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(string(a.ContainerID), string(b.ContainerID))
	})
	return out, nil
}

func (m *MockBackend) ResolveTarget(ctx context.Context, nameOrID string) (ContainerSummary, error) {
	if err := ctx.Err(); err != nil {
		return ContainerSummary{}, SanitizeError(err)
	}
	if !m.safety.Ready() {
		return ContainerSummary{}, ErrUnverified
	}
	cleaned := normalizeContainerName(nameOrID)
	if cleaned == "" {
		return ContainerSummary{}, ErrInvalidTarget
	}
	if cid, err := ParseContainerID(cleaned); err == nil && m.safety.IsProtected(cid) {
		return ContainerSummary{}, ErrProtectedTarget
	}
	if err := m.verifySelfContinuity(); err != nil {
		return ContainerSummary{}, err
	}

	m.safetyListCalls.Add(1)
	m.mu.RLock()
	var matched *MockContainerFixture
	for _, c := range m.containers {
		if string(c.ID) == cleaned || c.Name == cleaned {
			matched = cloneFixture(*c)
			break
		}
	}
	m.mu.RUnlock()

	if matched == nil {
		return ContainerSummary{}, ErrTargetNotFound
	}
	if HasProtectedNamespaceLabel(matched.Labels) || m.safety.IsProtected(matched.ID) {
		m.safety.MarkProtected(matched.ID)
		return ContainerSummary{}, ErrProtectedTarget
	}
	return m.summaryFromFixture(matched), nil
}

func (m *MockBackend) InspectStatus(ctx context.Context, target TargetIdentity) (InspectStatus, error) {
	if err := ctx.Err(); err != nil {
		return InspectStatus{}, SanitizeError(err)
	}
	c, err := m.verifyTargetForOperation(OpInspectStatus, target)
	if err != nil {
		return InspectStatus{}, err
	}
	m.operationalInspects.Add(1)
	return InspectStatus{
		EndpointID:        m.endpointID,
		ContainerID:       c.ID,
		Name:              c.Name,
		Image:             c.Image,
		ImageDigest:       c.ImageDigest,
		State:             c.State,
		Running:           c.State == "running",
		Paused:            c.State == "paused",
		Restarting:        c.State == "restarting",
		ExitCode:          c.ExitCode,
		HealthStatus:      c.HealthStatus,
		HealthFailingRuns: c.FailingStreak,
		StartedAt:         c.StartedAt,
		FinishedAt:        c.FinishedAt,
		Ports:             slices.Clone(c.Ports),
		Labels:            FilterSafeLabels(c.Labels),
	}, nil
}

func (m *MockBackend) InspectConfig(ctx context.Context, target TargetIdentity) (InspectConfig, error) {
	if err := ctx.Err(); err != nil {
		return InspectConfig{}, SanitizeError(err)
	}
	c, err := m.verifyTargetForOperation(OpInspectConfig, target)
	if err != nil {
		return InspectConfig{}, err
	}
	m.operationalInspects.Add(1)

	mounts := make([]MountSummary, 0, len(c.Mounts))
	for _, mt := range c.Mounts {
		mtCopy := mt
		mtCopy.Source = SanitizeArgument(mt.Source)
		mounts = append(mounts, mtCopy)
	}

	entrypoint, cmd := sanitizeCommand(c.Entrypoint, c.Cmd)
	return InspectConfig{
		EndpointID:  m.endpointID,
		ContainerID: c.ID,
		Name:        c.Name,
		Image:       c.Image,
		ImageDigest: c.ImageDigest,
		User:        c.User,
		WorkingDir:  c.WorkingDir,
		Entrypoint:  entrypoint,
		Cmd:         cmd,
		Env:         SanitizeEnvSlice(c.Env),
		Mounts:      mounts,
		Network:     c.Network,
		Resources:   c.Resources,
	}, nil
}

func (m *MockBackend) Logs(ctx context.Context, target TargetIdentity, opts LogOptions) (LogStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, SanitizeError(err)
	}
	normOpts, err := ValidateLogOptions(opts)
	if err != nil {
		return nil, err
	}
	c, err := m.verifyTargetForOperation(OpLogs, target)
	if err != nil {
		return nil, err
	}

	streamCtx, unregister, err := m.safety.RegisterStream(ctx)
	if err != nil {
		return nil, err
	}
	m.operationalLogs.Add(1)

	var filtered []MockLogLine
	for _, l := range c.Logs {
		if !matchesLogFilter(l, normOpts) {
			continue
		}
		filtered = append(filtered, l)
	}
	if len(filtered) > normOpts.Tail {
		filtered = filtered[len(filtered)-normOpts.Tail:]
	}

	var followCh chan MockLogLine
	var unsub func()
	if normOpts.Follow {
		followCh = make(chan MockLogLine, 64)
		m.mu.Lock()
		m.nextSubID++
		subID := m.nextSubID
		if m.subscribers[c.ID] == nil {
			m.subscribers[c.ID] = make(map[uint64]chan MockLogLine)
		}
		m.subscribers[c.ID][subID] = followCh
		m.mu.Unlock()

		unsub = func() {
			m.mu.Lock()
			if subs, ok := m.subscribers[c.ID]; ok {
				delete(subs, subID)
			}
			m.mu.Unlock()
		}
	}

	stream := &mockLogStream{
		ctx:        streamCtx,
		unregister: unregister,
		unsub:      unsub,
		opts:       normOpts,
		backlog:    filtered,
		followCh:   followCh,
	}
	return guardLogStream(streamCtx, stream, func(context.Context) error {
		return m.verifySelfContinuity()
	}, m.safety.operationError), nil
}

func matchesLogFilter(l MockLogLine, opts LogOptions) bool {
	if l.Stream == LogStreamStdout && !opts.Stdout {
		return false
	}
	if l.Stream == LogStreamStderr && !opts.Stderr {
		return false
	}
	if !opts.Since.IsZero() && !l.Timestamp.IsZero() && l.Timestamp.Before(opts.Since) {
		return false
	}
	if !opts.Until.IsZero() && !l.Timestamp.IsZero() && l.Timestamp.After(opts.Until) {
		return false
	}
	return true
}

func (m *MockBackend) Start(ctx context.Context, target TargetIdentity) error {
	if err := ctx.Err(); err != nil {
		return SanitizeError(err)
	}
	if _, err := m.verifyTargetForOperation(OpStart, target); err != nil {
		return err
	}
	m.operationalStarts.Add(1)

	m.mu.Lock()
	if c, ok := m.containers[target.ContainerID]; ok {
		c.State = "running"
		c.Status = "Up Less than a second"
	}
	m.mu.Unlock()
	return nil
}

func (m *MockBackend) Stop(ctx context.Context, target TargetIdentity, opts StopOptions) error {
	if err := ctx.Err(); err != nil {
		return SanitizeError(err)
	}
	if _, err := ValidateStopTimeout(opts.TimeoutSeconds); err != nil {
		return err
	}
	if _, err := m.verifyTargetForOperation(OpStop, target); err != nil {
		return err
	}
	m.operationalStops.Add(1)

	m.mu.Lock()
	if c, ok := m.containers[target.ContainerID]; ok {
		c.State = "exited"
		c.Status = "Exited (0) Less than a second ago"
	}
	m.mu.Unlock()
	return nil
}

func (m *MockBackend) Restart(ctx context.Context, target TargetIdentity, opts RestartOptions) error {
	if err := ctx.Err(); err != nil {
		return SanitizeError(err)
	}
	if _, err := ValidateStopTimeout(opts.TimeoutSeconds); err != nil {
		return err
	}
	if _, err := m.verifyTargetForOperation(OpRestart, target); err != nil {
		return err
	}
	m.operationalRestarts.Add(1)

	m.mu.Lock()
	if c, ok := m.containers[target.ContainerID]; ok {
		c.State = "running"
		c.Status = "Up Less than a second"
	}
	m.mu.Unlock()
	return nil
}

type mockLogStream struct {
	ctx        context.Context
	unregister func()
	unsub      func()
	opts       LogOptions
	mu         sync.Mutex
	backlog    []MockLogLine
	followCh   chan MockLogLine
	totalBytes int64
	readBuf    []byte
	readMu     sync.Mutex
	closed     bool
}

func (s *mockLogStream) formatLine(l MockLogLine) (LogFrame, error) {
	text := l.Line
	if s.opts.Timestamps && !l.Timestamp.IsZero() {
		text = l.Timestamp.UTC().Format(time.RFC3339Nano) + " " + text
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	payload := []byte(text)
	if len(payload) > MaxLogFrameBytes {
		return LogFrame{}, ErrLogLimitExceeded
	}
	if !s.opts.Follow && s.totalBytes+int64(len(payload)) > MaxLogResponseBytes {
		return LogFrame{}, ErrLogLimitExceeded
	}
	s.totalBytes += int64(len(payload))
	stream := l.Stream
	if stream == "" {
		stream = LogStreamStdout
	}
	return LogFrame{
		Stream:  stream,
		Payload: payload,
	}, nil
}

func (s *mockLogStream) Next(ctx context.Context) (LogFrame, error) {
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
	if s.closed {
		s.mu.Unlock()
		return LogFrame{}, io.EOF
	}
	if len(s.backlog) > 0 {
		line := s.backlog[0]
		s.backlog = s.backlog[1:]
		frame, err := s.formatLine(line)
		s.mu.Unlock()
		if err != nil {
			_ = s.Close()
			return LogFrame{}, err
		}
		return frame, nil
	}
	followCh := s.followCh
	s.mu.Unlock()

	if followCh == nil {
		return LogFrame{}, io.EOF
	}

	for {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return LogFrame{}, SanitizeError(ctx.Err())
		case <-s.ctx.Done():
			_ = s.Close()
			return LogFrame{}, ErrUnverified
		case line, ok := <-followCh:
			if !ok {
				return LogFrame{}, io.EOF
			}
			if !matchesLogFilter(line, s.opts) {
				continue
			}
			s.mu.Lock()
			frame, err := s.formatLine(line)
			s.mu.Unlock()
			if err != nil {
				_ = s.Close()
				return LogFrame{}, err
			}
			return frame, nil
		}
	}
}

func (s *mockLogStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.ctx.Err() != nil {
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
	if s.ctx.Err() != nil {
		s.readBuf = nil
		return 0, ErrUnverified
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *mockLogStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.unsub != nil {
		s.unsub()
	}
	if s.unregister != nil {
		s.unregister()
	}
	return nil
}
