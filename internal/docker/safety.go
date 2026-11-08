package docker

import (
	"cmp"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

// ProcessEvidenceReader supplies current-process runtime container identity evidence.
type ProcessEvidenceReader func(ctx context.Context) (ProcessEvidence, error)

// ProcessEvidence represents the current process's cgroup/runtime evidence.
type ProcessEvidence struct {
	ContainerID     string
	PrivateCgroupNS bool
	Mandatory       bool
}

// SelfIdentityConfig holds trusted host/operator identity configuration.
type SelfIdentityConfig struct {
	EndpointID          domain.EndpointID
	ExplicitContainerID string
	InstanceUUID        string
	EvidenceReader      ProcessEvidenceReader
}

// SafetyCandidate holds container safety metadata used during self and peer verification.
type SafetyCandidate struct {
	ID        ContainerID
	Created   string
	StartedAt string
	Labels    map[string]string
}

// HasExactSelfLabel reports whether labels contain exact io.mandatary.self=true.
func HasExactSelfLabel(labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	return strings.TrimSpace(labels[SelfLabelKey]) == SelfLabelValue
}

// HasProtectedNamespaceLabel reports whether labels contain io.mandatary.self=true
// or any label in the reserved io.mandatary.* namespace.
func HasProtectedNamespaceLabel(labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	for k, v := range labels {
		trimmedKey := strings.TrimSpace(k)
		if trimmedKey == SelfLabelKey && strings.TrimSpace(v) == SelfLabelValue {
			return true
		}
		if strings.HasPrefix(trimmedKey, SelfLabelNamespacePrefix) {
			return true
		}
	}
	return false
}

// ParseCgroupContainerID extracts a unique 64-hex container ID from Linux cgroup/mountinfo text.
func ParseCgroupContainerID(cgroupContent string) (ContainerID, bool, error) {
	lines := strings.Split(cgroupContent, "\n")
	var foundID ContainerID
	var sawRootOnly bool

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		pathPart := line
		if len(parts) == 3 {
			pathPart = strings.TrimSpace(parts[2])
		}
		if pathPart == "/" || pathPart == "/.." {
			sawRootOnly = true
			continue
		}

		candidates := extract64HexCandidates(pathPart)
		for _, cand := range candidates {
			if foundID == "" {
				foundID = cand
			} else if foundID != cand {
				return "", false, ErrUnverified
			}
		}
	}

	if foundID != "" {
		return foundID, false, nil
	}
	if sawRootOnly {
		return "", true, nil
	}
	return "", false, nil
}

func extract64HexCandidates(s string) []ContainerID {
	var out []ContainerID
	segments := strings.FieldsFunc(s, func(r rune) bool {
		return r == '/' || r == '-' || r == '.' || r == ':' || r == '_' || r == ' '
	})
	for _, seg := range segments {
		if cid, err := ParseContainerID(seg); err == nil {
			out = append(out, cid)
		}
	}
	return out
}

// DefaultProcessEvidenceReader reads /proc/self/cgroup when present on Linux.
func DefaultProcessEvidenceReader(_ context.Context) (ProcessEvidence, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		if os.IsNotExist(err) {
			return ProcessEvidence{}, nil
		}
		return ProcessEvidence{}, ErrUnverified
	}
	cid, priv, err := ParseCgroupContainerID(string(data))
	if err != nil {
		return ProcessEvidence{}, err
	}
	return ProcessEvidence{
		ContainerID:     string(cid),
		PrivateCgroupNS: priv,
	}, nil
}

// SafetyMonitor manages the UNVERIFIED -> VERIFIED -> UNVERIFIED state machine,
// protected container set, and active stream cancellation.
type SafetyMonitor struct {
	mu            sync.RWMutex
	epoch         uint64
	closed        bool
	cfg           SelfIdentityConfig
	state         VerificationState
	selfID        ContainerID
	daemonID      string
	selfCreated   string
	selfStartedAt string
	protected     map[ContainerID]struct{}
	nextStreamID  uint64
	activeStreams map[uint64]context.CancelFunc
}

func NewSafetyMonitor(cfg SelfIdentityConfig) (*SafetyMonitor, error) {
	epID, err := domain.ParseEndpointID(string(cfg.EndpointID))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	cfg.EndpointID = epID
	if cfg.EvidenceReader == nil {
		cfg.EvidenceReader = DefaultProcessEvidenceReader
	}
	return &SafetyMonitor{
		cfg:           cfg,
		state:         StateUnverified,
		protected:     make(map[ContainerID]struct{}),
		activeStreams: make(map[uint64]context.CancelFunc),
	}, nil
}

func (m *SafetyMonitor) SetConfig(cfg SelfIdentityConfig) {
	m.mu.Lock()
	if cfg.EndpointID == "" {
		cfg.EndpointID = m.cfg.EndpointID
	}
	if cfg.EvidenceReader == nil {
		cfg.EvidenceReader = DefaultProcessEvidenceReader
	}
	m.cfg = cfg
	m.invalidateLocked()
	m.mu.Unlock()
}

func (m *SafetyMonitor) currentEpoch() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.epoch
}

func (m *SafetyMonitor) requireEpoch(epoch uint64) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed || m.epoch != epoch || m.state != StateVerified {
		return ErrUnverified
	}
	return nil
}

func (m *SafetyMonitor) State() VerificationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *SafetyMonitor) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state == StateVerified && m.selfID != ""
}

func (m *SafetyMonitor) SelfContainerID() (ContainerID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state != StateVerified || m.selfID == "" {
		return "", false
	}
	return m.selfID, true
}

func (m *SafetyMonitor) IsProtected(id ContainerID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state != StateVerified {
		return true
	}
	if id == m.selfID {
		return true
	}
	_, ok := m.protected[id]
	return ok
}

func (m *SafetyMonitor) MarkProtected(id ContainerID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id != "" {
		m.protected[id] = struct{}{}
	}
}

func (m *SafetyMonitor) ProtectedSet() []ContainerID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ContainerID, 0, len(m.protected))
	for id := range m.protected {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b ContainerID) int {
		return cmp.Compare(string(a), string(b))
	})
	return out
}

func (m *SafetyMonitor) Invalidate() {
	m.mu.Lock()
	m.invalidateLocked()
	m.mu.Unlock()
}

// Only known logical target/input denials preserve proof. Unknown errors,
// including canceled I/O, cannot establish current daemon continuity.
func (m *SafetyMonitor) operationError(err error) error {
	safe := SanitizeError(err)
	if safe != nil && !errors.Is(safe, ErrTargetNotFound) && !errors.Is(safe, ErrInvalidParameter) {
		m.Invalidate()
	}
	return safe
}

func (m *SafetyMonitor) invalidateLocked() {
	m.epoch++
	m.state = StateUnverified
	m.selfID = ""
	m.daemonID = ""
	m.selfCreated = ""
	m.selfStartedAt = ""
	for id, cancel := range m.activeStreams {
		cancel()
		delete(m.activeStreams, id)
	}
}

// Verify executes the §S1.1 and §S1.2 startup/re-verification algorithm.
func (m *SafetyMonitor) Verify(
	ctx context.Context,
	daemonID string,
	allContainers []SafetyCandidate,
	inspectFn func(ContainerID) (SafetyCandidate, error),
) error {
	epoch := m.beginVerification()
	return m.verifyAt(ctx, epoch, daemonID, allContainers, inspectFn)
}

// Reserve proof publication before any fallible inventory or identity I/O.
// Invalidation, config changes, closure and every newer attempt revoke this epoch.
func (m *SafetyMonitor) beginVerification() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateLocked()
	return m.epoch
}

func (m *SafetyMonitor) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.invalidateLocked()
}

func (m *SafetyMonitor) verifyAt(ctx context.Context, epoch uint64, daemonID string, allContainers []SafetyCandidate, inspectFn func(ContainerID) (SafetyCandidate, error)) error {
	m.mu.RLock()
	cfg := m.cfg
	stale := m.closed || m.epoch != epoch
	m.mu.RUnlock()
	if stale || ctx.Err() != nil {
		return ErrUnverified
	}

	if strings.TrimSpace(daemonID) == "" {
		m.Invalidate()
		return ErrUnverified
	}

	ev, err := cfg.EvidenceReader(ctx)
	if err != nil {
		m.Invalidate()
		return ErrUnverified
	}

	var explicitID ContainerID
	if strings.TrimSpace(cfg.ExplicitContainerID) != "" {
		parsed, pErr := ParseContainerID(cfg.ExplicitContainerID)
		if pErr != nil {
			m.Invalidate()
			return ErrUnverified
		}
		explicitID = parsed
	}

	var processID ContainerID
	if strings.TrimSpace(ev.ContainerID) != "" {
		parsed, pErr := ParseContainerID(ev.ContainerID)
		if pErr != nil {
			m.Invalidate()
			return ErrUnverified
		}
		processID = parsed
	}

	if explicitID != "" && processID != "" && explicitID != processID {
		m.Invalidate()
		return ErrUnverified
	}

	var instanceUUID string
	if strings.TrimSpace(cfg.InstanceUUID) != "" {
		parsedUUID, uErr := domain.ParseEndpointID(cfg.InstanceUUID)
		if uErr != nil {
			m.Invalidate()
			return ErrUnverified
		}
		instanceUUID = string(parsedUUID)
	}

	protected := make(map[ContainerID]struct{})
	var uuidMatches []ContainerID
	seen := make(map[ContainerID]bool, len(allContainers))

	for _, c := range allContainers {
		if _, err := ParseContainerID(string(c.ID)); err != nil || seen[c.ID] {
			m.Invalidate()
			return ErrUnverified
		}
		seen[c.ID] = true
		if HasProtectedNamespaceLabel(c.Labels) {
			protected[c.ID] = struct{}{}
		}
		if instanceUUID != "" {
			if strings.TrimSpace(c.Labels[SelfInstanceUUIDLabelKey]) == instanceUUID {
				uuidMatches = append(uuidMatches, c.ID)
			}
		}
	}

	if instanceUUID != "" && len(uuidMatches) != 1 {
		m.Invalidate()
		return ErrUnverified
	}

	var candidateID ContainerID
	switch {
	case processID != "":
		candidateID = processID
	case ev.PrivateCgroupNS:
		// Private cgroup namespace requires deployment instance-UUID binding.
		if instanceUUID == "" || len(uuidMatches) != 1 {
			m.Invalidate()
			return ErrUnverified
		}
		candidateID = uuidMatches[0]
		if explicitID != "" && explicitID != candidateID {
			m.Invalidate()
			return ErrUnverified
		}
	default:
		if ev.Mandatory {
			m.Invalidate()
			return ErrUnverified
		}
		if instanceUUID != "" && len(uuidMatches) == 1 {
			candidateID = uuidMatches[0]
		}
		if explicitID != "" && explicitID != candidateID {
			m.Invalidate()
			return ErrUnverified
		}
	}

	if candidateID == "" {
		m.Invalidate()
		return ErrUnverified
	}
	if instanceUUID != "" && len(uuidMatches) == 1 && uuidMatches[0] != candidateID {
		m.Invalidate()
		return ErrUnverified
	}

	inspectedSelf, err := inspectFn(candidateID)
	if err != nil {
		m.Invalidate()
		return ErrUnverified
	}
	if inspectedSelf.ID != candidateID || !HasExactSelfLabel(inspectedSelf.Labels) {
		m.Invalidate()
		return ErrUnverified
	}
	if instanceUUID != "" && strings.TrimSpace(inspectedSelf.Labels[SelfInstanceUUIDLabelKey]) != instanceUUID {
		m.Invalidate()
		return ErrUnverified
	}

	protected[candidateID] = struct{}{}

	m.mu.Lock()
	if m.closed || m.epoch != epoch || ctx.Err() != nil {
		m.mu.Unlock()
		return ErrUnverified
	}
	m.state = StateVerified
	m.selfID = candidateID
	m.daemonID = daemonID
	m.selfCreated = inspectedSelf.Created
	m.selfStartedAt = inspectedSelf.StartedAt
	m.protected = protected
	m.mu.Unlock()

	return nil
}

// VerifyContinuity checks that the daemon ID and own-instance container identity
// have not changed since Verify succeeded (SELF-05).
func (m *SafetyMonitor) VerifyContinuity(currentDaemonID string, currentSelf SafetyCandidate) error {
	m.mu.RLock()
	state := m.state
	selfID := m.selfID
	daemonID := m.daemonID
	created := m.selfCreated
	startedAt := m.selfStartedAt
	m.mu.RUnlock()

	if state != StateVerified || selfID == "" {
		return ErrUnverified
	}
	if currentDaemonID == "" || currentDaemonID != daemonID {
		m.Invalidate()
		return ErrUnverified
	}
	if currentSelf.ID != selfID ||
		!HasExactSelfLabel(currentSelf.Labels) ||
		currentSelf.Created != created ||
		currentSelf.StartedAt != startedAt {
		m.Invalidate()
		return ErrUnverified
	}
	return nil
}

// VerifyInventory rechecks the complete all-state inventory, including deployment
// binding uniqueness. An overlap invalidates proof until explicit re-verification;
// merely removing the overlapping member cannot resurrect cached authority.
func (m *SafetyMonitor) VerifyInventory(all []SafetyCandidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateVerified {
		return ErrUnverified
	}
	seen := make(map[ContainerID]bool, len(all))
	var matches []ContainerID
	for _, c := range all {
		if _, err := ParseContainerID(string(c.ID)); err != nil || seen[c.ID] {
			m.invalidateLocked()
			return ErrUnverified
		}
		seen[c.ID] = true
		if HasProtectedNamespaceLabel(c.Labels) {
			m.protected[c.ID] = struct{}{}
		}
		if m.cfg.InstanceUUID != "" && strings.TrimSpace(c.Labels[SelfInstanceUUIDLabelKey]) == m.cfg.InstanceUUID {
			matches = append(matches, c.ID)
		}
	}
	if !seen[m.selfID] || (m.cfg.InstanceUUID != "" && (len(matches) != 1 || matches[0] != m.selfID)) {
		m.invalidateLocked()
		return ErrUnverified
	}
	return nil
}

func (m *SafetyMonitor) RegisterStream(parent context.Context) (context.Context, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateVerified || m.selfID == "" {
		return nil, nil, ErrUnverified
	}
	streamCtx, cancel := context.WithCancel(parent)
	m.nextStreamID++
	id := m.nextStreamID
	m.activeStreams[id] = cancel

	unregister := func() {
		m.mu.Lock()
		if fn, ok := m.activeStreams[id]; ok {
			fn()
			delete(m.activeStreams, id)
		}
		m.mu.Unlock()
	}
	return streamCtx, unregister, nil
}
