// Package docker provides the restricted Phase 1 Docker backend interface,
// official moby/client adapter, self-protection state machine, response
// sanitizers, and container-free in-memory mock implementation.
package docker

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

const redactedValue = "[REDACTED]"

// Error is a fixed, secret-free sentinel error. Raw SDK, HTTP, daemon, and
// transport errors are never wrapped or echoed to callers or logs.
type Error string

func (e Error) Error() string        { return string(e) }
func (e Error) String() string       { return string(e) }
func (e Error) GoString() string     { return string(e) }
func (e Error) LogValue() slog.Value { return slog.StringValue(string(e)) }

const (
	ErrUnverified            Error = "docker backend self-identity is unverified"
	ErrProtectedTarget       Error = "docker target is protected"
	ErrEndpointMismatch      Error = "docker target endpoint mismatch"
	ErrTargetNotFound        Error = "docker target not found"
	ErrInvalidTarget         Error = "invalid docker target identity"
	ErrUnsupportedOperation  Error = "unsupported docker operation"
	ErrInvalidParameter      Error = "invalid docker operation parameter"
	ErrUnsupportedAPIVersion Error = "unsupported docker engine API version"
	ErrLogLimitExceeded      Error = "docker log output limit exceeded"
	ErrBackendUnavailable    Error = "docker backend unavailable"
	ErrBackendFailed         Error = "docker backend operation failed"
	ErrInvalidConfig         Error = "invalid docker backend configuration"
)

// Self-protection labels, environment variable names, and Engine API bounds.
const (
	SelfLabelKey             = "io.mandatary.self"
	SelfLabelValue           = "true"
	SelfLabelNamespacePrefix = "io.mandatary."
	SelfInstanceUUIDLabelKey = "io.mandatary.self.instance-uuid"
	EnvSelfContainerID       = "MANDATARY_SELF_CONTAINER_ID"
	EnvSelfInstanceUUID      = "MANDATARY_SELF_INSTANCE_UUID"
	MinEngineAPIVersion      = "1.44"
)

// Approved Phase 1 parameter bounds (TD §1.2, §10.2).
const (
	DefaultLogTail            = 10000
	MinLogTail                = 1
	MaxLogTail                = 10000
	MaxLogFrameBytes          = 64 * 1024
	MaxLogResponseBytes       = 4 * 1024 * 1024
	DefaultStopTimeoutSeconds = 10
	MinStopTimeoutSeconds     = 1
	MaxStopTimeoutSeconds     = 300
)

// Operation identifies an approved Phase 1 container operation.
type Operation string

const (
	OpLogs          Operation = "container:logs"
	OpInspectStatus Operation = "container:inspect_status"
	OpInspectConfig Operation = "container:inspect_config"
	OpStart         Operation = "container:start"
	OpStop          Operation = "container:stop"
	OpRestart       Operation = "container:restart"
)

// ContainerID is an immutable full 64-character lowercase hexadecimal Docker container ID.
type ContainerID string

// TargetIdentity binds an immutable container ID to its endpoint UUID.
type TargetIdentity struct {
	EndpointID  domain.EndpointID `json:"endpoint_id"`
	ContainerID ContainerID       `json:"container_id"`
}

// VerificationState represents the §S1.2 runtime safety state machine.
type VerificationState string

const (
	StateUnverified VerificationState = "UNVERIFIED"
	StateVerified   VerificationState = "VERIFIED"
)

// LogOptions defines bounded parameters for container:logs.
type LogOptions struct {
	Tail       int
	TailAll    bool
	Since      time.Time
	Until      time.Time
	Timestamps bool
	Follow     bool
	Stdout     bool
	Stderr     bool
}

// StopOptions defines bounded parameters for container:stop.
type StopOptions struct {
	TimeoutSeconds *int
}

// RestartOptions defines bounded parameters for container:restart.
type RestartOptions struct {
	TimeoutSeconds *int
}

// PortMapping is an allowlisted port mapping entry.
type PortMapping struct {
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
}

// ContainerSummary provides sanitized metadata for non-protected containers.
type ContainerSummary struct {
	EndpointID     domain.EndpointID `json:"endpoint_id"`
	ContainerID    ContainerID       `json:"container_id"`
	Name           string            `json:"name"`
	State          string            `json:"state"`
	Status         string            `json:"status"`
	Image          string            `json:"image"`
	ImageDigest    string            `json:"image_digest,omitempty"`
	ComposeProject string            `json:"compose_project,omitempty"`
	ComposeService string            `json:"compose_service,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// InspectStatus is the explicit allowlisted response for container:inspect_status.
type InspectStatus struct {
	EndpointID        domain.EndpointID `json:"endpoint_id"`
	ContainerID       ContainerID       `json:"container_id"`
	Name              string            `json:"name"`
	Image             string            `json:"image"`
	ImageDigest       string            `json:"image_digest,omitempty"`
	State             string            `json:"state"`
	Running           bool              `json:"running"`
	Paused            bool              `json:"paused"`
	Restarting        bool              `json:"restarting"`
	ExitCode          int               `json:"exit_code"`
	HealthStatus      string            `json:"health_status"`
	HealthFailingRuns int               `json:"health_failing_streak,omitempty"`
	StartedAt         string            `json:"started_at,omitempty"`
	FinishedAt        string            `json:"finished_at,omitempty"`
	Ports             []PortMapping     `json:"ports,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

// MountSummary is an allowlisted mount entry for container:inspect_config.
type MountSummary struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"read_write"`
	Propagation string `json:"propagation,omitempty"`
}

// NetworkEndpointSummary is an allowlisted per-network attachment summary.
type NetworkEndpointSummary struct {
	NetworkName string   `json:"network_name"`
	NetworkID   string   `json:"network_id,omitempty"`
	IPv4Address string   `json:"ipv4_address,omitempty"`
	IPv6Address string   `json:"ipv6_address,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	IPv6Gateway string   `json:"ipv6_gateway,omitempty"`
	MacAddress  string   `json:"mac_address,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	DNSNames    []string `json:"dns_names,omitempty"`
}

// NetworkSummary is the allowlisted network configuration for container:inspect_config.
type NetworkSummary struct {
	NetworkMode string                   `json:"network_mode"`
	Ports       []PortMapping            `json:"ports,omitempty"`
	Networks    []NetworkEndpointSummary `json:"networks,omitempty"`
}

// UlimitSummary is an allowlisted resource ulimit entry.
type UlimitSummary struct {
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
}

// ResourceLimits is the allowlisted resource configuration for container:inspect_config.
type ResourceLimits struct {
	MemoryBytes            int64           `json:"memory_bytes"`
	MemoryReservationBytes int64           `json:"memory_reservation_bytes"`
	MemorySwapBytes        int64           `json:"memory_swap_bytes"`
	NanoCPUs               int64           `json:"nano_cpus"`
	CPUShares              int64           `json:"cpu_shares"`
	CPUPeriod              int64           `json:"cpu_period"`
	CPUQuota               int64           `json:"cpu_quota"`
	CpusetCpus             string          `json:"cpuset_cpus,omitempty"`
	PidsLimit              *int64          `json:"pids_limit,omitempty"`
	OomKillDisable         *bool           `json:"oom_kill_disable,omitempty"`
	ReadonlyRootfs         bool            `json:"readonly_rootfs"`
	Ulimits                []UlimitSummary `json:"ulimits,omitempty"`
}

// InspectConfig is the explicit allowlisted response for container:inspect_config.
type InspectConfig struct {
	EndpointID  domain.EndpointID `json:"endpoint_id"`
	ContainerID ContainerID       `json:"container_id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	ImageDigest string            `json:"image_digest,omitempty"`
	User        string            `json:"user,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Entrypoint  []string          `json:"entrypoint,omitempty"`
	Cmd         []string          `json:"cmd,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Mounts      []MountSummary    `json:"mounts,omitempty"`
	Network     NetworkSummary    `json:"network"`
	Resources   ResourceLimits    `json:"resources"`
}

// LogStreamType identifies the demultiplexed origin of a log frame.
type LogStreamType string

const (
	LogStreamStdout LogStreamType = "stdout"
	LogStreamStderr LogStreamType = "stderr"
)

// LogFrame represents a single bounded log frame from a container stream.
type LogFrame struct {
	Stream  LogStreamType `json:"stream"`
	Payload []byte        `json:"payload"`
}

// LogStream provides cancellable, bounded access to container logs.
type LogStream interface {
	Next(ctx context.Context) (LogFrame, error)
	io.ReadCloser
}

// DockerBackend defines the restricted Phase 1 Docker intermediary interface.
type DockerBackend interface {
	EndpointID() domain.EndpointID
	Ready() bool
	VerificationState() VerificationState
	VerifySelf(ctx context.Context) error
	InvalidateSafety()
	ResolveTarget(ctx context.Context, nameOrID string) (ContainerSummary, error)
	ListContainers(ctx context.Context) ([]ContainerSummary, error)
	InspectStatus(ctx context.Context, target TargetIdentity) (InspectStatus, error)
	InspectConfig(ctx context.Context, target TargetIdentity) (InspectConfig, error)
	Logs(ctx context.Context, target TargetIdentity, opts LogOptions) (LogStream, error)
	Start(ctx context.Context, target TargetIdentity) error
	Stop(ctx context.Context, target TargetIdentity, opts StopOptions) error
	Restart(ctx context.Context, target TargetIdentity, opts RestartOptions) error
	Close() error
}

// ParseContainerID validates a canonical 64-character lowercase hex container ID.
func ParseContainerID(value string) (ContainerID, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) != 64 {
		return "", ErrInvalidTarget
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", ErrInvalidTarget
		}
	}
	return ContainerID(trimmed), nil
}

// ParseTargetIdentity validates both endpoint UUID and full container ID.
func ParseTargetIdentity(endpointID domain.EndpointID, containerID string) (TargetIdentity, error) {
	epID, err := domain.ParseEndpointID(string(endpointID))
	if err != nil {
		return TargetIdentity{}, ErrInvalidTarget
	}
	cid, err := ParseContainerID(containerID)
	if err != nil {
		return TargetIdentity{}, ErrInvalidTarget
	}
	return TargetIdentity{
		EndpointID:  epID,
		ContainerID: cid,
	}, nil
}

// ValidateOperation checks that op is in the approved Phase 1 operation catalog.
func ValidateOperation(op Operation) error {
	switch op {
	case OpLogs, OpInspectStatus, OpInspectConfig, OpStart, OpStop, OpRestart:
		return nil
	default:
		return ErrUnsupportedOperation
	}
}

// ValidateLogOptions validates and normalizes log request parameters.
func ValidateLogOptions(opts LogOptions) (LogOptions, error) {
	if opts.TailAll {
		return LogOptions{}, ErrInvalidParameter
	}
	if !opts.Stdout && !opts.Stderr {
		return LogOptions{}, ErrInvalidParameter
	}
	if opts.Tail == 0 {
		opts.Tail = DefaultLogTail
	}
	if opts.Tail < MinLogTail || opts.Tail > MaxLogTail {
		return LogOptions{}, ErrInvalidParameter
	}
	if !opts.Since.IsZero() && !opts.Until.IsZero() && opts.Until.Before(opts.Since) {
		return LogOptions{}, ErrInvalidParameter
	}
	return opts, nil
}

// ValidateStopTimeout validates and normalizes stop/restart timeout seconds.
func ValidateStopTimeout(timeout *int) (int, error) {
	if timeout == nil {
		return DefaultStopTimeoutSeconds, nil
	}
	v := *timeout
	if v < MinStopTimeoutSeconds || v > MaxStopTimeoutSeconds {
		return 0, ErrInvalidParameter
	}
	return v, nil
}
