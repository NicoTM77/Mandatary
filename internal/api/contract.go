// Package api is the versioned REST adapter (P1.14, /api/v1) and the transport-neutral
// contract shared with the MCP adapter (internal/mcp). Both adapters are thin: they
// authenticate a Bearer agent token, decode a strict request, and call exactly one
// function, ops.Service.Execute, which owns authorization and dispatch (TD §§3.2-3.3).
//
// Nothing here can reach Docker except through Execute. There is no raw Docker path,
// query or body pass-through, no exec, no discovery and no route outside the exact
// inventory below; an unrecognized route, method, query parameter, body field or tool
// is refused before authentication state, storage or any backend is consulted for it.
package api

import (
	"fmt"
	"log/slog"

	"github.com/NicoTM77/Mandatary/internal/docker"
)

// Contract versions. The REST base path and the MCP tool names/schemas are frozen per
// major version; docs/api-mcp.md and internal/api/testdata/contract-v1.json pin them.
const (
	// APIVersion is the REST major version, part of every route.
	APIVersion = "v1"
	// BasePath is the root of every REST route.
	BasePath = "/api/v1"
	// ContractVersion is the full contract version reported by the MCP server and the
	// readiness route. A breaking change requires a new major route/tool set.
	ContractVersion = "1.0.0"
	// MCPPath is the single Streamable HTTP MCP route.
	MCPPath = "/mcp"
)

// Spec describes one supported operation across both adapters. The catalog is exactly
// the six approved Phase 1 permission keys (ops.Operations()).
type Spec struct {
	Operation   docker.Operation
	Tool        string // MCP tool name
	Segment     string // REST path segment after .../containers/{container}/
	Method      string // REST method
	Title       string
	Description string
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
}

// Specs returns the exact supported operation catalog in a fixed order. Unsupported
// operations (exec, discovery, listing, raw Docker access, ...) are absent, not denied.
func Specs() []Spec {
	return []Spec{
		{docker.OpInspectStatus, "container_status", "status", "GET", "Inspect container status", "Return the allowlisted runtime status of one container (state, health, ports, labels).", true, false, true},
		{docker.OpInspectConfig, "container_config", "config", "GET", "Inspect container configuration", "Return the allowlisted, secret-redacted configuration of one container.", true, false, true},
		{docker.OpLogs, "container_logs", "logs", "GET", "Read container logs", "Return bounded, labelled log frames of one container (REST also offers follow=true as NDJSON).", true, false, true},
		{docker.OpStart, "container_start", "start", "POST", "Start a container", "Start one stopped container.", false, false, true},
		{docker.OpStop, "container_stop", "stop", "POST", "Stop a container", "Stop one container, waiting at most timeout_seconds before it is killed.", false, true, true},
		{docker.OpRestart, "container_restart", "restart", "POST", "Restart a container", "Restart one container, waiting at most timeout_seconds before it is killed.", false, true, false},
	}
}

// SpecFor returns the spec of op.
func SpecFor(op docker.Operation) (Spec, bool) {
	for _, s := range Specs() {
		if s.Operation == op {
			return s, true
		}
	}
	return Spec{}, false
}

// SpecForTool returns the spec of an MCP tool name.
func SpecForTool(name string) (Spec, bool) {
	for _, s := range Specs() {
		if s.Tool == name {
			return s, true
		}
	}
	return Spec{}, false
}

// Bounds of the request schema (also enforced by the authorizer's parameter rules).
const (
	MaxTargetBytes   = 255
	MaxEndpointBytes = 64
	// MaxBodyBytes bounds a REST request body (only stop/restart accept one).
	MaxBodyBytes = 4096
	// MaxMCPBodyBytes bounds one MCP JSON-RPC request body.
	MaxMCPBodyBytes = 64 * 1024
)

// Call is the transport-neutral, already-decoded request of one operation.
type Call struct {
	Operation      docker.Operation
	Endpoint       string // endpoint UUID or configured slug ("local")
	Container      string // container name or full 64-hex ID
	Logs           *docker.LogOptions
	Follow         bool // REST logs only
	TimeoutSeconds *int // stop and restart
}

// Token is a presented Bearer agent token. It prints as a redaction in every fmt,
// JSON and slog path and is never stored in an error.
type Token struct{ v string }

const redactionMark = "api.Token{[REDACTED]}"

func (Token) String() string             { return redactionMark }
func (Token) GoString() string           { return redactionMark }
func (Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redactionMark)) }
func (Token) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactionMark + `"`), nil
}
func (Token) LogValue() slog.Value { return slog.StringValue(redactionMark) }

// Response shapes (JSON). Inspect operations return docker.InspectStatus and
// docker.InspectConfig unchanged: the P1.12 allowlisted, sanitized structures.

// LogFrame is one labelled log frame. Text is the frame payload as UTF-8 (invalid
// bytes become U+FFFD); a payload is never interpreted or forwarded raw.
type LogFrame struct {
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

// LogsResult is the bounded, non-streaming logs response.
type LogsResult struct {
	EndpointID  string     `json:"endpoint_id"`
	ContainerID string     `json:"container_id"`
	Name        string     `json:"name"`
	Frames      []LogFrame `json:"frames"`
	// Truncated is true when the 4 MiB response bound (TD §1.2) ended the read.
	Truncated bool `json:"truncated"`
}

// ActionResult is the response of start, stop and restart.
type ActionResult struct {
	EndpointID  string `json:"endpoint_id"`
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Operation   string `json:"operation"`
	Outcome     string `json:"outcome"` // always "completed"
}

// ReadyResult is the body of GET /api/v1/readyz.
type ReadyResult struct {
	Ready   bool   `json:"ready"`
	Version string `json:"version"`
}
