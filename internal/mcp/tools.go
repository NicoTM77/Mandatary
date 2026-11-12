package mcp

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

func forbiddenOrigin() *api.Problem {
	return api.ProblemOf(api.CodeForbidden, api.ReasonForbiddenOrigin)
}
func problemNotFound() *api.Problem { return api.ProblemOf(api.CodeNotFound, "") }
func problemMethod() *api.Problem   { return api.ProblemOf(api.CodeMethodNotAllowed, "") }
func problemInvalid() *api.Problem  { return api.ProblemOf(api.CodeInvalidRequest, "") }

var errUnauthenticated = api.ProblemOf(api.CodeUnauthenticated, "")

func ptr[T any](v T) *T { return &v }

// toolFor builds the strict, versioned tool definition of one operation. The input
// schema is the contract: closed (additionalProperties:false), typed and bounded.
func toolFor(spec api.Spec) *mcp.Tool {
	return &mcp.Tool{
		Name:        spec.Tool,
		Title:       spec.Title,
		Description: spec.Description,
		InputSchema: InputSchema(spec.Operation),
		Annotations: &mcp.ToolAnnotations{
			Title:           spec.Title,
			ReadOnlyHint:    spec.ReadOnly,
			DestructiveHint: ptr(spec.Destructive),
			IdempotentHint:  spec.Idempotent,
			OpenWorldHint:   ptr(false),
		},
	}
}

// InputSchema returns the JSON Schema (2020-12) of the tool arguments of op. It is the
// same schema decodeArguments enforces and the one pinned by contract-v1.json.
func InputSchema(op docker.Operation) map[string]any {
	props := map[string]any{
		"endpoint": map[string]any{
			"type": "string", "minLength": 1, "maxLength": api.MaxEndpointBytes,
			"description": "Endpoint UUID or its configured slug (Phase 1: \"local\").",
		},
		"container": map[string]any{
			"type": "string", "minLength": 1, "maxLength": api.MaxTargetBytes,
			"pattern":     "^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
			"description": "Container name or full 64-character container ID.",
		},
	}
	switch op {
	case docker.OpLogs:
		props["tail"] = map[string]any{"type": "integer", "minimum": docker.MinLogTail, "maximum": docker.MaxLogTail, "description": "Number of most recent lines (default 10000; a policy may cap it lower)."}
		props["stdout"] = map[string]any{"type": "boolean", "description": "Include stdout (default true)."}
		props["stderr"] = map[string]any{"type": "boolean", "description": "Include stderr (default true)."}
		props["timestamps"] = map[string]any{"type": "boolean", "description": "Prefix each line with its timestamp."}
		props["since"] = map[string]any{"type": "string", "format": "date-time", "description": "RFC 3339 lower bound."}
		props["until"] = map[string]any{"type": "string", "format": "date-time", "description": "RFC 3339 upper bound."}
	case docker.OpStop, docker.OpRestart:
		props["timeout_seconds"] = map[string]any{"type": "integer", "minimum": docker.MinStopTimeoutSeconds, "maximum": docker.MaxStopTimeoutSeconds, "description": "Seconds to wait before the container is killed (default 10)."}
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             []string{"endpoint", "container"},
		"additionalProperties": false,
	}
}
