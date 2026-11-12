package adapters_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/api"
	apimcp "github.com/NicoTM77/Mandatary/internal/mcp"
)

// contractPath is the committed, versioned contract of /api/v1 and the MCP tools.
var contractPath = filepath.Join("..", "..", "internal", "api", "testdata", "contract-v1.json")

// buildContract derives the contract from the code that serves it. The committed file is
// the reviewed copy: any change to a route, parameter, schema, error code, status or
// limit must change the fixture in the same diff (and, if it is breaking, the version).
func buildContract() map[string]any {
	routes := []map[string]any{{
		"method": "GET", "path": api.BasePath + "/readyz", "auth": "none", "operation": nil,
		"response": "ReadyResult {ready: bool, version: string}; 200 ready, 503 not ready",
	}}
	tools := []map[string]any{}
	for _, s := range api.Specs() {
		route := map[string]any{
			"method": s.Method, "path": api.BasePath + "/endpoints/{endpoint}/containers/{container}/" + s.Segment,
			"auth": "bearer-agent-token", "operation": string(s.Operation),
		}
		switch s.Segment {
		case "logs":
			route["query"] = []string{"tail", "stdout", "stderr", "timestamps", "since", "until", "follow"}
			route["response"] = "LogsResult (follow=true: application/x-ndjson, REST only)"
		case "stop", "restart":
			route["body"] = map[string]any{"content_type": "application/json", "fields": []string{"timeout_seconds"}, "optional": true}
			route["response"] = "ActionResult"
		case "status", "config":
			route["response"] = map[string]string{"status": "docker.InspectStatus", "config": "docker.InspectConfig"}[s.Segment]
		default:
			route["response"] = "ActionResult"
		}
		routes = append(routes, route)
		tools = append(tools, map[string]any{
			"name": s.Tool, "operation": string(s.Operation), "read_only": s.ReadOnly, "destructive": s.Destructive, "idempotent": s.Idempotent,
			"input_schema": apimcp.InputSchema(s.Operation),
		})
	}
	codes := []string{api.CodeUnauthenticated, api.CodeForbidden, api.CodeInvalidRequest, api.CodeNotFound, api.CodeMethodNotAllowed, api.CodePayloadTooLarge,
		api.CodeUnsupportedMedia, api.CodeTooManyStreams, api.CodeCanceled, api.CodeInternal, api.CodeBackendFailed, api.CodeBackendUnavailable, api.CodeTimeout}
	errs := []map[string]any{}
	for _, c := range codes {
		p := api.ProblemOf(c, "")
		errs = append(errs, map[string]any{"code": c, "status": p.Status, "message": p.Message})
	}
	return map[string]any{
		"contract_version": api.ContractVersion,
		"rest_base_path":   api.BasePath,
		"mcp": map[string]any{
			"path": api.MCPPath, "transport": "streamable-http", "stateless": true, "methods": []string{"POST"},
			"auth": "bearer-agent-token on every HTTP request, before the JSON-RPC body is parsed",
		},
		"routes": routes,
		"tools":  tools,
		"errors": map[string]any{
			"shape":             `{"error":{"code":string,"status":int,"message":string,"reason"?:string}}`,
			"codes":             errs,
			"forbidden_reasons": []string{api.ReasonDefaultDeny, api.ReasonRestoreQuarantined, api.ReasonSafetyUnverified, api.ReasonEndpointInactive, api.ReasonCapExceeded, api.ReasonAuthorizationEnded, api.ReasonForbiddenOrigin},
			"mcp_mapping":       "a tool failure is a CallToolResult with isError=true whose structuredContent is the same error object; HTTP-level failures (401, 403 origin, 404, 405, 413, 415) are HTTP responses",
		},
		"limits": map[string]any{
			"max_container_bytes": api.MaxTargetBytes, "max_endpoint_bytes": api.MaxEndpointBytes,
			"max_rest_body_bytes": api.MaxBodyBytes, "max_mcp_body_bytes": api.MaxMCPBodyBytes,
		},
		"absent": []string{"exec", "container list/discovery", "access requests", "raw Docker paths, queries or bodies", "image/volume/network operations", "MCP prompts and resources", "MCP sessions", "MCP server-initiated requests"},
	}
}

func TestContractFixtureIsCurrentAndExact(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(buildContract()); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("MANDATARY_UPDATE_CONTRACT") == "1" {
		if err := os.MkdirAll(filepath.Dir(contractPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(contractPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("contract fixture missing: %v (regenerate with MANDATARY_UPDATE_CONTRACT=1)", err)
	}
	if !bytes.Equal(committed, buf.Bytes()) {
		t.Fatalf("internal/api/testdata/contract-v1.json is stale: the served contract changed. Review the change, bump contract_version if it is breaking, and regenerate with MANDATARY_UPDATE_CONTRACT=1")
	}
}
