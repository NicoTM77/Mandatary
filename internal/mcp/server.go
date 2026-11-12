// Package mcp is the authenticated Model Context Protocol adapter (P1.14): the Streamable
// HTTP route /mcp served with the official go-sdk. It is the twin of internal/api: the
// same Bearer agent tokens, the same strict argument schema, the same shared service
// (ops.Service.Execute) and the same common errors, so the identical positive/negative
// matrix holds over HTTP and over MCP.
//
// Security properties (TD §§3.2-3.3):
//   - Every HTTP request to /mcp is authenticated BEFORE the JSON-RPC body is parsed,
//     including initialize and tools/list. Listing tools is never evidence of
//     authorization: the catalog is public to any authenticated agent, and every
//     tools/call is authenticated and authorized again by the shared service.
//   - The server is stateless. There is no Mcp-Session-Id to steal, replay or outlive a
//     revoked credential: authority is evaluated per request from the Bearer token.
//   - Tools are exactly the six approved operations. There is no exec, discovery,
//     listing or raw-Docker tool; an unknown tool name is a protocol error that reaches
//     nothing. Tool arguments are decoded strictly (unknown or duplicate properties,
//     wrong types, null and trailing data are refused).
//   - Only the opaque agent token comes from the caller. Cookies, sessions, setup or
//     recovery capabilities, JWTs and OAuth metadata are not credentials here.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

// Config configures the MCP handler.
type Config struct {
	// Gateway is the shared authentication/execution core (also used by REST).
	Gateway *api.Gateway
	// AllowedOrigins lists the only Origin header values a request may carry; the
	// default (empty) refuses every request that carries one (DNS-rebinding and
	// cross-site browser protection; non-browser MCP clients send no Origin).
	AllowedOrigins []string
}

// ErrInvalidConfig reports an unusable Config.
var ErrInvalidConfig = errors.New("invalid mcp configuration")

// Handler is the http.Handler of the single Streamable HTTP route /mcp.
type Handler struct {
	gw      *api.Gateway
	origins map[string]bool
	sdk     http.Handler
}

// NewHandler builds the server and its six tools. It fails closed on invalid config.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Gateway == nil {
		return nil, ErrInvalidConfig
	}
	h := &Handler{gw: cfg.Gateway, origins: map[string]bool{}}
	for _, o := range cfg.AllowedOrigins {
		if o == "" || o == "null" || o == "*" {
			return nil, ErrInvalidConfig
		}
		h.origins[o] = true
	}
	server := mcp.NewServer(
		&mcp.Implementation{Name: "mandatary", Title: "Mandatary container operations", Version: api.ContractVersion},
		&mcp.ServerOptions{
			Instructions: "Six authorized container operations. Listing tools grants nothing: every call is authenticated and authorized against the caller's policy.",
			Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		},
	)
	for _, spec := range api.Specs() {
		server.AddTool(toolFor(spec), h.callTool(spec))
	}
	h.sdk = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			JSONResponse:                 true,
			MaxRequestBodyBytes:          api.MaxMCPBodyBytes,
			PropagateRequestCancellation: true,
		},
	)
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !api.OriginAllowed(r.Header, h.origins) {
		api.WriteProblem(w, forbiddenOrigin())
		return
	}
	if r.URL.EscapedPath() != api.MCPPath {
		api.WriteProblem(w, problemNotFound())
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		api.WriteProblem(w, problemMethod())
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		// Authentication still comes first for everything that is not a plain route
		// error: an unauthenticated caller never learns how a query would be judged.
		if tok, prob := api.BearerToken(r.Header); prob != nil || h.gw.Authenticate(r.Context(), tok) != nil {
			api.WriteProblem(w, h.authProblem(r))
			return
		}
		api.WriteProblem(w, problemInvalid())
		return
	}
	// Authentication before the JSON-RPC body is parsed: initialize and tools/list too.
	if prob := h.authProblem(r); prob != nil {
		api.WriteProblem(w, prob)
		return
	}
	h.sdk.ServeHTTP(w, r)
}

func (h *Handler) authProblem(r *http.Request) *api.Problem {
	tok, prob := api.BearerToken(r.Header)
	if prob != nil {
		return prob
	}
	return h.gw.Authenticate(r.Context(), tok)
}

// callTool is the handler of one tool. It re-authenticates (the HTTP-level check does
// not bind a JSON-RPC call), decodes strictly, and calls the shared service once.
func (h *Handler) callTool(spec api.Spec) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if req == nil || req.Extra == nil {
			return problemResult(api.Classify(errUnauthenticated)), nil
		}
		tok, prob := api.BearerToken(req.Extra.Header)
		if prob == nil {
			prob = h.gw.Authenticate(ctx, tok)
		}
		if prob != nil {
			return problemResult(prob), nil
		}
		call, prob := decodeArguments(spec.Operation, req.Params.Arguments)
		if prob != nil {
			return problemResult(prob), nil
		}
		value, prob := h.gw.Run(ctx, tok, call)
		if prob != nil {
			return problemResult(prob), nil
		}
		return valueResult(value)
	}
}

// decodeArguments applies the strict schema: endpoint and container are required
// strings, every other property must be one the operation defines (never follow, which
// is REST-only), with the declared JSON type; unknown/duplicate/null/trailing data is
// invalid_request.
func decodeArguments(op docker.Operation, raw json.RawMessage) (api.Call, *api.Problem) {
	if len(raw) == 0 {
		return api.Call{}, problemInvalid()
	}
	fields, err := api.DecodeObject(raw)
	if err != nil {
		return api.Call{}, problemInvalid()
	}
	var ids [2]string
	for i, key := range []string{"endpoint", "container"} {
		v, ok := fields[key]
		if !ok {
			return api.Call{}, problemInvalid()
		}
		if err := json.Unmarshal(v, &ids[i]); err != nil || len(v) == 0 || v[0] != '"' {
			return api.Call{}, problemInvalid()
		}
		delete(fields, key)
	}
	return api.BuildCall(op, ids[0], ids[1], fields, false)
}

func valueResult(value any) (*mcp.CallToolResult, error) {
	text, err := json.Marshal(value)
	if err != nil {
		return problemResult(api.Classify(err)), nil
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(text)}},
		StructuredContent: json.RawMessage(text),
	}, nil
}

// problemResult reports a failure as a tool error carrying the common error body (the
// same code/status/reason as the REST response for the same condition).
func problemResult(p *api.Problem) *mcp.CallToolResult {
	body, _ := json.Marshal(p.Body())
	return &mcp.CallToolResult{
		IsError:           true,
		Content:           []mcp.Content{&mcp.TextContent{Text: string(body)}},
		StructuredContent: json.RawMessage(body),
	}
}
