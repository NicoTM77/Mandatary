package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// Executor is the shared operation service (ops.Service). It is the ONLY path from an
// adapter to authorization and to Docker.
type Executor interface {
	Execute(ctx context.Context, req ops.Request) (ops.Result, error)
}

// Authenticator verifies a credential's validity without any target or backend
// involvement (authz.Authorizer.Authenticate).
type Authenticator interface {
	Authenticate(ctx context.Context, creds authz.PrincipalCredentials) error
}

// GatewayConfig configures the pieces both adapters share.
type GatewayConfig struct {
	Executor      Executor
	Authenticator Authenticator
	// Endpoints maps endpoint slugs (Phase 1: "local") to endpoint UUIDs. A request may
	// name an endpoint by canonical UUID or by a configured slug; nothing else.
	Endpoints map[string]domain.EndpointID
	// LogReadTimeout bounds one non-streaming logs response read. Default 30s.
	LogReadTimeout time.Duration
}

// DefaultLogReadTimeout bounds a non-streaming log read.
const DefaultLogReadTimeout = 30 * time.Second

// Gateway is the transport-neutral core: Bearer extraction, authentication-first,
// endpoint resolution and one call to the shared service with error mapping.
type Gateway struct {
	exec      Executor
	auth      Authenticator
	endpoints map[string]domain.EndpointID
	logRead   time.Duration
}

// ErrInvalidGateway reports an unusable GatewayConfig.
var ErrInvalidGateway = errors.New("invalid api gateway configuration")

// NewGateway validates the configuration fail-closed.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.Executor == nil || cfg.Authenticator == nil {
		return nil, ErrInvalidGateway
	}
	g := &Gateway{exec: cfg.Executor, auth: cfg.Authenticator, endpoints: map[string]domain.EndpointID{}, logRead: cfg.LogReadTimeout}
	for slug, id := range cfg.Endpoints {
		if slug == "" || len(slug) > MaxEndpointBytes || strings.ContainsAny(slug, "/?#% \t\r\n") {
			return nil, ErrInvalidGateway
		}
		if _, err := domain.ParseEndpointID(slug); err == nil { // a slug may not shadow a UUID
			return nil, ErrInvalidGateway
		}
		parsed, err := domain.ParseEndpointID(string(id))
		if err != nil {
			return nil, ErrInvalidGateway
		}
		g.endpoints[slug] = parsed
	}
	if g.logRead == 0 {
		g.logRead = DefaultLogReadTimeout
	}
	if g.logRead < 0 {
		return nil, ErrInvalidGateway
	}
	return g, nil
}

// BearerToken extracts the one Bearer agent token from the request headers. Exactly one
// Authorization header must be present, with the Bearer scheme (case-insensitive), one
// space and a canonical agent token (auth.ValidAgentTokenFormat). Cookies, Basic and
// other schemes, query-string tokens, JWTs, setup/recovery capabilities and session
// secrets are never credentials here: they yield 401 without any storage access.
func BearerToken(h http.Header) (Token, *Problem) {
	vals := h.Values("Authorization")
	if len(vals) != 1 {
		return Token{}, newProblem(http.StatusUnauthorized, CodeUnauthenticated)
	}
	v := vals[0]
	const scheme = "Bearer "
	if len(v) <= len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) {
		return Token{}, newProblem(http.StatusUnauthorized, CodeUnauthenticated)
	}
	tok := v[len(scheme):]
	if !auth.ValidAgentTokenFormat(tok) {
		return Token{}, newProblem(http.StatusUnauthorized, CodeUnauthenticated)
	}
	return Token{v: tok}, nil
}

func (g *Gateway) credentials(tok Token) authz.PrincipalCredentials {
	// Only the opaque token ever comes from the caller. Identity, assurance, role and
	// generation attributes are loaded from trusted storage by the authorizer.
	return authz.PrincipalCredentials{AgentToken: tok.v}
}

// Authenticate verifies tok before any target is resolved (C1 O1): an unauthenticated
// caller learns nothing about targets, protected or not.
func (g *Gateway) Authenticate(ctx context.Context, tok Token) *Problem {
	return Classify(g.auth.Authenticate(ctx, g.credentials(tok)))
}

func (g *Gateway) endpoint(ref string) (domain.EndpointID, *Problem) {
	if id, err := domain.ParseEndpointID(ref); err == nil {
		return id, nil
	}
	if id, ok := g.endpoints[ref]; ok {
		return id, nil
	}
	return "", invalid()
}

func (g *Gateway) request(tok Token, c Call) (ops.Request, *Problem) {
	ep, prob := g.endpoint(c.Endpoint)
	if prob != nil {
		return ops.Request{}, prob
	}
	r := ops.Request{Credentials: g.credentials(tok), EndpointID: ep, Target: c.Container, Operation: c.Operation}
	switch c.Operation {
	case docker.OpLogs:
		r.Logs = c.Logs
	case docker.OpStop:
		r.Stop = &docker.StopOptions{TimeoutSeconds: c.TimeoutSeconds}
	case docker.OpRestart:
		r.Restart = &docker.RestartOptions{TimeoutSeconds: c.TimeoutSeconds}
	}
	return r, nil
}

// Run executes one non-streaming operation through the shared service and returns the
// typed response value (docker.InspectStatus, docker.InspectConfig, LogsResult or
// ActionResult). Logs are read to their end under the 4 MiB response bound.
func (g *Gateway) Run(ctx context.Context, tok Token, c Call) (any, *Problem) {
	if c.Follow {
		return nil, invalid() // streaming is a separate entry point (Follow)
	}
	req, prob := g.request(tok, c)
	if prob != nil {
		return nil, prob
	}
	res, err := g.exec.Execute(ctx, req)
	if err != nil {
		return nil, Classify(err)
	}
	switch c.Operation {
	case docker.OpInspectStatus:
		if res.Status == nil {
			return nil, newProblem(http.StatusInternalServerError, CodeInternal)
		}
		return *res.Status, nil
	case docker.OpInspectConfig:
		if res.Config == nil {
			return nil, newProblem(http.StatusInternalServerError, CodeInternal)
		}
		return *res.Config, nil
	case docker.OpLogs:
		if res.Logs == nil {
			return nil, newProblem(http.StatusInternalServerError, CodeInternal)
		}
		return g.collect(ctx, res)
	}
	return ActionResult{
		EndpointID:  string(res.Target.EndpointID),
		ContainerID: string(res.Target.ContainerID),
		Name:        res.ContainerName,
		Operation:   string(res.Operation),
		Outcome:     "completed",
	}, nil
}

func frameOf(f docker.LogFrame) LogFrame {
	return LogFrame{Stream: string(f.Stream), Text: strings.ToValidUTF8(string(f.Payload), "\uFFFD")}
}

func (g *Gateway) collect(ctx context.Context, res ops.Result) (any, *Problem) {
	stream := res.Logs
	defer func() { _ = stream.Close() }()
	rctx, cancel := context.WithTimeout(ctx, g.logRead)
	defer cancel()
	out := LogsResult{EndpointID: string(res.Target.EndpointID), ContainerID: string(res.Target.ContainerID), Name: res.ContainerName, Frames: []LogFrame{}}
	total := 0
	for {
		f, err := stream.Next(rctx)
		switch {
		case err == nil:
			total += len(f.Payload)
			if total > docker.MaxLogResponseBytes {
				out.Truncated = true
				return out, nil
			}
			out.Frames = append(out.Frames, frameOf(f))
		case errors.Is(err, io.EOF):
			return out, nil
		case errors.Is(err, docker.ErrLogLimitExceeded):
			out.Truncated = true
			return out, nil
		default:
			return nil, Classify(err)
		}
	}
}

// Followed is an open follow-mode log stream. Close it exactly once when done; it
// holds the authorizer lease that ends the stream on revocation or expiry.
type Followed struct {
	stream      *ops.LogStream
	EndpointID  string
	ContainerID string
	Name        string
}

// Follow opens a follow-mode log stream through the shared service (REST only).
func (g *Gateway) Follow(ctx context.Context, tok Token, c Call) (*Followed, *Problem) {
	if c.Operation != docker.OpLogs || !c.Follow || c.Logs == nil {
		return nil, invalid()
	}
	req, prob := g.request(tok, c)
	if prob != nil {
		return nil, prob
	}
	res, err := g.exec.Execute(ctx, req)
	if err != nil {
		return nil, Classify(err)
	}
	if res.Logs == nil {
		return nil, newProblem(http.StatusInternalServerError, CodeInternal)
	}
	return &Followed{stream: res.Logs, EndpointID: string(res.Target.EndpointID), ContainerID: string(res.Target.ContainerID), Name: res.ContainerName}, nil
}

// Next returns the next frame. It returns (frame, nil, false) for data, (zero, nil, true)
// when the stream ended normally and (zero, problem, true) when it ended abnormally
// (authorization ended, backend fault, caller gone).
func (f *Followed) Next(ctx context.Context) (LogFrame, *Problem, bool) {
	fr, err := f.stream.Next(ctx)
	switch {
	case err == nil:
		return frameOf(fr), nil, false
	case errors.Is(err, io.EOF):
		return LogFrame{}, nil, true
	case errors.Is(err, docker.ErrLogLimitExceeded):
		return LogFrame{}, newProblem(http.StatusBadGateway, CodeBackendFailed), true
	}
	return LogFrame{}, Classify(err), true
}

// Done is closed as soon as the stream's authorization ends.
func (f *Followed) Done() <-chan struct{} { return f.stream.Done() }

// Close ends the stream and releases its lease. It is idempotent.
func (f *Followed) Close() { _ = f.stream.Close() }
