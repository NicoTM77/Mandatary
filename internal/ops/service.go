// Package ops is the shared operation execution service (P1.13). REST, MCP and
// the later Operations UI call exactly one entry point, Service.Execute, which
// authorizes through the single authz.Authorizer and only then dispatches one of
// the six approved Phase 1 operations to the DockerBackend, using the immutable
// target identity bound into the authorization decision (TD §§1.2, 3.3).
//
// The service has no raw Docker path, query, method or body anywhere in its API,
// no operation outside the approved catalog, and no way to reach a backend before
// authorization succeeds. Container:logs streams stay under an authorizer lease
// that ends on token, session or policy revocation or expiry.
package ops

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
)

// Error is a fixed, secret-free sentinel for failures the service itself raises.
// Raw backend, SDK, SQL and credential material is never wrapped into an error.
type Error string

func (e Error) Error() string        { return string(e) }
func (e Error) String() string       { return string(e) }
func (e Error) GoString() string     { return string(e) }
func (e Error) LogValue() slog.Value { return slog.StringValue(string(e)) }

const (
	// ErrInvalidRequest: malformed or unsupported input, rejected before any
	// authorization, storage or backend interaction.
	ErrInvalidRequest Error = "invalid operation request"
	// ErrInvalidConfig: the service was constructed or used without valid configuration.
	ErrInvalidConfig Error = "invalid operation service configuration"
	// ErrStreamRevoked: the authorization behind a log stream ended (token, session
	// or policy revoked or expired, target or safety state changed).
	ErrStreamRevoked Error = "log stream authorization ended"
	// ErrStreamClosed: the stream was closed by its consumer.
	ErrStreamClosed Error = "log stream closed"
)

// Bounds and defaults for Config (zero values select the defaults).
const (
	DefaultRevalidateInterval = time.Second
	MinRevalidateInterval     = 10 * time.Millisecond
	MaxRevalidateInterval     = 30 * time.Second
	DefaultRevalidateTimeout  = 10 * time.Second
	MaxRevalidateTimeout      = time.Minute
	DefaultAcquireTimeout     = 10 * time.Second
	MinAcquireTimeout         = time.Millisecond
	MaxAcquireTimeout         = time.Minute
	DefaultOperationTimeout   = 30 * time.Second
	MaxOperationTimeout       = 10 * time.Minute
	DefaultStopGrace          = 15 * time.Second
	MaxStopGrace              = 5 * time.Minute

	// notifyTimeout bounds one whole NotifyAuthorityChange sweep.
	notifyTimeout = 30 * time.Second
)

// Ticker abstracts the stream revalidation clock so tests drive it deterministically.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type timeTicker struct{ *time.Ticker }

func (t timeTicker) C() <-chan time.Time { return t.Ticker.C }

// Config configures a Service. Only Authorizer is required.
type Config struct {
	// Authorizer is the single shared policy engine; it also owns the backends.
	Authorizer *authz.Authorizer
	// RevalidateInterval bounds how long a stream can outlive a revocation that
	// nothing pushed (the pull path: session expiry, idle timeout, token expiry,
	// and session revocation paths that do not notify). Default 1s.
	RevalidateInterval time.Duration
	// RevalidateTimeout bounds one revalidation pass; a pass that cannot finish
	// fails closed and ends the stream. Default 10s.
	RevalidateTimeout time.Duration
	// AcquireTimeout bounds one whole lease acquisition (authorization plus the
	// revalidation under the registered lease). Acquisition runs detached from the
	// caller's cancellation, so this is its only bound; expiry is a real fault and
	// fails closed. Default 10s.
	AcquireTimeout time.Duration
	// OperationTimeout bounds inspect and start dispatches. Default 30s.
	OperationTimeout time.Duration
	// StopGrace is added to the daemon stop timeout to bound stop and restart
	// dispatches. Default 15s.
	StopGrace time.Duration
	// NewTicker, WithTimeout and AfterAuthorize are test seams (production leaves
	// them nil): the revalidation clock, the dispatch deadline, and a hook that runs
	// after admission and before backend selection so tests can change authority
	// inside that window deterministically.
	NewTicker      func(time.Duration) Ticker
	WithTimeout    func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	AfterAuthorize func()
}

// Request is one operation request. It carries no raw Docker path, query, method
// or body: only the target reference, the operation key and that operation's own
// typed options. Credentials are redacted in every formatted or encoded form.
type Request struct {
	Credentials authz.PrincipalCredentials
	EndpointID  domain.EndpointID
	// Target is a container name or full 64-hex container ID. It is resolved exactly
	// once, inside authorization; dispatch uses only the resulting immutable ID.
	Target    string
	Operation docker.Operation
	Logs      *docker.LogOptions
	Stop      *docker.StopOptions
	Restart   *docker.RestartOptions
}

const redactedRequest = "ops.Request{[REDACTED]}"

func (r Request) String() string   { return redactedRequest }
func (r Request) GoString() string { return redactedRequest }
func (r Request) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedRequest))
}
func (r Request) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedRequest + `"`), nil }
func (r Request) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("endpoint_id", string(r.EndpointID)),
		slog.String("operation", string(r.Operation)),
		slog.String("credentials", "[REDACTED]"),
	)
}

// Result carries exactly the typed, sanitized outcome of one operation: at most one
// of Status, Config or Logs is set, and operations without output set none.
type Result struct {
	Target        docker.TargetIdentity
	ContainerName string
	Operation     docker.Operation
	Status        *docker.InspectStatus
	Config        *docker.InspectConfig
	Logs          *LogStream
}

// Service executes authorized operations. It is safe for concurrent use.
type Service struct {
	az                *authz.Authorizer
	interval          time.Duration
	revalidateTimeout time.Duration
	acquireTimeout    time.Duration
	operationTimeout  time.Duration
	stopGrace         time.Duration
	newTicker         func(time.Duration) Ticker
	withTimeout       func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	afterAuthorize    func()
}

// New constructs a Service, validating configuration fail-closed.
func New(cfg Config) (*Service, error) {
	if cfg.Authorizer == nil {
		return nil, ErrInvalidConfig
	}
	pick := func(v, def, lo, hi time.Duration) (time.Duration, bool) {
		switch {
		case v == 0:
			return def, true
		case v < lo || v > hi:
			return 0, false
		}
		return v, true
	}
	var ok [5]bool
	s := &Service{az: cfg.Authorizer, newTicker: cfg.NewTicker, withTimeout: cfg.WithTimeout, afterAuthorize: cfg.AfterAuthorize}
	s.interval, ok[0] = pick(cfg.RevalidateInterval, DefaultRevalidateInterval, MinRevalidateInterval, MaxRevalidateInterval)
	s.revalidateTimeout, ok[1] = pick(cfg.RevalidateTimeout, DefaultRevalidateTimeout, time.Millisecond, MaxRevalidateTimeout)
	s.operationTimeout, ok[2] = pick(cfg.OperationTimeout, DefaultOperationTimeout, time.Millisecond, MaxOperationTimeout)
	s.stopGrace, ok[3] = pick(cfg.StopGrace, DefaultStopGrace, time.Millisecond, MaxStopGrace)
	s.acquireTimeout, ok[4] = pick(cfg.AcquireTimeout, DefaultAcquireTimeout, MinAcquireTimeout, MaxAcquireTimeout)
	for _, good := range ok {
		if !good {
			return nil, ErrInvalidConfig
		}
	}
	if s.newTicker == nil {
		s.newTicker = func(d time.Duration) Ticker { return timeTicker{time.NewTicker(d)} }
	}
	if s.withTimeout == nil {
		s.withTimeout = context.WithTimeout
	}
	return s, nil
}

// Operations returns the exact six approved Phase 1 permission keys (container:logs,
// container:inspect_status, container:inspect_config, container:start,
// container:stop, container:restart). Anything else is absent, not merely denied.
func Operations() []docker.Operation { return authz.AllOperations() }

func supported(op docker.Operation) bool {
	for _, known := range authz.AllOperations() {
		if op == known {
			return true
		}
	}
	return false
}

// normalizeTarget accepts only what Docker itself accepts as a container name
// (an optional single leading "/" then [a-zA-Z0-9][a-zA-Z0-9_.-]*, at most 255
// bytes), which also covers a full container ID. Paths, queries, sub-resources,
// wildcards, whitespace, control and non-ASCII characters never reach a backend.
func normalizeTarget(ref string) (string, bool) {
	if len(ref) > 0 && ref[0] == '/' {
		ref = ref[1:]
	}
	if len(ref) == 0 || len(ref) > 255 {
		return "", false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if alnum || (i > 0 && (c == '_' || c == '.' || c == '-')) {
			continue
		}
		return "", false
	}
	return ref, true
}

// credentialShape mirrors the verifier's exactly-one-kind rule so an anonymous or
// ambiguous caller is refused (401) before any backend interaction.
func credentialShape(c authz.PrincipalCredentials) error {
	hasUser := c.SessionID != "" || len(c.SessionSecret) > 0 || c.UserID != ""
	hasAgent := c.AgentCredentialID != "" || c.AgentToken != "" || len(c.AgentTokenHash) > 0 || c.AgentID != ""
	if hasUser == hasAgent {
		return authz.ErrUnauthenticated
	}
	return nil
}

// Execute authorizes and runs one operation.
//
// Order is fixed: pure input validation (no backend, storage or authorizer
// involvement), credential shape, then one authz.AcquireLease (self-protection ->
// authentication -> explicit DENY -> explicit ALLOW with caps -> default DENY, then a
// revalidation under the registered lease), and only then dispatch on exactly the
// immutable identity the decision bound. Every refusal leaves the backend with zero
// operational calls. The lease stays registered while the operation runs, so a
// revocation reaches an in-flight call; for container:logs it is handed to the
// returned stream.
func (s *Service) Execute(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.az == nil {
		return Result{}, ErrInvalidConfig
	}
	if ctx == nil {
		return Result{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Result{}, docker.SanitizeError(err)
	}
	if !supported(req.Operation) {
		return Result{}, ErrInvalidRequest
	}
	if _, err := domain.ParseEndpointID(string(req.EndpointID)); err != nil {
		return Result{}, ErrInvalidRequest
	}
	target, ok := normalizeTarget(req.Target)
	if !ok {
		return Result{}, ErrInvalidRequest
	}
	if _, _, err := authz.ValidateRequestParameters(req.Operation, req.Logs, req.Stop, req.Restart); err != nil {
		return Result{}, ErrInvalidRequest
	}
	if err := credentialShape(req.Credentials); err != nil {
		return Result{}, err
	}

	lease, err := s.acquire(ctx, authz.AuthorizeRequest{
		Principal:      req.Credentials,
		EndpointID:     req.EndpointID,
		TargetRef:      target,
		Operation:      req.Operation,
		LogOptions:     req.Logs,
		StopOptions:    req.Stop,
		RestartOptions: req.Restart,
	})
	if err != nil {
		return Result{}, err
	}
	return s.dispatch(ctx, lease)
}

// acquire obtains the lease with the authorizer DETACHED from the caller's
// cancellation. A caller whose request ends is a local event: if it reached
// Authorize, backend.ResolveTarget or the revalidation under the freshly registered
// lease, the authorizer would treat it as a fault, fail-close the same principal's
// healthy sibling leases on the target, and the SDK adapter would invalidate the
// endpoint's global safety proof. Acquisition is therefore bounded only by
// AcquireTimeout (a real fault that fails closed), and the admitted lease is bound
// to the caller's lifetime only once a log stream is handed off (newLogStream). A
// caller that left during acquisition gets its own context error, never an
// authorization denial, and the lease it won is released before any backend
// operation.
func (s *Service) acquire(ctx context.Context, areq authz.AuthorizeRequest) (*authz.Lease, error) {
	life, endLife := context.WithCancel(context.WithoutCancel(ctx))
	var timedOut atomic.Bool
	bound := time.AfterFunc(s.acquireTimeout, func() {
		timedOut.Store(true)
		endLife()
	})
	lease, err := s.az.AcquireLease(life, areq)
	inTime := bound.Stop() // false: the bound fired, so any lease won is already dead
	switch {
	case err != nil:
		endLife()
		if cerr := ctx.Err(); cerr != nil {
			return nil, docker.SanitizeError(cerr)
		}
		if timedOut.Load() {
			return nil, docker.SanitizeError(context.DeadlineExceeded)
		}
		return nil, err
	case !inTime:
		lease.Release()
		endLife()
		return nil, docker.SanitizeError(context.DeadlineExceeded)
	}
	if cerr := ctx.Err(); cerr != nil {
		lease.Release()
		endLife()
		return nil, docker.SanitizeError(cerr)
	}
	// The lease is deliberately NOT bound to the caller here: dispatch hands the
	// backend lease.Context(), and a caller that leaves mid-call must not cancel it
	// (see dispatch). Binding to the caller's lifetime happens only for an open log
	// stream, after hand-off.
	context.AfterFunc(lease.Context(), endLife)
	return lease, nil
}

// dispatch runs the authorized operation. It reads ONLY the decision (immutable
// TargetIdentity, normalized parameters), never the request, and never resolves a
// name. The lease is released unless it is handed to a log stream.
//
// Every backend call (one-shot operations and the Logs open call) runs under the
// lease context, which only a revocation, a release or the dispatch deadline can
// cancel. The caller's cancellation is never forwarded to the backend: when the
// caller has gone the call is allowed to finish (bounded by the dispatch deadline
// and still cancellable by revocation), its outcome is withheld and the caller's
// context error is returned.
func (s *Service) dispatch(ctx context.Context, lease *authz.Lease) (Result, error) {
	handedOff := false
	defer func() {
		if !handedOff {
			lease.Release()
		}
	}()

	dec := lease.Decision
	if s.afterAuthorize != nil {
		s.afterAuthorize()
	}
	backend, err := s.az.BackendFor(dec)
	if err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil || lease.Context().Err() != nil { // gone or revoked between admission and dispatch
		return Result{}, s.failure(ctx, lease, nil)
	}
	res := Result{Target: dec.Target, ContainerName: dec.ContainerName, Operation: dec.Operation}

	if dec.Operation == docker.OpLogs {
		if dec.LogOptions == nil {
			return Result{}, ErrInvalidRequest
		}
		inner, expired, err := s.openLogs(lease, backend, dec)
		if expired != nil { // the open outlived its deadline: the lease was released to end it
			return Result{}, docker.SanitizeError(expired)
		}
		if err != nil {
			return Result{}, s.failure(ctx, lease, err)
		}
		if ctx.Err() != nil || lease.Context().Err() != nil { // gone or revoked while opening: withhold
			_ = inner.Close()
			return Result{}, s.failure(ctx, lease, nil)
		}
		res.Logs = s.newLogStream(ctx, lease, inner)
		handedOff = true
		return res, nil
	}

	dctx, cancel := s.dispatchContext(lease.Context(), dec)
	defer cancel()
	if err := dctx.Err(); err != nil {
		return Result{}, s.failure(ctx, lease, err)
	}
	var callErr error
	switch dec.Operation {
	case docker.OpInspectStatus:
		var st docker.InspectStatus
		if st, callErr = backend.InspectStatus(dctx, dec.Target); callErr == nil {
			res.Status = &st
		}
	case docker.OpInspectConfig:
		var cfg docker.InspectConfig
		if cfg, callErr = backend.InspectConfig(dctx, dec.Target); callErr == nil {
			res.Config = &cfg
		}
	case docker.OpStart:
		callErr = backend.Start(dctx, dec.Target)
	case docker.OpStop:
		callErr = backend.Stop(dctx, dec.Target, docker.StopOptions{TimeoutSeconds: copyInt(dec.TimeoutSeconds)})
	case docker.OpRestart:
		callErr = backend.Restart(dctx, dec.Target, docker.RestartOptions{TimeoutSeconds: copyInt(dec.TimeoutSeconds)})
	default:
		return Result{}, ErrInvalidRequest
	}
	if callErr != nil {
		return Result{}, s.failure(ctx, lease, callErr)
	}
	// The call ran under the lease context only, so the caller leaving never
	// canceled it; its outcome is withheld and the caller's own context error is
	// returned instead (the daemon may nevertheless have performed the operation).
	// A read that completed after its authorization ended is withheld too.
	if ctx.Err() != nil || ((res.Status != nil || res.Config != nil) && lease.Context().Err() != nil) {
		return Result{}, s.failure(ctx, lease, nil)
	}
	return res, nil
}

func copyInt(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// openLogs runs the Logs open call under the lease context only (a revocation or a
// release reaches it, the caller leaving does not: the SDK adapter reads a canceled
// operational context as a fault of the whole endpoint) and bounds it with the
// dispatch deadline. The deadline ends only the OPEN: a watcher releases the lease
// if the open has not finished when it fires, and the watcher is retired the moment
// the open returns, so a handed-off stream (whose context is the lease) is never
// ended by it. A stream that finishes opening only after the deadline fired is
// closed. The deadline's error is returned separately: the released lease would
// otherwise make the failure look like a revocation.
func (s *Service) openLogs(lease *authz.Lease, backend docker.DockerBackend, dec authz.Decision) (stream docker.LogStream, expired error, err error) {
	dctx, dcancel := s.dispatchContext(context.WithoutCancel(lease.Context()), dec)
	var (
		mu       sync.Mutex
		finished bool
		fired    error
	)
	stop := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-dctx.Done():
			mu.Lock()
			if !finished {
				fired = dctx.Err()
				lease.Release() // cancels the lease context the open call runs under
			}
			mu.Unlock()
		case <-stop:
		}
	}()
	inner, err := backend.Logs(lease.Context(), dec.Target, *dec.LogOptions)
	mu.Lock()
	finished = true
	why := fired
	mu.Unlock()
	close(stop)
	dcancel()
	<-watcherDone
	if why != nil {
		if err == nil {
			_ = inner.Close()
		}
		return nil, why, nil
	}
	return inner, nil, err
}

// dispatchContext bounds one-shot operations and the Logs open call: the daemon's stop timeout plus a
// fixed grace for stop and restart, the operation timeout otherwise.
func (s *Service) dispatchContext(parent context.Context, dec authz.Decision) (context.Context, context.CancelFunc) {
	d := s.operationTimeout
	if dec.Operation == docker.OpStop || dec.Operation == docker.OpRestart {
		secs := docker.DefaultStopTimeoutSeconds
		if dec.TimeoutSeconds != nil {
			secs = *dec.TimeoutSeconds
		}
		d = time.Duration(secs)*time.Second + s.stopGrace
	}
	return s.withTimeout(parent, d)
}

// failure maps an error observed after admission to a secret-free outcome. A
// vanished caller yields its context error; an authorization that ended mid-flight
// yields the authorizer's own denial; otherwise the sanitized backend sentinel.
func (s *Service) failure(ctx context.Context, lease *authz.Lease, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return docker.SanitizeError(cerr)
	}
	if lease.Context().Err() != nil {
		if rerr := lease.Revalidate(ctx); rerr != nil {
			return rerr
		}
		return ErrStreamRevoked
	}
	if err == nil {
		return docker.ErrBackendFailed
	}
	return docker.SanitizeError(err)
}

// NotifyAuthorityChange revalidates every active lease and stream NOW. Callers
// invoke it AFTER committing any change that can end authority, including session
// revocation paths (logout, saved-code recovery entry, MFA-reset issuance,
// protective reports), which do not notify the authorizer themselves. It is
// detached from the caller's cancellation (a request context that ends mid-sweep
// must not fail-close healthy streams) and bounded by its own timeout; a sweep that
// cannot finish fails closed.
func (s *Service) NotifyAuthorityChange(ctx context.Context) error {
	if s == nil || s.az == nil {
		return ErrInvalidConfig
	}
	if ctx == nil {
		ctx = context.Background()
	}
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
	defer cancel()
	return s.az.NotifyPolicyChange(nctx)
}
