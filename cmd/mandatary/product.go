package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/config"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/logging"
	apimcp "github.com/NicoTM77/Mandatary/internal/mcp"
	"github.com/NicoTM77/Mandatary/internal/ops"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// The composition root of the Docker-backed surface (P1.19). It wires, in the only order that keeps the
// approved boundaries intact:
//
//	DockerBackend (real SDK adapter over the configured unix socket, or the explicit in-memory mock)
//	  -> ONE shared authz.Authorizer (self-protection, default deny)
//	    -> ONE shared ops.Service (the single accounting and dispatch point, persistent usage ledger)
//	      -> api.Gateway -> REST (/api/v1) and MCP (/mcp)
//
// and hands the administrative service the three pieces of deployment wiring it must not invent itself:
// the read-only target source, the safety-proof reset used by restore and endpoint reapproval, and the
// authority-change notification. Nothing here reads a request header, a path or a body.

// verifyInterval is how often an unverified backend retries its fresh self-verification.
var verifyInterval = 5 * time.Second

// verifyTimeout bounds one VerifySelf attempt (a hung daemon leaves the backend unverified, never half-ready).
const verifyTimeout = 15 * time.Second

// productOptions are test seams; production passes the zero value.
type productOptions struct {
	// evidence replaces the /proc/self/cgroup reader.
	evidence docker.ProcessEvidenceReader
}

// product is the composed Docker-backed surface. A nil *product means no Docker backend is configured:
// the machine namespaces stay reserved and answer the common 404, and nothing can reach a daemon.
type product struct {
	rest, mcp http.Handler
	ready     func() bool
	// Administrative wiring (see accountBrowser).
	notify      func(context.Context) error
	targets     auth.TargetSource
	safetyReset func()
	stop        func()
}

// composeProduct returns (nil, true) when no backend is configured, (nil, false) for an invalid
// deployment (unusable identity settings or an internal wiring failure) and the surface otherwise.
// The first verification runs before it returns (bounded by verifyTimeout) so a healthy deployment is
// ready as soon as it serves; every later verification is the background loop's.
func composeProduct(ctx context.Context, logger *slog.Logger, c config.Config, repo *store.Repository, opts productOptions) (*product, bool) {
	if c.DockerSocket == "" && !c.MockDocker {
		return nil, true
	}
	var local domain.EndpointID
	if err := repo.Read(ctx, func(q *store.Queries) error {
		ep, err := q.GetLocalEndpoint(ctx)
		local = ep.ID
		return err
	}); err != nil {
		return nil, false
	}
	var backend docker.DockerBackend
	var counts *requestCounts // set only for a real daemon: the mock sends no request
	if c.MockDocker {
		// SELF-13: the mock identifies a synthetic protected fixture and applies the identical state
		// machine. There is no real socket in this branch and no fallback to one.
		id, fixtures := docker.DefaultMockFixtures(local)
		mock, err := docker.NewMockBackend(docker.MockOptions{EndpointID: local, Identity: id, Containers: fixtures})
		if err != nil {
			return nil, false
		}
		backend = mock
		logger.Warn(logging.DockerMockActive)
	} else {
		evidence := mandatoryEvidence(opts.evidence)
		dials := &dialMonitor{}
		counts = &requestCounts{}
		adapter, err := docker.NewSDKAdapter(docker.SDKOptions{
			EndpointID: local,
			Transport:  observeRoundTrips(unixTransport(c.DockerSocket), dials, counts),
			Identity: docker.SelfIdentityConfig{
				EndpointID:          local,
				ExplicitContainerID: c.SelfContainerID,
				InstanceUUID:        c.SelfInstanceUUID,
				EvidenceReader:      evidence,
				Observer:            transitionLogger(logger, dials),
			},
		})
		if err != nil {
			return nil, false
		}
		backend = adapter
	}

	az, err := authz.NewAuthorizer(authz.Config{Repository: repo, Backends: map[domain.EndpointID]docker.DockerBackend{local: backend}})
	if err != nil {
		_ = backend.Close()
		return nil, false
	}
	// The approved retention and ring bound (TD §9.1, docs/usage-accounting.md D4), stated explicitly:
	// 90 days of rollups and recent events, at most 1000 recent events, pruned at most hourly. No
	// environment variable and no usage endpoint exist for it.
	ledger, err := store.NewUsageLedger(repo, store.UsageConfig{Retention: 90 * 24 * time.Hour, RecentEventLimit: store.DefaultRecentEventLimit, PruneInterval: store.DefaultPruneInterval})
	if err != nil {
		_ = az.Close()
		return nil, false
	}
	svc, err := ops.New(ops.Config{Authorizer: az, Usage: ledger})
	if err != nil {
		_ = az.Close()
		return nil, false
	}
	gateway, err := api.NewGateway(api.GatewayConfig{Executor: svc, Authenticator: az, Endpoints: map[string]domain.EndpointID{"local": local}})
	if err != nil {
		_ = az.Close()
		return nil, false
	}
	p := &product{targets: auth.AuthorizerTargets{A: az}, notify: svc.NotifyAuthorityChange, safetyReset: az.InvalidateSelfProtection}
	// Readiness (SELF-01/02, rest.go Config.Ready) is the endpoint's safety proof: the backend is ready
	// AND its self-protection state is VERIFIED. A missing socket, unproven identity, unsupported API,
	// an unreachable daemon or a dropped proof (restore, reapproval, lost continuity) is false. It is
	// deliberately not about accounts: a fresh installation awaiting setup is ready for nobody to use,
	// and authorization (default deny, quarantine, assurance) is enforced per request, not by this flag.
	p.ready = func() bool {
		return backend.Ready() && backend.VerificationState() == docker.StateVerified
	}
	if p.rest, err = api.NewHandler(api.Config{Gateway: gateway, Ready: p.ready}); err != nil {
		_ = az.Close()
		return nil, false
	}
	if p.mcp, err = apimcp.NewHandler(apimcp.Config{Gateway: gateway}); err != nil {
		_ = az.Close()
		return nil, false
	}

	// First verification before the surface is served (bounded); the loop owns every later one.
	v := &verifier{logger: logger, backend: backend}
	v.attempt(ctx)
	background, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); v.run(background) }()
	if counts != nil {
		wg.Add(1)
		go func() { defer wg.Done(); counts.run(background, logger, requestLogInterval) }()
	}
	var once sync.Once
	p.stop = func() {
		once.Do(func() {
			cancel()
			wg.Wait()
			_ = az.Close() // cancels every active stream and closes the backends
			counts.log(logger)
		})
	}
	return p, true
}

// mandatoryEvidence makes the process's own runtime evidence mandatory for a real socket (SELF-13, S1.4).
// With a real daemon there is no native exception: the process must be provably inside a container (its
// cgroup names the container, or it is the root of a private cgroup namespace). Anything else, including a
// native host process, a masked or absent /proc/self/cgroup and an unreadable one, leaves the safety proof
// unverified even when the deployment binding names a labelled member of the inventory: a borrowed
// binding must never let a host process pose as that container.
func mandatoryEvidence(read docker.ProcessEvidenceReader) docker.ProcessEvidenceReader {
	if read == nil {
		read = docker.DefaultProcessEvidenceReader
	}
	return func(ctx context.Context) (docker.ProcessEvidence, error) {
		ev, err := read(ctx)
		ev.Mandatory = true
		return ev, err
	}
}

// verifier performs the fresh VerifySelf the contract requires at process start and after every loss of
// proof (daemon restart, lost continuity, restore, endpoint reapproval). It never restores a previous
// state from storage or a cache, and logs only state transitions with a fixed reason.
type verifier struct {
	logger  *slog.Logger
	backend docker.DockerBackend
	// verified is the last state logged; outage limits the unverified line to one per outage.
	verified, outage bool
}

func (v *verifier) attempt(ctx context.Context) {
	if v.backend.VerificationState() == docker.StateVerified && v.backend.Ready() {
		// Heartbeat: while verified, one all-state inventory read through the adapter's own admission
		// path (daemon identity, own container, labelled peers; no operational call). Any fault drops the
		// proof in the adapter itself, so readiness reports the daemon being gone or the identity having
		// changed within one interval instead of waiting for the next request to discover it
		// (P112-event-reconnect-contract: discontinuity is detected here, recovery is only a fresh VerifySelf).
		check, cancel := context.WithTimeout(ctx, verifyTimeout)
		_, err := v.backend.ListContainers(check)
		cancel()
		if err != nil && ctx.Err() == nil {
			v.logger.Warn(logging.DockerUnverified, "reason", dockerReason(err))
			v.verified, v.outage = false, true
		}
		return
	}
	check, cancel := context.WithTimeout(ctx, verifyTimeout)
	err := v.backend.VerifySelf(check)
	cancel()
	switch {
	case err == nil && v.backend.VerificationState() == docker.StateVerified:
		if !v.verified {
			v.logger.Info(logging.DockerVerified)
		}
		v.verified, v.outage = true, false
	case ctx.Err() != nil:
	default:
		if v.verified || !v.outage {
			v.logger.Warn(logging.DockerUnverified, "reason", dockerReason(err))
		}
		v.verified, v.outage = false, true
	}
}

// run retries on every tick until ctx ends.
func (v *verifier) run(ctx context.Context) {
	ticker := time.NewTicker(verifyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.attempt(ctx)
		}
	}
}

// transitionLogger reports every loss and restoration of the endpoint's safety proof (P1.20, R2). Without it
// a proof lost during a request and re-established by the next verification tick left no trace at all, so an
// operator saw authorized calls refused with safety_unverified and nothing in the log. Only members of the
// closed vocabularies in internal/docker/transition.go and counts or durations are logged; the logging
// boundary admits nothing else, so no error text, path, ID, token or payload can reach the line.
func transitionLogger(logger *slog.Logger, dials *dialMonitor) docker.TransitionObserver {
	return func(tr docker.Transition) {
		if tr.Verified {
			logger.Info(logging.DockerSafetyRestored, "outage_ms", tr.Outage.Milliseconds())
			return
		}
		attrs := []any{
			"reason", string(tr.Drop.Reason), "step", string(tr.Drop.Step), "cause", string(tr.Drop.Cause),
			"elapsed_ms", tr.Drop.Elapsed.Milliseconds(), "inflight", tr.Inflight, "streams", int64(tr.Streams),
		}
		// The Docker SDK discards the error behind a connection failure, so the failed connects since the last
		// report are counted at the dialer, with the class of the last one.
		if n, last := dials.take(); n > 0 {
			attrs = append(attrs, "dial_faults", n, "dial_last", last)
		}
		logger.Warn(logging.DockerSafetyDropped, attrs...)
	}
}

// dialMonitor counts the transport failures of the calls to the Docker socket by a closed class (diagnostics only).
// The Docker SDK replaces the error behind a connection failure with a fixed text, so the class is taken here, below it.
type dialMonitor struct {
	faults atomic.Int64
	last   atomic.Value // string
}

// observedTransport records the class of every failed round trip, then returns the error unchanged.
type observedTransport struct {
	base   http.RoundTripper
	mon    *dialMonitor
	counts *requestCounts
}

func observeRoundTrips(base http.RoundTripper, mon *dialMonitor, counts *requestCounts) http.RoundTripper {
	return &observedTransport{base: base, mon: mon, counts: counts}
}

func (t *observedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.counts.record(req)
	resp, err := t.base.RoundTrip(req)
	t.mon.record(err)
	return resp, err
}

func (m *dialMonitor) record(err error) {
	// A caller's own cancellation or deadline is not a transport fault.
	if m == nil || err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	class := "other"
	var ne net.Error
	switch {
	case errors.Is(err, syscall.EAGAIN):
		class = "would_block"
	case errors.Is(err, syscall.ECONNREFUSED):
		class = "refused"
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		class = "no_descriptors"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		class = "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		class = "eof"
	case errors.Is(err, syscall.ETIMEDOUT), errors.As(err, &ne) && ne.Timeout():
		class = "timeout"
	}
	m.last.Store(class)
	m.faults.Add(1)
}

// take returns the failed round trips since the previous call and the class of the last one.
func (m *dialMonitor) take() (int64, string) {
	if m == nil {
		return 0, ""
	}
	n := m.faults.Swap(0)
	last, _ := m.last.Load().(string)
	return n, last
}

func dockerReason(err error) string {
	switch {
	case errors.Is(err, docker.ErrUnsupportedAPIVersion):
		return "unsupported_api"
	case errors.Is(err, docker.ErrUnverified):
		return "identity"
	default:
		return "unreachable"
	}
}

// unixTransport dials only the one configured socket, whatever address the SDK asks for. No proxy
// environment, no TLS and no other network destination is reachable through it.
func unixTransport(path string) *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer.DialContext(ctx, "unix", path) },
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

// newBackupService builds the logical backup service that arms the P1.18 export/restore routes.
func newBackupService(repo *store.Repository) (*backup.Service, error) {
	return backup.New(repo, buildIdentity())
}
