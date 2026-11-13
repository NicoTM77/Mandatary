package ops_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/ops"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/NicoTM77/Mandatary/tests/security/fixtures"
)

const (
	localEP = domain.EndpointID("00000000-0000-4000-8000-000000000001")
	otherEP = domain.EndpointID("00000000-0000-4000-8000-000000000002")

	aliceID   = "10000000-0000-4000-8000-000000000001"
	bobID     = "10000000-0000-4000-8000-000000000002"
	aliceSess = "20000000-0000-4000-8000-000000000001"
	bobSess   = "20000000-0000-4000-8000-000000000002"
	botID     = "40000000-0000-4000-8000-000000000001"
	botCredID = "50000000-0000-4000-8000-000000000001"
	groupID   = "30000000-0000-4000-8000-000000000001"
	selEdge   = "60000000-0000-4000-8000-000000000001"
	selGlob   = "60000000-0000-4000-8000-000000000002"
	selOther  = "60000000-0000-4000-8000-000000000003"

	edgeID    = docker.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	billingID = docker.ContainerID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	// Synthetic canaries: they must never appear in any formatted output.
	canaryToken  = "mdt_CANARYTOKEN0123456789abcdef0123456789abcdef"
	canarySecret = "session-secret-CANARY-0123456789abcdef0123456789abcdef"
)

var operational = map[string]bool{
	"InspectStatus": true, "InspectConfig": true, "Logs": true,
	"Start": true, "Stop": true, "Restart": true,
}

// call is one recorded DockerBackend invocation.
type call struct {
	Method  string
	Ref     string
	Target  docker.TargetIdentity
	Timeout *int
	Tail    int
}

// spy counts EVERY DockerBackend invocation BEFORE delegating (C1 O2): the mock's
// own counters only increment after verification succeeds, so they cannot prove an
// attempt never happened. Hooks let tests interleave deterministically.
type spy struct {
	*docker.MockBackend
	mu    sync.Mutex
	calls []call

	// afterResolve runs after a ResolveTarget has returned (rename races).
	afterResolve func(ref string)
	// resolveBlock runs inside ResolveTarget before it delegates (slow daemon).
	resolveBlock func(ctx context.Context, ref string)
	// resolveCtxErr records, per ResolveTarget, the context error the BACKEND
	// observed after the afterResolve hook ran (a caller cancellation that leaked
	// into the backend call shows up here).
	resolveCtxErr []error
	// beforeOperation runs before the operational call is delegated; blocking
	// here models a slow daemon.
	beforeOperation func(method string, ctx context.Context)
	// wrapLogs decorates the stream returned for container:logs.
	wrapLogs func(docker.LogStream) docker.LogStream
	// opCtx captures the context handed to each operational call.
	opCtx []context.Context
	// ignoreCtx models a daemon that completes the call even though its context was
	// canceled meanwhile (a transport that does not honor cancellation).
	ignoreCtx bool
}

func (s *spy) delegateCtx(ctx context.Context) context.Context {
	if s.ignoreCtx {
		return context.WithoutCancel(ctx)
	}
	return ctx
}

func (s *spy) record(c call) {
	s.mu.Lock()
	s.calls = append(s.calls, c)
	s.mu.Unlock()
}

func (s *spy) snapshot() []call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]call(nil), s.calls...)
}

func (s *spy) operationalCalls() []call {
	var out []call
	for _, c := range s.snapshot() {
		if operational[c.Method] {
			out = append(out, c)
		}
	}
	return out
}

func (s *spy) total() int { return len(s.snapshot()) }

func (s *spy) enter(method string, ctx context.Context) {
	s.mu.Lock()
	s.opCtx = append(s.opCtx, ctx)
	hook := s.beforeOperation
	s.mu.Unlock()
	if hook != nil {
		hook(method, ctx)
	}
}

func (s *spy) ResolveTarget(ctx context.Context, ref string) (docker.ContainerSummary, error) {
	s.record(call{Method: "ResolveTarget", Ref: ref})
	if s.resolveBlock != nil {
		s.resolveBlock(ctx, ref)
	}
	sum, err := s.MockBackend.ResolveTarget(ctx, ref)
	if s.afterResolve != nil {
		s.afterResolve(ref)
	}
	s.mu.Lock()
	s.resolveCtxErr = append(s.resolveCtxErr, ctx.Err())
	s.mu.Unlock()
	return sum, err
}

func (s *spy) ListContainers(ctx context.Context) ([]docker.ContainerSummary, error) {
	s.record(call{Method: "ListContainers"})
	return s.MockBackend.ListContainers(ctx)
}

func (s *spy) InspectStatus(ctx context.Context, t docker.TargetIdentity) (docker.InspectStatus, error) {
	s.record(call{Method: "InspectStatus", Target: t})
	s.enter("InspectStatus", ctx)
	return s.MockBackend.InspectStatus(s.delegateCtx(ctx), t)
}

func (s *spy) InspectConfig(ctx context.Context, t docker.TargetIdentity) (docker.InspectConfig, error) {
	s.record(call{Method: "InspectConfig", Target: t})
	s.enter("InspectConfig", ctx)
	return s.MockBackend.InspectConfig(s.delegateCtx(ctx), t)
}

func (s *spy) Logs(ctx context.Context, t docker.TargetIdentity, o docker.LogOptions) (docker.LogStream, error) {
	s.record(call{Method: "Logs", Target: t, Tail: o.Tail})
	s.enter("Logs", ctx)
	st, err := s.MockBackend.Logs(s.delegateCtx(ctx), t, o)
	if err == nil && s.wrapLogs != nil {
		st = s.wrapLogs(st)
	}
	return st, err
}

func (s *spy) Start(ctx context.Context, t docker.TargetIdentity) error {
	s.record(call{Method: "Start", Target: t})
	s.enter("Start", ctx)
	return s.MockBackend.Start(s.delegateCtx(ctx), t)
}

func (s *spy) Stop(ctx context.Context, t docker.TargetIdentity, o docker.StopOptions) error {
	s.record(call{Method: "Stop", Target: t, Timeout: o.TimeoutSeconds})
	s.enter("Stop", ctx)
	return s.MockBackend.Stop(s.delegateCtx(ctx), t, o)
}

func (s *spy) Restart(ctx context.Context, t docker.TargetIdentity, o docker.RestartOptions) error {
	s.record(call{Method: "Restart", Target: t, Timeout: o.TimeoutSeconds})
	s.enter("Restart", ctx)
	return s.MockBackend.Restart(s.delegateCtx(ctx), t, o)
}

var _ docker.DockerBackend = (*spy)(nil)

// fakeTicker is the deterministic revalidation clock: a tick is delivered only
// when the test sends it, so nothing in the suite sleeps or polls.
type fakeTicker struct {
	ch      chan time.Time
	stopped chan struct{}
	once    sync.Once
	d       time.Duration
}

func (f *fakeTicker) C() <-chan time.Time { return f.ch }
func (f *fakeTicker) Stop()               { f.once.Do(func() { close(f.stopped) }) }

// Tick delivers one tick; false means the watcher already exited (stopped).
func (f *fakeTicker) Tick() bool {
	select {
	case f.ch <- time.Time{}:
		return true
	case <-f.stopped:
		return false
	}
}

// Settle returns true if the watcher completed the pass for an earlier tick and
// is still running (a second tick is only accepted once it is back at its select).
func (f *fakeTicker) Settle() bool { return f.Tick() }

type env struct {
	t     *testing.T
	dir   string // data directory of the file-backed store (reopened by restart tests)
	repo  *store.Repository
	db    *sql.DB
	clock *fixtures.Clock
	mock  *docker.MockBackend
	spy   *spy
	az    *authz.Authorizer
	svc   *ops.Service

	mu      sync.Mutex
	tickers []*fakeTicker
	// timeouts records every dispatch deadline the service requested.
	timeouts []time.Duration
	// timeoutCtxs lets a test cancel a dispatch deadline deterministically.
	timeoutCancel []context.CancelFunc
}

type envOption func(*envConfig)

type envConfig struct {
	acquireTimeout time.Duration
	withTimeout    func(*env) func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	afterAuthorize func(*env) func()
	interval       time.Duration
	usage          ops.UsageRecorder
}

// withUsage installs the usage recorder (P1.15); nil keeps accounting off.
func withUsage(r ops.UsageRecorder) envOption { return func(c *envConfig) { c.usage = r } }

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	var cfg envConfig
	for _, o := range opts {
		o(&cfg)
	}
	dir := filepath.Join(t.TempDir(), "data")
	dbPath := filepath.Join(dir, "mandatary.db")
	mk, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	// Opening a fresh store runs every migration, which dominates a test's cost under
	// the race detector. Each environment starts from a byte copy of one pristine,
	// cleanly closed store created once per process.
	copyPristineStore(t, dir)
	repo, err := store.Open(context.Background(), store.Options{DataDir: dir, MasterKey: mk, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		_ = repo.Close()
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close(); _ = repo.Close() })

	idCfg, containers := docker.DefaultMockFixtures(localEP)
	mock, err := docker.NewMockBackend(docker.MockOptions{EndpointID: localEP, Identity: idCfg, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if err = mock.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, repo: repo, db: raw, clock: fixtures.NewClock(), mock: mock, spy: &spy{MockBackend: mock}}
	e.exec(`UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0 WHERE singleton=1`)
	e.exec(`UPDATE endpoints SET id=?,state='active',authority_generation=1 WHERE slug='local'`, string(localEP))

	e.az, err = authz.NewAuthorizer(authz.Config{Repository: repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{localEP: e.spy}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.az.Close() })

	scfg := ops.Config{Authorizer: e.az, NewTicker: func(d time.Duration) ops.Ticker {
		f := &fakeTicker{ch: make(chan time.Time), stopped: make(chan struct{}), d: d}
		e.mu.Lock()
		e.tickers = append(e.tickers, f)
		e.mu.Unlock()
		return f
	}}
	scfg.Usage = cfg.usage
	if cfg.interval != 0 {
		scfg.RevalidateInterval = cfg.interval
	}
	if cfg.acquireTimeout != 0 {
		scfg.AcquireTimeout = cfg.acquireTimeout
	}
	if cfg.withTimeout != nil {
		scfg.WithTimeout = cfg.withTimeout(e)
	}
	if cfg.afterAuthorize != nil {
		scfg.AfterAuthorize = cfg.afterAuthorize(e)
	}
	e.svc, err = ops.New(scfg)
	if err != nil {
		t.Fatal(err)
	}
	e.seedStandard()
	return e
}

var (
	pristineOnce sync.Once
	pristineDir  string
	pristineErr  error
)

// TestMain owns the pristine store's lifetime.
func TestMain(m *testing.M) {
	code := m.Run()
	if pristineDir != "" {
		_ = os.RemoveAll(pristineDir)
	}
	os.Exit(code)
}

func copyPristineStore(t *testing.T, dst string) {
	t.Helper()
	pristineOnce.Do(func() {
		root, err := os.MkdirTemp("", "ops-pristine-")
		if err != nil {
			pristineErr = err
			return
		}
		pristineDir = root
		data := filepath.Join(root, "data")
		mk, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
		if err != nil {
			pristineErr = err
			return
		}
		repo, err := store.Open(context.Background(), store.Options{DataDir: data, MasterKey: mk, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
		if err != nil {
			pristineErr = err
			return
		}
		pristineErr = repo.Close()
	})
	if pristineErr != nil {
		t.Fatalf("pristine store: %v", pristineErr)
	}
	src := filepath.Join(pristineDir, "data")
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if !ent.Type().IsRegular() {
			t.Fatalf("unexpected non-regular entry %q in the pristine store", ent.Name())
		}
		b, err := os.ReadFile(filepath.Join(src, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dst, ent.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.ExecContext(context.Background(), q, args...); err != nil {
		e.t.Fatalf("exec %q: %v", q, err)
	}
}

func (e *env) ticker(i int) *fakeTicker {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if i >= len(e.tickers) {
		e.t.Fatalf("no ticker %d (have %d)", i, len(e.tickers))
	}
	return e.tickers[i]
}

func (e *env) tickerCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.tickers)
}

func (e *env) seedUser(id, name, mfa string) {
	e.exec(`INSERT INTO users (id, username, state, mfa_requirement, compromised, credential_generation, authority_generation, password_revision) VALUES (?, ?, 'active', ?, 0, 1, 1, 1)`, id, name, mfa)
}

func secretFor(id string) []byte {
	return []byte("session-secret-0123456789abcdef0123456789abcdef-" + id)
}

// seedSession stores an AAL2 (password+TOTP) normal session like the real issuer.
func (e *env) seedSession(id, userID string, assurance, methods int64) []byte {
	now := e.clock.Now().Unix()
	secret := secretFor(id)
	sum := sha256.Sum256(secret)
	e.exec(`INSERT INTO sessions (id, user_id, secret_hash, purpose, achieved_assurance, methods, phishing_resistant, authenticated_at, created_at, expires_at, last_activity_at, idle_timeout_seconds, credential_generation, session_generation, state)
		VALUES (?, ?, ?, 'normal', ?, ?, 0, ?, ?, ?, ?, 1800, 1, 1, 'active')`,
		id, userID, sum[:], assurance, methods, now-60, now-60, now-60+43200, now-30)
	return secret
}

func tokenFor(n string) string { return "mdt_testtoken0123456789abcdef0123456789abcdef" + n }

func (e *env) seedAgent(id, name, ownerUser string) string {
	e.exec(`INSERT INTO agents (id, name, owner_user_id, state, credential_generation, authority_generation) VALUES (?, ?, ?, 'active', 1, 1)`, id, name, ownerUser)
	return id
}

func (e *env) seedCredential(id, agentID, token string, expiresIn time.Duration) {
	now := e.clock.Now().Unix()
	sum := sha256.Sum256([]byte(token))
	e.exec(`INSERT INTO agent_credentials (id, agent_id, token_hash, display_prefix, issued_at, expires_at, nonexpiring_approved, credential_generation, state)
		VALUES (?, ?, ?, 'mdt_test1234', ?, ?, 0, 1, 'active')`, id, agentID, sum[:], now-600, now+int64(expiresIn/time.Second))
}

func (e *env) seedSelector(id, name string, glob bool, endpoint domain.EndpointID) {
	g := 0
	if glob {
		g = 1
	}
	e.exec(`INSERT INTO container_selectors (id, endpoint_id, container_name, name_is_glob) VALUES (?, ?, ?, ?)`, id, string(endpoint), name, g)
}

var policySeq atomic.Int64

// allow inserts one ACTIVE ALLOW for every operation of ops on selector.
func (e *env) policy(col, subject, selector, effect string, op docker.Operation, tailMax, stopMax any) {
	id := fmt.Sprintf("70000000-0000-4000-8000-%012d", policySeq.Add(1))
	e.exec(`INSERT INTO policies (id, `+col+`, endpoint_id, selector_id, operation, effect, state, authority_generation, log_tail_max, stop_timeout_max)
		VALUES (?, ?, ?, ?, ?, ?, 'active', 1, ?, ?)`, id, subject, string(localEP), selector, string(op), effect, tailMax, stopMax)
}

func (e *env) allowAll(col, subject, selector string) {
	for _, op := range ops.Operations() {
		e.policy(col, subject, selector, "ALLOW", op, nil, nil)
	}
}

// seedStandard creates alice (AAL2 session) and an agent each allowed all six
// operations on edge-proxy only; bob has a session but no grants.
func (e *env) seedStandard() {
	e.seedUser(aliceID, "alice", "required")
	e.seedUser(bobID, "bob", "required")
	e.seedSession(aliceSess, aliceID, 2, 3)
	e.seedSession(bobSess, bobID, 2, 3)
	e.seedAgent(botID, "bot", aliceID)
	e.seedCredential(botCredID, botID, tokenFor("1"), 24*time.Hour)
	e.seedSelector(selEdge, "edge-proxy", false, localEP)
	e.allowAll("user_id", aliceID, selEdge)
	e.allowAll("agent_id", botID, selEdge)
}

func aliceCreds() authz.PrincipalCredentials {
	return authz.PrincipalCredentials{SessionID: authz.SessionID(aliceSess), SessionSecret: secretFor(aliceSess)}
}

func botCreds() authz.PrincipalCredentials {
	return authz.PrincipalCredentials{AgentToken: tokenFor("1")}
}

func five() *int { v := 5; return &v }

// req builds a well-formed request for op on target with valid parameters.
func req(creds authz.PrincipalCredentials, target string, op docker.Operation) ops.Request {
	r := ops.Request{Credentials: creds, EndpointID: localEP, Target: target, Operation: op}
	switch op {
	case docker.OpLogs:
		r.Logs = &docker.LogOptions{Tail: 5, Stdout: true, Stderr: true}
	case docker.OpStop:
		r.Stop = &docker.StopOptions{TimeoutSeconds: five()}
	case docker.OpRestart:
		r.Restart = &docker.RestartOptions{TimeoutSeconds: five()}
	}
	return r
}

// waitDone fails (never asserts timing) if ch is not closed; the bound is only a
// hang guard for the test run.
func waitDone(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(60 * time.Second):
		t.Fatalf("%s: not observed", what)
	}
}

func isAllowedOutcome(r ops.Result, op docker.Operation) bool {
	switch op {
	case docker.OpInspectStatus:
		return r.Status != nil
	case docker.OpInspectConfig:
		return r.Config != nil
	case docker.OpLogs:
		return r.Logs != nil
	default:
		return r.Status == nil && r.Config == nil && r.Logs == nil
	}
}
