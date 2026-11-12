// Package adapters_test is the real API/MCP acceptance suite (P1.14, roadmap R).
//
// The whole stack is real except the Docker daemon: SQLite store + the shared
// authz.Authorizer + ops.Service + the REST adapter and the official MCP server, served
// over real loopback HTTP and driven by net/http and by the official go-sdk MCP client.
// The backend is the in-memory MockBackend behind an attempt-counting spy, so "must not
// reach Docker" is measured, never inferred. No Docker socket, container build, real
// mail or secret is involved.
package adapters_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	apimcp "github.com/NicoTM77/Mandatary/internal/mcp"
	"github.com/NicoTM77/Mandatary/internal/ops"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/NicoTM77/Mandatary/tests/security/fixtures"
)

const (
	localEP = domain.EndpointID("00000000-0000-4000-8000-000000000001")
	otherEP = domain.EndpointID("00000000-0000-4000-8000-000000000002")

	ownerID = "10000000-0000-4000-8000-000000000001" // ordinary owner of most agents
	adminID = "10000000-0000-4000-8000-000000000002" // holds the super_admin role, owns agentAdmin
	aliceID = "10000000-0000-4000-8000-000000000003" // human with a normal AAL2 session

	aliceSess = "20000000-0000-4000-8000-000000000001"

	selEdge     = "60000000-0000-4000-8000-000000000001"
	selBilling  = "60000000-0000-4000-8000-000000000002"
	selWildcard = "60000000-0000-4000-8000-000000000003"

	edgeID    = docker.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	billingID = docker.ContainerID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	rogueID   = docker.ContainerID("9999999999999999999999999999999999999999999999999999999999999999")

	// Synthetic canaries: they must never appear in any response.
	canaryEnv = "CANARY_ENV_SECRET_VALUE_0123456789"
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// canonToken derives a deterministic canonical agent token (mdt_ + 43 base62 digits).
func canonToken(label string) string {
	sum := sha256.Sum256([]byte("p114-token-" + label))
	b := make([]byte, 0, 47)
	b = append(b, "mdt_"...)
	for i := 0; i < 43; i++ {
		b = append(b, base62[int(sum[i%32]+byte(i))%62])
	}
	return string(b)
}

// agentSpec describes one agent, its credential and its policies.
type agentSpec struct {
	key       string
	agentID   string
	credID    string
	owner     string
	state     string // agent state, default active
	token     string
	grants    []grant
	issuedAgo time.Duration
	expiresIn time.Duration // default 24h
	overlap   time.Duration // rotation_overlap_until relative to now (negative: passed); 0 = none
	credState string        // default active
	credGen   int64         // default 1
}

type grant struct {
	selector string
	op       docker.Operation // "" = all six
	effect   string           // default ALLOW
	tailMax  any
	stopMax  any
}

// spy counts EVERY DockerBackend invocation BEFORE delegating (C1 O2): the mock's own
// counters only move after its checks pass, so they cannot prove an attempt never
// happened.
type spy struct {
	*docker.MockBackend
	mu    sync.Mutex
	calls []string
}

var operational = map[string]bool{"InspectStatus": true, "InspectConfig": true, "Logs": true, "Start": true, "Stop": true, "Restart": true}

func (s *spy) rec(m string) { s.mu.Lock(); s.calls = append(s.calls, m); s.mu.Unlock() }
func (s *spy) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}
func (s *spy) total() int { return len(s.snapshot()) }
func (s *spy) operationalCalls() []string {
	var out []string
	for _, c := range s.snapshot() {
		if operational[c] {
			out = append(out, c)
		}
	}
	return out
}
func (s *spy) reset() { s.mu.Lock(); s.calls = nil; s.mu.Unlock() }

func (s *spy) ResolveTarget(ctx context.Context, r string) (docker.ContainerSummary, error) {
	s.rec("ResolveTarget")
	return s.MockBackend.ResolveTarget(ctx, r)
}
func (s *spy) ListContainers(ctx context.Context) ([]docker.ContainerSummary, error) {
	s.rec("ListContainers")
	return s.MockBackend.ListContainers(ctx)
}
func (s *spy) InspectStatus(ctx context.Context, t docker.TargetIdentity) (docker.InspectStatus, error) {
	s.rec("InspectStatus")
	return s.MockBackend.InspectStatus(ctx, t)
}
func (s *spy) InspectConfig(ctx context.Context, t docker.TargetIdentity) (docker.InspectConfig, error) {
	s.rec("InspectConfig")
	return s.MockBackend.InspectConfig(ctx, t)
}
func (s *spy) Logs(ctx context.Context, t docker.TargetIdentity, o docker.LogOptions) (docker.LogStream, error) {
	s.rec("Logs")
	return s.MockBackend.Logs(ctx, t, o)
}
func (s *spy) Start(ctx context.Context, t docker.TargetIdentity) error {
	s.rec("Start")
	return s.MockBackend.Start(ctx, t)
}
func (s *spy) Stop(ctx context.Context, t docker.TargetIdentity, o docker.StopOptions) error {
	s.rec("Stop")
	return s.MockBackend.Stop(ctx, t, o)
}
func (s *spy) Restart(ctx context.Context, t docker.TargetIdentity, o docker.RestartOptions) error {
	s.rec("Restart")
	return s.MockBackend.Restart(ctx, t, o)
}

var _ docker.DockerBackend = (*spy)(nil)

type env struct {
	t     *testing.T
	db    *sql.DB
	repo  *store.Repository
	clock *fixtures.Clock
	mock  *docker.MockBackend
	spy   *spy
	other *spy
	az    *authz.Authorizer
	svc   *ops.Service
	rest  *api.Handler
	mcp   *apimcp.Handler
	srv   *httptest.Server

	agents map[string]agentSpec
}

type envOptions struct {
	interval  time.Duration // stream revalidation interval (pull path); default 1s
	perStream int
	streams   int
}

var policySeq atomic.Int64

func newEnv(t *testing.T, opt ...func(*envOptions)) *env {
	t.Helper()
	var o envOptions
	for _, f := range opt {
		f(&o)
	}
	dir := filepath.Join(t.TempDir(), "data")
	mk, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	copyPristineStore(t, dir)
	repo, err := store.Open(context.Background(), store.Options{DataDir: dir, MasterKey: mk, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", filepath.Join(dir, "mandatary.db"))
	if err != nil {
		_ = repo.Close()
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close(); _ = repo.Close() })

	idCfg, containers := docker.DefaultMockFixtures(localEP)
	containers = append(containers, docker.MockContainerFixture{
		ID: rogueID, Name: "reverse-proxy", Image: "nginx:1.27-alpine", State: "running", Status: "Up",
		Labels: map[string]string{docker.SelfLabelKey: docker.SelfLabelValue}, // an innocuously named labelled peer (SELF-08)
	})
	mock, err := docker.NewMockBackend(docker.MockOptions{EndpointID: localEP, Identity: idCfg, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if err = mock.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Plant a secret canary into the edge-proxy environment: inspect_config must redact it.
	if err = upsertEnv(mock, "edge-proxy", "DATABASE_PASSWORD="+canaryEnv); err != nil {
		t.Fatal(err)
	}
	otherIdent, otherContainers := docker.DefaultMockFixtures(otherEP)
	otherMock, err := docker.NewMockBackend(docker.MockOptions{EndpointID: otherEP, Identity: otherIdent, Containers: otherContainers})
	if err != nil {
		t.Fatal(err)
	}
	if err = otherMock.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}

	e := &env{t: t, db: raw, repo: repo, clock: fixtures.NewClock(), mock: mock, spy: &spy{MockBackend: mock}, other: &spy{MockBackend: otherMock}, agents: map[string]agentSpec{}}
	e.exec(`UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0 WHERE singleton=1`)
	e.exec(`UPDATE endpoints SET id=?,state='active',authority_generation=1 WHERE slug='local'`, string(localEP))

	e.az, err = authz.NewAuthorizer(authz.Config{Repository: repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{localEP: e.spy, otherEP: e.other}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.az.Close() })
	scfg := ops.Config{Authorizer: e.az}
	if o.interval != 0 {
		scfg.RevalidateInterval = o.interval
	}
	e.svc, err = ops.New(scfg)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := api.NewGateway(api.GatewayConfig{Executor: e.svc, Authenticator: e.az, Endpoints: map[string]domain.EndpointID{"local": localEP}})
	if err != nil {
		t.Fatal(err)
	}
	e.rest, err = api.NewHandler(api.Config{Gateway: gw, Ready: e.ready, MaxStreamsPerCredential: o.perStream, MaxStreams: o.streams})
	if err != nil {
		t.Fatal(err)
	}
	e.mcp, err = apimcp.NewHandler(apimcp.Config{Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(api.Compose(e.rest, e.mcp, http.NotFoundHandler()))
	t.Cleanup(e.srv.Close)
	e.seed()
	return e
}

func upsertEnv(m *docker.MockBackend, name string, extra string) error {
	_, list := docker.DefaultMockFixtures(localEP)
	for _, c := range list {
		if c.Name == name {
			c.Env = append(append([]string(nil), c.Env...), extra)
			return m.UpsertContainer(c)
		}
	}
	return fmt.Errorf("no fixture %s", name)
}

// ready is the composition's readiness: every endpoint backend ready and verified.
func (e *env) ready() bool {
	for _, b := range []docker.DockerBackend{e.spy, e.other} {
		if !b.Ready() || b.VerificationState() != docker.StateVerified {
			return false
		}
	}
	return true
}

var (
	pristineOnce sync.Once
	pristineDir  string
	pristineErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if pristineDir != "" {
		_ = os.RemoveAll(pristineDir)
	}
	os.Exit(code)
}

// copyPristineStore starts every environment from a byte copy of one cleanly closed
// store (migrations dominate a test's cost under the race detector).
func copyPristineStore(t *testing.T, dst string) {
	t.Helper()
	pristineOnce.Do(func() {
		root, err := os.MkdirTemp("", "adapters-pristine-")
		if err != nil {
			pristineErr = err
			return
		}
		pristineDir = root
		mk, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
		if err != nil {
			pristineErr = err
			return
		}
		repo, err := store.Open(context.Background(), store.Options{DataDir: filepath.Join(root, "data"), MasterKey: mk, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
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

func (e *env) seedUser(id, name, mfa string) {
	e.exec(`INSERT INTO users (id, username, state, mfa_requirement, compromised, credential_generation, authority_generation, password_revision) VALUES (?, ?, 'active', ?, 0, 1, 1, 1)`, id, name, mfa)
}

func (e *env) seedSelector(id, name string, glob bool, endpoint domain.EndpointID) {
	g := 0
	if glob {
		g = 1
	}
	e.exec(`INSERT INTO container_selectors (id, endpoint_id, container_name, name_is_glob) VALUES (?, ?, ?, ?)`, id, string(endpoint), name, g)
}

func (e *env) policy(col, subject, selector, effect string, op docker.Operation, tailMax, stopMax any) {
	id := fmt.Sprintf("70000000-0000-4000-8000-%012d", policySeq.Add(1))
	e.exec(`INSERT INTO policies (id, `+col+`, endpoint_id, selector_id, operation, effect, state, authority_generation, log_tail_max, stop_timeout_max)
		VALUES (?, ?, ?, ?, ?, ?, 'active', 1, ?, ?)`, id, subject, string(localEP), selector, string(op), effect, tailMax, stopMax)
}

func (e *env) addAgent(a agentSpec) agentSpec {
	e.t.Helper()
	if a.state == "" {
		a.state = "active"
	}
	if a.credState == "" {
		a.credState = "active"
	}
	if a.credGen == 0 {
		a.credGen = 1
	}
	if a.expiresIn == 0 {
		a.expiresIn = 24 * time.Hour
	}
	if a.issuedAgo == 0 {
		a.issuedAgo = 10 * time.Minute
	}
	if a.owner == "" {
		a.owner = ownerID
	}
	if a.token == "" {
		a.token = canonToken(a.key)
	}
	now := e.clock.Now().Unix()
	e.exec(`INSERT INTO agents (id, name, owner_user_id, state, credential_generation, authority_generation) VALUES (?, ?, ?, ?, 1, 1)`, a.agentID, a.key, a.owner, a.state)
	sum := sha256.Sum256([]byte(a.token))
	var overlap, revoked any
	if a.overlap != 0 {
		overlap = now + int64(a.overlap/time.Second)
	}
	if a.credState == "revoked" {
		revoked = now - 5
	}
	e.exec(`INSERT INTO agent_credentials (id, agent_id, token_hash, display_prefix, issued_at, expires_at, nonexpiring_approved, rotation_overlap_until, revoked_at, credential_generation, state)
		VALUES (?, ?, ?, 'mdt_test1234', ?, ?, 0, ?, ?, ?, ?)`, a.credID, a.agentID, sum[:], now-int64(a.issuedAgo/time.Second), now+int64(a.expiresIn/time.Second), overlap, revoked, a.credGen, a.credState)
	for _, g := range a.grants {
		ops := []docker.Operation{g.op}
		if g.op == "" {
			ops = authz.AllOperations()
		}
		eff := g.effect
		if eff == "" {
			eff = "ALLOW"
		}
		for _, op := range ops {
			e.policy("agent_id", a.agentID, g.selector, eff, op, g.tailMax, g.stopMax)
		}
	}
	e.agents[a.key] = a
	return a
}

func agentN(n int) (agentID, credID string) {
	return fmt.Sprintf("40000000-0000-4000-8000-%012d", n), fmt.Sprintf("50000000-0000-4000-8000-%012d", n)
}

// seed builds the standard world. Every agent has exactly the authority its key says.
func (e *env) seed() {
	e.seedUser(ownerID, "owner", "required")
	e.seedUser(adminID, "admin", "required")
	e.seedUser(aliceID, "alice", "required")
	e.exec(`INSERT INTO administrative_roles (id, user_id, role, endpoint_id, state, authority_generation) VALUES ('80000000-0000-4000-8000-000000000001', ?, 'super_admin', NULL, 'active', 1)`, adminID)
	e.seedSelector(selEdge, "edge-proxy", false, localEP)
	e.seedSelector(selBilling, "billing-worker", false, localEP)
	e.seedSelector(selWildcard, "*", true, localEP)

	add := func(n int, a agentSpec) agentSpec {
		a.agentID, a.credID = agentN(n)
		return e.addAgent(a)
	}
	add(1, agentSpec{key: "granted", grants: []grant{{selector: selEdge}}})
	add(2, agentSpec{key: "readonly", grants: []grant{
		{selector: selEdge, op: docker.OpInspectStatus}, {selector: selEdge, op: docker.OpInspectConfig}, {selector: selEdge, op: docker.OpLogs}}})
	add(3, agentSpec{key: "capped", grants: []grant{
		{selector: selEdge, op: docker.OpLogs, tailMax: 5}, {selector: selEdge, op: docker.OpStop, stopMax: 20}, {selector: selEdge, op: docker.OpRestart, stopMax: 20},
		{selector: selEdge, op: docker.OpInspectStatus}}})
	add(4, agentSpec{key: "wildcard", grants: []grant{{selector: selWildcard}}})
	add(5, agentSpec{key: "deny", grants: []grant{{selector: selWildcard}, {selector: selBilling, effect: "DENY"}}})
	add(6, agentSpec{key: "nogrant"})
	add(7, agentSpec{key: "adminowned", owner: adminID}) // owner is the administrator: no inherited authority
	add(8, agentSpec{key: "short", expiresIn: 90 * time.Second, grants: []grant{{selector: selEdge}}})
	add(9, agentSpec{key: "revoked", credState: "revoked", grants: []grant{{selector: selEdge}}})
	add(10, agentSpec{key: "rotatedout", overlap: -30 * time.Second, grants: []grant{{selector: selEdge}}})
	add(11, agentSpec{key: "overlapping", overlap: 10 * time.Minute, grants: []grant{{selector: selEdge}}})
	add(12, agentSpec{key: "importedquarantined", credState: "quarantined", credGen: 1, grants: []grant{{selector: selEdge}}})
	add(13, agentSpec{key: "disabledagent", state: "disabled", grants: []grant{{selector: selEdge}}})
	add(14, agentSpec{key: "stalegen", credGen: 2, grants: []grant{{selector: selEdge}}})
}

func (e *env) token(key string) string {
	e.t.Helper()
	a, ok := e.agents[key]
	if !ok {
		e.t.Fatalf("no agent %q", key)
	}
	return a.token
}
