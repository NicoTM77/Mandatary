package ops_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
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
)

// P1.15 exact-count fixture (TD 9.1; phase-1-plan row P1.15). The committed, versioned
// fixture testdata/usage_fixture_v1.json declares a predetermined allowed / denied /
// backend-error sequence and the EXACT hourly and daily totals per attribution tuple
// (user, agent, endpoint, selector, operation) that must result. This file drives the
// sequence through ops.Service.Execute against the in-memory Docker mock and a real
// file-backed SQLite store and compares the real ledger with the declared totals:
//
//	after the sequence;
//	after a restart (the store is closed and reopened: totals must be unchanged);
//	after a concurrent phase and further requests (exact increments, none lost);
//	after retention removed ONLY the selected windows;
//	after the service itself was replaced by a new instance ("re-run after service
//	changes"), and again after one more restart.
//
// The fixture is also checked for self-consistency against its own steps, and mutant
// recorders (drop, duplicate, count-only-allowed) prove the comparison is not vacuous.

const usageFixturePath = "testdata/usage_fixture_v1.json"

type fixtureRow struct {
	Window    string `json:"window"`
	User      string `json:"user"`
	Agent     string `json:"agent"`
	Selector  string `json:"selector"`
	Operation string `json:"operation"`
	Allowed   int64  `json:"allowed"`
	Denied    int64  `json:"denied"`
	Error     int64  `json:"error"`
}

type fixtureStep struct {
	ID       string `json:"id"`
	At       string `json:"at"`
	Who      string `json:"who"`
	Op       string `json:"op"`
	Target   string `json:"target"`
	Tail     int    `json:"tail"`
	Follow   bool   `json:"follow"`
	Fault    string `json:"fault"`
	Client   string `json:"client"`
	Outcome  string `json:"outcome"`
	Selector string `json:"selector"`
}

type fixtureIteration struct {
	Who     string `json:"who"`
	Op      string `json:"op"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
}

type fixtureConcurrent struct {
	At           string             `json:"at"`
	Workers      int                `json:"workers"`
	Iterations   int                `json:"iterations"`
	PerIteration []fixtureIteration `json:"per_iteration"`
}

type fixtureCheckpoint struct {
	Now          string       `json:"now"`
	Hourly       []fixtureRow `json:"hourly"`
	Daily        []fixtureRow `json:"daily"`
	RecentEvents int          `json:"recent_events"`
	Removed      *struct {
		Hourly       int `json:"hourly"`
		Daily        int `json:"daily"`
		RecentEvents int `json:"recent_events"`
	} `json:"removed"`
}

type usageFixture struct {
	Schema      string `json:"schema"`
	Version     int    `json:"version"`
	Description string `json:"description"`
	Setup       struct {
		RetentionHours         int  `json:"retention_hours"`
		RecentEventLimit       int  `json:"recent_event_limit"`
		BotRestartExplicitDeny bool `json:"bot_restart_explicit_deny"`
		BotLogsTailCap         int  `json:"bot_logs_tail_cap"`
	} `json:"setup"`
	Phases struct {
		Sequence           []fixtureStep     `json:"sequence"`
		AfterRestart       []fixtureStep     `json:"after_restart"`
		Concurrent         fixtureConcurrent `json:"concurrent"`
		AfterServiceChange []fixtureStep     `json:"after_service_change"`
	} `json:"phases"`
	Checkpoints map[string]fixtureCheckpoint `json:"checkpoints"`
}

func loadUsageFixture(t testing.TB) usageFixture {
	t.Helper()
	data, err := os.ReadFile(usageFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // a typo in the committed fixture is an error, never ignored
	var fx usageFixture
	if err := dec.Decode(&fx); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if fx.Schema != "mandatary.usage-fixture" || fx.Version != 1 {
		t.Fatalf("fixture schema/version %q/%d unsupported", fx.Schema, fx.Version)
	}
	for _, name := range []string{"after_sequence", "after_restart_and_concurrent", "after_retention", "after_service_change"} {
		if _, ok := fx.Checkpoints[name]; !ok {
			t.Fatalf("fixture lacks checkpoint %s", name)
		}
	}
	return fx
}

// --- symbolic names <-> the harness's identifiers ---

var (
	userNames  = map[string]string{aliceID: "alice", bobID: "bob", "": ""}
	agentNames = map[string]string{botID: "bot", "": ""}
	selNames   = map[string]string{selEdge: "edge", "": ""}
)

func rowKey(r fixtureRow) string {
	return strings.Join([]string{r.Window, r.User, r.Agent, r.Selector, r.Operation}, "|")
}

// diffRows reports every difference between two rollup tables (empty means equal).
func diffRows(got, want []fixtureRow) []string {
	g, w := map[string]fixtureRow{}, map[string]fixtureRow{}
	var out []string
	for _, r := range got {
		if _, dup := g[rowKey(r)]; dup {
			out = append(out, "duplicate row "+rowKey(r))
		}
		g[rowKey(r)] = r
	}
	for _, r := range want {
		w[rowKey(r)] = r
	}
	for k, wr := range w {
		gr, ok := g[k]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("missing row %s want A%d D%d E%d", k, wr.Allowed, wr.Denied, wr.Error))
		case gr != wr:
			out = append(out, fmt.Sprintf("row %s got A%d D%d E%d want A%d D%d E%d", k, gr.Allowed, gr.Denied, gr.Error, wr.Allowed, wr.Denied, wr.Error))
		}
	}
	for k, gr := range g {
		if _, ok := w[k]; !ok {
			out = append(out, fmt.Sprintf("unexpected row %s A%d D%d E%d", k, gr.Allowed, gr.Denied, gr.Error))
		}
	}
	sort.Strings(out)
	return out
}

// --- the run ---

type lazyUsage struct {
	mu sync.Mutex
	r  ops.UsageRecorder
}

func (l *lazyUsage) set(r ops.UsageRecorder) { l.mu.Lock(); l.r = r; l.mu.Unlock() }
func (l *lazyUsage) RecordUsage(ctx context.Context, e domain.UsageEvent) error {
	l.mu.Lock()
	r := l.r
	l.mu.Unlock()
	if r == nil {
		return errors.New("no recorder installed")
	}
	return r.RecordUsage(ctx, e)
}

type fixtureRun struct {
	t      *testing.T
	fx     usageFixture
	e      *env
	lazy   *lazyUsage
	repo   *store.Repository
	ledger *store.UsageLedger
	az     *authz.Authorizer
	svc    *ops.Service
	wrap   func(ops.UsageRecorder) ops.UsageRecorder
	now    atomic.Pointer[time.Time]
	hook   atomic.Pointer[func()]
}

func (r *fixtureRun) clock() time.Time { return *r.now.Load() }

func mustTime(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (r *fixtureRun) setNow(s string) { v := mustTime(r.t, s); r.now.Store(&v) }

func newFixtureRun(t *testing.T, fx usageFixture, wrap func(ops.UsageRecorder) ops.UsageRecorder) *fixtureRun {
	t.Helper()
	r := &fixtureRun{t: t, fx: fx, lazy: &lazyUsage{}, wrap: wrap}
	r.setNow(fx.Phases.Sequence[0].At)
	r.e = newEnv(t, withUsage(r.lazy), recordDeadlines(), func(c *envConfig) {
		c.afterAuthorize = func(*env) func() {
			return func() {
				if h := r.hook.Load(); h != nil {
					(*h)()
				}
			}
		}
	})
	r.repo, r.svc, r.az = r.e.repo, r.e.svc, r.e.az
	if fx.Setup.BotRestartExplicitDeny {
		r.e.policy("agent_id", botID, selEdge, "DENY", docker.OpRestart, nil, nil)
	}
	if fx.Setup.BotLogsTailCap > 0 {
		r.e.exec(`UPDATE policies SET log_tail_max=? WHERE agent_id=? AND operation='container:logs'`, fx.Setup.BotLogsTailCap, botID)
	}
	r.installLedger()
	return r
}

func (r *fixtureRun) installLedger() {
	l, err := store.NewUsageLedger(r.repo, store.UsageConfig{
		Retention:        time.Duration(r.fx.Setup.RetentionHours) * time.Hour,
		RecentEventLimit: r.fx.Setup.RecentEventLimit,
		DisableAutoPrune: true, // the fixture applies retention explicitly, at a declared instant
		Clock:            r.clock,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	r.ledger = l
	var rec ops.UsageRecorder = l
	if r.wrap != nil {
		rec = r.wrap(l)
	}
	r.lazy.set(rec)
}

// restart closes the store and reopens the same files with a brand-new repository,
// authorizer, service and ledger (a process restart).
func (r *fixtureRun) restart() {
	r.t.Helper()
	if err := r.repo.Close(); err != nil {
		r.t.Fatal(err)
	}
	mk, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if err != nil {
		r.t.Fatal(err)
	}
	repo, err := store.Open(context.Background(), store.Options{DataDir: r.e.dir, MasterKey: mk, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = repo.Close() })
	r.repo = repo
	r.replaceService()
}

// replaceService builds a new authorizer, operation service and ledger on the current
// repository: "the service changed", the stored totals must be untouched and keep counting.
func (r *fixtureRun) replaceService() {
	r.t.Helper()
	az, err := authz.NewAuthorizer(authz.Config{Repository: r.repo, Clock: r.e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{localEP: r.e.spy}})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = az.Close() })
	r.az = az
	r.installLedger()
	svc, err := ops.New(ops.Config{Authorizer: az, Usage: r.lazy})
	if err != nil {
		r.t.Fatal(err)
	}
	r.svc = svc
}

func (r *fixtureRun) credsOf(who string) authz.PrincipalCredentials {
	switch who {
	case "alice":
		return aliceCreds()
	case "bob":
		return bobCreds()
	case "bot":
		return botCreds()
	case "anonymous":
		return authz.PrincipalCredentials{}
	}
	r.t.Fatalf("unknown principal %q", who)
	return authz.PrincipalCredentials{}
}

func (r *fixtureRun) request(who, op, target string, tail int, follow bool) ops.Request {
	rq := req(r.credsOf(who), target, docker.Operation(op))
	if rq.Logs != nil {
		if tail > 0 {
			rq.Logs.Tail = tail
		}
		rq.Logs.Follow = follow
	}
	return rq
}

func matchesClient(want string, err error) bool {
	switch want {
	case "ok":
		return err == nil
	case "unauthenticated":
		return errors.Is(err, authz.ErrUnauthenticated)
	case "forbidden":
		return errors.Is(err, authz.ErrForbidden)
	case "denied":
		return isDenial(err)
	case "invalid":
		return errors.Is(err, ops.ErrInvalidRequest)
	case "backend_failed":
		return errors.Is(err, docker.ErrBackendFailed)
	case "not_found":
		return errors.Is(err, docker.ErrTargetNotFound)
	case "canceled":
		return errors.Is(err, context.Canceled)
	case "deadline":
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	return false
}

// execute performs one step, applying its declared fault deterministically.
func (r *fixtureRun) execute(s fixtureStep) (ops.Result, error) {
	t, e := r.t, r.e
	t.Helper()
	rq := r.request(s.Who, s.Op, s.Target, s.Tail, s.Follow)
	op := docker.Operation(s.Op)
	// blockCall holds the backend call until the test lets it go; on runs while it is in flight.
	blockCall := func(on func(ctx context.Context, cancelCaller func())) outcome {
		entered := make(chan context.Context, 1)
		release := make(chan struct{})
		e.spy.beforeOperation = func(_ string, ctx context.Context) { entered <- ctx; <-release }
		defer func() { e.spy.beforeOperation = nil }()
		reqCtx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan outcome, 1)
		go func() { res, err := r.svc.Execute(reqCtx, rq); done <- outcome{res, err} }()
		on(<-entered, func() { cancel(); settle() })
		close(release)
		return <-done
	}
	switch s.Fault {
	case "":
		return r.svc.Execute(t.Context(), rq)
	case "backend_failed":
		e.mock.SetOperationFailure(op, docker.ErrBackendFailed)
		res, err := r.svc.Execute(t.Context(), rq)
		e.mock.SetOperationFailure(op, nil)
		if verr := e.mock.VerifySelf(context.Background()); verr != nil { // the mock, like the adapter, lost its safety proof on a backend fault
			t.Fatalf("%s: re-verification after the injected fault: %v", s.ID, verr)
		}
		return res, err
	case "target_vanishes":
		saved := fixtureOf(e, edgeID)
		hook := func() { e.mock.RemoveContainer(edgeID) }
		r.hook.Store(&hook)
		res, err := r.svc.Execute(t.Context(), rq)
		r.hook.Store(nil)
		if uerr := e.mock.UpsertContainer(saved); uerr != nil {
			t.Fatal(uerr)
		}
		return res, err
	case "authority_lost_before_dispatch": // the authorization is invalidated between admission and dispatch
		hook := func() { r.az.InvalidateAll() }
		r.hook.Store(&hook)
		res, err := r.svc.Execute(t.Context(), rq)
		r.hook.Store(nil)
		return res, err
	case "stream_backend_failure": // the open succeeds, the first read fails terminally
		e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { return &failingStream{LogStream: inner} }
		defer func() { e.spy.wrapLogs = nil }()
		res, err := r.svc.Execute(t.Context(), rq)
		if err != nil || res.Logs == nil {
			return res, err
		}
		if _, nerr := res.Logs.Next(t.Context()); !errors.Is(nerr, docker.ErrBackendFailed) {
			t.Fatalf("%s: stream read = %v, want the terminal backend failure", s.ID, nerr)
		}
		_ = res.Logs.Close()
		return ops.Result{}, nil
	case "stream_request_cancel": // the open succeeds, then the request ends
		reqCtx, cancel := context.WithCancel(t.Context())
		defer cancel()
		res, err := r.svc.Execute(reqCtx, rq)
		if err != nil || res.Logs == nil {
			return res, err
		}
		cancel()
		waitDone(t, res.Logs.Done(), "stream ended by its request")
		if _, nerr := res.Logs.Next(t.Context()); !errors.Is(nerr, context.Canceled) {
			t.Fatalf("%s: stream read after the request ended = %v", s.ID, nerr)
		}
		_ = res.Logs.Close()
		return ops.Result{}, nil
	case "caller_leaves_mid_call":
		o := blockCall(func(_ context.Context, cancelCaller func()) { cancelCaller() })
		return o.res, o.err
	case "revoke_mid_call":
		o := blockCall(func(backendCtx context.Context, _ func()) {
			revokeCredential(e)
			if err := r.svc.NotifyAuthorityChange(t.Context()); err != nil {
				t.Fatal(err)
			}
			if backendCtx.Err() == nil {
				t.Fatalf("%s: revocation did not cancel the in-flight call", s.ID)
			}
		})
		return o.res, o.err
	case "deadline_fires": // a daemon that never answers until its dispatch bound fires
		entered := make(chan struct{}, 1)
		e.spy.beforeOperation = func(_ string, ctx context.Context) { entered <- struct{}{}; <-ctx.Done() }
		defer func() { e.spy.beforeOperation = nil }()
		done := make(chan outcome, 1)
		go func() { res, err := r.svc.Execute(t.Context(), rq); done <- outcome{res, err} }()
		<-entered
		e.fireDeadline(len(e.deadlines()) - 1)
		o := <-done
		return o.res, o.err
	}
	t.Fatalf("%s: unknown fault %q", s.ID, s.Fault)
	return ops.Result{}, nil
}

// runStep executes one step and, when perStep, verifies what the caller saw and that
// the ledger gained exactly the declared event (or none).
func (r *fixtureRun) runStep(s fixtureStep, perStep bool) {
	t := r.t
	t.Helper()
	r.setNow(s.At)
	before, err := r.ledger.Recent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	res, execErr := r.execute(s)
	if res.Logs != nil {
		for range 2 {
			if _, err := res.Logs.Next(t.Context()); err != nil {
				t.Fatalf("%s: frame: %v", s.ID, err)
			}
		}
		if err := res.Logs.Revalidate(t.Context()); err != nil {
			t.Fatalf("%s: revalidate: %v", s.ID, err)
		}
		_ = res.Logs.Close()
	}
	if !perStep {
		return
	}
	if !matchesClient(s.Client, execErr) {
		t.Fatalf("%s: caller saw %v, fixture declares %q", s.ID, execErr, s.Client)
	}
	after, err := r.ledger.Recent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if s.Outcome == "none" {
		if len(after) != len(before) {
			t.Fatalf("%s: accounted %d event(s) for an attempt the fixture declares uncounted", s.ID, len(after)-len(before))
		}
		return
	}
	if len(after) != len(before)+1 {
		t.Fatalf("%s: accounted %d event(s), fixture declares exactly one", s.ID, len(after)-len(before))
	}
	got := after[len(after)-1]
	if string(got.Outcome) != s.Outcome || got.Operation != s.Op || userNames[string(got.UserID)] != userNameOf(s.Who) ||
		agentNames[string(got.AgentID)] != agentNameOf(s.Who) || selNames[string(got.SelectorID)] != s.Selector || got.EndpointID != localEP {
		t.Fatalf("%s: accounted %+v, fixture declares %s on %s/%s selector %q", s.ID, got, s.Outcome, s.Who, s.Op, s.Selector)
	}
}

func userNameOf(who string) string {
	if who == "bot" {
		return "alice" // the agent's owner is recorded with it
	}
	return who
}

func agentNameOf(who string) string {
	if who == "bot" {
		return "bot"
	}
	return ""
}

func (r *fixtureRun) runSteps(steps []fixtureStep, perStep bool) {
	r.t.Helper()
	for _, s := range steps {
		r.runStep(s, perStep)
	}
}

// runConcurrent runs the declared concurrent phase: workers x iterations x per-iteration
// requests, all at one instant, all through the same service.
func (r *fixtureRun) runConcurrent(c fixtureConcurrent) {
	t := r.t
	t.Helper()
	r.setNow(c.At)
	var wg sync.WaitGroup
	errs := make(chan string, c.Workers*c.Iterations*len(c.PerIteration))
	for range c.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range c.Iterations {
				for _, it := range c.PerIteration {
					res, err := r.svc.Execute(t.Context(), r.request(it.Who, it.Op, it.Target, 0, false))
					closeLogs(res)
					want := map[string]string{"allowed": "ok", "denied": "forbidden"}[it.Outcome]
					if !matchesClient(want, err) {
						errs <- fmt.Sprintf("%s %s: %v, want %s", it.Who, it.Op, err, want)
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func (r *fixtureRun) actual(g store.UsageGranularity) []fixtureRow {
	r.t.Helper()
	rows, err := r.ledger.Rollups(r.t.Context(), g)
	if err != nil {
		r.t.Fatal(err)
	}
	out := make([]fixtureRow, 0, len(rows))
	for _, x := range rows {
		u, uok := userNames[string(x.UserID)]
		a, aok := agentNames[string(x.AgentID)]
		s, sok := selNames[string(x.SelectorID)]
		if !uok || !aok || !sok || x.EndpointID != localEP {
			r.t.Fatalf("a rollup row carries an identifier the fixture does not know: %+v", x)
		}
		out = append(out, fixtureRow{Window: x.Window.Format(time.RFC3339), User: u, Agent: a, Selector: s, Operation: x.Operation, Allowed: x.Allowed, Denied: x.Denied, Error: x.Error})
	}
	return out
}

func (r *fixtureRun) recentCount() int {
	r.t.Helper()
	ev, err := r.ledger.Recent(r.t.Context())
	if err != nil {
		r.t.Fatal(err)
	}
	return len(ev)
}

// compare returns every difference between the real ledger and a declared checkpoint.
func (r *fixtureRun) compare(cp fixtureCheckpoint) []string {
	var out []string
	for _, d := range diffRows(r.actual(store.UsageHourly), cp.Hourly) {
		out = append(out, "hourly: "+d)
	}
	for _, d := range diffRows(r.actual(store.UsageDaily), cp.Daily) {
		out = append(out, "daily: "+d)
	}
	if n := r.recentCount(); n != cp.RecentEvents {
		out = append(out, fmt.Sprintf("recent events: got %d want %d", n, cp.RecentEvents))
	}
	return out
}

func (r *fixtureRun) mustMatch(name string) {
	r.t.Helper()
	if d := r.compare(r.fx.Checkpoints[name]); len(d) > 0 {
		r.t.Fatalf("checkpoint %s differs from the committed fixture:\n  %s", name, strings.Join(d, "\n  "))
	}
}

// The acceptance test of P1.15.
func TestUsageFixtureDeclaresExactTotalsThatSurviveRestartConcurrencyRetentionAndServiceChange(t *testing.T) {
	fx := loadUsageFixture(t)
	r := newFixtureRun(t, fx, nil)

	r.runSteps(fx.Phases.Sequence, true)
	r.mustMatch("after_sequence")

	r.restart() // new repository, authorizer, service and ledger over the same files
	r.mustMatch("after_sequence")

	r.runSteps(fx.Phases.AfterRestart, true)
	r.runConcurrent(fx.Phases.Concurrent)
	r.mustMatch("after_restart_and_concurrent")

	cp := fx.Checkpoints["after_retention"]
	r.setNow(cp.Now)
	pruned, err := r.ledger.Prune(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cp.Removed == nil || pruned.Hourly != int64(cp.Removed.Hourly) || pruned.Daily != int64(cp.Removed.Daily) || pruned.Recent != int64(cp.Removed.RecentEvents) {
		t.Fatalf("retention removed %+v, fixture declares %+v", pruned, cp.Removed)
	}
	r.mustMatch("after_retention")

	// A changed service (new authorizer, operation service and ledger instance) re-runs
	// the same store: surviving totals are untouched and counting continues exactly.
	r.replaceService()
	r.mustMatch("after_retention")
	r.runSteps(fx.Phases.AfterServiceChange, true)
	r.mustMatch("after_service_change")
	r.restart()
	r.mustMatch("after_service_change")
}

// The fixture must agree with itself: its declared totals equal what its own steps
// imply (guards against a typo in either), computed independently of the generator.
func TestUsageFixtureIsSelfConsistent(t *testing.T) {
	fx := loadUsageFixture(t)
	type ev struct {
		at                    time.Time
		user, agent, selector string
		op, outcome           string
	}
	toEvent := func(s fixtureStep) (ev, bool) {
		if s.Outcome == "none" {
			return ev{}, false
		}
		return ev{mustTime(t, s.At), userNameOf(s.Who), agentNameOf(s.Who), s.Selector, s.Op, s.Outcome}, true
	}
	var seq, rest, conc, later []ev
	for _, s := range fx.Phases.Sequence {
		if e, ok := toEvent(s); ok {
			seq = append(seq, e)
		}
	}
	for _, s := range fx.Phases.AfterRestart {
		if e, ok := toEvent(s); ok {
			rest = append(rest, e)
		}
	}
	c := fx.Phases.Concurrent
	for range c.Workers * c.Iterations {
		for _, it := range c.PerIteration {
			sel := "edge"
			if it.Outcome == "denied" {
				sel = "" // bob has no grant: default deny matches no selector
			}
			conc = append(conc, ev{mustTime(t, c.At), userNameOf(it.Who), agentNameOf(it.Who), sel, it.Op, it.Outcome})
		}
	}
	for _, s := range fx.Phases.AfterServiceChange {
		if e, ok := toEvent(s); ok {
			later = append(later, e)
		}
	}
	aggregate := func(events []ev, daily bool) []fixtureRow {
		m := map[string]*fixtureRow{}
		for _, e := range events {
			w := e.at.UTC().Truncate(time.Hour)
			if daily {
				w = e.at.UTC().Truncate(24 * time.Hour)
			}
			row := fixtureRow{Window: w.Format(time.RFC3339), User: e.user, Agent: e.agent, Selector: e.selector, Operation: e.op}
			p := m[rowKey(row)]
			if p == nil {
				p = &row
				m[rowKey(row)] = p
			}
			switch e.outcome {
			case "allowed":
				p.Allowed++
			case "denied":
				p.Denied++
			case "error":
				p.Error++
			default:
				t.Fatalf("outcome %q", e.outcome)
			}
		}
		var out []fixtureRow
		for _, p := range m {
			out = append(out, *p)
		}
		return out
	}
	check := func(name string, events []ev) {
		cp := fx.Checkpoints[name]
		if d := diffRows(cp.Hourly, aggregate(events, false)); len(d) > 0 {
			t.Errorf("%s hourly is not what the steps imply: %v", name, d)
		}
		if d := diffRows(cp.Daily, aggregate(events, true)); len(d) > 0 {
			t.Errorf("%s daily is not what the steps imply: %v", name, d)
		}
	}
	all := append(append(append([]ev(nil), seq...), rest...), conc...)
	check("after_sequence", seq)
	check("after_restart_and_concurrent", all)
	if got := fx.Checkpoints["after_sequence"].RecentEvents; got != len(seq) {
		t.Errorf("after_sequence recent events %d, steps imply %d", got, len(seq))
	}
	if got := fx.Checkpoints["after_restart_and_concurrent"].RecentEvents; got != len(all) {
		t.Errorf("recent events %d, steps imply %d", got, len(all))
	}

	// retention: whole windows strictly before now-retention, events past their own retain_until
	rc := fx.Checkpoints["after_retention"]
	now := mustTime(t, rc.Now)
	cutoff := now.Add(-time.Duration(fx.Setup.RetentionHours) * time.Hour)
	var keptH, keptD []fixtureRow
	for _, row := range aggregate(all, false) {
		if mustTime(t, row.Window).Add(time.Hour).After(cutoff) {
			keptH = append(keptH, row)
		}
	}
	for _, row := range aggregate(all, true) {
		if mustTime(t, row.Window).Add(24 * time.Hour).After(cutoff) {
			keptD = append(keptD, row)
		}
	}
	if d := diffRows(rc.Hourly, keptH); len(d) > 0 {
		t.Errorf("retained hourly windows are not what retention implies: %v", d)
	}
	if d := diffRows(rc.Daily, keptD); len(d) > 0 {
		t.Errorf("retained daily windows are not what retention implies: %v", d)
	}
	expired := 0
	for _, e := range all {
		if !e.at.Add(time.Duration(fx.Setup.RetentionHours) * time.Hour).After(now) {
			expired++
		}
	}
	if rc.Removed == nil || rc.Removed.Hourly != len(aggregate(all, false))-len(keptH) || rc.Removed.Daily != len(aggregate(all, true))-len(keptD) || rc.Removed.RecentEvents != expired {
		t.Errorf("declared removals %+v, retention implies hourly %d daily %d recent %d", rc.Removed, len(aggregate(all, false))-len(keptH), len(aggregate(all, true))-len(keptD), expired)
	}
	if rc.RecentEvents != len(all)-expired {
		t.Errorf("recent events after retention %d, implied %d", rc.RecentEvents, len(all)-expired)
	}
	// after the service change: retained windows plus the new events
	var afterH []ev
	for _, row := range keptH {
		for range row.Allowed {
			afterH = append(afterH, ev{mustTime(t, row.Window), row.User, row.Agent, row.Selector, row.Operation, "allowed"})
		}
		for range row.Denied {
			afterH = append(afterH, ev{mustTime(t, row.Window), row.User, row.Agent, row.Selector, row.Operation, "denied"})
		}
		for range row.Error {
			afterH = append(afterH, ev{mustTime(t, row.Window), row.User, row.Agent, row.Selector, row.Operation, "error"})
		}
	}
	sc := fx.Checkpoints["after_service_change"]
	if d := diffRows(sc.Hourly, aggregate(append(afterH, later...), false)); len(d) > 0 {
		t.Errorf("after_service_change hourly: %v", d)
	}
	dailyMerged := map[string]fixtureRow{}
	for _, row := range append(keptD, aggregate(later, true)...) {
		k := rowKey(row)
		m := dailyMerged[k]
		if m.Window == "" {
			m = fixtureRow{Window: row.Window, User: row.User, Agent: row.Agent, Selector: row.Selector, Operation: row.Operation}
		}
		m.Allowed += row.Allowed
		m.Denied += row.Denied
		m.Error += row.Error
		dailyMerged[k] = m
	}
	var wantD []fixtureRow
	for _, row := range dailyMerged {
		wantD = append(wantD, row)
	}
	if d := diffRows(sc.Daily, wantD); len(d) > 0 {
		t.Errorf("after_service_change daily: %v", d)
	}
	if sc.RecentEvents != rc.RecentEvents+len(later) {
		t.Errorf("after_service_change recent events %d, implied %d", sc.RecentEvents, rc.RecentEvents+len(later))
	}
	// Every operation key and every outcome is exercised by the fixture.
	seenOps, seenOutcomes := map[string]bool{}, map[string]bool{}
	for _, e := range all {
		seenOps[e.op], seenOutcomes[e.outcome] = true, true
	}
	for _, op := range ops.Operations() {
		if !seenOps[string(op)] {
			t.Errorf("fixture never accounts %s", op)
		}
	}
	for _, o := range []string{"allowed", "denied", "error"} {
		if !seenOutcomes[o] {
			t.Errorf("fixture never accounts a %s outcome", o)
		}
	}
}

// The comparison is not vacuous: every kind of wrong total is detected, and the
// identical table is not reported.
func TestUsageFixtureComparisonDetectsEveryKindOfWrongTotal(t *testing.T) {
	fx := loadUsageFixture(t)
	want := fx.Checkpoints["after_sequence"].Hourly
	if d := diffRows(want, want); len(d) != 0 {
		t.Fatalf("identical tables reported different: %v", d)
	}
	clone := func() []fixtureRow { return append([]fixtureRow(nil), want...) }
	mutations := map[string]func([]fixtureRow) []fixtureRow{
		"one extra allowed": func(r []fixtureRow) []fixtureRow { r[0].Allowed++; return r },
		"one extra denied":  func(r []fixtureRow) []fixtureRow { r[0].Denied++; return r },
		"one extra error":   func(r []fixtureRow) []fixtureRow { r[0].Error++; return r },
		"one missing count": func(r []fixtureRow) []fixtureRow {
			r[len(r)-1].Allowed, r[len(r)-1].Denied, r[len(r)-1].Error = 0, 0, 0
			return r
		},
		"a dropped row": func(r []fixtureRow) []fixtureRow { return r[1:] },
		"an invented row": func(r []fixtureRow) []fixtureRow {
			return append(r, fixtureRow{Window: r[0].Window, User: "bob", Operation: r[0].Operation, Denied: 1})
		},
		"a duplicated row": func(r []fixtureRow) []fixtureRow { return append(r, r[0]) },
		"wrong hour":       func(r []fixtureRow) []fixtureRow { r[0].Window = "2030-01-01T09:00:00Z"; return r },
		"wrong selector":   func(r []fixtureRow) []fixtureRow { r[0].Selector = "other"; return r },
		"wrong user":       func(r []fixtureRow) []fixtureRow { r[0].User = "bob"; return r },
		"wrong agent":      func(r []fixtureRow) []fixtureRow { r[0].Agent = "bot2"; return r },
		"wrong operation":  func(r []fixtureRow) []fixtureRow { r[0].Operation = "container:restart"; return r },
		"outcome moved":    func(r []fixtureRow) []fixtureRow { r[0].Allowed, r[0].Denied = r[0].Allowed-1, r[0].Denied+1; return r },
		"agent folded into user": func(r []fixtureRow) []fixtureRow {
			for i := range r {
				r[i].Agent = ""
			}
			return r
		},
	}
	for name, mutate := range mutations {
		if d := diffRows(mutate(clone()), want); len(d) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
}

// Mutant accounting layers must be caught by the same fixture: a recorder that drops
// events, one that double counts denials, one that counts only allowed outcomes. The
// honest recorder is the control (empty difference).
func TestUsageFixtureCatchesDroppedAndDuplicatedAccounting(t *testing.T) {
	fx := loadUsageFixture(t)
	type mutant struct {
		name string
		wrap func(ops.UsageRecorder) ops.UsageRecorder
		bad  bool
	}
	mutants := []mutant{
		{"honest", func(r ops.UsageRecorder) ops.UsageRecorder { return r }, false},
		{"drops-every-third", func(r ops.UsageRecorder) ops.UsageRecorder {
			var n atomic.Int64
			return recorderFunc(func(ctx context.Context, e domain.UsageEvent) error {
				if n.Add(1)%3 == 0 {
					return nil
				}
				return r.RecordUsage(ctx, e)
			})
		}, true},
		{"double-counts-denials", func(r ops.UsageRecorder) ops.UsageRecorder {
			return recorderFunc(func(ctx context.Context, e domain.UsageEvent) error {
				if err := r.RecordUsage(ctx, e); err != nil {
					return err
				}
				if e.Outcome == domain.UsageDenied {
					return r.RecordUsage(ctx, e)
				}
				return nil
			})
		}, true},
		{"counts-only-allowed", func(r ops.UsageRecorder) ops.UsageRecorder {
			return recorderFunc(func(ctx context.Context, e domain.UsageEvent) error {
				if e.Outcome != domain.UsageAllowed {
					return nil
				}
				return r.RecordUsage(ctx, e)
			})
		}, true},
		{"folds-agent-into-user", func(r ops.UsageRecorder) ops.UsageRecorder {
			return recorderFunc(func(ctx context.Context, e domain.UsageEvent) error {
				e.AgentID = ""
				return r.RecordUsage(ctx, e)
			})
		}, true},
	}
	for _, m := range mutants {
		t.Run(m.name, func(t *testing.T) {
			r := newFixtureRun(t, fx, m.wrap)
			r.runSteps(fx.Phases.Sequence, false)
			d := r.compare(fx.Checkpoints["after_sequence"])
			if m.bad && len(d) == 0 {
				t.Fatal("the fixture did not detect this miscounting layer")
			}
			if !m.bad && len(d) != 0 {
				t.Fatalf("honest accounting differs from the fixture:\n  %s", strings.Join(d, "\n  "))
			}
		})
	}
}

type recorderFunc func(context.Context, domain.UsageEvent) error

func (f recorderFunc) RecordUsage(ctx context.Context, e domain.UsageEvent) error { return f(ctx, e) }

// The ledger's closed operation list is the service's catalog: exactly the six keys
// are accepted by the store, anything else (including exec) is refused.
func TestLedgerAcceptsExactlyTheSixPermissionKeys(t *testing.T) {
	e := newEnv(t)
	l, err := store.NewUsageLedger(e.repo, store.UsageConfig{Clock: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops.Operations() {
		ev := domain.UsageEvent{UserID: aliceID, EndpointID: localEP, SelectorID: selEdge, Operation: string(op), Outcome: domain.UsageAllowed}
		if err := l.RecordUsage(t.Context(), ev); err != nil {
			t.Errorf("%s refused: %v", op, err)
		}
	}
	for _, op := range []string{"container:exec", "container:remove", "container:*", "container:logs ", ""} {
		ev := domain.UsageEvent{UserID: aliceID, EndpointID: localEP, SelectorID: selEdge, Operation: op, Outcome: domain.UsageAllowed}
		if err := l.RecordUsage(t.Context(), ev); err == nil {
			t.Errorf("operation %q accepted", op)
		}
	}
}
