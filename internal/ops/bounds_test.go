package ops_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// recordDeadlines makes every dispatch deadline observable and controllable without
// real time: the service asks for a bounded context, the test records the bound and
// can fire it at will.
func recordDeadlines() envOption {
	return func(c *envConfig) {
		c.withTimeout = func(e *env) func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
			return func(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(parent)
				e.mu.Lock()
				e.timeouts = append(e.timeouts, d)
				e.timeoutCancel = append(e.timeoutCancel, cancel)
				e.mu.Unlock()
				return ctx, cancel
			}
		}
	}
}

func (e *env) deadlines() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]time.Duration(nil), e.timeouts...)
}

func (e *env) fireDeadline(i int) {
	e.mu.Lock()
	c := e.timeoutCancel[i]
	e.mu.Unlock()
	c()
}

// P113-BOUND-01: stop and restart forward ONLY the validated, normalized timeout:
// default 10, the 1 and 300 boundaries unchanged, never a caller pointer.
func TestStopAndRestartForwardOnlyNormalizedBoundedTimeouts(t *testing.T) {
	vals := func(v int) *int { return &v }
	cases := []struct {
		name string
		in   *int
		want int
	}{{"default", nil, 10}, {"min", vals(1), 1}, {"typical", vals(30), 30}, {"max", vals(300), 300}}
	for _, op := range []docker.Operation{docker.OpStop, docker.OpRestart} {
		for _, c := range cases {
			t.Run(string(op)+"/"+c.name, func(t *testing.T) {
				e := newEnv(t)
				r := req(botCreds(), "edge-proxy", op)
				r.Stop, r.Restart = nil, nil
				if op == docker.OpStop {
					r.Stop = &docker.StopOptions{TimeoutSeconds: c.in}
				} else {
					r.Restart = &docker.RestartOptions{TimeoutSeconds: c.in}
				}
				if _, err := e.svc.Execute(t.Context(), r); err != nil {
					t.Fatal(err)
				}
				got := e.spy.operationalCalls()
				if len(got) != 1 || got[0].Timeout == nil || *got[0].Timeout != c.want {
					t.Fatalf("backend received %+v, want timeout %d", got, c.want)
				}
				if c.in != nil && got[0].Timeout == c.in {
					t.Fatal("the caller's pointer was forwarded to the backend")
				}
			})
		}
	}
}

// P113-BOUND-02: a policy's stop_timeout_max is enforced at the service boundary:
// a request above the cap dispatches nothing, one at the cap dispatches once.
func TestPolicyStopTimeoutCapIsEnforced(t *testing.T) {
	for _, op := range []docker.Operation{docker.OpStop, docker.OpRestart} {
		e := newEnv(t)
		e.exec(`UPDATE policies SET stop_timeout_max=20 WHERE agent_id=? AND operation=?`, botID, string(op))
		over := 21
		at := 20
		mk := func(v *int) ops.Request {
			r := req(botCreds(), "edge-proxy", op)
			r.Stop, r.Restart = nil, nil
			if op == docker.OpStop {
				r.Stop = &docker.StopOptions{TimeoutSeconds: v}
			} else {
				r.Restart = &docker.RestartOptions{TimeoutSeconds: v}
			}
			return r
		}
		if _, err := e.svc.Execute(t.Context(), mk(&over)); !authz.HasReason(err, authz.ReasonParameterCapExceeded) {
			t.Fatalf("%s over the cap: %v", op, err)
		}
		if n := len(e.spy.operationalCalls()); n != 0 {
			t.Fatalf("%s over the cap made %d operational attempts", op, n)
		}
		if _, err := e.svc.Execute(t.Context(), mk(&at)); err != nil {
			t.Fatalf("%s at the cap: %v", op, err)
		}
		if n := len(e.spy.operationalCalls()); n != 1 {
			t.Fatalf("%s at the cap made %d operational attempts", op, n)
		}
	}
}

// P113-BOUND-03: every one-shot dispatch runs under a bounded context: the
// operation timeout, or the daemon stop timeout plus a fixed grace for stop and
// restart. Logs are exempt because the stream context is the lease, not a deadline.
func TestOneShotDispatchIsBoundedByDeadline(t *testing.T) {
	e := newEnv(t, recordDeadlines())
	seven := 7
	steps := []struct {
		op   docker.Operation
		mod  func(*ops.Request)
		want time.Duration
	}{
		{docker.OpInspectStatus, nil, ops.DefaultOperationTimeout},
		{docker.OpInspectConfig, nil, ops.DefaultOperationTimeout},
		{docker.OpStart, nil, ops.DefaultOperationTimeout},
		{docker.OpStop, func(r *ops.Request) { r.Stop = &docker.StopOptions{TimeoutSeconds: &seven} }, 7*time.Second + ops.DefaultStopGrace},
		{docker.OpRestart, func(r *ops.Request) { r.Restart = &docker.RestartOptions{} }, 10*time.Second + ops.DefaultStopGrace},
		{docker.OpStop, func(r *ops.Request) { r.Stop = &docker.StopOptions{} }, 10*time.Second + ops.DefaultStopGrace},
		{docker.OpRestart, func(r *ops.Request) {
			r.Restart = &docker.RestartOptions{TimeoutSeconds: func() *int { v := 300; return &v }()}
		}, 300*time.Second + ops.DefaultStopGrace},
	}
	for i, s := range steps {
		r := req(botCreds(), "edge-proxy", s.op)
		if s.mod != nil {
			s.mod(&r)
		}
		if _, err := e.svc.Execute(t.Context(), r); err != nil {
			t.Fatalf("step %d %s: %v", i, s.op, err)
		}
		got := e.deadlines()
		if len(got) != i+1 || got[i] != s.want {
			t.Fatalf("step %d %s: deadlines %v, want last = %v", i, s.op, got, s.want)
		}
	}
	// Logs open under the lease context, with no deadline requested.
	r := req(botCreds(), "edge-proxy", docker.OpLogs)
	res, err := e.svc.Execute(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Logs.Close() }()
	if got := e.deadlines(); len(got) != len(steps) {
		t.Fatalf("logs requested a dispatch deadline: %v", got)
	}
}

// P113-BOUND-04: the deadline is real: an in-flight operation is released when its
// bound fires, an already-expired bound dispatches nothing, and nothing leaks.
func TestDispatchDeadlineFiringReleasesInFlightOperation(t *testing.T) {
	for _, op := range []docker.Operation{docker.OpStop, docker.OpRestart, docker.OpStart, docker.OpInspectStatus, docker.OpInspectConfig} {
		t.Run(string(op), func(t *testing.T) {
			e := newEnv(t, recordDeadlines())
			entered := make(chan context.Context, 1)
			e.spy.beforeOperation = func(_ string, ctx context.Context) {
				entered <- ctx
				<-ctx.Done() // a daemon that never answers
			}
			done := make(chan error, 1)
			go func() { _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op)); done <- err }()
			ctx := <-entered
			if ctx.Err() != nil {
				t.Fatal("dispatch context was already done")
			}
			e.fireDeadline(0)
			select {
			case err := <-done:
				if err == nil || !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expired dispatch = %v, want a context error", err)
				}
			case <-time.After(60 * time.Second):
				t.Fatal("dispatch not released by its deadline")
			}
			if e.az.ActiveLeaseCount() != 0 {
				t.Fatal("lease leaked after a deadline")
			}
		})
	}
}

// P113-BOUND-05: revocation reaches an operation that is already in flight: the
// backend call's context is canceled, the caller gets an error and, for inspect, no
// data (publication fence at the service boundary).
func TestRevocationDuringInFlightOperationCancelsItAndWithholdsData(t *testing.T) {
	for _, op := range ops.Operations() {
		if op == docker.OpLogs {
			continue
		}
		for _, mode := range []string{"context-honoring-daemon", "daemon-completes-despite-cancellation"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				inFlightRevocation(t, op, mode == "daemon-completes-despite-cancellation")
			})
		}
	}
}

func inFlightRevocation(t *testing.T, op docker.Operation, completes bool) {
	e := newEnv(t)
	e.spy.ignoreCtx = completes
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	e.spy.beforeOperation = func(_ string, ctx context.Context) {
		entered <- ctx
		<-release
	}
	type outcome struct {
		res ops.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
		done <- outcome{res, err}
	}()
	ctx := <-entered
	revokeCredential(e)
	if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("revocation did not cancel the in-flight backend context")
	}
	close(release)
	r := <-done
	if r.res.Status != nil || r.res.Config != nil {
		t.Fatalf("%s: data must be withheld after revocation, got %+v", op, r.res)
	}
	if (op == docker.OpInspectStatus || op == docker.OpInspectConfig) && r.err == nil {
		t.Fatalf("%s: a read that finished after its authorization ended returned success", op)
	}
	if e.az.ActiveLeaseCount() != 0 {
		t.Fatal("lease leaked")
	}
	// Everything after the revocation is refused with zero further attempts.
	n := len(e.spy.operationalCalls())
	if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op)); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("post-revocation request: %v", err)
	}
	if len(e.spy.operationalCalls()) != n {
		t.Fatal("operational attempt after revocation")
	}
}

// P113-BOUND-08: authority lost in the window between admission and dispatch
// dispatches NOTHING: every cause, every permission key, zero operational attempts.
// Rebinding, removal, invalidation and loss of safety proof are caught by the
// decision-bound backend selection; credential and policy revocation (which leave the
// backend untouched) only by the revoked lease, so each guard is exercised alone.
func TestAuthorityLostBetweenAdmissionAndDispatchDispatchesNothing(t *testing.T) {
	causes := map[string]func(e *env){
		"backend-rebound":    func(e *env) { _ = e.az.RegisterBackend(localEP, e.spy) },
		"backend-removed":    func(e *env) { e.az.RemoveBackend(localEP) },
		"all-invalidated":    func(e *env) { e.az.InvalidateAll() },
		"safety-proof-lost":  func(e *env) { e.mock.SimulateEventDiscontinuity() },
		"credential-revoked": func(e *env) { revokeCredential(e); _ = e.az.NotifyPolicyChange(context.Background()) },
		"policy-allow-removed": func(e *env) {
			e.exec(`DELETE FROM policies WHERE agent_id=?`, botID)
			_ = e.az.NotifyPolicyChange(context.Background())
		},
	}
	for name, cause := range causes {
		for _, op := range ops.Operations() {
			t.Run(name+"/"+string(op), func(t *testing.T) {
				fire := false
				var e *env
				e = newEnv(t, func(c *envConfig) {
					c.afterAuthorize = func(*env) func() {
						return func() {
							if fire {
								cause(e)
							}
						}
					}
				})
				// Control: with no change in the window the same request is dispatched.
				res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
				if err != nil {
					t.Fatalf("control: %v", err)
				}
				if res.Logs != nil {
					_ = res.Logs.Close()
				}
				before := len(e.spy.operationalCalls())
				fire = true
				res, err = e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
				if res.Logs != nil {
					_ = res.Logs.Close()
					t.Fatal("log stream returned although authority was lost before dispatch")
				}
				if err == nil || res.Status != nil || res.Config != nil {
					t.Fatalf("dispatched after authority was lost: %v", err)
				}
				if got := len(e.spy.operationalCalls()); got != before {
					t.Fatalf("%d operational attempts after authority was lost", got-before)
				}
				if e.az.ActiveLeaseCount() != 0 {
					t.Fatal("lease leaked")
				}
			})
		}
	}
}

// P113-BOUND-06: configuration is validated fail-closed.
func TestConfigValidation(t *testing.T) {
	e := newEnv(t)
	bad := []ops.Config{
		{},
		{Authorizer: e.az, RevalidateInterval: -time.Second},
		{Authorizer: e.az, RevalidateInterval: ops.MaxRevalidateInterval + time.Second},
		{Authorizer: e.az, RevalidateInterval: time.Nanosecond},
		{Authorizer: e.az, RevalidateTimeout: -1},
		{Authorizer: e.az, OperationTimeout: -1},
		{Authorizer: e.az, OperationTimeout: 11 * time.Minute},
		{Authorizer: e.az, StopGrace: -1},
		{Authorizer: e.az, StopGrace: time.Hour},
	}
	for i, c := range bad {
		if s, err := ops.New(c); !errors.Is(err, ops.ErrInvalidConfig) || s != nil {
			t.Errorf("config %d accepted: %v", i, err)
		}
	}
	if s, err := ops.New(ops.Config{Authorizer: e.az}); err != nil || s == nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	var nilSvc *ops.Service
	if _, err := nilSvc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus)); !errors.Is(err, ops.ErrInvalidConfig) {
		t.Fatalf("nil service Execute = %v", err)
	}
	if err := nilSvc.NotifyAuthorityChange(t.Context()); !errors.Is(err, ops.ErrInvalidConfig) {
		t.Fatalf("nil service Notify = %v", err)
	}
	if _, err := (&ops.Service{}).Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus)); !errors.Is(err, ops.ErrInvalidConfig) {
		t.Fatalf("zero service Execute = %v", err)
	}
}

// P113-BOUND-07: concurrent requests and revocation under the race detector. After
// the revocation has committed and been announced, EVERY later request is refused
// and the backend sees no further operational attempt.
func TestConcurrentExecuteAndRevocation(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, op := range ops.Operations() {
				res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
				if err == nil && res.Logs != nil {
					_ = res.Logs.Close()
				}
			}
		}()
	}
	wg.Wait()
	before := len(e.spy.operationalCalls())
	if before == 0 {
		t.Fatal("control: concurrent allowed requests dispatched nothing")
	}
	revokeCredential(e)
	if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, op := range ops.Operations() {
				if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op)); !errors.Is(err, authz.ErrUnauthenticated) {
					t.Errorf("%s after revocation: %v", op, err)
				}
			}
		}()
	}
	wg.Wait()
	if got := len(e.spy.operationalCalls()); got != before {
		t.Fatalf("%d operational attempts after revocation", got-before)
	}
	if e.az.ActiveLeaseCount() != 0 {
		t.Fatal("leases leaked")
	}
}
