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

// observerLog records every notice and, for each, whether the backend had been called yet.
type observerLog struct {
	mu     sync.Mutex
	bounds []time.Duration
	calls  func() int // operational calls made so far
	seen   []int      // operational calls already made when each notice arrived
}

func (l *observerLog) observe(bound time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bounds = append(l.bounds, bound)
	l.seen = append(l.seen, l.calls())
}

func (l *observerLog) snapshot() ([]time.Duration, []int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Duration(nil), l.bounds...), append([]int(nil), l.seen...)
}

func observed(e *env) (*observerLog, context.Context) {
	l := &observerLog{calls: func() int { return len(e.spy.operationalCalls()) }}
	return l, ops.WithDispatchObserver(context.Background(), l.observe)
}

// P120-F2-OBS-01: an admitted stop or restart tells the transport its own dispatch bound exactly once,
// BEFORE the backend call starts, and that bound is the deadline the call really runs under (the
// daemon stop timeout plus StopGrace). The 10 s transport write bound is shorter than every default.
func TestAdmittedStopAndRestartTellTheTransportTheirDispatchBound(t *testing.T) {
	vals := func(v int) *int { return &v }
	cases := []struct {
		name string
		in   *int
		want time.Duration
	}{
		{"default", nil, 10*time.Second + ops.DefaultStopGrace},
		{"min", vals(1), 1*time.Second + ops.DefaultStopGrace},
		{"typical", vals(7), 7*time.Second + ops.DefaultStopGrace},
		{"max", vals(300), 300*time.Second + ops.DefaultStopGrace},
	}
	for _, op := range []docker.Operation{docker.OpStop, docker.OpRestart} {
		for _, c := range cases {
			t.Run(string(op)+"/"+c.name, func(t *testing.T) {
				e := newEnv(t, recordDeadlines())
				r := req(botCreds(), "edge-proxy", op)
				r.Stop, r.Restart = nil, nil
				if op == docker.OpStop {
					r.Stop = &docker.StopOptions{TimeoutSeconds: c.in}
				} else {
					r.Restart = &docker.RestartOptions{TimeoutSeconds: c.in}
				}
				log, ctx := observed(e)
				if _, err := e.svc.Execute(ctx, r); err != nil {
					t.Fatal(err)
				}
				bounds, seen := log.snapshot()
				if len(bounds) != 1 || bounds[0] != c.want {
					t.Fatalf("observer bounds = %v, want exactly [%v]", bounds, c.want)
				}
				if seen[0] != 0 {
					t.Fatalf("observer was told after %d backend call(s); it must come first", seen[0])
				}
				if got := e.deadlines(); len(got) != 1 || got[0] != bounds[0] {
					t.Fatalf("the call ran under %v but the transport was told %v", got, bounds)
				}
				if n := len(e.spy.operationalCalls()); n != 1 {
					t.Fatalf("operational calls = %d, want 1", n)
				}
			})
		}
	}
}

// P120-F2-OBS-02: nothing else is ever announced. Reads, start and logs keep the transport's own bound,
// and a context without an observer changes nothing (every existing caller).
func TestOtherOperationsNeverTellTheTransportAnything(t *testing.T) {
	for _, op := range []docker.Operation{docker.OpInspectStatus, docker.OpInspectConfig, docker.OpStart, docker.OpLogs} {
		t.Run(string(op), func(t *testing.T) {
			e := newEnv(t)
			log, ctx := observed(e)
			res, err := e.svc.Execute(ctx, req(botCreds(), "edge-proxy", op))
			if err != nil {
				t.Fatal(err)
			}
			if res.Logs != nil {
				_ = res.Logs.Close()
			}
			if bounds, _ := log.snapshot(); len(bounds) != 0 {
				t.Fatalf("%s told the transport %v", op, bounds)
			}
		})
	}
	e := newEnv(t)
	if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpStop)); err != nil {
		t.Fatalf("a context without an observer must work unchanged: %v", err)
	}
	if ops.DispatchObserverFrom(t.Context()) != nil {
		t.Fatal("a plain context carries an observer")
	}
}

// P120-F2-OBS-03 (negative control): a request that is not admitted gets NO notice and the backend is
// never touched: an unknown credential, a default deny, a request over the policy's stop cap, a
// credential-less call and an invalid target. Each control also asserts the real refusal, so the
// test cannot pass on a request that was refused for another reason.
func TestRefusedStopAndRestartNeverTellTheTransportAnything(t *testing.T) {
	over := 21
	for _, op := range []docker.Operation{docker.OpStop, docker.OpRestart} {
		withStop := func(r ops.Request, secs *int) ops.Request {
			r.Stop, r.Restart = nil, nil
			if op == docker.OpStop {
				r.Stop = &docker.StopOptions{TimeoutSeconds: secs}
			} else {
				r.Restart = &docker.RestartOptions{TimeoutSeconds: secs}
			}
			return r
		}
		refused := []struct {
			name  string
			setup func(*env)
			r     func() ops.Request
			check func(error) bool
		}{
			{"unknown-token", func(*env) {}, func() ops.Request {
				return req(authz.PrincipalCredentials{AgentToken: tokenFor("9")}, "edge-proxy", op)
			}, func(err error) bool { return errors.Is(err, authz.ErrUnauthenticated) }},
			{"no-credential", func(*env) {}, func() ops.Request {
				return req(authz.PrincipalCredentials{}, "edge-proxy", op)
			}, func(err error) bool { return errors.Is(err, authz.ErrUnauthenticated) }},
			{"default-deny", func(*env) {}, func() ops.Request {
				return req(bobCreds(), "edge-proxy", op)
			}, func(err error) bool { return authz.HasReason(err, authz.ReasonDefaultDeny) }},
			{"over-the-policy-cap", func(e *env) {
				e.exec(`UPDATE policies SET stop_timeout_max=20 WHERE agent_id=? AND operation=?`, botID, string(op))
			}, func() ops.Request {
				return withStop(req(botCreds(), "edge-proxy", op), &over)
			}, func(err error) bool { return authz.HasReason(err, authz.ReasonParameterCapExceeded) }},
			{"invalid-target", func(*env) {}, func() ops.Request {
				return req(botCreds(), "../etc", op)
			}, func(err error) bool { return errors.Is(err, ops.ErrInvalidRequest) }},
		}
		for _, c := range refused {
			t.Run(string(op)+"/"+c.name, func(t *testing.T) {
				e := newEnv(t, recordDeadlines())
				c.setup(e)
				log, ctx := observed(e)
				_, err := e.svc.Execute(ctx, c.r())
				if err == nil || !c.check(err) {
					t.Fatalf("control: request was not refused for the expected reason: %v", err)
				}
				if bounds, _ := log.snapshot(); len(bounds) != 0 {
					t.Fatalf("a refused request told the transport %v", bounds)
				}
				if n := len(e.spy.operationalCalls()); n != 0 {
					t.Fatalf("a refused request made %d operational attempts", n)
				}
			})
		}
	}
}
