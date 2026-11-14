package ops_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// P1.15 persistent usage accounting, service level (TD 9.1). The accounting point is
// the shared Execute entry point, so REST, MCP and the later Operations UI count
// identically. Definitions pinned here (see docs/usage-accounting.md):
//
//   - allowed  : authorized AND the backend call returned success (even when the
//     caller left or the authorization ended while it ran: execution evidence, not
//     the HTTP/service result, decides);
//   - denied   : a verified principal was refused (403), or its authorization ended
//     and the backend call was cut off by that;
//   - error    : authorized, but the backend failed or did not finish (backend
//     error, target gone after authorization, deadline expiry);
//   - nothing  : no verified principal, or no decision and no backend evidence
//     (invalid input, 401, pre-authentication safety refusals, a caller that left
//     before dispatch, a pre-expired dispatch bound).
//
// Streams are counted once, when the backend open call returns. Nothing after that
// (frames, close, revalidation, revocation, terminal failure) is an accounting event.

// usageSpy is a recording ops.UsageRecorder.
type usageSpy struct {
	mu      sync.Mutex
	events  []domain.UsageEvent
	ctxErrs []error
	fail    error
}

func (u *usageSpy) RecordUsage(ctx context.Context, e domain.UsageEvent) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ctxErrs = append(u.ctxErrs, ctx.Err())
	if u.fail != nil {
		return u.fail
	}
	u.events = append(u.events, e)
	return nil
}

func (u *usageSpy) all() []domain.UsageEvent {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]domain.UsageEvent(nil), u.events...)
}

func evt(user, agent, selector string, op docker.Operation, o domain.UsageOutcome) domain.UsageEvent {
	return domain.UsageEvent{UserID: domain.UserID(user), AgentID: domain.AgentID(agent), EndpointID: localEP, SelectorID: domain.SelectorID(selector), Operation: string(op), Outcome: o}
}

// aliceEvt / botEvt: alice acts as a human; bot is her agent (BOTH ids recorded).
func aliceEvt(op docker.Operation, o domain.UsageOutcome) domain.UsageEvent {
	return evt(aliceID, "", selEdge, op, o)
}
func botEvt(op docker.Operation, o domain.UsageOutcome) domain.UsageEvent {
	return evt(aliceID, botID, selEdge, op, o)
}

func wantEvents(t *testing.T, u *usageSpy, want ...domain.UsageEvent) {
	t.Helper()
	got := u.all()
	if len(got) != len(want) {
		t.Fatalf("accounted %d events %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func closeLogs(res ops.Result) {
	if res.Logs != nil {
		_ = res.Logs.Close()
	}
}

// Every permission key, human and agent: exactly one allowed event with the exact
// attribution tuple. This is also the control for every negative case below.
func TestEveryPermissionKeyIsCountedAllowedOnceWithExactAttribution(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, who := range []string{"human", "agent"} {
			t.Run(string(op)+"/"+who, func(t *testing.T) {
				u := &usageSpy{}
				e := newEnv(t, withUsage(u))
				res, err := e.svc.Execute(t.Context(), req(credsFor(who), "edge-proxy", op))
				if err != nil || !isAllowedOutcome(res, op) {
					t.Fatalf("Execute = %v", err)
				}
				closeLogs(res)
				want := aliceEvt(op, domain.UsageAllowed)
				if who == "agent" {
					want = botEvt(op, domain.UsageAllowed)
				}
				wantEvents(t, u, want)
				if n := e.svc.UsageFailures(); n != 0 {
					t.Fatalf("%d accounting failures", n)
				}
			})
		}
	}
}

// A refusal of an authenticated principal by policy is a denied count attributed to
// the DECIDING selector, or to none when no selector matched (a default deny, a
// missing target). The backend is never invoked.
func TestPolicyDenialsAreCountedDeniedWithTheDecidingSelector(t *testing.T) {
	cases := []struct {
		name   string
		reason authz.DenialReason
		setup  func(e *env)
		req    func() ops.Request
		want   domain.UsageEvent
	}{
		{"default deny (no grant at all)", authz.ReasonDefaultDeny, func(*env) {},
			func() ops.Request { return req(bobCreds(), "edge-proxy", docker.OpInspectStatus) },
			evt(bobID, "", "", docker.OpInspectStatus, domain.UsageDenied)},
		{"explicit deny names the deny rule's selector", authz.ReasonExplicitDeny,
			func(e *env) { e.policy("agent_id", botID, selEdge, "DENY", docker.OpInspectStatus, nil, nil) },
			func() ops.Request { return req(botCreds(), "edge-proxy", docker.OpInspectStatus) },
			botEvt(docker.OpInspectStatus, domain.UsageDenied)},
		{"parameter cap names the capped allow's selector", authz.ReasonParameterCapExceeded,
			func(e *env) {
				e.exec(`UPDATE policies SET log_tail_max=3 WHERE agent_id=? AND operation='container:logs'`, botID)
			},
			func() ops.Request { return req(botCreds(), "edge-proxy", docker.OpLogs) }, // tail 5 > 3
			botEvt(docker.OpLogs, domain.UsageDenied)},
		{"missing target matched no selector", authz.ReasonTargetMissing, func(*env) {},
			func() ops.Request { return req(aliceCreds(), "no-such-container", docker.OpStart) },
			evt(aliceID, "", "", docker.OpStart, domain.UsageDenied)},
		{"a target outside every granted selector is a default deny", authz.ReasonDefaultDeny, func(*env) {},
			func() ops.Request { return req(aliceCreds(), "billing-worker", docker.OpStop) },
			evt(aliceID, "", "", docker.OpStop, domain.UsageDenied)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := &usageSpy{}
			e := newEnv(t, withUsage(u))
			c.setup(e)
			res, err := e.svc.Execute(t.Context(), c.req())
			closeLogs(res)
			if !authz.HasReason(err, c.reason) || !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("Execute = %v, want a %s denial", err, c.reason)
			}
			wantEvents(t, u, c.want)
			if n := len(e.spy.operationalCalls()); n != 0 {
				t.Fatalf("a denied request made %d operational attempts", n)
			}
		})
	}
}

// Nobody is attributed on unverified input, and an attempt that produced neither a
// decision nor backend evidence is not an event: zero accounting, zero failures.
func TestRefusalsWithoutAVerifiedPrincipalOrDecisionAreNeverCounted(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *env)
		req   func() ops.Request
	}{
		{"unsupported operation key", nil, func() ops.Request { return req(aliceCreds(), "edge-proxy", "container:exec") }},
		{"endpoint is not a UUID", nil, func() ops.Request {
			r := req(aliceCreds(), "edge-proxy", docker.OpStart)
			r.EndpointID = "local"
			return r
		}},
		{"target is a path", nil, func() ops.Request { return req(aliceCreds(), "../etc/passwd", docker.OpStart) }},
		{"invalid log options", nil, func() ops.Request {
			r := req(aliceCreds(), "edge-proxy", docker.OpLogs)
			r.Logs = &docker.LogOptions{Tail: 0}
			return r
		}},
		{"no credentials", nil, func() ops.Request { return req(authz.PrincipalCredentials{}, "edge-proxy", docker.OpStart) }},
		{"session and token together", nil, func() ops.Request {
			c := aliceCreds()
			c.AgentToken = tokenFor("1")
			return req(c, "edge-proxy", docker.OpStart)
		}},
		{"unknown token", nil, func() ops.Request {
			return req(authz.PrincipalCredentials{AgentToken: tokenFor("unknown")}, "edge-proxy", docker.OpStart)
		}},
		{"wrong session secret", nil, func() ops.Request {
			c := aliceCreds()
			c.SessionSecret = []byte("wrong-secret-0123456789abcdef0123456789abcdef")
			return req(c, "edge-proxy", docker.OpStart)
		}},
		{"revoked token", func(e *env) { revokeCredential(e) }, func() ops.Request { return req(botCreds(), "edge-proxy", docker.OpStart) }},
		{"expired session", func(e *env) { e.clock.Advance(13 * time.Hour) }, func() ops.Request { return req(aliceCreds(), "edge-proxy", docker.OpStart) }},
		{"self-protected target (precedes authentication)", nil, func() ops.Request { return req(aliceCreds(), "mandatary-self", docker.OpStart) }},
		{"backend safety proof lost (precedes authentication)", func(e *env) { e.mock.SimulateEventDiscontinuity() }, func() ops.Request {
			return req(aliceCreds(), "edge-proxy", docker.OpStart)
		}},
		{"restore quarantine (precedes authentication)", func(e *env) {
			e.exec(`UPDATE installation_control SET restore_quarantined=1 WHERE singleton=1`)
		}, func() ops.Request { return req(aliceCreds(), "edge-proxy", docker.OpStart) }},
		{"endpoint without a backend (precedes authentication)", nil, func() ops.Request {
			r := req(aliceCreds(), "edge-proxy", docker.OpStart)
			r.EndpointID = otherEP
			return r
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := &usageSpy{}
			e := newEnv(t, withUsage(u))
			if c.setup != nil {
				c.setup(e)
			}
			res, err := e.svc.Execute(t.Context(), c.req())
			closeLogs(res)
			if err == nil {
				t.Fatal("the refused request succeeded")
			}
			wantEvents(t, u)
			if n := e.svc.UsageFailures(); n != 0 {
				t.Fatalf("%d accounting failures", n)
			}
		})
	}
	t.Run("caller already gone", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := e.svc.Execute(ctx, req(aliceCreds(), "edge-proxy", docker.OpStart)); !errors.Is(err, context.Canceled) {
			t.Fatalf("Execute = %v", err)
		}
		wantEvents(t, u)
	})
}

// Authorization alone is not execution success: a backend failure after a granted
// decision is an ERROR, never allowed and never denied, for every key including the
// Logs open call. Control: the same environment without the fault is allowed.
func TestBackendFailureAfterAuthorizationIsCountedErrorNotDenied(t *testing.T) {
	for _, fault := range []error{docker.ErrBackendFailed, docker.ErrBackendUnavailable} {
		for _, op := range ops.Operations() {
			t.Run(fault.Error()+"/"+string(op), func(t *testing.T) {
				u := &usageSpy{}
				e := newEnv(t, withUsage(u))
				e.mock.SetOperationFailure(op, fault)
				res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
				closeLogs(res)
				if !errors.Is(err, fault) || isDenial(err) {
					t.Fatalf("Execute = %v, want the backend fault, not a denial", err)
				}
				wantEvents(t, u, botEvt(op, domain.UsageError))
				if n := len(e.spy.operationalCalls()); n != 1 {
					t.Fatalf("%d operational attempts, want the one that failed", n)
				}
			})
		}
	}
}

// Target disappearing AFTER authorization: dispatch-time ErrTargetNotFound (the REST
// 404) is an authorized backend failure, not a policy denial. Before authorization
// the same missing target is a 403 default deny (covered above).
func TestTargetDisappearingAfterAuthorizationIsABackendErrorNotADenial(t *testing.T) {
	for _, op := range ops.Operations() {
		t.Run(string(op), func(t *testing.T) {
			u := &usageSpy{}
			var e *env
			e = newEnv(t, withUsage(u), func(c *envConfig) {
				c.afterAuthorize = func(*env) func() { return func() { e.mock.RemoveContainer(edgeID) } }
			})
			res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
			closeLogs(res)
			if !errors.Is(err, docker.ErrTargetNotFound) || isDenial(err) {
				t.Fatalf("Execute = %v, want ErrTargetNotFound at dispatch, not a denial", err)
			}
			wantEvents(t, u, botEvt(op, domain.UsageError))
			if n := len(e.spy.operationalCalls()); n != 1 {
				t.Fatalf("%d operational attempts, want the one that found the target gone", n)
			}
		})
	}
}

// Authority lost between admission and dispatch dispatches nothing and is a DENIED
// count (the authorizer refused it), whatever the cause: pre-dispatch rejection is
// not a backend failure.
func TestAuthorityLostBeforeDispatchIsDeniedNotAnError(t *testing.T) {
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
				u := &usageSpy{}
				var e *env
				e = newEnv(t, withUsage(u), func(c *envConfig) {
					c.afterAuthorize = func(*env) func() { return func() { cause(e) } }
				})
				res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
				closeLogs(res)
				if err == nil || !isDenial(err) {
					t.Fatalf("Execute = %v, want a denial", err)
				}
				wantEvents(t, u, botEvt(op, domain.UsageDenied))
				if n := len(e.spy.operationalCalls()); n != 0 {
					t.Fatalf("%d operational attempts after authority was lost", n)
				}
			})
		}
	}
}

// Caller cancellation during a backend call: the call is not bound to the caller, so
// it finishes, Execute withholds the result and returns the caller's cancellation, and
// the accounting follows the BACKEND evidence: success is allowed (the daemon did
// execute), failure is an error. The record is made although the caller is gone.
func TestCallerLeavingMidCallIsCountedFromTheBackendEvidence(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, backendFails := range []bool{false, true} {
			name := string(op) + "/backend-succeeds"
			want := domain.UsageAllowed
			if backendFails {
				name = string(op) + "/backend-fails"
				want = domain.UsageError
			}
			t.Run(name, func(t *testing.T) {
				u := &usageSpy{}
				e := newEnv(t, withUsage(u))
				if backendFails {
					e.mock.SetOperationFailure(op, docker.ErrBackendFailed)
				}
				entered := make(chan struct{}, 1)
				release := make(chan struct{})
				e.spy.beforeOperation = func(string, context.Context) { entered <- struct{}{}; <-release }
				reqCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan outcome, 1)
				go func() {
					res, err := e.svc.Execute(reqCtx, req(botCreds(), "edge-proxy", op))
					done <- outcome{res, err}
				}()
				<-entered
				cancel()
				settle()
				close(release)
				o := <-done
				closeLogs(o.res)
				if !errors.Is(o.err, context.Canceled) || isDenial(o.err) {
					t.Fatalf("Execute = %v, want the caller's own cancellation", o.err)
				}
				if o.res.Logs != nil || o.res.Status != nil || o.res.Config != nil {
					t.Fatal("a departed caller's result was not withheld")
				}
				wantEvents(t, u, botEvt(op, want))
				for _, cerr := range u.ctxErrs {
					if cerr != nil {
						t.Fatalf("the accounting context carried the departed caller's cancellation: %v", cerr)
					}
				}
			})
		}
	}
}

// A caller that leaves during acquisition: its own context error is returned either
// way, but an authorizer denial that really happened is still counted, and a won lease
// that never dispatched is not.
func TestCallerLeavingDuringAcquisitionCountsOnlyARealDenial(t *testing.T) {
	for _, c := range []struct {
		name  string
		creds authz.PrincipalCredentials
		want  []domain.UsageEvent
	}{
		{"authorized-then-abandoned", aliceCreds(), nil},
		{"denied-while-abandoned", bobCreds(), []domain.UsageEvent{evt(bobID, "", "", docker.OpStart, domain.UsageDenied)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := &usageSpy{}
			e := newEnv(t, withUsage(u))
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			e.spy.resolveBlock = func(_ context.Context, ref string) {
				if ref == "edge-proxy" {
					entered <- struct{}{}
					<-release
				}
			}
			reqCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := e.svc.Execute(reqCtx, req(c.creds, "edge-proxy", docker.OpStart))
				done <- err
			}()
			<-entered
			cancel()
			close(release)
			if err := <-done; !errors.Is(err, context.Canceled) || isDenial(err) {
				t.Fatalf("Execute = %v, want the caller's own cancellation", err)
			}
			wantEvents(t, u, c.want...)
			if n := len(e.spy.operationalCalls()); n != 0 {
				t.Fatalf("%d operational attempts for a caller that left before dispatch", n)
			}
		})
	}
}

// A caller that leaves between admission and dispatch dispatches nothing and leaves no
// decision against it and no backend evidence: NOT counted. If the authorization ended
// in that same window the authorizer refused it: DENIED (the caller still gets its own
// cancellation, never a 403).
func TestCallerGoneBetweenAdmissionAndDispatchIsNotCountedButARevocationIs(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, revoked := range []bool{false, true} {
			name := string(op) + "/caller-only"
			if revoked {
				name = string(op) + "/caller-and-revocation"
			}
			t.Run(name, func(t *testing.T) {
				u := &usageSpy{}
				reqCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var e *env
				e = newEnv(t, withUsage(u), func(c *envConfig) {
					c.afterAuthorize = func(*env) func() {
						return func() {
							if revoked {
								revokeCredential(e)
								_ = e.az.NotifyPolicyChange(context.Background())
							}
							cancel()
						}
					}
				})
				res, err := e.svc.Execute(reqCtx, req(botCreds(), "edge-proxy", op))
				closeLogs(res)
				if !errors.Is(err, context.Canceled) || isDenial(err) {
					t.Fatalf("Execute = %v, want the caller's own cancellation", err)
				}
				if revoked {
					wantEvents(t, u, botEvt(op, domain.UsageDenied))
				} else {
					wantEvents(t, u)
				}
				if n := len(e.spy.operationalCalls()); n != 0 {
					t.Fatalf("%d operational attempts for a caller that left before dispatch", n)
				}
			})
		}
	}
}

// A revocation or an explicit DENY that lands AFTER Authorize allowed the request but
// BEFORE the revalidation under the registered lease (AcquireLease resolves the target by
// its immutable ID there) is a refusal of a verified principal: one DENIED event for the
// decision's tuple, zero backend calls, for every key and for human and agent alike. The
// same change committed before the request is counted by the Authorize path
// (TestPolicyDenialsAreCountedDeniedWithTheDecidingSelector): no window may lose it.
func TestRefusalDuringLeaseAcquisitionIsCountedDenied(t *testing.T) {
	type change struct {
		name  string
		who   string
		apply func(e *env, op docker.Operation)
		creds func() authz.PrincipalCredentials
		want  func(op docker.Operation) domain.UsageEvent
	}
	changes := []change{
		{"agent credential revoked", "agent",
			func(e *env, _ docker.Operation) { revokeCredential(e) }, botCreds,
			func(op docker.Operation) domain.UsageEvent { return botEvt(op, domain.UsageDenied) }},
		{"explicit DENY committed for the agent", "agent",
			func(e *env, op docker.Operation) { e.policy("agent_id", botID, selEdge, "DENY", op, nil, nil) }, botCreds,
			func(op docker.Operation) domain.UsageEvent { return botEvt(op, domain.UsageDenied) }},
		{"explicit DENY committed for the human", "human",
			func(e *env, op docker.Operation) { e.policy("user_id", aliceID, selEdge, "DENY", op, nil, nil) }, aliceCreds,
			func(op docker.Operation) domain.UsageEvent { return aliceEvt(op, domain.UsageDenied) }},
	}
	for _, op := range ops.Operations() {
		for _, c := range changes {
			t.Run(string(op)+"/"+c.name, func(t *testing.T) {
				u := &usageSpy{}
				e := newEnv(t, withUsage(u))
				var fired atomic.Int32
				e.spy.resolveBlock = func(_ context.Context, ref string) {
					if ref == string(edgeID) && fired.Add(1) == 1 {
						c.apply(e, op)
					}
				}
				res, err := e.svc.Execute(t.Context(), req(c.creds(), "edge-proxy", op))
				closeLogs(res)
				if fired.Load() == 0 {
					t.Fatal("the hook never fired: no immutable-ID resolution during acquisition")
				}
				if !isDenial(err) {
					t.Fatalf("Execute = %v, want a 403 denial", err)
				}
				if n := len(e.spy.operationalCalls()); n != 0 {
					t.Fatalf("a refused acquisition made %d operational calls", n)
				}
				wantEvents(t, u, c.want(op))
			})
		}
	}
}

// The refusal inside the acquisition window is still a refusal of a verified principal
// when the caller leaves during it: counted denied once, the caller gets its own error.
// A bound that fires (AcquireTimeout) stays a fault with no decision: not counted, even
// when the lease acquisition itself was refused in the same window.
func TestRefusalDuringLeaseAcquisitionWithCallerGoneOrBoundFired(t *testing.T) {
	t.Run("caller leaves: counted once", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u))
		ctx, cancel := context.WithCancel(t.Context())
		var fired atomic.Int32
		e.spy.resolveBlock = func(_ context.Context, ref string) {
			if ref == string(edgeID) && fired.Add(1) == 1 {
				revokeCredential(e)
				cancel() // the caller leaves in the same window
			}
		}
		_, err := e.svc.Execute(ctx, req(botCreds(), "edge-proxy", docker.OpStart))
		if fired.Load() == 0 || err == nil || isDenial(err) {
			t.Fatalf("fired=%d Execute = %v, want the caller's own context error", fired.Load(), err)
		}
		wantEvents(t, u, botEvt(docker.OpStart, domain.UsageDenied))
	})
	t.Run("bound fired: not counted", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u), func(c *envConfig) { c.acquireTimeout = ops.MinAcquireTimeout })
		e.spy.resolveBlock = func(ctx context.Context, ref string) {
			if ref == string(edgeID) {
				revokeCredential(e)
				<-ctx.Done() // only the acquisition bound ends this
			}
		}
		if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpStart)); err == nil {
			t.Fatal("Execute against a hung backend succeeded")
		}
		wantEvents(t, u)
	})
}

// A storage fault in the acquisition window is not a policy refusal: the caller is
// still refused fail-closed (403 decision_stale, no backend call), but nothing is
// attributed, exactly like the same fault before Authorize (AttributionOf contract).
func TestStorageFaultDuringLeaseAcquisitionIsNotCounted(t *testing.T) {
	for _, op := range ops.Operations() {
		t.Run(string(op), func(t *testing.T) {
			u := &usageSpy{}
			e := newEnv(t, withUsage(u))
			var fired atomic.Int32
			e.spy.resolveBlock = func(_ context.Context, ref string) {
				if ref == string(edgeID) && fired.Add(1) == 1 {
					_ = e.repo.Close() // the store fails inside the acquisition window
				}
			}
			res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
			closeLogs(res)
			if fired.Load() == 0 {
				t.Fatal("the hook never fired: no immutable-ID resolution during acquisition")
			}
			if !isDenial(err) {
				t.Fatalf("Execute = %v, want the fail-closed 403", err)
			}
			if n := len(e.spy.operationalCalls()); n != 0 {
				t.Fatalf("a refused acquisition made %d operational calls", n)
			}
			wantEvents(t, u)
		})
	}
}

// An acquisition that outlives AcquireTimeout is a fault with no decision: not counted.
func TestAcquisitionTimeoutIsNotCounted(t *testing.T) {
	u := &usageSpy{}
	e := newEnv(t, withUsage(u), func(c *envConfig) { c.acquireTimeout = ops.MinAcquireTimeout })
	e.spy.resolveBlock = func(ctx context.Context, ref string) {
		if ref == "edge-proxy" {
			<-ctx.Done()
		}
	}
	if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpStart)); err == nil {
		t.Fatal("Execute against a hung backend succeeded")
	}
	wantEvents(t, u)
}

// In-flight revocation: a call cut off by the ending authorization is DENIED (no
// Docker fault happened); a daemon that completes despite the cancellation did execute
// (the mock mode "daemon-completes-despite-cancellation"), which is ALLOWED even though
// Execute withholds the data and refuses the caller.
func TestInFlightRevocationIsDeniedWhenCutOffAndAllowedWhenTheDaemonCompleted(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, completes := range []bool{false, true} {
			name, want := string(op)+"/context-honoring-daemon", domain.UsageDenied
			if completes {
				name, want = string(op)+"/daemon-completes-despite-cancellation", domain.UsageAllowed
			}
			t.Run(name, func(t *testing.T) {
				u := &usageSpy{}
				e := newEnv(t, withUsage(u))
				e.spy.ignoreCtx = completes
				entered := make(chan context.Context, 1)
				release := make(chan struct{})
				e.spy.beforeOperation = func(_ string, ctx context.Context) { entered <- ctx; <-release }
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
				o := <-done
				closeLogs(o.res)
				if o.res.Logs != nil || o.res.Status != nil || o.res.Config != nil {
					t.Fatal("data was not withheld after revocation")
				}
				wantEvents(t, u, botEvt(op, want))
			})
		}
	}
}

// Deadline expiry is a fault of the backend call: an ERROR for every one-shot key and
// for the Logs open call (the open outlived its bound). A pre-expired bound dispatches
// nothing and is not counted.
func TestDeadlineExpiryIsAnErrorAndAPreExpiredBoundIsNotCounted(t *testing.T) {
	for _, op := range ops.Operations() {
		t.Run(string(op), func(t *testing.T) {
			u := &usageSpy{}
			e := newEnv(t, withUsage(u), recordDeadlines())
			entered := make(chan struct{}, 1)
			e.spy.beforeOperation = func(_ string, ctx context.Context) { entered <- struct{}{}; <-ctx.Done() }
			done := make(chan outcome, 1)
			go func() {
				res, err := e.svc.Execute(t.Context(), midCallRequest(op))
				done <- outcome{res, err}
			}()
			<-entered
			e.fireDeadline(0)
			o := <-done
			closeLogs(o.res)
			if o.err == nil || isDenial(o.err) {
				t.Fatalf("Execute = %v, want the deadline's context error", o.err)
			}
			wantEvents(t, u, botEvt(op, domain.UsageError))
		})
	}
	t.Run("pre-expired bound", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u), func(c *envConfig) {
			c.withTimeout = func(*env) func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
				return func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
					ctx, cancel := context.WithCancel(parent)
					cancel()
					return ctx, cancel
				}
			}
		})
		if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus)); err == nil {
			t.Fatal("an expired bound dispatched")
		}
		if n := len(e.spy.operationalCalls()); n != 0 {
			t.Fatalf("%d operational attempts under an expired bound", n)
		}
		wantEvents(t, u)
	})
}

// A hung Logs open cut off by revocation is denied; by the caller leaving it is not
// cut off at all (see the mid-call test). Open succeeded while authority ended: allowed.
func TestLogsOpenRevokedWhileOpeningFollowsTheBackendEvidence(t *testing.T) {
	for _, completes := range []bool{false, true} {
		name, want := "context-honoring-daemon", domain.UsageDenied
		if completes {
			name, want = "daemon-completes-despite-cancellation", domain.UsageAllowed
		}
		t.Run(name, func(t *testing.T) {
			u := &usageSpy{}
			e := newEnv(t, withUsage(u))
			e.spy.ignoreCtx = completes
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			e.spy.beforeOperation = func(_ string, ctx context.Context) { entered <- ctx; <-release }
			done := make(chan outcome, 1)
			go func() {
				res, err := e.svc.Execute(t.Context(), followReq(botCreds()))
				done <- outcome{res, err}
			}()
			ctx := <-entered
			revokeCredential(e)
			if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
				t.Fatal(err)
			}
			if ctx.Err() == nil {
				t.Fatal("revocation did not cancel the Logs open call")
			}
			close(release)
			o := <-done
			closeLogs(o.res)
			if o.res.Logs != nil {
				t.Fatal("a stream was handed out after revocation")
			}
			wantEvents(t, u, botEvt(docker.OpLogs, want))
		})
	}
}

// A stream is ONE accounting event, made when the backend open call returns. Frames,
// end of stream, close (twice), request cancellation, revalidation (pull and push),
// revocation and a terminal backend failure are not events: the count never changes.
func TestStreamsAreCountedExactlyOnceAtOpen(t *testing.T) {
	t.Run("finite stream: open, read to EOF, close, revalidate", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u))
		r := req(botCreds(), "edge-proxy", docker.OpLogs)
		res, err := e.svc.Execute(t.Context(), r)
		if err != nil || res.Logs == nil {
			t.Fatalf("Execute = %v", err)
		}
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed))
		for {
			if _, err := res.Logs.Next(t.Context()); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("Next = %v", err)
				}
				break
			}
		}
		_ = res.Logs.Close()
		_ = res.Logs.Close()
		_ = res.Logs.Revalidate(t.Context())
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed))
	})
	t.Run("follow stream: revalidation ticks, push, revocation, close", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u))
		st, _ := openFollow(t, e, botCreds())
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed))
		tick := e.ticker(0)
		for range 3 {
			if !tick.Tick() {
				t.Fatal("the watcher stopped on a healthy stream")
			}
		}
		if err := st.Revalidate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
			t.Fatal(err)
		}
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed))
		revokeCredential(e)
		if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
			t.Fatal(err)
		}
		waitDone(t, st.Done(), "stream ended by the revocation")
		if _, err := st.Next(t.Context()); !isTermination(err) {
			t.Fatalf("Next after revocation = %v", err)
		}
		if err := st.Revalidate(t.Context()); err == nil {
			t.Fatal("a revoked stream revalidated")
		}
		_ = st.Close()
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed)) // still one: ending is not an event
	})
	t.Run("follow stream: terminal backend failure after open", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u))
		e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { return &failingStream{LogStream: inner} }
		res, err := e.svc.Execute(t.Context(), followReq(botCreds()))
		if err != nil || res.Logs == nil {
			t.Fatalf("Execute = %v", err)
		}
		defer func() { _ = res.Logs.Close() }()
		if _, err := res.Logs.Next(t.Context()); !errors.Is(err, docker.ErrBackendFailed) {
			t.Fatalf("Next = %v, want the backend failure", err)
		}
		// The open succeeded and was counted allowed; the later failure is not a second event.
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed))
	})
	t.Run("follow stream: consumer close and request cancellation", func(t *testing.T) {
		u := &usageSpy{}
		e := newEnv(t, withUsage(u))
		ctx, cancel := context.WithCancel(t.Context())
		res, err := e.svc.Execute(ctx, followReq(botCreds()))
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		waitDone(t, res.Logs.Done(), "stream ended by its request")
		_ = res.Logs.Close()
		res2, err := e.svc.Execute(t.Context(), followReq(aliceCreds()))
		if err != nil {
			t.Fatal(err)
		}
		_ = res2.Logs.Close()
		wantEvents(t, u, botEvt(docker.OpLogs, domain.UsageAllowed), aliceEvt(docker.OpLogs, domain.UsageAllowed))
	})
}

// failingStream delivers one backend failure from its first read.
type failingStream struct{ docker.LogStream }

func (f *failingStream) Next(context.Context) (docker.LogFrame, error) {
	return docker.LogFrame{}, docker.ErrBackendFailed
}

// An accounting failure (storage down) never changes the operation's outcome, never
// invents a count, and is surfaced by a counter and a fixed secret-free log line.
func TestAccountingFailureNeverChangesTheOutcomeAndIsSurfacedWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	canary := "SECRET-CANARY-DISK-DETAIL"
	u := &usageSpy{fail: errors.New(canary)}
	e := newEnv(t, withUsage(u))
	res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus))
	if err != nil || res.Status == nil {
		t.Fatalf("an accounting failure changed an allowed outcome: %v", err)
	}
	if _, err := e.svc.Execute(t.Context(), req(bobCreds(), "edge-proxy", docker.OpInspectStatus)); !authz.HasReason(err, authz.ReasonDefaultDeny) {
		t.Fatalf("an accounting failure changed a denial: %v", err)
	}
	if n := e.svc.UsageFailures(); n != 2 {
		t.Fatalf("UsageFailures = %d, want 2", n)
	}
	wantEvents(t, u)
	out := logs.String()
	if bytes.Contains([]byte(out), []byte(canary)) || bytes.Contains([]byte(out), []byte(aliceID)) || bytes.Contains([]byte(out), []byte(tokenFor("1"))) {
		t.Fatalf("the accounting-failure log line leaks a detail: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("usage accounting failed")) {
		t.Fatalf("accounting failure not logged: %q", out)
	}
	// Control: a healthy recorder resumes counting; nothing was queued or replayed.
	u.fail = nil
	if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus)); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, u, botEvt(docker.OpInspectStatus, domain.UsageAllowed))
}

// Accounting is optional configuration: no recorder, no accounting, no side effect.
func TestServiceWithoutARecorderBehavesAsBefore(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus)); err != nil {
		t.Fatal(err)
	}
	if n := e.svc.UsageFailures(); n != 0 {
		t.Fatalf("UsageFailures = %d", n)
	}
}

// P1.18.4 P115-I1: a storage fault of an authorizer callback during admission
// (Authorize) or the revalidation under the freshly registered lease keeps the
// fail-closed refusal but is NEVER accounted as a denial: there is no policy
// decision, so no usage event exists. The controls (a real removal of the ALLOW
// rule at the same boundaries) are still exactly one denied event.
func TestStorageFaultDuringAdmissionIsNeverCountedDenied(t *testing.T) {
	type cause struct {
		fault  func(e *env)
		denied bool
	}
	causes := map[string]cause{
		"policy-query-fault":         {func(e *env) { e.exec(`ALTER TABLE policies RENAME TO policies_x`) }, false},
		"get-endpoint-fault":         {func(e *env) { e.exec(`ALTER TABLE endpoints RENAME TO endpoints_x`) }, false},
		"verification-query-fault":   {func(e *env) { e.exec(`ALTER TABLE agents RENAME TO agents_x`) }, false},
		"transaction-begin-fault":    {func(e *env) { e.repo.FailClosed() }, false},
		"control-allow-rule-removed": {func(e *env) { e.exec(`DELETE FROM policies WHERE agent_id=?`, botID) }, true},
	}
	// at-admission hooks the name resolution that precedes the Authorize callback;
	// at-revalidation hooks the immutable-ID resolution that precedes the callback
	// revalidating the freshly registered lease.
	for _, phase := range []string{"at-admission", "at-revalidation"} {
		for name, c := range causes {
			for _, op := range ops.Operations() {
				t.Run(phase+"/"+name+"/"+string(op), func(t *testing.T) {
					u := &usageSpy{}
					e := newEnv(t, withUsage(u))
					var fired atomic.Bool
					e.spy.resolveBlock = func(_ context.Context, ref string) {
						if (phase == "at-revalidation") == (len(ref) == 64) && fired.CompareAndSwap(false, true) {
							c.fault(e)
						}
					}
					res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
					closeLogs(res)
					if err == nil {
						t.Fatal("a callback fault/refusal must never dispatch")
					}
					if !fired.Load() {
						t.Fatal("the fault hook never ran")
					}
					if c.denied {
						if !isDenial(err) {
							t.Fatalf("Execute = %v, want a denial", err)
						}
						// A default deny at admission matched no selector; the lease's own
						// revalidation refusal carries the decision's selector.
						sel := selEdge
						if phase == "at-admission" {
							sel = ""
						}
						wantEvents(t, u, evt(aliceID, botID, sel, op, domain.UsageDenied))
					} else {
						wantEvents(t, u)
					}
					if n := len(e.spy.operationalCalls()); n != 0 {
						t.Fatalf("%d operational attempts", n)
					}
					if n := e.svc.UsageFailures(); n != 0 {
						t.Fatalf("%d accounting failures", n)
					}
				})
			}
		}
	}
}
