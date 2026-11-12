package ops_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// A caller's own cancellation is local to that caller. The acquisition seam
// (Authorize -> backend.ResolveTarget -> post-registration revalidation) must run
// detached from it: otherwise one aborted request would fail-close the same
// principal's healthy sibling leases (authorizer peer cancellation) and, with the
// production SDK adapter, invalidate the endpoint's global safety proof.

// cancelWindows are the two points inside acquisition where a request context can
// end: the name resolution of Authorize, and the immutable-ID resolution of the
// revalidation under the freshly registered lease. Both are driven by the spy hook
// (deterministic, no sleeps).
var cancelWindows = []struct {
	name string
	ref  string
}{
	{"during-authorize-name-resolution", "edge-proxy"},
	{"during-acquire-revalidation-id-resolution", string(edgeID)},
}

func isDenial(err error) bool {
	return errors.Is(err, authz.ErrForbidden) || errors.Is(err, authz.ErrUnauthenticated)
}

// P113-CANCEL-01 (reviewer RP-01 regression + control): a NEW Execute whose
// request context ends mid-acquisition returns its own context error, makes no
// operational call, leaks no lease, and leaves the same principal's open follow
// stream (and the backend's safety proof) untouched.
func TestCanceledExecuteNeverCancelsSiblingLeasesOrBackendSafety(t *testing.T) {
	for _, who := range []string{"agent", "human"} {
		for _, w := range cancelWindows {
			for _, cancelIt := range []bool{false, true} {
				name := who + "/" + w.name + "/control"
				if cancelIt {
					name = who + "/" + w.name + "/cancel"
				}
				t.Run(name, func(t *testing.T) {
					e := newEnv(t)
					sibling, _ := openFollow(t, e, credsFor(who))
					e.spy.wrapLogs = nil
					before := len(e.spy.operationalCalls())

					reqCtx, cancel := context.WithCancel(t.Context())
					defer cancel()
					var armed atomic.Bool
					armed.Store(true)
					var once sync.Once
					e.spy.afterResolve = func(ref string) {
						if cancelIt && armed.Load() && ref == w.ref {
							once.Do(cancel)
						}
					}
					res, err := e.svc.Execute(reqCtx, followReq(credsFor(who)))
					armed.Store(false)
					e.spy.afterResolve = nil
					if res.Logs != nil {
						defer func() { _ = res.Logs.Close() }()
					}

					select {
					case <-sibling.Done():
						t.Fatalf("healthy sibling stream was canceled by another request's local cancellation (err=%v)", err)
					default:
					}
					e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "sibling alive\n"})
					f, nerr := sibling.Next(t.Context())
					if nerr != nil || string(f.Payload) != "sibling alive\n" {
						t.Fatalf("sibling Next = %q, %v", f.Payload, nerr)
					}
					if !e.mock.Ready() || e.mock.VerificationState() != docker.StateVerified {
						t.Fatalf("backend safety proof lost (state=%v)", e.mock.VerificationState())
					}

					if !cancelIt {
						if err != nil || res.Logs == nil {
							t.Fatalf("control Execute = %v logs=%v", err, res.Logs != nil)
						}
						return
					}
					if !errors.Is(err, context.Canceled) || isDenial(err) {
						t.Fatalf("canceled Execute returned %v, want its own context.Canceled (not a 403)", err)
					}
					if res.Logs != nil || res.Status != nil || res.Config != nil {
						t.Fatal("a canceled Execute returned data")
					}
					if got := len(e.spy.operationalCalls()); got != before {
						t.Fatalf("canceled Execute reached the backend operationally: %d -> %d", before, got)
					}
					if n := e.az.ActiveLeaseCount(); n != 1 {
						t.Fatalf("active leases = %d, want only the sibling's", n)
					}
				})
			}
		}
	}
}

// P113-CANCEL-02 (F2): the caller's cancellation never reaches the backend's
// ResolveTarget at all (it is what the SDK adapter treats as a global safety
// fault), for every operation key and both windows.
func TestCallerCancellationNeverReachesBackendResolveTarget(t *testing.T) {
	for _, op := range ops.Operations() {
		for _, w := range cancelWindows {
			t.Run(string(op)+"/"+w.name, func(t *testing.T) {
				e := newEnv(t)
				reqCtx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var once sync.Once
				e.spy.afterResolve = func(ref string) {
					if ref == w.ref {
						once.Do(cancel)
					}
				}
				res, err := e.svc.Execute(reqCtx, req(botCreds(), "edge-proxy", op))
				if res.Logs != nil {
					defer func() { _ = res.Logs.Close() }()
				}
				if reqCtx.Err() == nil {
					t.Fatal("hook never canceled the request: test is not exercising the window")
				}
				e.spy.mu.Lock()
				seen := append([]error(nil), e.spy.resolveCtxErr...)
				e.spy.mu.Unlock()
				if len(seen) == 0 {
					t.Fatal("backend ResolveTarget was never called")
				}
				for i, cerr := range seen {
					if cerr != nil {
						t.Fatalf("ResolveTarget #%d observed the caller's cancellation (%v)", i, cerr)
					}
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Execute = %v, want context.Canceled", err)
				}
				if n := len(e.spy.operationalCalls()); n != 0 {
					t.Fatalf("%d operational attempts after the caller left", n)
				}
				if !e.mock.Ready() || e.mock.VerificationState() != docker.StateVerified {
					t.Fatalf("backend safety proof lost (state=%v)", e.mock.VerificationState())
				}
				if n := e.az.ActiveLeaseCount(); n != 0 {
					t.Fatalf("leaked %d leases", n)
				}
			})
		}
	}
}

// P113-CANCEL-03 (adverse control): a REAL revocation landing in the same window
// still fail-closes the principal's sibling leases and denies the new call, with or
// without the caller also leaving.
func TestRealRevocationInTheAcquisitionWindowStillCancelsPeers(t *testing.T) {
	revokers := map[string]func(e *env){
		"agent": func(e *env) { revokeCredential(e) },
		"human": func(e *env) { revokeSession(e, aliceSess) },
	}
	for who, revoke := range revokers {
		for _, w := range cancelWindows {
			for _, alsoCancel := range []bool{false, true} {
				name := who + "/" + w.name
				if alsoCancel {
					name += "/with-caller-cancel"
				}
				t.Run(name, func(t *testing.T) {
					e := newEnv(t)
					sibling, _ := openFollow(t, e, credsFor(who))
					e.spy.wrapLogs = nil
					before := len(e.spy.operationalCalls())

					reqCtx, cancel := context.WithCancel(t.Context())
					defer cancel()
					var once sync.Once
					e.spy.afterResolve = func(ref string) {
						if ref == w.ref {
							once.Do(func() {
								revoke(e)
								if alsoCancel {
									cancel()
								}
							})
						}
					}
					res, err := e.svc.Execute(reqCtx, followReq(credsFor(who)))
					e.spy.afterResolve = nil
					if res.Logs != nil {
						defer func() { _ = res.Logs.Close() }()
					}
					if err == nil || res.Logs != nil {
						t.Fatalf("Execute under a real revocation succeeded (err=%v)", err)
					}
					if !alsoCancel && !isDenial(err) {
						t.Fatalf("err = %v, want the authorizer's denial", err)
					}
					if w.ref == "edge-proxy" {
						// A denial in Authorize never touches existing leases; the
						// revocation reaches the sibling by the push path.
						if nerr := e.svc.NotifyAuthorityChange(t.Context()); nerr != nil {
							t.Fatal(nerr)
						}
					}
					waitDone(t, sibling.Done(), "sibling stream canceled by the real revocation")
					if got := len(e.spy.operationalCalls()); got != before {
						t.Fatalf("revoked Execute reached the backend operationally: %d -> %d", before, got)
					}
				})
			}
		}
	}
}

// P113-CANCEL-04: once admitted, the lease and any in-flight work stay bound to the
// caller's lifetime: ending the request releases the lease and ends the stream, and
// an in-flight one-shot call is canceled.
func TestAdmittedLeaseStaysBoundToTheCallerLifetime(t *testing.T) {
	t.Run("stream-ends-on-cancel", func(t *testing.T) {
		e := newEnv(t)
		reqCtx, cancel := context.WithCancel(t.Context())
		res, err := e.svc.Execute(reqCtx, followReq(botCreds()))
		if err != nil || res.Logs == nil {
			t.Fatalf("Execute = %v", err)
		}
		defer func() { _ = res.Logs.Close() }()
		cancel()
		waitDone(t, res.Logs.Done(), "stream ended by the request context")
		if _, nerr := res.Logs.Next(t.Context()); !errors.Is(nerr, context.Canceled) {
			t.Fatalf("Next after caller cancel = %v, want context.Canceled", nerr)
		}
	})
	t.Run("stream-survives-while-request-lives", func(t *testing.T) {
		e := newEnv(t)
		reqCtx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Hour))
		defer cancel()
		res, err := e.svc.Execute(reqCtx, followReq(botCreds()))
		if err != nil || res.Logs == nil {
			t.Fatalf("Execute = %v", err)
		}
		defer func() { _ = res.Logs.Close() }()
		select {
		case <-res.Logs.Done():
			t.Fatal("stream ended while its request context was live")
		default:
		}
	})
	t.Run("in-flight-one-shot", func(t *testing.T) {
		e := newEnv(t)
		reqCtx, cancel := context.WithCancel(t.Context())
		entered := make(chan struct{}, 1)
		e.spy.beforeOperation = func(_ string, ctx context.Context) {
			entered <- struct{}{}
			<-ctx.Done() // a slow daemon: answers only when its context ends
		}
		done := make(chan error, 1)
		go func() {
			_, err := e.svc.Execute(reqCtx, req(botCreds(), "edge-proxy", docker.OpStart))
			done <- err
		}()
		<-entered
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("in-flight Execute = %v, want context.Canceled", err)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("in-flight call never ended after the caller left")
		}
		if n := e.az.ActiveLeaseCount(); n != 0 {
			t.Fatalf("leaked %d leases", n)
		}
	})
}

// P113-CANCEL-05: acquisition is detached from the caller but still BOUNDED: a
// backend that never answers is cut off by AcquireTimeout (a real fault that fails
// closed), never by the caller's cancellation. The block ends only when the bound
// fires, so nothing asserts elapsed time.
func TestAcquisitionIsBoundedByAcquireTimeout(t *testing.T) {
	e := newEnv(t, func(c *envConfig) { c.acquireTimeout = ops.MinAcquireTimeout })
	e.spy.resolveBlock = func(ctx context.Context, ref string) {
		if ref == "edge-proxy" {
			<-ctx.Done()
		}
	}
	res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpStart))
	if err == nil || res.Logs != nil || res.Status != nil {
		t.Fatalf("Execute against a hung backend succeeded (err=%v)", err)
	}
	if n := len(e.spy.operationalCalls()); n != 0 {
		t.Fatalf("%d operational attempts after a timed-out acquisition", n)
	}
	if n := e.az.ActiveLeaseCount(); n != 0 {
		t.Fatalf("leaked %d leases", n)
	}
}
