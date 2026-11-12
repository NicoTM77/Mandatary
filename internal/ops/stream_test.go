package ops_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// probeStream wraps the backend stream to report when the consumer is inside
// Next, so "pending follow read" tests are ordered by channels, never by sleeps.
type probeStream struct {
	docker.LogStream
	enter  chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newProbe(inner docker.LogStream) *probeStream {
	return &probeStream{LogStream: inner, enter: make(chan struct{}, 64), closed: make(chan struct{})}
}

func (p *probeStream) Next(ctx context.Context) (docker.LogFrame, error) {
	p.enter <- struct{}{}
	return p.LogStream.Next(ctx)
}

func (p *probeStream) Close() error {
	p.once.Do(func() { close(p.closed) })
	return p.LogStream.Close()
}

// stubbornStream models a transport read that ignores its context and only
// unblocks when the stream is closed (as an HTTP body read does).
type stubbornStream struct {
	enter   chan struct{}
	release chan struct{}
	once    sync.Once
	closed  chan struct{}
}

func newStubborn() *stubbornStream {
	return &stubbornStream{enter: make(chan struct{}, 8), release: make(chan struct{}), closed: make(chan struct{})}
}

func (s *stubbornStream) Next(context.Context) (docker.LogFrame, error) {
	s.enter <- struct{}{}
	<-s.release // deliberately ignores ctx
	return docker.LogFrame{}, io.ErrUnexpectedEOF
}
func (s *stubbornStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *stubbornStream) Close() error {
	s.once.Do(func() { close(s.closed); close(s.release) })
	return nil
}

func followReq(creds authz.PrincipalCredentials) ops.Request {
	r := req(creds, "edge-proxy", docker.OpLogs)
	r.Logs = &docker.LogOptions{Tail: 10, Stdout: true, Stderr: true, Follow: true}
	return r
}

// openFollow opens a follow stream and consumes the two backlog frames.
func openFollow(t *testing.T, e *env, creds authz.PrincipalCredentials) (*ops.LogStream, *probeStream) {
	t.Helper()
	var probe *probeStream
	e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { probe = newProbe(inner); return probe }
	res, err := e.svc.Execute(t.Context(), followReq(creds))
	if err != nil || res.Logs == nil {
		t.Fatalf("open follow stream: %v", err)
	}
	t.Cleanup(func() { _ = res.Logs.Close() })
	for i := 0; i < 2; i++ {
		f, err := res.Logs.Next(t.Context())
		if err != nil || len(f.Payload) == 0 {
			t.Fatalf("backlog frame %d: %v", i, err)
		}
		<-probe.enter
	}
	return res.Logs, probe
}

type nextResult struct {
	frame docker.LogFrame
	err   error
}

// pendingNext starts a Next that blocks in the backend's follow wait.
func pendingNext(t *testing.T, st *ops.LogStream, probe *probeStream) <-chan nextResult {
	t.Helper()
	ch := make(chan nextResult, 1)
	go func() {
		f, err := st.Next(context.Background())
		ch <- nextResult{f, err}
	}()
	<-probe.enter
	return ch
}

func waitResult(t *testing.T, ch <-chan nextResult, what string) nextResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(60 * time.Second):
		t.Fatalf("%s: pending Next never returned", what)
		return nextResult{}
	}
}

func isTermination(err error) bool {
	return errors.Is(err, ops.ErrStreamRevoked) || errors.Is(err, docker.ErrUnverified)
}

type revocation struct {
	id    string
	who   []string
	apply func(e *env, who string)
	// backendSide: the backend itself ends the stream (loss of self/peer proof).
	backendSide bool
}

func revocations() []revocation {
	human, agent := []string{"human"}, []string{"agent"}
	return []revocation{
		// token revocation / expiry
		{id: "token-revoked", who: agent, apply: func(e *env, _ string) { revokeCredential(e) }},
		{id: "token-expired", who: agent, apply: func(e *env, _ string) { e.clock.Advance(25 * time.Hour) }},
		{id: "agent-disabled", who: agent, apply: func(e *env, _ string) { e.exec(`UPDATE agents SET state='disabled' WHERE id=?`, botID) }},
		{id: "credential-generation-bumped", apply: func(e *env, _ string) {
			e.exec(`UPDATE installation_control SET credential_generation=credential_generation+1`)
		}},
		// session revocation / expiry
		{id: "session-revoked", who: human, apply: func(e *env, _ string) { revokeSession(e, aliceSess) }},
		{id: "session-idle-expired", who: human, apply: func(e *env, _ string) { e.clock.Advance(31 * time.Minute) }},
		{id: "session-absolute-expired", who: human, apply: func(e *env, _ string) {
			e.exec(`UPDATE sessions SET expires_at=? WHERE id=?`, e.clock.Now().Unix()+10, aliceSess)
			e.clock.Advance(10 * time.Second)
		}},
		{id: "session-generation-bumped", who: human, apply: func(e *env, _ string) {
			e.exec(`UPDATE installation_control SET session_generation=session_generation+1`)
		}},
		{id: "mfa-floor-raised-to-webauthn", who: human, apply: func(e *env, _ string) {
			e.exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id=?`, aliceID)
		}},
		{id: "user-disabled", who: human, apply: func(e *env, _ string) { e.exec(`UPDATE users SET state='disabled' WHERE id=?`, aliceID) }},
		{id: "user-compromised", who: human, apply: func(e *env, _ string) { e.exec(`UPDATE users SET compromised=1 WHERE id=?`, aliceID) }},
		// policy revocation / tightening
		{id: "allow-removed", apply: func(e *env, who string) {
			col, id := ownSubject(who)
			e.exec(`DELETE FROM policies WHERE `+col+`=? AND operation='container:logs'`, id)
		}},
		{id: "explicit-deny-added", apply: func(e *env, who string) {
			col, id := ownSubject(who)
			e.policy(col, id, selEdge, "DENY", docker.OpLogs, nil, nil)
		}},
		{id: "log-tail-cap-tightened-below-granted-request", apply: func(e *env, who string) {
			col, id := ownSubject(who)
			e.exec(`UPDATE policies SET log_tail_max=3 WHERE `+col+`=? AND operation='container:logs'`, id)
		}},
		{id: "allow-quarantined", apply: func(e *env, _ string) { e.exec(`UPDATE policies SET state='quarantined'`) }},
		{id: "authority-generation-moved", apply: func(e *env, _ string) { e.exec(`UPDATE policies SET authority_generation=2`) }},
		{id: "group-membership-disabled", apply: func(e *env, who string) {
			// the allow came through a group, then membership is disabled
			e.exec(`INSERT INTO groups (id, name, state, authority_generation) VALUES (?, 'g', 'active', 1)`, groupID)
			if who == "human" {
				e.exec(`INSERT INTO user_group_memberships (user_id, group_id, state, authority_generation) VALUES (?, ?, 'active', 1)`, aliceID, groupID)
			} else {
				e.exec(`INSERT INTO agent_group_memberships (agent_id, group_id, state, authority_generation) VALUES (?, ?, 'active', 1)`, botID, groupID)
			}
			col, id := ownSubject(who)
			e.exec(`DELETE FROM policies WHERE `+col+`=?`, id)
			e.policy("group_id", groupID, selEdge, "ALLOW", docker.OpLogs, nil, nil)
			// membership stays active here; the revocation itself is the next statement
			if who == "human" {
				e.exec(`UPDATE user_group_memberships SET state='disabled' WHERE group_id=?`, groupID)
			} else {
				e.exec(`UPDATE agent_group_memberships SET state='disabled' WHERE group_id=?`, groupID)
			}
		}},
		// installation / endpoint / target state
		{id: "restore-quarantine", apply: func(e *env, _ string) { e.exec(`UPDATE installation_control SET restore_quarantined=1`) }},
		{id: "endpoint-disabled", apply: func(e *env, _ string) { e.exec(`UPDATE endpoints SET state='disabled' WHERE slug='local'`) }},
		{id: "target-removed", apply: func(e *env, _ string) { e.mock.RemoveContainer(edgeID) }},
		{id: "target-renamed-out-of-selector", apply: func(e *env, _ string) {
			f := fixtureOf(e, edgeID)
			f.Name = "renamed-away"
			if err := e.mock.UpsertContainer(f); err != nil {
				e.t.Fatal(err)
			}
		}},
		{id: "name-recreated-as-different-container", apply: func(e *env, _ string) {
			e.mock.RemoveContainer(edgeID)
			f := fixtureOf(e, billingID)
			f.Name = "edge-proxy"
			if err := e.mock.UpsertContainer(f); err != nil {
				e.t.Fatal(err)
			}
		}},
		// safety state
		{id: "backend-continuity-lost", backendSide: true, apply: func(e *env, _ string) { e.mock.SimulateEventDiscontinuity() }},
		{id: "backend-removed", apply: func(e *env, _ string) { e.az.RemoveBackend(localEP) }},
	}
}

// P113-STREAM-01: active follow-stream termination on token / session / policy
// revocation or expiry, via BOTH triggers: the immediate push (the revoking path
// notifies) and the bounded pull (the stream's own revalidation tick). The pending
// read is released by deterministic cancellation: nothing sleeps or polls.
func TestFollowStreamTerminatesOnEveryRevocationOrExpiryCause(t *testing.T) {
	for _, rv := range revocations() {
		kinds := rv.who
		if len(kinds) == 0 {
			kinds = []string{"human", "agent"}
		}
		for _, who := range kinds {
			for _, trigger := range []string{"push", "pull"} {
				t.Run(rv.id+"/"+who+"/"+trigger, func(t *testing.T) {
					t.Parallel()
					e := newEnv(t)
					st, probe := openFollow(t, e, credsFor(who))
					if e.az.ActiveLeaseCount() != 1 || e.tickerCount() != 1 {
						t.Fatalf("leases=%d watchers=%d, want 1/1", e.az.ActiveLeaseCount(), e.tickerCount())
					}
					select {
					case <-st.Done():
						t.Fatal("stream already terminated before the cause")
					default:
					}
					pending := pendingNext(t, st, probe)
					opCallsBefore := len(e.spy.operationalCalls())
					rv.apply(e, who)

					switch trigger {
					case "push":
						if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
							t.Fatalf("NotifyAuthorityChange: %v", err)
						}
					case "pull":
						if !e.ticker(0).Tick() && !stopped(e.ticker(0)) {
							t.Fatal("revalidation tick was not accepted")
						}
					}
					waitDone(t, st.Done(), "stream termination")
					res := waitResult(t, pending, "pending follow read")
					if res.err == nil || !isTermination(res.err) || len(res.frame.Payload) != 0 {
						t.Fatalf("pending read = %q, %v; want termination and no frame", res.frame.Payload, res.err)
					}
					// No frame can be delivered after revocation, even if the container logs more.
					e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "after revocation\n"})
					f, err := st.Next(t.Context())
					if err == nil || len(f.Payload) != 0 {
						t.Fatalf("frame %q delivered after revocation (err %v)", f.Payload, err)
					}
					if rv.id != "backend-continuity-lost" && !errors.Is(err, ops.ErrStreamRevoked) {
						t.Fatalf("post-revocation Next = %v, want ErrStreamRevoked", err)
					}
					waitDone(t, e.ticker(0).stopped, "revalidation watcher exit")
					if n := e.az.ActiveLeaseCount(); n != 0 {
						t.Fatalf("%d leases still registered", n)
					}
					if got := len(e.spy.operationalCalls()); got != opCallsBefore {
						t.Fatalf("termination caused %d extra operational calls", got-opCallsBefore)
					}
					if err := st.Close(); err != nil {
						t.Fatalf("Close after termination: %v", err)
					}
					select {
					case <-probe.closed:
					default:
						t.Fatal("backend stream was not closed")
					}
				})
			}
		}
	}
}

func stopped(f *fakeTicker) bool {
	select {
	case <-f.stopped:
		return true
	default:
		return false
	}
}

// P113-STREAM-02: control. Without any adverse change neither trigger ends the
// stream, no-op notifications included (P1.11 survival property), and fresh log
// lines are still delivered afterwards.
func TestHealthyStreamSurvivesTicksAndNoopNotifications(t *testing.T) {
	for _, who := range []string{"human", "agent"} {
		t.Run(who, func(t *testing.T) {
			e := newEnv(t)
			st, _ := openFollow(t, e, credsFor(who))
			tk := e.ticker(0)
			if !tk.Tick() || !tk.Settle() { // second tick is only accepted once the first pass is done
				t.Fatal("watcher stopped on a healthy stream")
			}
			if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-st.Done():
				t.Fatal("healthy stream was terminated")
			default:
			}
			e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "still flowing\n"})
			f, err := st.Next(t.Context())
			if err != nil || string(f.Payload) != "still flowing\n" || f.Stream != docker.LogStreamStdout {
				t.Fatalf("healthy stream Next = %q, %v", f.Payload, err)
			}
			if e.az.ActiveLeaseCount() != 1 {
				t.Fatal("lease dropped on a healthy stream")
			}
		})
	}
}

// P113-STREAM-03: a revoked principal ends only its own streams. Peers on the same
// container and operation, and streams of a closed sibling, are unaffected.
func TestRevocationIsolationBetweenStreams(t *testing.T) {
	e := newEnv(t)
	stA, _ := openFollow(t, e, aliceCreds())
	stB, _ := openFollow(t, e, botCreds())
	stB2, _ := openFollow(t, e, botCreds())

	// Closing one stream of a principal must not cancel its sibling (no collateral
	// cancellation through the authorizer's matching-lease cancellation).
	if err := stB2.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, e.ticker(2).stopped, "closed stream watcher exit")
	if !e.ticker(0).Tick() || !e.ticker(0).Settle() || !e.ticker(1).Tick() || !e.ticker(1).Settle() {
		t.Fatal("a watcher stopped without cause")
	}
	for name, st := range map[string]*ops.LogStream{"alice": stA, "bot": stB} {
		select {
		case <-st.Done():
			t.Fatalf("%s stream ended because a sibling closed", name)
		default:
		}
	}

	// Revoking alice's session ends alice's stream only.
	revokeSession(e, aliceSess)
	if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, stA.Done(), "alice stream")
	select {
	case <-stB.Done():
		t.Fatal("the bot's stream ended with alice's session revocation")
	default:
	}
	e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "bot continues\n"})
	if f, err := stB.Next(t.Context()); err != nil || string(f.Payload) != "bot continues\n" {
		t.Fatalf("surviving stream: %q %v", f.Payload, err)
	}

	// Revoking the bot's token ends it.
	revokeCredential(e)
	if !e.ticker(1).Tick() && !stopped(e.ticker(1)) {
		t.Fatal("tick refused")
	}
	waitDone(t, stB.Done(), "bot stream")
}

// P113-STREAM-04: deterministic context cancellation bounds a pending read.
func TestPendingFollowReadIsBoundedByContextCancellation(t *testing.T) {
	t.Run("per-read context ends the read and the stream", func(t *testing.T) {
		e := newEnv(t)
		st, probe := openFollow(t, e, botCreds())
		ctx, cancel := context.WithCancel(t.Context())
		ch := make(chan nextResult, 1)
		go func() { f, err := st.Next(ctx); ch <- nextResult{f, err} }()
		<-probe.enter
		cancel()
		r := waitResult(t, ch, "canceled read")
		if !errors.Is(r.err, context.Canceled) || len(r.frame.Payload) != 0 {
			t.Fatalf("canceled read = %q, %v; want context.Canceled", r.frame.Payload, r.err)
		}
		// A backend stream cannot resume after an interrupted read: the stream ends
		// and releases its lease and watcher instead of lingering half-usable.
		waitDone(t, st.Done(), "stream end")
		waitDone(t, e.ticker(0).stopped, "watcher exit")
		if e.az.ActiveLeaseCount() != 0 {
			t.Fatal("lease survived an interrupted read")
		}
		e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStderr, Line: "next\n"})
		if f, err := st.Next(t.Context()); !errors.Is(err, context.Canceled) || len(f.Payload) != 0 {
			t.Fatalf("read after interrupted read: %q %v", f.Payload, err)
		}
	})
	t.Run("waiting for another reader does not end the stream", func(t *testing.T) {
		e := newEnv(t)
		st, probe := openFollow(t, e, botCreds())
		first := pendingNext(t, st, probe) // holds the single read slot
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := st.Next(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("second reader with canceled ctx = %v", err)
		}
		select {
		case <-st.Done():
			t.Fatal("a reader that never read ended the stream")
		default:
		}
		e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "first reader gets it\n"})
		r := waitResult(t, first, "first reader")
		if r.err != nil || string(r.frame.Payload) != "first reader gets it\n" {
			t.Fatalf("first reader: %q %v", r.frame.Payload, r.err)
		}
	})
	t.Run("request context ends the stream", func(t *testing.T) {
		e := newEnv(t)
		reqCtx, cancel := context.WithCancel(t.Context())
		var probe *probeStream
		e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { probe = newProbe(inner); return probe }
		res, err := e.svc.Execute(reqCtx, followReq(botCreds()))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := res.Logs.Next(t.Context()); err != nil {
				t.Fatal(err)
			}
			<-probe.enter
		}
		pending := pendingNext(t, res.Logs, probe)
		cancel()
		r := waitResult(t, pending, "read after request cancellation")
		if !errors.Is(r.err, context.Canceled) {
			t.Fatalf("pending read = %v, want context.Canceled", r.err)
		}
		waitDone(t, res.Logs.Done(), "stream end")
		waitDone(t, e.ticker(0).stopped, "watcher exit")
		if e.az.ActiveLeaseCount() != 0 {
			t.Fatal("lease survived request cancellation")
		}
	})
	t.Run("close releases a pending read", func(t *testing.T) {
		e := newEnv(t)
		st, probe := openFollow(t, e, aliceCreds())
		pending := pendingNext(t, st, probe)
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		r := waitResult(t, pending, "read released by Close")
		if !errors.Is(r.err, ops.ErrStreamClosed) {
			t.Fatalf("pending read after Close = %v, want ErrStreamClosed", r.err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if _, err := st.Next(t.Context()); !errors.Is(err, ops.ErrStreamClosed) {
			t.Fatalf("Next after Close = %v", err)
		}
		waitDone(t, e.ticker(0).stopped, "watcher exit")
		if e.az.ActiveLeaseCount() != 0 {
			t.Fatal("Close left the lease registered")
		}
	})
}

// P113-STREAM-05: a transport read that ignores its context cannot outlive
// revocation, because the service closes the backend stream on lease cancellation.
func TestRevocationClosesTransportThatIgnoresContext(t *testing.T) {
	e := newEnv(t)
	stub := newStubborn()
	e.spy.wrapLogs = func(inner docker.LogStream) docker.LogStream { _ = inner.Close(); return stub }
	res, err := e.svc.Execute(t.Context(), followReq(botCreds()))
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan nextResult, 1)
	go func() { f, err := res.Logs.Next(context.Background()); ch <- nextResult{f, err} }()
	<-stub.enter
	revokeCredential(e)
	if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitDone(t, stub.closed, "backend stream Close")
	r := waitResult(t, ch, "read on ctx-ignoring transport")
	if !errors.Is(r.err, ops.ErrStreamRevoked) || len(r.frame.Payload) != 0 {
		t.Fatalf("read = %q, %v; want ErrStreamRevoked and no data", r.frame.Payload, r.err)
	}
}

// P113-STREAM-06: no name is ever re-resolved for the lifetime of a stream, across
// many revalidation passes; the only name resolution is the authorizing one.
func TestStreamLifetimeNeverResolvesTheNameAgain(t *testing.T) {
	e := newEnv(t)
	st, _ := openFollow(t, e, botCreds())
	tk := e.ticker(0)
	for i := 0; i < 5; i++ {
		if !tk.Tick() {
			t.Fatal("watcher stopped")
		}
	}
	if !tk.Settle() {
		t.Fatal("watcher stopped")
	}
	if err := e.svc.NotifyAuthorityChange(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = st
	names, ids := 0, 0
	for _, c := range e.spy.snapshot() {
		if c.Method != "ResolveTarget" {
			continue
		}
		switch c.Ref {
		case "edge-proxy":
			names++
		case string(edgeID):
			ids++
		default:
			t.Fatalf("ResolveTarget(%q)", c.Ref)
		}
	}
	if names != 1 || ids < 5 {
		t.Fatalf("name resolutions %d (want exactly 1), ID revalidations %d (want >= 5)", names, ids)
	}
	if got := e.spy.operationalCalls(); len(got) != 1 || got[0].Method != "Logs" {
		t.Fatalf("operational calls %v, want exactly the one Logs dispatch", got)
	}
}

// P113-STREAM-07: finite streams (follow=false) end with io.EOF, respect the
// requested bounded tail, and release their lease and watcher on EOF.
func TestNonFollowStreamEndsWithEOFAndReleasesLease(t *testing.T) {
	e := newEnv(t)
	r := req(botCreds(), "edge-proxy", docker.OpLogs)
	r.Logs = &docker.LogOptions{Tail: 1, Stdout: true, Stderr: true}
	res, err := e.svc.Execute(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	f, err := res.Logs.Next(t.Context())
	if err != nil || string(f.Payload) != "notice: configuration loaded\n" || f.Stream != docker.LogStreamStderr {
		t.Fatalf("tail=1 frame: %q %v", f.Payload, err)
	}
	if _, err = res.Logs.Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatalf("end of finite stream = %v, want io.EOF", err)
	}
	waitDone(t, res.Logs.Done(), "stream completion")
	waitDone(t, e.ticker(0).stopped, "watcher exit")
	if e.az.ActiveLeaseCount() != 0 {
		t.Fatal("lease survived EOF")
	}
	if _, err = res.Logs.Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatalf("Next after EOF = %v, want io.EOF again", err)
	}
}

// P113-STREAM-08: NotifyAuthorityChange is detached from the caller's request
// context. A canceled context must NOT fail-close healthy streams (P1.11 L1) and a
// real revocation is still applied under it.
func TestNotifyAuthorityChangeIsNotKilledByRequestContext(t *testing.T) {
	e := newEnv(t)
	st, _ := openFollow(t, e, botCreds())
	dead, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.svc.NotifyAuthorityChange(dead); err != nil {
		t.Fatalf("NotifyAuthorityChange(canceled ctx) = %v", err)
	}
	select {
	case <-st.Done():
		t.Fatal("a canceled notification context fail-closed a healthy stream")
	default:
	}
	revokeCredential(e)
	if err := e.svc.NotifyAuthorityChange(dead); err != nil {
		t.Fatal(err)
	}
	waitDone(t, st.Done(), "revocation under a canceled notification context")
}

// P113-STREAM-09: explicit Revalidate gives adapters a synchronous, deterministic
// pass (e.g. immediately after their own logout handler) without the authorizer's
// epoch churn, and fails closed.
func TestStreamRevalidateIsSynchronous(t *testing.T) {
	e := newEnv(t)
	st, _ := openFollow(t, e, aliceCreds())
	if err := st.Revalidate(t.Context()); err != nil {
		t.Fatalf("healthy Revalidate = %v", err)
	}
	revokeSession(e, aliceSess)
	if err := st.Revalidate(t.Context()); err == nil {
		t.Fatal("Revalidate accepted a revoked session")
	}
	select {
	case <-st.Done():
	default:
		t.Fatal("stream still live after a failed Revalidate returned")
	}
}

// P113-STREAM-09b: Revalidate (and so the watcher) is detached from the caller's
// cancellation. A caller whose context has ended must not fail-close the principal's
// healthy sibling streams through the authorizer's matching-lease cancellation
// (P1.11 L1), while a real revocation is still applied under the same context.
func TestStreamRevalidateIgnoresCallerCancellation(t *testing.T) {
	e := newEnv(t)
	stA, _ := openFollow(t, e, botCreds())
	stB, _ := openFollow(t, e, botCreds())
	dead, cancel := context.WithCancel(t.Context())
	cancel()
	if err := stA.Revalidate(dead); err != nil {
		t.Fatalf("Revalidate(canceled ctx) on a healthy stream = %v", err)
	}
	for name, st := range map[string]*ops.LogStream{"A": stA, "B": stB} {
		select {
		case <-st.Done():
			t.Fatalf("stream %s was fail-closed by a canceled caller context", name)
		default:
		}
	}
	revokeCredential(e)
	if err := stA.Revalidate(dead); err == nil {
		t.Fatal("Revalidate accepted a revoked token under a canceled context")
	}
	waitDone(t, stA.Done(), "stream A end")
	waitDone(t, stB.Done(), "stream B end (same revoked principal)")
}

// P113-STREAM-10: the backend losing safety proof ends the stream and rejects new
// dispatches with zero further operational calls (SELF-07 through the service).
func TestLossOfSafetyProofEndsStreamAndBlocksNewDispatch(t *testing.T) {
	e := newEnv(t)
	st, probe := openFollow(t, e, botCreds())
	pending := pendingNext(t, st, probe)
	e.mock.SimulateEventDiscontinuity()
	r := waitResult(t, pending, "pending read on safety loss")
	if r.err == nil || len(r.frame.Payload) != 0 {
		t.Fatalf("pending read = %q, %v", r.frame.Payload, r.err)
	}
	waitDone(t, st.Done(), "stream end")
	before := len(e.spy.operationalCalls())
	for _, op := range ops.Operations() {
		if _, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op)); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("%s after safety loss: %v", op, err)
		}
	}
	if got := len(e.spy.operationalCalls()); got != before {
		t.Fatalf("%d operational calls after safety loss", got-before)
	}
}

// P113-CLOCK-01 (N63B4-SESSION-CLOCKS S06 / SB-5 / SB-8.4, EXP-1, E13): a log stream
// is not human activity. Reading frames and revalidating never refresh the session's
// idle clock, so a follow stream cannot keep a session alive; the stream ends exactly
// at the idle boundary or the absolute lifetime (before / at / after, deterministic
// synthetic clock), and an agent token's expiry ends it exactly at its boundary.
func TestStreamActivityNeverRefreshesClocksAndEndsExactlyAtExpiry(t *testing.T) {
	boundary := func(t *testing.T, e *env, st *ops.LogStream, tk *fakeTicker, until time.Duration, what string) {
		t.Helper()
		e.clock.Advance(until - time.Second)
		e.mock.AppendLog(edgeID, docker.MockLogLine{Stream: docker.LogStreamStdout, Line: "heartbeat\n"})
		if f, err := st.Next(t.Context()); err != nil || string(f.Payload) != "heartbeat\n" {
			t.Fatalf("%s: frame one second before the boundary: %q %v", what, f.Payload, err)
		}
		if !tk.Tick() || !tk.Settle() {
			t.Fatalf("%s: stream ended before the boundary", what)
		}
		select {
		case <-st.Done():
			t.Fatalf("%s: stream ended one second before the boundary", what)
		default:
		}
		e.clock.Advance(time.Second) // exactly at the boundary
		tk.Tick()
		waitDone(t, st.Done(), what+": stream end at the boundary")
		if _, err := st.Next(t.Context()); !errors.Is(err, ops.ErrStreamRevoked) {
			t.Fatalf("%s: Next at the boundary = %v", what, err)
		}
	}
	t.Run("session idle boundary", func(t *testing.T) {
		e := newEnv(t)
		var before int64
		if err := e.db.QueryRow(`SELECT last_activity_at FROM sessions WHERE id=?`, aliceSess).Scan(&before); err != nil {
			t.Fatal(err)
		}
		st, _ := openFollow(t, e, aliceCreds())
		// idle timeout is 1800s from last activity, which was 30s before "now".
		boundary(t, e, st, e.ticker(0), 1770*time.Second, "idle")
		var after int64
		if err := e.db.QueryRow(`SELECT last_activity_at FROM sessions WHERE id=?`, aliceSess).Scan(&after); err != nil || after != before {
			t.Fatalf("stream traffic and revalidation moved last_activity_at %d -> %d (%v)", before, after, err)
		}
	})
	t.Run("session absolute boundary", func(t *testing.T) {
		e := newEnv(t)
		// A lifetime shorter than the idle window, so only the absolute limit can end it.
		e.exec(`UPDATE sessions SET expires_at=created_at+600 WHERE id=?`, aliceSess)
		st, _ := openFollow(t, e, aliceCreds())
		boundary(t, e, st, e.ticker(0), 540*time.Second, "absolute") // created 60s ago, lifetime 600s
	})
	t.Run("agent token expiry boundary", func(t *testing.T) {
		e := newEnv(t)
		st, _ := openFollow(t, e, botCreds())
		boundary(t, e, st, e.ticker(0), 24*time.Hour, "token") // expiry is 24h after "now"
	})
}
