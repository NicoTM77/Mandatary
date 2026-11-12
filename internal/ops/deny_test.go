package ops_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

// Every deny condition below is exercised for EVERY one of the six permission
// keys (container:logs both one-shot and follow), for a human AAL2 session and an
// agent token unless a case is principal-specific. Acceptance: the attempt-counting
// spy records ZERO operational backend invocations (C1 O2: the mock's own counters
// only move after verification succeeds, so they could hide an attempt), no lease
// or revalidation watcher survives or starts, no result data is returned, and the
// identical request is ALLOWED immediately before the adverse state change, so the
// denial is attributable to the condition and not to a broken fixture.
//
// Fixture IDs follow the C2 checkpoint (C2R-H/E/Q assurance, expiry and state
// denials; C2R-B/R bootstrap and recovery identities; C2R-T token revocation).

type denyCase struct {
	id  string
	who []string // empty: both "human" and "agent"
	// only restricts the operations the case applies to (empty: all six).
	only []docker.Operation
	// perOp applies mutate to a fresh environment per operation (op-specific state).
	perOp bool
	// mutate changes persisted/backend state once per environment.
	mutate func(e *env, who string, op docker.Operation)
	// shape changes the request itself, per cell, without touching state.
	shape func(r *ops.Request, who string, op docker.Operation)
	// status is 401/403 for authorization denials.
	status int
	reason authz.DenialReason
	// invalid expects ops.ErrInvalidRequest (rejected before ANY backend call).
	invalid bool
	// zeroTotal asserts not even a safety lookup reached the backend.
	zeroTotal bool
	// ctxErr runs the request with an already-canceled context.
	ctxErr bool
}

func (c denyCase) kinds() []string {
	if len(c.who) > 0 {
		return c.who
	}
	return []string{"human", "agent"}
}

func (c denyCase) applies(op docker.Operation) bool {
	if len(c.only) == 0 {
		return true
	}
	for _, o := range c.only {
		if o == op {
			return true
		}
	}
	return false
}

func credsFor(who string) authz.PrincipalCredentials {
	if who == "human" {
		return aliceCreds()
	}
	return botCreds()
}

func ownSubject(who string) (col, id string) {
	if who == "human" {
		return "user_id", aliceID
	}
	return "agent_id", botID
}

func bobCreds() authz.PrincipalCredentials {
	return authz.PrincipalCredentials{SessionID: authz.SessionID(bobSess), SessionSecret: secretFor(bobSess)}
}

func sqlf(q string) func(e *env, who string, op docker.Operation) {
	return func(e *env, _ string, _ docker.Operation) { e.exec(q) }
}

func denyCases() []denyCase {
	human, agent := []string{"human"}, []string{"agent"}
	logs := []docker.Operation{docker.OpLogs}
	timed := []docker.Operation{docker.OpStop, docker.OpRestart}
	return []denyCase{
		// --- authentication / credential status (401) ---
		{id: "C2R-A01-no-credentials", who: human, status: 401, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Credentials = authz.PrincipalCredentials{} }},
		{id: "C2R-A02-session-and-token-together", who: human, status: 401, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Credentials.AgentToken = tokenFor("1") }},
		{id: "C2R-A03-unknown-session-secret", who: human, status: 401,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Credentials = authz.PrincipalCredentials{SessionSecret: []byte("unknown-session-secret-0123456789abcdef0123456789abcdef")}
			}},
		{id: "C2R-A04-wrong-secret-for-session-id", who: human, status: 401,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Credentials.SessionSecret = secretFor(bobSess) }},
		{id: "C2R-A05-unknown-token", who: agent, status: 401,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Credentials = authz.PrincipalCredentials{AgentToken: tokenFor("9")}
			}},
		{id: "C2R-A06-token-without-bearer-prefix", who: agent, status: 401,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Credentials = authz.PrincipalCredentials{AgentToken: "not-a-bearer-token-0123456789abcdef"}
			}},
		{id: "C2R-T05-token-revoked", who: agent, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) { revokeCredential(e) }},
		{id: "C2R-T06-token-expired", who: agent, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) { e.clock.Advance(25 * time.Hour) }},
		{id: "C2R-H09-session-revoked-logout", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) { revokeSession(e, aliceSess) }},
		{id: "C2R-E01-session-idle-expired", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) { e.clock.Advance(31 * time.Minute) }},
		{id: "C2R-E02-session-absolute-expired", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE sessions SET expires_at=? WHERE id=?`, e.clock.Now().Unix()+10, aliceSess)
				e.clock.Advance(10 * time.Second)
			}},
		{id: "C2R-H01-password-only-AAL1-vs-required-MFA", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE sessions SET achieved_assurance=1, methods=1 WHERE id=?`, aliceSess)
			}},
		{id: "C2R-H06-caller-asserted-AAL2-ignored", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE sessions SET achieved_assurance=1, methods=1 WHERE id=?`, aliceSess)
			},
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Credentials.UntrustedCallerAssurance = 2
				r.Credentials.UntrustedCallerAdmin = true
			}},
		{id: "C2R-H07-TOTP-vs-webauthn-floor", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id=?`, aliceID)
			}},
		{id: "C2R-H02-preauth-capability-is-not-an-identity", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE sessions SET purpose='preauth', achieved_assurance=0, methods=1 WHERE id=?`, aliceSess)
			}},
		{id: "C2R-R02-recovery-purpose-session", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE sessions SET purpose='recovery', achieved_assurance=0, methods=1 WHERE id=?`, aliceSess)
			}},
		{id: "C2R-B01-setup-purpose-session", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE sessions SET purpose='setup', achieved_assurance=0, methods=1 WHERE id=?`, aliceSess)
			}},
		{id: "C2R-B04-session-secret-presented-as-agent-token", who: agent, status: 401,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Credentials = authz.PrincipalCredentials{AgentToken: string(secretFor(aliceSess))}
			}},
		{id: "C2R-Q01-user-quarantined", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE users SET state='quarantined' WHERE id=?`, aliceID)
			}},
		{id: "C2R-Q02-user-disabled", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE users SET state='disabled' WHERE id=?`, aliceID)
			}},
		{id: "C2R-Q08-user-compromised", who: human, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE users SET compromised=1 WHERE id=?`, aliceID)
			}},
		{id: "C2R-Q09-agent-disabled", who: agent, status: 401,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.exec(`UPDATE agents SET state='disabled' WHERE id=?`, botID)
			}},
		{id: "C2R-Q04-session-generation-bumped", who: human, status: 401,
			mutate: sqlf(`UPDATE installation_control SET session_generation=session_generation+1`)},
		{id: "C2R-Q05-credential-generation-bumped", status: 401,
			mutate: sqlf(`UPDATE installation_control SET credential_generation=credential_generation+1`)},

		// --- restore quarantine / endpoint state / safety (403) ---
		{id: "C2R-Q03-restore-quarantined", status: 403, reason: authz.ReasonRestoreQuarantined,
			mutate: sqlf(`UPDATE installation_control SET restore_quarantined=1`)},
		{id: "RESTORE-endpoint-disabled", status: 403, reason: authz.ReasonEndpointInactive,
			mutate: sqlf(`UPDATE endpoints SET state='disabled' WHERE slug='local'`)},
		{id: "RESTORE-endpoint-stale-authority-generation", status: 403, reason: authz.ReasonEndpointInactive,
			mutate: sqlf(`UPDATE endpoints SET authority_generation=2 WHERE slug='local'`)},
		{id: "SELF-01-endpoint-without-backend", status: 403, reason: authz.ReasonSafetyUnverified, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.EndpointID = otherEP }},
		{id: "SELF-05-backend-lost-continuity", status: 403, reason: authz.ReasonSafetyUnverified,
			mutate: func(e *env, _ string, _ docker.Operation) { e.mock.SimulateEventDiscontinuity() }},
		{id: "SELF-09-backend-safety-invalidated", status: 403, reason: authz.ReasonSafetyUnverified,
			mutate: func(e *env, _ string, _ docker.Operation) { e.mock.InvalidateSafety() }},
		{id: "SELF-13-backend-removed", status: 403, reason: authz.ReasonSafetyUnverified, zeroTotal: true,
			mutate: func(e *env, _ string, _ docker.Operation) { e.az.RemoveBackend(localEP) }},

		// --- self / protected targets (403) ---
		{id: "SELF-04-self-by-name", status: 403, reason: authz.ReasonSelfProtected,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "mandatary-self" }},
		{id: "SELF-04-self-by-full-id", status: 403, reason: authz.ReasonSelfProtected,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = string(docker.MockSelfContainerID) }},
		{id: "SELF-04-wildcard-allow-cannot-reach-self", status: 403, reason: authz.ReasonSelfProtected,
			mutate: func(e *env, who string, _ docker.Operation) {
				const wild = "60000000-0000-4000-8000-0000000000aa"
				e.seedSelector(wild, "*", true, localEP)
				col, id := ownSubject(who)
				e.allowAll(col, id, wild)
			},
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "mandatary-self" }},
		{id: "SELF-08-peer-by-name", status: 403, reason: authz.ReasonSelfProtected,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "mandatary-peer-stopped" }},
		{id: "SELF-08-peer-by-full-id", status: 403, reason: authz.ReasonSelfProtected,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = string(docker.MockPeerContainerID) }},
		{id: "TD7-target-missing", status: 403, reason: authz.ReasonTargetMissing,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "ghost-container" }},
		{id: "TD7-target-removed-after-grant", status: 403, reason: authz.ReasonTargetMissing,
			mutate: func(e *env, _ string, _ docker.Operation) { e.mock.RemoveContainer(edgeID) }},

		// --- policy: default deny, explicit deny, caps (403) ---
		{id: "AZ-no-policy-default-deny", who: human, status: 403, reason: authz.ReasonDefaultDeny,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Credentials = bobCreds() }},
		{id: "AZ-explicit-deny-overrides-allow", status: 403, reason: authz.ReasonExplicitDeny,
			mutate: func(e *env, who string, _ docker.Operation) {
				col, id := ownSubject(who)
				for _, op := range ops.Operations() {
					e.policy(col, id, selEdge, "DENY", op, nil, nil)
				}
			}},
		{id: "AZ-group-deny-overrides-direct-allow", status: 403, reason: authz.ReasonExplicitDeny,
			mutate: func(e *env, who string, _ docker.Operation) {
				e.exec(`INSERT INTO groups (id, name, state, authority_generation) VALUES (?, 'deniers', 'active', 1)`, groupID)
				if who == "human" {
					e.exec(`INSERT INTO user_group_memberships (user_id, group_id, state, authority_generation) VALUES (?, ?, 'active', 1)`, aliceID, groupID)
				} else {
					e.exec(`INSERT INTO agent_group_memberships (agent_id, group_id, state, authority_generation) VALUES (?, ?, 'active', 1)`, botID, groupID)
				}
				for _, op := range ops.Operations() {
					e.policy("group_id", groupID, selEdge, "DENY", op, nil, nil)
				}
			}},
		{id: "AZ-allow-for-other-operations-only", status: 403, reason: authz.ReasonDefaultDeny, perOp: true,
			mutate: func(e *env, who string, op docker.Operation) {
				col, id := ownSubject(who)
				e.exec(`DELETE FROM policies WHERE `+col+`=? AND operation=?`, id, string(op))
			}},
		{id: "AZ-allow-for-other-container-only", status: 403, reason: authz.ReasonDefaultDeny,
			mutate: func(e *env, _ string, _ docker.Operation) {
				e.seedSelector(selOther, "billing-worker", false, localEP)
				e.exec(`UPDATE policies SET selector_id=? WHERE selector_id=?`, selOther, selEdge)
			}},
		{id: "RESTORE-03-quarantined-allow-grants-nothing", status: 403, reason: authz.ReasonDefaultDeny,
			mutate: sqlf(`UPDATE policies SET state='quarantined'`)},
		{id: "RESTORE-stale-policy-authority-generation", status: 403, reason: authz.ReasonDefaultDeny,
			mutate: sqlf(`UPDATE policies SET authority_generation=2`)},
		{id: "AZ-agent-owner-grant-not-inherited", who: agent, status: 403, reason: authz.ReasonDefaultDeny,
			mutate: func(e *env, _ string, _ docker.Operation) { e.exec(`DELETE FROM policies WHERE agent_id=?`, botID) }},
		{id: "AZ-administrator-role-grants-no-operation", who: human, status: 403, reason: authz.ReasonDefaultDeny,
			mutate: sqlf(`INSERT INTO administrative_roles (id, user_id, role, state, authority_generation) VALUES ('adm-1', '` + bobID + `', 'super_admin', 'active', 1)`),
			shape:  func(r *ops.Request, _ string, _ docker.Operation) { r.Credentials = bobCreds() }},
		{id: "AZ-log-tail-cap-exceeded", only: logs, status: 403, reason: authz.ReasonParameterCapExceeded,
			mutate: func(e *env, who string, _ docker.Operation) {
				col, id := ownSubject(who)
				e.exec(`UPDATE policies SET log_tail_max=3 WHERE `+col+`=? AND operation='container:logs'`, id)
			}},
		{id: "AZ-stop-timeout-cap-exceeded", only: timed, status: 403, reason: authz.ReasonParameterCapExceeded,
			mutate: func(e *env, who string, _ docker.Operation) {
				col, id := ownSubject(who)
				e.exec(`UPDATE policies SET stop_timeout_max=3 WHERE `+col+`=? AND operation IN ('container:stop','container:restart')`, id)
			}},

		// --- malformed input: rejected before ANY backend call ---
		{id: "MAL-endpoint-id-empty", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.EndpointID = "" }},
		{id: "MAL-endpoint-id-slug", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.EndpointID = "local" }},
		{id: "MAL-endpoint-id-traversal", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.EndpointID = "../local" }},
		{id: "MAL-target-empty", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "" }},
		{id: "MAL-target-whitespace-only", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = " \t" }},
		{id: "MAL-target-too-long", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = strings.Repeat("a", 4096) }},
		{id: "MAL-target-path-traversal", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge-proxy/../../images/json" }},
		{id: "MAL-target-query-injection", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge-proxy?all=1&v=1" }},
		{id: "MAL-target-sub-resource", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge-proxy/exec" }},
		{id: "MAL-target-nul-byte", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge-proxy\x00" }},
		{id: "MAL-target-newline-header-injection", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge-proxy\nHost: x" }},
		{id: "MAL-target-percent-encoding", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "%2e%2e%2fedge-proxy" }},
		{id: "MAL-target-wildcard", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "*" }},
		{id: "MAL-target-trailing-space", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge-proxy " }},
		{id: "MAL-target-unicode-lookalike", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Target = "edge\u2011proxy" }},
		{id: "MAL-foreign-option-block-for-operation", invalid: true, zeroTotal: true,
			shape: func(r *ops.Request, _ string, op docker.Operation) {
				r.Logs, r.Stop, r.Restart = nil, nil, nil
				if op == docker.OpLogs {
					r.Stop = &docker.StopOptions{TimeoutSeconds: five()}
				} else {
					r.Logs = &docker.LogOptions{Tail: 5, Stdout: true}
				}
			}},
		{id: "MAL-stop-block-on-restart-and-restart-block-on-stop", invalid: true, zeroTotal: true, only: timed,
			shape: func(r *ops.Request, _ string, op docker.Operation) {
				r.Logs, r.Stop, r.Restart = nil, nil, nil
				if op == docker.OpStop {
					r.Restart = &docker.RestartOptions{TimeoutSeconds: five()}
				} else {
					r.Stop = &docker.StopOptions{TimeoutSeconds: five()}
				}
			}},
		{id: "MAL-log-tail-above-bound", invalid: true, zeroTotal: true, only: logs,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Logs = &docker.LogOptions{Tail: 10001, Stdout: true}
			}},
		{id: "MAL-log-tail-negative", invalid: true, zeroTotal: true, only: logs,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Logs = &docker.LogOptions{Tail: -1, Stdout: true}
			}},
		{id: "MAL-log-tail-all", invalid: true, zeroTotal: true, only: logs,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				r.Logs = &docker.LogOptions{TailAll: true, Stdout: true}
			}},
		{id: "MAL-log-no-stream-selected", invalid: true, zeroTotal: true, only: logs,
			shape: func(r *ops.Request, _ string, _ docker.Operation) { r.Logs = &docker.LogOptions{Tail: 5} }},
		{id: "MAL-log-since-after-until", invalid: true, zeroTotal: true, only: logs,
			shape: func(r *ops.Request, _ string, _ docker.Operation) {
				now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
				r.Logs = &docker.LogOptions{Tail: 5, Stdout: true, Since: now, Until: now.Add(-time.Hour)}
			}},
		{id: "MAL-timeout-zero", invalid: true, zeroTotal: true, only: timed,
			shape: func(r *ops.Request, _ string, op docker.Operation) { setTimeout(r, op, 0) }},
		{id: "MAL-timeout-negative", invalid: true, zeroTotal: true, only: timed,
			shape: func(r *ops.Request, _ string, op docker.Operation) { setTimeout(r, op, -1) }},
		{id: "MAL-timeout-above-300", invalid: true, zeroTotal: true, only: timed,
			shape: func(r *ops.Request, _ string, op docker.Operation) { setTimeout(r, op, 301) }},
		{id: "MAL-timeout-int-max", invalid: true, zeroTotal: true, only: timed,
			shape: func(r *ops.Request, _ string, op docker.Operation) { setTimeout(r, op, math.MaxInt) }},

		// --- caller context ---
		{id: "CTX-canceled-before-call", ctxErr: true, zeroTotal: true},
	}
}

func setTimeout(r *ops.Request, op docker.Operation, v int) {
	r.Logs, r.Stop, r.Restart = nil, nil, nil
	if op == docker.OpRestart {
		r.Restart = &docker.RestartOptions{TimeoutSeconds: &v}
		return
	}
	r.Stop = &docker.StopOptions{TimeoutSeconds: &v}
}

func revokeSession(e *env, id string) {
	e.exec(`UPDATE sessions SET state='revoked', revoked_at=max(created_at, ?) WHERE id=?`, e.clock.Now().Unix(), id)
}

func revokeCredential(e *env) {
	e.exec(`UPDATE agent_credentials SET state='revoked', revoked_at=? WHERE id=?`, e.clock.Now().Unix(), botCredID)
}

type cell struct {
	op     docker.Operation
	follow bool
}

func (c cell) String() string {
	if c.follow {
		return string(c.op) + "+follow"
	}
	return string(c.op)
}

func cellsFor(c denyCase) []cell {
	var out []cell
	for _, op := range ops.Operations() {
		if !c.applies(op) {
			continue
		}
		out = append(out, cell{op: op})
		if op == docker.OpLogs {
			out = append(out, cell{op: op, follow: true})
		}
	}
	return out
}

func TestDenyMatrixCausesZeroOperationalBackendAttemptsForEveryPermissionKey(t *testing.T) {
	cases := denyCases()
	if len(cases) < 60 {
		t.Fatalf("deny matrix shrank to %d cases", len(cases))
	}
	for _, c := range cases {
		for _, who := range c.kinds() {
			t.Run(c.id+"/"+who, func(t *testing.T) {
				t.Parallel()
				if c.perOp {
					for _, cl := range cellsFor(c) {
						runDenyCells(t, c, who, []cell{cl})
					}
					return
				}
				runDenyCells(t, c, who, cellsFor(c))
			})
		}
	}
}

// runDenyCells prepares ONE environment, proves every cell is allowed there
// (control), applies the adverse change once, then proves every cell is denied.
func runDenyCells(t *testing.T, c denyCase, who string, cells []cell) {
	t.Helper()
	e := newEnv(t)
	build := func(cl cell) ops.Request {
		r := req(credsFor(who), "edge-proxy", cl.op)
		if cl.follow {
			r.Logs.Follow = true
		}
		return r
	}
	for _, cl := range cells {
		ctl, err := e.svc.Execute(t.Context(), build(cl))
		if err != nil {
			t.Fatalf("%s %s: control request failed before the adverse change: %v", c.id, cl, err)
		}
		if ctl.Logs != nil {
			_ = ctl.Logs.Close()
		}
	}
	if c.mutate != nil {
		c.mutate(e, who, cells[0].op)
	}
	opBefore := len(e.spy.operationalCalls())
	totalBefore := e.spy.total()
	watchersBefore := e.tickerCount()

	for _, cl := range cells {
		r := build(cl)
		if c.shape != nil {
			c.shape(&r, who, cl.op)
		}
		ctx := t.Context()
		if c.ctxErr {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		res, err := e.svc.Execute(ctx, r)
		if res.Logs != nil {
			_ = res.Logs.Close()
			t.Fatalf("%s %s: a log stream was returned on a denial", c.id, cl)
		}
		if err == nil {
			t.Fatalf("%s %s: expected a denial, the request was allowed", c.id, cl)
		}
		if res.Status != nil || res.Config != nil {
			t.Fatalf("%s %s: data returned alongside error %v", c.id, cl, err)
		}
		switch {
		case c.invalid:
			if !errors.Is(err, ops.ErrInvalidRequest) {
				t.Fatalf("%s %s: err = %v, want ErrInvalidRequest", c.id, cl, err)
			}
		case c.ctxErr:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s %s: err = %v, want context.Canceled", c.id, cl, err)
			}
		default:
			if got := authz.StatusCode(err); got != c.status {
				t.Fatalf("%s %s: status %d (%v), want %d", c.id, cl, got, err, c.status)
			}
			if (c.status == 401 && !errors.Is(err, authz.ErrUnauthenticated)) || (c.status == 403 && !errors.Is(err, authz.ErrForbidden)) {
				t.Fatalf("%s %s: %v is not the expected authz sentinel", c.id, cl, err)
			}
			if c.reason != "" && !authz.HasReason(err, c.reason) {
				got, _ := authz.ReasonOf(err)
				t.Fatalf("%s %s: reason %q, want %q", c.id, cl, got, c.reason)
			}
		}
	}
	// ACCEPTANCE: zero operational backend attempts across all denied cells.
	if got := e.spy.operationalCalls()[opBefore:]; len(got) != 0 {
		t.Fatalf("%s: %d operational backend attempts on denials: %v", c.id, len(got), got)
	}
	if c.zeroTotal {
		if got := e.spy.snapshot()[totalBefore:]; len(got) != 0 {
			t.Fatalf("%s: input rejected before authorization still reached the backend: %v", c.id, got)
		}
	}
	if n := e.az.ActiveLeaseCount(); n != 0 {
		t.Fatalf("%s: %d leases survived denials", c.id, n)
	}
	if n := e.tickerCount() - watchersBefore; n != 0 {
		t.Fatalf("%s: %d revalidation watchers started for denials", c.id, n)
	}
}

// The matrix must keep covering the families the C2 checkpoint reviewer named.
func TestDenyMatrixCoversTheNamedCheckpointFamilies(t *testing.T) {
	want := []string{"C2R-H", "C2R-E", "C2R-Q", "C2R-T", "C2R-B", "C2R-R", "SELF-", "RESTORE", "MAL-", "AZ-", "TD7-"}
	have := map[string]bool{}
	cells := 0
	for _, c := range denyCases() {
		for _, p := range want {
			if strings.HasPrefix(c.id, p) {
				have[p] = true
			}
		}
		cells += len(c.kinds()) * len(cellsFor(c))
	}
	for _, p := range want {
		if !have[p] {
			t.Errorf("deny matrix has no %s* case", p)
		}
	}
	t.Logf("deny matrix: %d cases, %d (case x principal x operation) cells", len(denyCases()), cells)
	if cells < 400 {
		t.Fatalf("only %d cells", cells)
	}
}
