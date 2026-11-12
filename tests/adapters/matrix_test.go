package adapters_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

// The six tools, by MCP name; the REST route of each is api.Specs().
var sixTools = []string{"container_status", "container_config", "container_logs", "container_start", "container_stop", "container_restart"}

func req(token, op, container string, args ...map[string]any) call {
	c := call{token: token, op: op, endpoint: "local", container: container}
	for _, a := range args {
		if c.args == nil {
			c.args = map[string]any{}
		}
		for k, v := range a {
			c.args[k] = v
		}
	}
	return c
}

func a(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func nothing(w want) want { w.reach = reachNothing; return w }

// ---- positive controls -------------------------------------------------------------------

func TestMatrixAllowedOperationsOnTheGrantedTargetOverBothTransports(t *testing.T) {
	e := newEnv(t)
	var cases []matrixCase
	for _, op := range sixTools {
		cases = append(cases, matrixCase{"granted/" + op + "/by-name", req(e.token("granted"), op, "edge-proxy"), ok()})
	}
	cases = append(cases,
		matrixCase{"granted/status/by-full-id", req(e.token("granted"), "container_status", string(edgeID)), ok()},
		matrixCase{"granted/status/by-endpoint-uuid", call{token: e.token("granted"), op: "container_status", endpoint: string(localEP), container: "edge-proxy"}, ok()},
		matrixCase{"granted/logs/tail2", req(e.token("granted"), "container_logs", "edge-proxy", a("tail", 2)), ok()},
		matrixCase{"granted/logs/stdout-only", req(e.token("granted"), "container_logs", "edge-proxy", a("tail", 5, "stdout", true, "stderr", false)), ok()},
		matrixCase{"granted/logs/timestamps-since-until", req(e.token("granted"), "container_logs", "edge-proxy", a("tail", 50, "timestamps", true, "since", "2000-01-01T00:00:00Z", "until", "2100-01-01T00:00:00Z")), ok()},
		matrixCase{"granted/stop/timeout", req(e.token("granted"), "container_stop", "edge-proxy", a("timeout_seconds", 5)), ok()},
		matrixCase{"granted/restart/timeout", req(e.token("granted"), "container_restart", "edge-proxy", a("timeout_seconds", 300)), ok()},
		matrixCase{"readonly/status", req(e.token("readonly"), "container_status", "edge-proxy"), ok()},
		matrixCase{"readonly/config", req(e.token("readonly"), "container_config", "edge-proxy"), ok()},
		matrixCase{"readonly/logs", req(e.token("readonly"), "container_logs", "edge-proxy", a("tail", 3)), ok()},
		matrixCase{"capped/logs-within-cap", req(e.token("capped"), "container_logs", "edge-proxy", a("tail", 5)), ok()},
		matrixCase{"capped/stop-within-cap", req(e.token("capped"), "container_stop", "edge-proxy", a("timeout_seconds", 20)), ok()},
		matrixCase{"capped/stop-default-timeout", req(e.token("capped"), "container_stop", "edge-proxy"), ok()},
		matrixCase{"overlapping-rotation-credential-is-still-accepted", req(e.token("overlapping"), "container_status", "edge-proxy"), ok()},
		matrixCase{"wildcard/status/billing-worker", req(e.token("wildcard"), "container_status", "billing-worker"), ok()},
		matrixCase{"wildcard/status/batch-migrator", req(e.token("wildcard"), "container_status", "batch-migrator"), ok()},
		matrixCase{"deny/status/ungranted-but-not-denied", req(e.token("deny"), "container_status", "batch-migrator"), ok()},
	)
	runMatrix(t, e, cases)
}

func TestSuccessPayloadsAreTheSanitizedAllowlistedStructures(t *testing.T) {
	e := newEnv(t)
	for _, tr := range transports {
		st := tr.do(t, e, req(e.token("granted"), "container_status", "edge-proxy"))
		if st.Status != 200 || st.Payload["name"] != "edge-proxy" || st.Payload["container_id"] != string(edgeID) || st.Payload["endpoint_id"] != string(localEP) {
			t.Fatalf("%s status: %s", tr.name(), st)
		}
		cfg := tr.do(t, e, req(e.token("granted"), "container_config", "edge-proxy"))
		if cfg.Status != 200 || cfg.Payload["name"] != "edge-proxy" {
			t.Fatalf("%s config: %s", tr.name(), cfg)
		}
		assertNoSecrets(t, tr.name(), cfg.String())
		logs := tr.do(t, e, req(e.token("granted"), "container_logs", "edge-proxy", a("tail", 3)))
		frames, _ := logs.Payload["frames"].([]any)
		if logs.Status != 200 || len(frames) == 0 || len(frames) > 3 || logs.Payload["truncated"] != false {
			t.Fatalf("%s logs: %s", tr.name(), logs)
		}
		for _, f := range frames {
			fm := f.(map[string]any)
			if (fm["stream"] != "stdout" && fm["stream"] != "stderr") || fm["text"] == "" || len(fm) != 2 {
				t.Fatalf("%s frame %v is not a labelled typed frame", tr.name(), f)
			}
		}
		act := tr.do(t, e, req(e.token("granted"), "container_stop", "edge-proxy", a("timeout_seconds", 5)))
		if act.Payload["operation"] != string(docker.OpStop) || act.Payload["outcome"] != "completed" || act.Payload["container_id"] != string(edgeID) {
			t.Fatalf("%s stop: %s", tr.name(), act)
		}
	}
}

// ---- authentication: 401, and nothing reaches Docker --------------------------------------

func TestMatrixUnauthenticatedExpiredRevokedAndRestoredCredentialsAreRefusedBeforeAnyTarget(t *testing.T) {
	e := newEnv(t)
	e.clock.Advance(2 * time.Minute) // the 90-second credential has now expired
	sessionSecret := "session-secret-0123456789abcdef0123456789abcdef-" + aliceSess
	hdr := func(k string, v ...string) http.Header { return http.Header{k: v} }
	variants := []struct {
		name string
		c    call
	}{
		{"no-authorization-header", call{noAuth: true}},
		{"empty-bearer", call{headers: hdr("Authorization", "Bearer ")}},
		{"basic-with-token-as-password", call{headers: hdr("Authorization", "Basic dXNlcjpwYXNz")}},
		{"token-scheme", call{headers: hdr("Authorization", "Token "+e.token("granted"))}},
		{"raw-token-without-scheme", call{headers: hdr("Authorization", e.token("granted"))}},
		{"two-authorization-headers", call{headers: hdr("Authorization", "Bearer "+e.token("granted"), "Bearer "+e.token("granted"))}},
		{"wrong-prefix", call{token: "mdx_" + e.token("granted")[4:]}},
		{"truncated-token", call{token: e.token("granted")[:20]}},
		{"jwt-like-oauth-access-token", call{token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJl"}},
		{"human-session-secret-as-bearer", call{token: sessionSecret}},
		{"human-session-id-as-bearer", call{token: aliceSess}},
		{"setup-or-recovery-capability-as-bearer", call{token: strings.Repeat("S", 43)}},
		{"session-cookie-only", call{noAuth: true, headers: hdr("Cookie", "mandatary_session="+sessionSecret+"; csrf="+sessionSecret)}},
		{"agent-token-in-cookie-only", call{noAuth: true, headers: hdr("Cookie", "token="+e.token("granted"))}},
		{"agent-token-in-custom-header-only", call{noAuth: true, headers: hdr("X-Api-Key", e.token("granted"))}},
		{"caller-asserted-admin-and-aal2", call{noAuth: true, headers: http.Header{"X-Mandatary-Admin": {"true"}, "X-Assurance": {"2"}, "X-User": {"admin"}}}},
		{"unknown-well-formed-token", call{token: canonToken("nobody-has-this")}},
		{"expired-token", call{token: e.token("short")}},
		{"revoked-token", call{token: e.token("revoked")}},
		{"rotated-out-token-after-overlap", call{token: e.token("rotatedout")}},
		{"restore-imported-quarantined-credential", call{token: e.token("importedquarantined")}},
		{"disabled-agent", call{token: e.token("disabledagent")}},
		{"stale-credential-generation", call{token: e.token("stalegen")}},
	}
	var cases []matrixCase
	for _, v := range variants {
		for _, target := range []string{"edge-proxy", "mandatary-self", string(docker.MockSelfContainerID), "no-such-container"} {
			c := v.c
			c.op, c.endpoint, c.container = "container_status", "local", target
			cases = append(cases, matrixCase{"401/" + v.name + "/" + target, c, unauth()})
		}
	}
	// Positive controls in the same world: the credential classes next to the refused ones work.
	cases = append(cases,
		matrixCase{"control/granted", req(e.token("granted"), "container_status", "edge-proxy"), ok()},
		matrixCase{"control/overlapping", req(e.token("overlapping"), "container_status", "edge-proxy"), ok()},
	)
	runMatrix(t, e, cases)
}

func TestMatrixRestoreQuarantineDeniesEveryCredentialUntilReapprovalAndRevocationsStayRevoked(t *testing.T) {
	e := newEnv(t)
	e.exec(`UPDATE installation_control SET restore_quarantined=1 WHERE singleton=1`)
	restoreDenied := nothing(denied(api.ReasonRestoreQuarantined)) // refused at the authentication gate: no lookup either
	var cases []matrixCase
	for _, key := range []string{"granted", "wildcard", "nogrant", "adminowned", "overlapping"} {
		for _, op := range sixTools {
			cases = append(cases, matrixCase{"quarantine/" + key + "/" + op, req(e.token(key), op, "edge-proxy"), restoreDenied})
		}
	}
	cases = append(cases,
		matrixCase{"quarantine/unknown-well-formed-token", req(canonToken("nobody-has-this"), "container_status", "edge-proxy"), restoreDenied},
		matrixCase{"quarantine/revoked-token", req(e.token("revoked"), "container_status", "edge-proxy"), restoreDenied},
		matrixCase{"quarantine/no-header-is-401", call{noAuth: true, op: "container_status", endpoint: "local", container: "edge-proxy"}, unauth()},
		matrixCase{"quarantine/protected-target", req(e.token("wildcard"), "container_status", "mandatary-self"), restoreDenied},
	)
	runMatrix(t, e, cases)

	// Clearing quarantine does not resurrect anything that was revoked, imported-inactive or stale.
	e.exec(`UPDATE installation_control SET restore_quarantined=0 WHERE singleton=1`)
	runMatrix(t, e, []matrixCase{
		{"after-quarantine/granted-works-again", req(e.token("granted"), "container_status", "edge-proxy"), ok()},
		{"after-quarantine/revoked-stays-revoked", req(e.token("revoked"), "container_status", "edge-proxy"), unauth()},
		{"after-quarantine/imported-inactive-stays-inactive", req(e.token("importedquarantined"), "container_status", "edge-proxy"), unauth()},
	})
}

func TestMatrixRestoredInstallationOldCredentialsFailAndNewOnesNeedNewlyApprovedRules(t *testing.T) {
	e := newEnv(t)
	oldTok := e.token("granted")
	runMatrix(t, e, []matrixCase{{"before-restore/old-token-works", req(oldTok, "container_status", "edge-proxy"), ok()}})

	// A restore bumps the credential and authority generations (RESTORE-01/02): nothing issued
	// before it is accepted, including non-expiring tokens and every previously approved rule.
	e.exec(`UPDATE installation_control SET credential_generation=2, authority_generation=2, restore_generation=2 WHERE singleton=1`)
	e.exec(`UPDATE endpoints SET authority_generation=2 WHERE slug='local'`)
	var old []matrixCase
	for _, key := range []string{"granted", "wildcard", "readonly", "overlapping"} {
		old = append(old, matrixCase{"after-restore/old/" + key, req(e.token(key), "container_status", "edge-proxy"), unauth()})
	}
	runMatrix(t, e, old)

	// A freshly issued credential (new generation) holds NO authority until a rule is newly approved.
	e.exec(`INSERT INTO agents (id, name, owner_user_id, state, credential_generation, authority_generation) VALUES ('40000000-0000-4000-8000-0000000000a1', 'reissued', ?, 'active', 2, 2)`, ownerID)
	fresh := canonToken("reissued")
	e.exec(`INSERT INTO agent_credentials (id, agent_id, token_hash, display_prefix, issued_at, expires_at, nonexpiring_approved, credential_generation, state)
		VALUES ('50000000-0000-4000-8000-0000000000a1', '40000000-0000-4000-8000-0000000000a1', ?, 'mdt_test1234', ?, ?, 0, 2, 'active')`,
		sha(fresh), e.clock.Now().Unix()-60, e.clock.Now().Unix()+3600)
	runMatrix(t, e, []matrixCase{
		{"after-restore/reissued-without-rules/status", req(fresh, "container_status", "edge-proxy"), denied(api.ReasonDefaultDeny)},
		{"after-restore/reissued-without-rules/stop", req(fresh, "container_stop", "edge-proxy"), denied(api.ReasonDefaultDeny)},
	})
	// The pre-restore rules (generation 1) stay inactive even for the new agent...
	e.exec(`INSERT INTO policies (id, agent_id, endpoint_id, selector_id, operation, effect, state, authority_generation) VALUES ('70000000-0000-4000-8000-0000000000a0', '40000000-0000-4000-8000-0000000000a1', ?, ?, 'container:inspect_status', 'ALLOW', 'active', 1)`, string(localEP), selEdge)
	runMatrix(t, e, []matrixCase{{"after-restore/stale-generation-rule-grants-nothing", req(fresh, "container_status", "edge-proxy"), denied(api.ReasonDefaultDeny)}})
	// ...and only a rule approved at the new generation grants, and only what it says.
	e.exec(`INSERT INTO policies (id, agent_id, endpoint_id, selector_id, operation, effect, state, authority_generation) VALUES ('70000000-0000-4000-8000-0000000000a2', '40000000-0000-4000-8000-0000000000a1', ?, ?, 'container:inspect_status', 'ALLOW', 'active', 2)`, string(localEP), selEdge)
	runMatrix(t, e, []matrixCase{
		{"after-restore/reapproved-rule-grants-exactly-its-operation", req(fresh, "container_status", "edge-proxy"), ok()},
		{"after-restore/reapproved-rule-does-not-grant-others", req(fresh, "container_config", "edge-proxy"), denied(api.ReasonDefaultDeny)},
		{"after-restore/reapproved-rule-does-not-grant-other-targets", req(fresh, "container_status", "billing-worker"), denied(api.ReasonDefaultDeny)},
	})
}

// ---- authorization: 403, zero operational calls --------------------------------------------

func TestMatrixAuthorizationDenialsCrossContainerAdminRoleDenyOverridesAndCaps(t *testing.T) {
	e := newEnv(t)
	dd := denied(api.ReasonDefaultDeny)
	var cases []matrixCase
	for _, op := range sixTools {
		cases = append(cases,
			matrixCase{"nogrant/" + op, req(e.token("nogrant"), op, "edge-proxy"), dd},
			// The agent is OWNED by the administrator: the role and ownership grant no Docker operation.
			matrixCase{"admin-owned-agent/" + op, req(e.token("adminowned"), op, "edge-proxy"), dd},
			// Cross-container: the grant is edge-proxy only.
			matrixCase{"cross-container/billing-worker/" + op, req(e.token("granted"), op, "billing-worker"), dd},
			matrixCase{"cross-container/batch-migrator/" + op, req(e.token("granted"), op, "batch-migrator"), dd},
			matrixCase{"nonexistent-target/" + op, req(e.token("granted"), op, "no-such-container"), dd}, // indistinguishable from ungranted
			// Explicit deny overrides a wildcard allow.
			matrixCase{"deny-overrides-allow/" + op, req(e.token("deny"), op, "billing-worker"), dd},
		)
	}
	for _, op := range []string{"container_start", "container_stop", "container_restart"} {
		cases = append(cases,
			matrixCase{"readonly-agent/" + op, req(e.token("readonly"), op, "edge-proxy"), dd},
			matrixCase{"capped-agent-without-start/" + op + "-of-an-ungranted-operation", req(e.token("capped"), "container_start", "edge-proxy"), dd},
		)
	}
	cases = append(cases,
		// Cross-endpoint and unknown endpoint: never matched to another endpoint's container.
		matrixCase{"cross-endpoint/other-backend", call{token: e.token("wildcard"), op: "container_status", endpoint: string(otherEP), container: "edge-proxy"}, denied(api.ReasonEndpointInactive)},
		matrixCase{"cross-endpoint/no-backend", call{token: e.token("wildcard"), op: "container_status", endpoint: "00000000-0000-4000-8000-0000000000ff", container: "edge-proxy"}, nothing(denied(api.ReasonSafetyUnverified))},
		// Policy parameter caps.
		matrixCase{"cap/logs-over-tail-cap", req(e.token("capped"), "container_logs", "edge-proxy", a("tail", 6)), denied(api.ReasonCapExceeded)},
		matrixCase{"cap/logs-default-tail-exceeds-cap", req(e.token("capped"), "container_logs", "edge-proxy"), denied(api.ReasonCapExceeded)},
		matrixCase{"cap/stop-over-timeout-cap", req(e.token("capped"), "container_stop", "edge-proxy", a("timeout_seconds", 21)), denied(api.ReasonCapExceeded)},
		matrixCase{"cap/restart-over-timeout-cap", req(e.token("capped"), "container_restart", "edge-proxy", a("timeout_seconds", 300)), denied(api.ReasonCapExceeded)},
	)
	runMatrix(t, e, cases)
}

// SELF-10: the protected set is unreachable through REST and a real MCP client even with a
// wildcard allow and every operation; hidden tools and alternate routes do not exist.
func TestMatrixSELF10SelfAndPeerTargetsAreDeniedOnEveryOperationEvenWithAWildcardAllow(t *testing.T) {
	e := newEnv(t)
	protected := []string{
		"mandatary-self", string(docker.MockSelfContainerID), // self by name and by immutable ID
		"mandatary-peer-stopped", string(docker.MockPeerContainerID), // a stopped labelled peer
		"reverse-proxy", string(rogueID), // an innocuously named labelled peer
	}
	var cases []matrixCase
	for _, key := range []string{"wildcard", "granted", "adminowned"} {
		for _, target := range protected {
			for _, op := range sixTools {
				cases = append(cases, matrixCase{fmt.Sprintf("SELF-10/%s/%s/%s", key, target, op), req(e.token(key), op, target), denied(api.ReasonDefaultDeny)})
			}
		}
	}
	// Control: the same wildcard agent works on the ordinary targets in the same world.
	for _, op := range sixTools {
		cases = append(cases, matrixCase{"SELF-10/control/" + op, req(e.token("wildcard"), op, "cache-redis"), ok()})
	}
	runMatrix(t, e, cases)
}

// SELF-01/02/03/05/07/13 through the adapters: no or conflicting identity, or lost event
// continuity, closes the whole Docker-backed surface for every principal and every
// operation; readiness reports it; only fresh verification reopens it.
func TestMatrixSELFSafetyStateClosesTheSurfaceAndReadinessReportsIt(t *testing.T) {
	denyAll := func(prefix string, e *env) []matrixCase {
		var cases []matrixCase
		for _, key := range []string{"wildcard", "granted"} {
			for _, op := range sixTools {
				cases = append(cases,
					matrixCase{prefix + "/" + key + "/" + op + "/ordinary", req(e.token(key), op, "edge-proxy"), nothing(denied(api.ReasonSafetyUnverified))},
					matrixCase{prefix + "/" + key + "/" + op + "/self", req(e.token(key), op, "mandatary-self"), nothing(denied(api.ReasonSafetyUnverified))},
				)
			}
		}
		return cases
	}
	e := newEnv(t)
	runMatrix(t, e, []matrixCase{{"SELF/verified-control", req(e.token("wildcard"), "container_status", "edge-proxy"), ok()}})
	if code, ready := readyz(t, e); code != 200 || !ready {
		t.Fatalf("readyz = %d %v while verified", code, ready)
	}

	// SELF-07: lose event continuity after the daemon was verified.
	e.mock.SimulateEventDiscontinuity()
	runMatrix(t, e, denyAll("SELF-07", e))
	if code, ready := readyz(t, e); code != 503 || ready {
		t.Fatalf("readyz = %d %v after continuity loss", code, ready)
	}
	// Re-verification (fresh evidence) reopens it.
	if err := e.mock.VerifySelf(t.Context()); err != nil {
		t.Fatal(err)
	}
	runMatrix(t, e, []matrixCase{{"SELF-07/reverified", req(e.token("wildcard"), "container_status", "edge-proxy"), ok()}})

	// SELF-01/02: no runtime evidence, and an explicit ID that conflicts with the runtime ID.
	for name, ident := range map[string]docker.SelfIdentityConfig{
		"SELF-01-no-evidence": {EndpointID: localEP, EvidenceReader: func(_ context.Context) (docker.ProcessEvidence, error) { return docker.ProcessEvidence{}, nil }},
		"SELF-02-conflicting-explicit-id": {EndpointID: localEP, ExplicitContainerID: string(edgeID),
			EvidenceReader: func(_ context.Context) (docker.ProcessEvidence, error) {
				return docker.ProcessEvidence{ContainerID: string(docker.MockSelfContainerID)}, nil
			}},
	} {
		e2 := newEnv(t)
		_, containers := docker.DefaultMockFixtures(localEP)
		b, err := docker.NewMockBackend(docker.MockOptions{EndpointID: localEP, Identity: ident, Containers: containers})
		if err != nil {
			t.Fatal(err)
		}
		if err = b.VerifySelf(t.Context()); err == nil {
			t.Fatalf("%s: VerifySelf accepted", name)
		}
		bad := &spy{MockBackend: b}
		if err = e2.az.RegisterBackend(localEP, bad); err != nil {
			t.Fatal(err)
		}
		e2.spy = bad
		runMatrix(t, e2, denyAll(name, e2))
		if code, ready := readyz(t, e2); code != 503 || ready {
			t.Fatalf("%s: readyz = %d %v", name, code, ready)
		}
		if n := len(bad.operationalCalls()); n != 0 {
			t.Fatalf("%s: %d operational calls", name, n)
		}
	}
}

// ---- strict schema: 400, nothing reaches Docker ---------------------------------------------

func TestMatrixStrictSchemasRefuseMalformedUnknownAndPassthroughInputOnBothTransports(t *testing.T) {
	e := newEnv(t)
	tok := e.token("granted")
	var cases []matrixCase
	add := func(id string, c call) { cases = append(cases, matrixCase{"400/" + id, c, invalid()}) }

	for _, name := range []string{"/edge-proxy", "/mandatary-self", "a b", "a;b", "a$(id)", "x/../y", "-leading-dash", ".hidden", "..", "tab\there", "new\nline", "caf\u00e9", "\U0001F600", "a:b", "a*b", "a?b", "a#b", "a%b", strings.Repeat("a", 256), "a\\b", "a\x7fb"} {
		for _, op := range []string{"container_status", "container_start"} {
			add(fmt.Sprintf("container/%q/%s", name, op), req(tok, op, name))
		}
	}
	for _, ep := range []string{"remote", "LOCAL", "local ", "0000", "gggggggg-0000-4000-8000-000000000001", strings.Repeat("a", 65)} {
		add("endpoint/"+ep, call{token: tok, op: "container_status", endpoint: ep, container: "edge-proxy"})
	}
	// Passthrough attempts: any Docker-style option, on every operation.
	for _, key := range []string{"all", "force", "v", "size", "signal", "t", "details", "path", "query", "raw", "method", "url", "host", "filters", "api_version", "socket", "container_id", "name", "command", "cmd", "env", "privileged", "tail_all", "TAIL", "Tail"} {
		for _, op := range sixTools {
			add(fmt.Sprintf("unknown-field/%s/%s", key, op), req(tok, op, "edge-proxy", a(key, "1")))
		}
	}
	add("logs/tail=all", req(tok, "container_logs", "edge-proxy", a("tail", "all")))
	add("logs/tail=0", req(tok, "container_logs", "edge-proxy", a("tail", 0)))
	add("logs/tail=-1", req(tok, "container_logs", "edge-proxy", a("tail", -1)))
	add("logs/tail=10001", req(tok, "container_logs", "edge-proxy", a("tail", 10001)))
	add("logs/tail=1.5", req(tok, "container_logs", "edge-proxy", a("tail", 1.5)))
	add("logs/tail=abc", req(tok, "container_logs", "edge-proxy", a("tail", "abc")))
	add("logs/stdout=maybe", req(tok, "container_logs", "edge-proxy", a("stdout", "maybe")))
	add("logs/no-stream-selected", req(tok, "container_logs", "edge-proxy", a("tail", 5, "stdout", false, "stderr", false)))
	add("logs/since=yesterday", req(tok, "container_logs", "edge-proxy", a("since", "yesterday")))
	add("logs/since-after-until", req(tok, "container_logs", "edge-proxy", a("since", "2026-02-01T00:00:00Z", "until", "2026-01-01T00:00:00Z")))
	add("logs/timestamps=2", req(tok, "container_logs", "edge-proxy", a("timestamps", "2")))
	for _, op := range []string{"container_stop", "container_restart"} {
		add(op+"/timeout=0", req(tok, op, "edge-proxy", a("timeout_seconds", 0)))
		add(op+"/timeout=301", req(tok, op, "edge-proxy", a("timeout_seconds", 301)))
		add(op+"/timeout=-1", req(tok, op, "edge-proxy", a("timeout_seconds", -1)))
		add(op+"/timeout=abc", req(tok, op, "edge-proxy", a("timeout_seconds", "abc")))
		add(op+"/timeout=2.5", req(tok, op, "edge-proxy", a("timeout_seconds", 2.5)))
	}
	// Parameters of another operation never ride along.
	add("status/with-tail", req(tok, "container_status", "edge-proxy", a("tail", 5)))
	add("logs/with-timeout", req(tok, "container_logs", "edge-proxy", a("timeout_seconds", 5)))
	add("start/with-timeout", req(tok, "container_start", "edge-proxy", a("timeout_seconds", 5)))
	add("stop/with-tail", req(tok, "container_stop", "edge-proxy", a("tail", 5)))
	runMatrix(t, e, cases)
}

// ---- unsupported operations, discovery, alternate routes: 404, nothing reaches Docker --------

func TestMatrixUnsupportedExecDiscoveryAndRawOperationsDoNotExist(t *testing.T) {
	e := newEnv(t)
	var cases []matrixCase
	for _, key := range []string{"granted", "wildcard", "adminowned"} {
		for _, name := range []string{"container_exec", "exec", "container_list", "list_containers", "containers", "discover", "container_discover", "request_container_access",
			"docker_api", "docker", "raw", "container_remove", "container_kill", "container_pause", "container_top", "container_rename", "system_info", "container_inspect"} {
			cases = append(cases, matrixCase{"unsupported/" + key + "/" + name, call{token: e.token(key), op: name, endpoint: "local", container: "edge-proxy", args: a("cmd", "id")}, notFound()})
		}
	}
	runMatrix(t, e, cases)
}
