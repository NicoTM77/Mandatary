package ops_test

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/ops"
)

var sixKeys = []docker.Operation{
	"container:logs", "container:inspect_status", "container:inspect_config",
	"container:start", "container:stop", "container:restart",
}

// P113-CAT-01: exactly the six approved permission keys (two inspect variants).
func TestOperationCatalogIsExactlyTheSixApprovedKeys(t *testing.T) {
	got := append([]docker.Operation(nil), ops.Operations()...)
	want := append([]docker.Operation(nil), sixKeys...)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog %v, want exactly %v", got, want)
	}
	// Mutating the returned slice must not widen the catalog.
	ops.Operations()[0] = "container:exec"
	if reflect.DeepEqual(ops.Operations()[0], docker.Operation("container:exec")) {
		t.Fatal("catalog is shared mutable state")
	}
}

// P113-CAT-02: unsupported operations are ABSENT from the service surface, not
// merely denied: the exported API is one Execute entry point plus the revocation
// push, and a Request has no raw Docker path/query/method/body field.
func TestServiceSurfaceHasNoUnsupportedOrRawForwardingEntryPoint(t *testing.T) {
	var methods []string
	svc := reflect.TypeOf(&ops.Service{})
	for i := 0; i < svc.NumMethod(); i++ {
		methods = append(methods, svc.Method(i).Name)
	}
	sort.Strings(methods)
	if want := []string{"Execute", "NotifyAuthorityChange"}; !reflect.DeepEqual(methods, want) {
		t.Fatalf("Service exported methods %v, want %v", methods, want)
	}
	var fields []string
	rt := reflect.TypeOf(ops.Request{})
	for i := 0; i < rt.NumField(); i++ {
		fields = append(fields, rt.Field(i).Name)
	}
	sort.Strings(fields)
	want := []string{"Credentials", "EndpointID", "Logs", "Operation", "Restart", "Stop", "Target"}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("Request fields %v, want %v (no raw path/query/method/body)", fields, want)
	}
	var streamMethods []string
	st := reflect.TypeOf(&ops.LogStream{})
	for i := 0; i < st.NumMethod(); i++ {
		streamMethods = append(streamMethods, st.Method(i).Name)
	}
	sort.Strings(streamMethods)
	// No Read(): the stream yields typed frames, never a raw byte pipe.
	for _, m := range streamMethods {
		if m == "Read" || m == "Write" {
			t.Fatalf("LogStream exposes raw I/O method %s", m)
		}
	}
}

// P113-CAT-03: forged, unsupported or lookalike operation keys never reach the
// authorizer, the lease set or ANY backend method.
func TestUnsupportedOperationKeysTouchNothing(t *testing.T) {
	e := newEnv(t)
	forged := []docker.Operation{
		"", " ", "*", "container:*", "container:exec", "container:kill", "container:remove",
		"container:rm", "container:create", "container:pause", "container:update",
		"container:attach", "container:top", "container:stats", "container:export",
		"endpoint:discover", "image:pull", "volume:ls", "network:ls", "system:info",
		"container:logs ", " container:logs", "CONTAINER:LOGS", "container:Logs",
		"container:inspect", "container:inspect_status\x00", "container:logs/../../exec",
		"container:logs?follow=1", "../containers/json", "POST /containers/x/exec",
	}
	for _, op := range forged {
		for _, creds := range []authz.PrincipalCredentials{aliceCreds(), botCreds()} {
			r := ops.Request{Credentials: creds, EndpointID: localEP, Target: "edge-proxy", Operation: op}
			res, err := e.svc.Execute(t.Context(), r)
			if !errors.Is(err, ops.ErrInvalidRequest) {
				t.Fatalf("op %q: err = %v, want ErrInvalidRequest", op, err)
			}
			if res.Status != nil || res.Config != nil || res.Logs != nil {
				t.Fatalf("op %q: data returned", op)
			}
		}
	}
	if n := e.spy.total(); n != 0 {
		t.Fatalf("forged operation keys caused %d backend calls: %v", n, e.spy.snapshot())
	}
	if n := e.az.ActiveLeaseCount(); n != 0 {
		t.Fatalf("%d leases registered", n)
	}
}

// P113-ALLOW-01: every permission key, human AAL2 session and agent token alike,
// is dispatched exactly once and ONLY with the immutable ContainerID bound by the
// decision; the mutable name is resolved once (inside authorization) and never
// again, including during the lease's own pre-dispatch revalidation.
func TestEveryPermissionKeyDispatchesOnceOnTheImmutableTarget(t *testing.T) {
	for _, who := range []struct {
		name  string
		creds authz.PrincipalCredentials
	}{{"human-AAL2-session", aliceCreds()}, {"agent-token", botCreds()}} {
		for _, op := range ops.Operations() {
			t.Run(who.name+"/"+string(op), func(t *testing.T) {
				e := newEnv(t)
				before := e.spy.total()
				res, err := e.svc.Execute(t.Context(), req(who.creds, "edge-proxy", op))
				if err != nil {
					t.Fatalf("allowed operation failed: %v", err)
				}
				if res.Logs != nil {
					defer func() { _ = res.Logs.Close() }()
				}
				if !isAllowedOutcome(res, op) || res.Operation != op {
					t.Fatalf("unexpected result shape for %s: %+v", op, res)
				}
				if res.Target.EndpointID != localEP || res.Target.ContainerID != edgeID || res.ContainerName != "edge-proxy" {
					t.Fatalf("result target %+v name %q", res.Target, res.ContainerName)
				}
				opCalls := e.spy.operationalCalls()
				if len(opCalls) != 1 {
					t.Fatalf("operational attempts = %d (%v), want exactly 1", len(opCalls), opCalls)
				}
				c := opCalls[0]
				if c.Target != (docker.TargetIdentity{EndpointID: localEP, ContainerID: edgeID}) {
					t.Fatalf("dispatched on %+v, want the immutable authorized identity", c.Target)
				}
				names := 0
				for i, rc := range e.spy.snapshot()[before:] {
					if rc.Method != "ResolveTarget" {
						continue
					}
					if rc.Ref == "edge-proxy" {
						names++
						if i != 0 {
							t.Fatalf("name resolved after authorization began (call %d)", i)
						}
						continue
					}
					if rc.Ref != string(edgeID) {
						t.Fatalf("ResolveTarget(%q): only the authorized ID may be resolved again", rc.Ref)
					}
				}
				if names != 1 {
					t.Fatalf("name resolved %d times, want exactly 1", names)
				}
				if op != docker.OpLogs && e.az.ActiveLeaseCount() != 0 {
					t.Fatal("one-shot operation left a lease registered")
				}
			})
		}
	}
}

// P113-ALLOW-02: a target given as its full container ID is authorized by the same
// selector and dispatched identically (no weaker ID path).
func TestTargetGivenAsFullContainerIDIsEquivalent(t *testing.T) {
	e := newEnv(t)
	res, err := e.svc.Execute(t.Context(), req(botCreds(), string(edgeID), docker.OpInspectStatus))
	if err != nil || res.Status == nil || res.Status.ContainerID != edgeID {
		t.Fatalf("by ID: %v %+v", err, res)
	}
	res, err = e.svc.Execute(t.Context(), req(botCreds(), "/edge-proxy", docker.OpInspectStatus))
	if err != nil || res.Target.ContainerID != edgeID {
		t.Fatalf("leading slash form: %v", err)
	}
}

// P113-ALLOW-03: responses are the backend's sanitized, allowlisted structures.
func TestInspectResponsesAreSanitizedAllowlistedStructures(t *testing.T) {
	e := newEnv(t)
	res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectConfig))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range res.Config.Env {
		for _, canary := range []string{"CANARY_MOCK_PROXY_SECRET", "mdt_mock_token_value_1234567890"} {
			if strings.Contains(entry, canary) {
				t.Fatalf("unredacted environment entry returned: %q", entry)
			}
		}
	}
	if len(res.Config.Env) == 0 {
		t.Fatal("control: expected sanitized environment entries")
	}
	res, err = e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", docker.OpInspectStatus))
	if err != nil || res.Status.Name != "edge-proxy" || !res.Status.Running {
		t.Fatalf("status: %v %+v", err, res.Status)
	}
}

// P113-ALLOW-04: a rename AFTER authorization cannot redirect dispatch. The test
// interleaves deterministically: the instant the name has been resolved for
// authorization it is moved to a different container. Every outcome must either
// deny with zero operational attempts, or operate on the originally authorized ID;
// it must never operate on the container that now carries the name.
func TestRenameAfterAuthorizationNeverRedirectsDispatch(t *testing.T) {
	for _, op := range ops.Operations() {
		t.Run(string(op), func(t *testing.T) {
			e := newEnv(t)
			e.seedSelector(selGlob, "edge-*", true, localEP)
			e.exec(`DELETE FROM policies WHERE selector_id=?`, selEdge)
			e.allowAll("agent_id", botID, selGlob)
			moved := false
			e.spy.afterResolve = func(ref string) {
				if ref != "edge-proxy" || moved {
					return
				}
				moved = true
				// The authorized container keeps matching the glob but frees the name;
				// an impostor takes the old name.
				orig := fixtureOf(e, edgeID)
				orig.Name = "edge-proxy-renamed"
				if err := e.mock.UpsertContainer(orig); err != nil {
					t.Error(err)
				}
				imp := fixtureOf(e, billingID)
				imp.Name = "edge-proxy"
				if err := e.mock.UpsertContainer(imp); err != nil {
					t.Error(err)
				}
			}
			res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
			if res.Logs != nil {
				defer func() { _ = res.Logs.Close() }()
			}
			for _, c := range e.spy.operationalCalls() {
				if c.Target.ContainerID == billingID {
					t.Fatalf("dispatched on the impostor that took the name: %v", c)
				}
			}
			if err != nil {
				t.Fatalf("authorized container still matches the glob; got %v", err)
			}
			if got := e.spy.operationalCalls(); len(got) != 1 || got[0].Target.ContainerID != edgeID {
				t.Fatalf("operational calls %v, want one on the originally authorized ID", got)
			}
			names := 0
			for _, c := range e.spy.snapshot() {
				if c.Method == "ResolveTarget" && c.Ref == "edge-proxy" {
					names++
				}
			}
			if !moved || names != 1 {
				t.Fatalf("rename interleaving happened=%v, name resolutions=%d (want exactly 1)", moved, names)
			}
		})
	}
}

// P113-ALLOW-05: when the rename also breaks the selector match the decision is
// stale and nothing is dispatched.
func TestRenameThatBreaksTheSelectorDeniesWithZeroOperationalCalls(t *testing.T) {
	for _, op := range ops.Operations() {
		t.Run(string(op), func(t *testing.T) {
			e := newEnv(t)
			moved := false
			e.spy.afterResolve = func(ref string) {
				if ref != "edge-proxy" || moved {
					return
				}
				moved = true
				orig := fixtureOf(e, edgeID)
				orig.Name = "totally-different"
				if err := e.mock.UpsertContainer(orig); err != nil {
					t.Error(err)
				}
			}
			res, err := e.svc.Execute(t.Context(), req(botCreds(), "edge-proxy", op))
			if err == nil || res.Logs != nil || res.Status != nil || res.Config != nil {
				t.Fatalf("op %s allowed after rename broke the selector: %v", op, err)
			}
			if !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("err = %v, want forbidden", err)
			}
			if n := len(e.spy.operationalCalls()); n != 0 {
				t.Fatalf("%d operational attempts", n)
			}
			if e.az.ActiveLeaseCount() != 0 {
				t.Fatal("lease left registered")
			}
		})
	}
}

func fixtureOf(e *env, id docker.ContainerID) docker.MockContainerFixture {
	e.t.Helper()
	_, fixtures := docker.DefaultMockFixtures(localEP)
	for _, f := range fixtures {
		if f.ID == id {
			return f
		}
	}
	e.t.Fatalf("no fixture %s", id)
	return docker.MockContainerFixture{}
}
