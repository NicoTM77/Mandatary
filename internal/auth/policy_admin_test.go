package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
)

// P1.17 policy-rule administration over a real SQLite repository and the real fresh-administrator
// transaction. The shared evaluator (internal/authz) is exercised against these rules end to end in
// policy_e2e_test.go; here the service's own contract is pinned: what it accepts, what it refuses
// (with NOTHING written), what it notifies, and what it reports about targets.

const (
	opLogs    = "container:logs"
	opStatus  = "container:inspect_status"
	opConfig  = "container:inspect_config"
	opStart   = "container:start"
	opStop    = "container:stop"
	opRestart = "container:restart"
)

func name(n string) SelectorSpec { return SelectorSpec{ContainerName: n} }

// fakeTargets is a TargetSource whose containers are scripted by the test.
type fakeTargets struct {
	mu   sync.Mutex
	list []docker.ContainerSummary
	err  error
}

func (f *fakeTargets) Containers(_ context.Context, endpoint domain.EndpointID) ([]docker.ContainerSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := append([]docker.ContainerSummary(nil), f.list...)
	for i := range out {
		out[i].EndpointID = endpoint // a backend lists the containers of the endpoint it is bound to
	}
	return out, nil
}

func (f *fakeTargets) set(list ...docker.ContainerSummary) {
	f.mu.Lock()
	f.list, f.err = list, nil
	f.mu.Unlock()
}

func (f *fakeTargets) fail(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

func container(id, nm, image string, labels map[string]string) docker.ContainerSummary {
	return docker.ContainerSummary{
		EndpointID: domain.EndpointID("00000000-0000-4000-8000-000000000001"), ContainerID: docker.ContainerID(id), Name: nm, State: "running", Image: image,
		ComposeProject: labels["com.docker.compose.project"], ComposeService: labels["com.docker.compose.service"], Labels: labels,
	}
}

func hex64(c string) string { return strings.Repeat(c, 64) }

// ruleEnv is an adminEnv with one user, group and agent to name in rules.
type ruleEnv struct {
	*adminEnv
	user, group, agent string
}

func newRuleEnv(t *testing.T) *ruleEnv {
	t.Helper()
	e := newAdminEnv(t)
	u := e.person("alice")
	return &ruleEnv{adminEnv: e, user: u, group: e.group("ops"), agent: e.agentOwnedBy("bot", u)}
}

func (e *ruleEnv) allow(subject RuleSubject, sel SelectorSpec, ops ...string) []RuleView {
	e.t.Helper()
	views, err := e.a.CreateRules(e.t.Context(), e.secret, RuleRequest{Subject: subject, Effect: "ALLOW", Operations: ops, Selector: sel})
	if err != nil {
		e.t.Fatalf("CreateRules: %v", err)
	}
	return views
}

func (e *ruleEnv) policyRows() int64   { return e.scalar(`SELECT count(*) FROM policies`) }
func (e *ruleEnv) selectorRows() int64 { return e.scalar(`SELECT count(*) FROM container_selectors`) }

func TestCreatingRulesWritesOnePolicyPerOperationAndNotifiesOnce(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	before := e.notifications()
	views := e.allow(RuleSubject{Kind: "agent", ID: e.agent}, SelectorSpec{ContainerName: "edge-proxy", ComposeProject: "platform", ComposeService: "edge"}, opLogs, opStatus)
	if len(views) != 2 || views[0].Operation != opLogs || views[1].Operation != opStatus {
		t.Fatalf("views %+v", views)
	}
	if e.policyRows() != 2 || e.selectorRows() != 1 {
		t.Fatalf("policies %d selectors %d: one policy per operation sharing ONE selector", e.policyRows(), e.selectorRows())
	}
	for _, v := range views {
		if v.State != "active" || v.Effect != "ALLOW" || v.Subject.Kind != "agent" || v.Subject.ID != e.agent || v.Subject.Name != "bot" || v.Selector.ComposeProject != "platform" {
			t.Fatalf("view %+v", v)
		}
	}
	// Stored exactly: current authority generation, the local endpoint, no caps, subject column XOR.
	if got := e.scalar(`SELECT count(*) FROM policies p JOIN installation_control c ON c.singleton=1 JOIN endpoints ep ON ep.slug='local'
		WHERE p.agent_id=? AND p.user_id IS NULL AND p.group_id IS NULL AND p.state='active' AND p.effect='ALLOW'
		AND p.authority_generation=c.authority_generation AND p.endpoint_id=ep.id AND p.log_tail_max IS NULL AND p.stop_timeout_max IS NULL`, e.agent); got != 2 {
		t.Fatalf("stored rows do not match: %d", got)
	}
	if e.notifications() != before+1 {
		t.Fatalf("notifications %d, want exactly one after the commit", e.notifications()-before)
	}
	// An identical selector reuses the row; a different one adds another.
	e.allow(RuleSubject{Kind: "user", ID: e.user}, SelectorSpec{ContainerName: "edge-proxy", ComposeProject: "platform", ComposeService: "edge"}, opLogs)
	if e.selectorRows() != 1 {
		t.Fatalf("selector rows %d: identical selectors must be shared", e.selectorRows())
	}
	e.allow(RuleSubject{Kind: "group", ID: e.group}, name("billing"), opStart)
	if e.selectorRows() != 2 {
		t.Fatalf("selector rows %d", e.selectorRows())
	}
}

func TestCreatingRulesAppliesCapsToTheOperationsThatTakeThemAndOnlyOnAllow(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	tail, timeout := 500, 30
	views, err := e.a.CreateRules(t.Context(), e.secret, RuleRequest{
		Subject: RuleSubject{Kind: "agent", ID: e.agent}, Effect: "ALLOW", Selector: name("web"),
		Operations: []string{opLogs, opStop, opRestart, opStart}, LogTailMax: &tail, StopTimeoutMax: &timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][2]string{}
	for _, v := range views {
		got[v.Operation] = [2]string{fmt.Sprint(ptr(v.LogTailMax)), fmt.Sprint(ptr(v.StopTimeoutMax))}
	}
	want := map[string][2]string{opLogs: {"500", "<nil>"}, opStop: {"<nil>", "30"}, opRestart: {"<nil>", "30"}, opStart: {"<nil>", "<nil>"}}
	for op, w := range want {
		if got[op] != w {
			t.Errorf("%s caps %v, want %v", op, got[op], w)
		}
	}
	// A ceiling on a Deny is meaningless (a Deny blocks outright), so it is refused rather than ignored.
	before := e.snapshot()
	if _, err = e.a.CreateRules(t.Context(), e.secret, RuleRequest{Subject: RuleSubject{Kind: "agent", ID: e.agent}, Effect: "DENY", Selector: name("other"), Operations: []string{opLogs}, LogTailMax: &tail}); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("cap on a deny: %v", err)
	}
	e.mustNoChange("refused deny cap", before)
}

func ptr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestCreatingRulesIsAllOrNoneAndRefusesEverythingMalformedWithoutWriting(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	ok := RuleRequest{Subject: RuleSubject{Kind: "agent", ID: e.agent}, Effect: "ALLOW", Operations: []string{opLogs}, Selector: name("web")}
	n := func(v int) *int { return &v }
	cases := map[string]func(*RuleRequest){
		"unknown operation among valid ones": func(r *RuleRequest) { r.Operations = []string{opLogs, "container:exec"} },
		"no operations":                      func(r *RuleRequest) { r.Operations = nil },
		"duplicate operation":                func(r *RuleRequest) { r.Operations = []string{opLogs, opLogs} },
		"wildcard operation":                 func(r *RuleRequest) { r.Operations = []string{"container:*"} },
		"create operation":                   func(r *RuleRequest) { r.Operations = []string{"container:create"} },
		"raw proxy operation":                func(r *RuleRequest) { r.Operations = []string{"docker:raw"} },
		"effect unknown":                     func(r *RuleRequest) { r.Effect = "PERMIT" },
		"effect lower case":                  func(r *RuleRequest) { r.Effect = "allow" },
		"subject kind unknown":               func(r *RuleRequest) { r.Subject.Kind = "role" },
		"subject administrator role":         func(r *RuleRequest) { r.Subject = RuleSubject{Kind: "role", ID: "super_admin"} },
		"subject id malformed":               func(r *RuleRequest) { r.Subject.ID = "bad id" },
		"subject unknown":                    func(r *RuleRequest) { r.Subject.ID = "ghost" },
		"log cap on a non-log operation":     func(r *RuleRequest) { r.Operations = []string{opStart}; r.LogTailMax = n(10) },
		"stop cap on a log operation":        func(r *RuleRequest) { r.StopTimeoutMax = n(10) },
		"log cap zero":                       func(r *RuleRequest) { r.LogTailMax = n(0) },
		"log cap above ceiling":              func(r *RuleRequest) { r.LogTailMax = n(10001) },
		"stop cap zero":                      func(r *RuleRequest) { r.Operations = []string{opStop}; r.StopTimeoutMax = n(0) },
		"stop cap above ceiling":             func(r *RuleRequest) { r.Operations = []string{opStop}; r.StopTimeoutMax = n(301) },
		"empty name":                         func(r *RuleRequest) { r.Selector.ContainerName = "" },
		"blank name":                         func(r *RuleRequest) { r.Selector.ContainerName = "   " },
		"name with edge space":               func(r *RuleRequest) { r.Selector.ContainerName = " web" },
		"name with newline":                  func(r *RuleRequest) { r.Selector.ContainerName = "web\nother" },
		"name with NUL":                      func(r *RuleRequest) { r.Selector.ContainerName = "web\x00" },
		"name with backslash":                func(r *RuleRequest) { r.Selector.ContainerName = `we\b` },
		"name non-ASCII look-alike":          func(r *RuleRequest) { r.Selector.ContainerName = "w\u0435b" },
		"name too long":                      func(r *RuleRequest) { r.Selector.ContainerName = strings.Repeat("a", 256) },
		"exact name with pattern characters": func(r *RuleRequest) { r.Selector.ContainerName = "web-*" },
		"exact name with class":              func(r *RuleRequest) { r.Selector.ContainerName = "web[12]" },
		"unterminated glob":                  func(r *RuleRequest) { r.Selector = SelectorSpec{ContainerName: "web[", NameIsGlob: true} },
		"empty class glob":                   func(r *RuleRequest) { r.Selector = SelectorSpec{ContainerName: "web[]", NameIsGlob: true} },
		"compose project with control":       func(r *RuleRequest) { r.Selector.ComposeProject = "a\nb" },
		"compose service non-ASCII":          func(r *RuleRequest) { r.Selector.ComposeService = "sérvice" },
		"image pattern unterminated":         func(r *RuleRequest) { r.Selector.ImagePattern = "nginx[" },
		"image pattern too long":             func(r *RuleRequest) { r.Selector.ImagePattern = strings.Repeat("i", 256) },
		"pinned id short":                    func(r *RuleRequest) { r.Selector.PinnedContainerID = "abc" },
		"pinned id upper case":               func(r *RuleRequest) { r.Selector.PinnedContainerID = strings.Repeat("A", 64) },
		"pinned id not hex":                  func(r *RuleRequest) { r.Selector.PinnedContainerID = strings.Repeat("g", 64) },
		"digest wrong algorithm":             func(r *RuleRequest) { r.Selector.PinnedImageDigest = "md5:" + strings.Repeat("a", 64) },
		"digest short":                       func(r *RuleRequest) { r.Selector.PinnedImageDigest = "sha256:abc" },
		"digest upper case":                  func(r *RuleRequest) { r.Selector.PinnedImageDigest = "sha256:" + strings.Repeat("A", 64) },
	}
	for label, mutate := range cases {
		r := ok
		r.Operations = append([]string(nil), ok.Operations...)
		mutate(&r)
		before := e.snapshot()
		sel, notified := e.selectorRows(), e.notifications()
		if _, err := e.a.CreateRules(t.Context(), e.secret, r); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%s: want ErrAdminInvalid, got %v", label, err)
		}
		e.mustNoChange(label, before)
		if e.selectorRows() != sel || e.notifications() != notified {
			t.Errorf("%s: wrote a selector or notified", label)
		}
	}
}

func TestCreatingRulesRefusesInactiveSubjectsAndDuplicates(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	req := RuleRequest{Subject: RuleSubject{Kind: "agent", ID: e.agent}, Effect: "ALLOW", Operations: []string{opLogs}, Selector: name("web")}
	if _, err := e.a.CreateRules(t.Context(), e.secret, req); err != nil {
		t.Fatal(err)
	}
	before := e.snapshot()
	if _, err := e.a.CreateRules(t.Context(), e.secret, req); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	// One duplicate among several new operations still writes nothing (all or none).
	req.Operations = []string{opStatus, opLogs}
	if _, err := e.a.CreateRules(t.Context(), e.secret, req); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("partial duplicate: %v", err)
	}
	e.mustNoChange("duplicates", before)
	// Opposite effect on the same target is a different rule, not a duplicate.
	req.Effect, req.Operations = "DENY", []string{opLogs}
	if _, err := e.a.CreateRules(t.Context(), e.secret, req); err != nil {
		t.Fatalf("deny of the same target: %v", err)
	}
	// Disabled, quarantined and stale subjects cannot be named.
	if err := e.a.DisableGroup(t.Context(), e.secret, e.group); err != nil {
		t.Fatal(err)
	}
	other := e.person("bob")
	e.exec(`UPDATE users SET state='quarantined', authority_generation=0 WHERE id=?`, other)
	for label, s := range map[string]RuleSubject{"disabled group": {Kind: "group", ID: e.group}, "quarantined user": {Kind: "user", ID: other}} {
		if _, err := e.a.CreateRules(t.Context(), e.secret, RuleRequest{Subject: s, Effect: "ALLOW", Operations: []string{opLogs}, Selector: name("x")}); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

func TestTheAdministratorIsAnOrdinarySubjectOfRules(t *testing.T) { // a rule is the only grant; the role is not one
	t.Parallel()
	e := newRuleEnv(t)
	views := e.allow(RuleSubject{Kind: "user", ID: "u"}, name("web"), opLogs)
	if len(views) != 1 || !views[0].Subject.Administrator {
		t.Fatalf("administrator rule view %+v", views)
	}
	// Without a rule the administrator has no rows at all.
	if e.scalar(`SELECT count(*) FROM policies WHERE user_id='u'`) != 1 {
		t.Fatal("exactly the rule that was written must exist for the administrator")
	}
}

func TestRulesAreEditedInPlaceKeepingSubjectOperationAndState(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	v := e.allow(RuleSubject{Kind: "agent", ID: e.agent}, name("web"), opLogs)[0]
	tail := 100
	before := e.notifications()
	got, err := e.a.UpdateRule(t.Context(), e.secret, v.ID, RuleEdit{Effect: "ALLOW", Selector: SelectorSpec{ContainerName: "web-*", NameIsGlob: true, ImagePattern: "nginx:*"}, LogTailMax: &tail})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != v.ID || got.Operation != opLogs || got.Subject.ID != e.agent || got.State != "active" || got.Selector.ContainerName != "web-*" || !got.Selector.NameIsGlob || ptr(got.LogTailMax) != 100 {
		t.Fatalf("updated %+v", got)
	}
	if e.notifications() != before+1 {
		t.Fatal("an edit must notify exactly once so a tightened rule cuts open streams")
	}
	// Flip to a Deny and drop the ceiling together.
	if got, err = e.a.UpdateRule(t.Context(), e.secret, v.ID, RuleEdit{Effect: "DENY", Selector: name("web")}); err != nil || got.Effect != "DENY" || got.LogTailMax != nil {
		t.Fatalf("to deny: %+v %v", got, err)
	}
	// A disabled rule stays disabled when edited; it is never enabled by an edit.
	if err = e.a.DisableRule(t.Context(), e.secret, v.ID); err != nil {
		t.Fatal(err)
	}
	if got, err = e.a.UpdateRule(t.Context(), e.secret, v.ID, RuleEdit{Effect: "DENY", Selector: name("web2")}); err != nil || got.State != "disabled" {
		t.Fatalf("edit of a disabled rule: %+v %v", got, err)
	}
	// Invalid edits and duplicates change nothing.
	other := e.allow(RuleSubject{Kind: "agent", ID: e.agent}, name("other"), opLogs)[0]
	snap := e.snapshot()
	for label, ed := range map[string]RuleEdit{
		"bad effect":       {Effect: "x", Selector: name("a")},
		"bad selector":     {Effect: "ALLOW", Selector: name("")},
		"cap on deny":      {Effect: "DENY", Selector: name("a"), LogTailMax: &tail},
		"cap not accepted": {Effect: "ALLOW", Selector: name("a"), StopTimeoutMax: &tail},
	} {
		if _, err = e.a.UpdateRule(t.Context(), e.secret, other.ID, ed); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if _, err = e.a.UpdateRule(t.Context(), e.secret, other.ID, RuleEdit{Effect: "DENY", Selector: name("web2")}); !errors.Is(err, ErrAdminConflict) {
		t.Errorf("an edit into a duplicate: %v", err)
	}
	if _, err = e.a.UpdateRule(t.Context(), e.secret, "ghost", RuleEdit{Effect: "ALLOW", Selector: name("a")}); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("unknown rule: %v", err)
	}
	e.mustNoChange("refused edits", snap)
}

func TestRuleStateTransitionsAreExactAndNeverReviveStaleOrRestoredRules(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	v := e.allow(RuleSubject{Kind: "user", ID: e.user}, name("web"), opStart)[0]
	ctx := t.Context()
	n := e.notifications()
	if err := e.a.DisableRule(ctx, e.secret, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.a.DisableRule(ctx, e.secret, v.ID); err != nil { // idempotent, notifies so a failed notification can be retried
		t.Fatal(err)
	}
	if e.notifications() != n+2 {
		t.Fatal("each disable must notify")
	}
	if err := e.a.EnableRule(ctx, e.secret, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.a.EnableRule(ctx, e.secret, v.ID); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling an active rule: %v", err)
	}
	// A rule from an earlier generation or a restore can only be deleted.
	e.exec(`UPDATE policies SET state='disabled', authority_generation=0 WHERE id=?`, v.ID)
	if err := e.a.EnableRule(ctx, e.secret, v.ID); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling a stale rule: %v", err)
	}
	e.exec(`UPDATE policies SET state='quarantined' WHERE id=?`, v.ID)
	if err := e.a.EnableRule(ctx, e.secret, v.ID); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("enabling a restored rule: %v", err)
	}
	if err := e.a.DisableRule(ctx, e.secret, v.ID); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("disabling a restored rule: %v", err)
	}
	if _, err := e.a.UpdateRule(ctx, e.secret, v.ID, RuleEdit{Effect: "ALLOW", Selector: name("x")}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("editing a restored rule: %v", err)
	}
	if err := e.a.DeleteRule(ctx, e.secret, v.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if e.policyRows() != 0 {
		t.Fatal("rule remains")
	}
	if err := e.a.DeleteRule(ctx, e.secret, v.ID); !errors.Is(err, ErrAdminNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	for _, bad := range []string{"", "bad id", strings.Repeat("a", 200)} {
		if err := e.a.DeleteRule(ctx, e.secret, bad); !errors.Is(err, ErrAdminInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestConcurrentIdenticalCreationsYieldExactlyOneRule(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	req := RuleRequest{Subject: RuleSubject{Kind: "agent", ID: e.agent}, Effect: "ALLOW", Operations: []string{opLogs}, Selector: name("web")}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.a.CreateRules(context.Background(), e.secret, req)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	created := 0
	for err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrAdminConflict):
		default:
			t.Errorf("unexpected %v", err)
		}
	}
	if created != 1 || e.policyRows() != 1 {
		t.Fatalf("created %d, rows %d", created, e.policyRows())
	}
}

func TestRulePageReportsMissingPresentAndUnknownTargetsAndNeverInventsAMatch(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	src := &fakeTargets{}
	e.a.WithTargetSource(src)
	web := e.allow(RuleSubject{Kind: "agent", ID: e.agent}, SelectorSpec{ContainerName: "web", ComposeProject: "shop"}, opLogs)[0]
	gone := e.allow(RuleSubject{Kind: "agent", ID: e.agent}, name("gone"), opLogs)[0]
	wide := e.allow(RuleSubject{Kind: "user", ID: e.user}, SelectorSpec{ContainerName: "web*", NameIsGlob: true}, opStatus)[0]
	src.set(
		container(hex64("a"), "web", "nginx:1", map[string]string{"com.docker.compose.project": "shop"}),
		container(hex64("b"), "web2", "nginx:1", nil),
	)
	page, err := e.a.RulesPage(t.Context(), e.secret)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]TargetView{}
	for _, r := range page.Rules {
		status[r.ID] = r.Target
	}
	if status[web.ID].Status != "present" || status[web.ID].Matches != 1 {
		t.Errorf("web: %+v", status[web.ID])
	}
	if status[gone.ID].Status != "missing" {
		t.Errorf("gone: %+v", status[gone.ID])
	}
	if status[wide.ID].Status != "present" || status[wide.ID].Matches != 2 {
		t.Errorf("wide: %+v", status[wide.ID])
	}
	if page.Endpoint.Safety != "verified" || page.Inventory == nil || len(page.Inventory) != 2 {
		t.Fatalf("endpoint %+v inventory %v", page.Endpoint, page.Inventory)
	}
	// Subjects are offered with their state and the administrator flagged; no role is a subject.
	kinds := map[string]int{}
	var adminSeen bool
	for _, s := range page.Subjects {
		kinds[s.Kind]++
		adminSeen = adminSeen || (s.Administrator && s.ID == "u")
	}
	if kinds["user"] < 2 || kinds["group"] != 1 || kinds["agent"] != 1 || !adminSeen {
		t.Fatalf("subjects %v admin %v", kinds, adminSeen)
	}
	// The endpoint cannot be inspected: every target is UNKNOWN (never present, never missing) and the
	// inventory is withheld.
	src.fail(errors.New("backend unverified"))
	page, err = e.a.RulesPage(t.Context(), e.secret)
	if err != nil {
		t.Fatal(err)
	}
	if page.Endpoint.Safety != "unverified" || page.Inventory != nil {
		t.Fatalf("endpoint %+v inventory %v", page.Endpoint, page.Inventory)
	}
	for _, r := range page.Rules {
		if r.Target.Status != "unknown" {
			t.Errorf("rule %s is %q while the endpoint cannot be inspected", r.ID, r.Target.Status)
		}
	}
	// No source at all (the binary before a Docker backend is composed) behaves the same.
	e.a.WithTargetSource(nil)
	if page, err = e.a.RulesPage(t.Context(), e.secret); err != nil || page.Endpoint.Safety != "unverified" || page.Rules[0].Target.Status != "unknown" {
		t.Fatalf("nil source %+v %v", page.Endpoint, err)
	}
}

func TestSelectorPreviewMatchesTheEvaluatorAndRefusesBadSelectors(t *testing.T) {
	t.Parallel()
	e := newRuleEnv(t)
	src := &fakeTargets{}
	e.a.WithTargetSource(src)
	src.set(
		container(hex64("a"), "web", "nginx:1.27", map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.service": "web"}),
		container(hex64("b"), "web-old", "nginx:1.20", nil),
		container(hex64("c"), "db", "postgres:16", nil),
	)
	names := func(p Preview) string {
		var out []string
		for _, m := range p.Matches {
			out = append(out, m.Name)
		}
		return strings.Join(out, ",")
	}
	for label, c := range map[string]struct {
		sel  SelectorSpec
		want string
	}{
		"exact":           {name("web"), "web"},
		"glob":            {SelectorSpec{ContainerName: "web*", NameIsGlob: true}, "web,web-old"},
		"image":           {SelectorSpec{ContainerName: "web*", NameIsGlob: true, ImagePattern: "nginx:1.27*"}, "web"},
		"compose":         {SelectorSpec{ContainerName: "web", ComposeProject: "shop", ComposeService: "web"}, "web"},
		"compose differs": {SelectorSpec{ContainerName: "web", ComposeProject: "other"}, ""},
		"pinned id":       {SelectorSpec{ContainerName: "web*", NameIsGlob: true, PinnedContainerID: hex64("b")}, "web-old"},
		"nothing":         {name("nope"), ""},
	} {
		p, err := e.a.PreviewSelector(t.Context(), e.secret, c.sel)
		if err != nil || !p.Available {
			t.Fatalf("%s: %+v %v", label, p, err)
		}
		if got := names(p); got != c.want {
			t.Errorf("%s: matches %q, want %q", label, got, c.want)
		}
	}
	if _, err := e.a.PreviewSelector(t.Context(), e.secret, SelectorSpec{ContainerName: "web["}); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("invalid selector: %v", err)
	}
	src.fail(errors.New("unverified"))
	if p, err := e.a.PreviewSelector(t.Context(), e.secret, name("web")); err != nil || p.Available || len(p.Matches) != 0 {
		t.Fatalf("unavailable: %+v %v", p, err)
	}
	e.a.WithTargetSource(nil)
	if p, err := e.a.PreviewSelector(t.Context(), e.secret, name("web")); err != nil || p.Available {
		t.Fatalf("no source: %+v %v", p, err)
	}
	// A preview writes nothing and notifies nothing.
	before := e.snapshot()
	n := e.notifications()
	_, _ = e.a.PreviewSelector(t.Context(), e.secret, name("web"))
	e.mustNoChange("preview", before)
	if e.notifications() != n || e.selectorRows() != 0 {
		t.Fatal("preview wrote or notified")
	}
}

// abortingTargets simulates the HTTP client going away while the endpoint is being read: it cancels the
// caller's context and then records what context the source itself was handed.
type abortingTargets struct {
	cancel   context.CancelFunc
	mu       sync.Mutex
	calls    int
	errAtUse error
	deadline bool
}

func (s *abortingTargets) Containers(ctx context.Context, _ domain.EndpointID) ([]docker.ContainerSummary, error) {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.errAtUse = ctx.Err()
	_, s.deadline = ctx.Deadline()
	return nil, ctx.Err()
}

// A caller that goes away mid-read must not cancel the endpoint read: the production Docker adapter treats
// ANY error from the read as loss of the endpoint-wide safety proof, which would refuse every principal's
// operations until self-verification ran again (review F1). The read stays bounded by targetTimeout.
func TestEndpointReadIsDetachedFromCallerCancellationButBounded(t *testing.T) {
	t.Parallel()
	for label, call := range map[string]func(e *ruleEnv, ctx context.Context) error{
		"rules page": func(e *ruleEnv, ctx context.Context) error { _, err := e.a.RulesPage(ctx, e.secret); return err },
		"preview": func(e *ruleEnv, ctx context.Context) error {
			_, err := e.a.PreviewSelector(ctx, e.secret, name("web"))
			return err
		},
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			e := newRuleEnv(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			src := &abortingTargets{cancel: cancel}
			e.a.WithTargetSource(src)
			if err := call(e, ctx); err != nil {
				t.Fatalf("an aborted caller must still get a well-formed answer, got %v", err)
			}
			src.mu.Lock()
			defer src.mu.Unlock()
			if src.calls != 1 {
				t.Fatalf("source consulted %d times", src.calls)
			}
			if src.errAtUse != nil {
				t.Fatalf("the endpoint read inherited the caller's cancellation: %v", src.errAtUse)
			}
			if !src.deadline {
				t.Fatal("the endpoint read is unbounded")
			}
		})
	}
}
