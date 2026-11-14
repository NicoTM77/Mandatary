package backup

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18.4 FC4-1: the manifest names exactly the authority an approval would restore, resolved
// from the stored rows by stable IDs, and an approval bound to what was shown is refused when
// that changed. Real SQLite fixtures only; synthetic names.

// restoredWithLookalikes extends the standard seed with records an approver could confuse:
// the same operation on the same selector for a different subject, a similarly named group, a
// second selector (glob, compose constraints) on the same container name, and a membership of
// the same agent in both groups.
func restoredWithLookalikes(t *testing.T) *env {
	t.Helper()
	src := newEnv(t, keyHexA)
	src.seed()
	ep := src.text(`SELECT id FROM endpoints WHERE slug='local'`)
	src.exec(`INSERT INTO groups(id,name,state,authority_generation) VALUES('ops-two','ops ',  'active',1)`) // similar name, different ID
	src.exec(`INSERT INTO container_selectors(id,endpoint_id,container_name,name_is_glob,compose_project,compose_service,image_pattern) VALUES('sel-web-glob',?,'web*',1,'platform','web','registry.invalid/web:*')`, ep)
	src.exec(`INSERT INTO agent_group_memberships(agent_id,group_id,state,authority_generation) VALUES('bot','ops-two','active',1)`)
	// Same operation (container:logs, ALLOW) on the same selector: only the subject differs.
	src.exec(`INSERT INTO policies(id,group_id,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES('pol-allow-group','ops',?,'sel-web','container:logs','ALLOW','active',1)`, ep)
	src.exec(`INSERT INTO policies(id,group_id,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES('pol-allow-group-two','ops-two',?,'sel-web','container:logs','ALLOW','active',1)`, ep)
	// Same subject and operation: only the selector differs, plus a bounded limit.
	src.exec(`INSERT INTO policies(id,agent_id,endpoint_id,selector_id,operation,effect,state,authority_generation,log_tail_max) VALUES('pol-allow-glob','bot',?,'sel-web-glob','container:logs','ALLOW','active',1,500)`, ep)
	dst := freshSameKey(t)
	dst.mustRestore(src.export(ModeFull))
	dst.leaveQuarantine()
	return dst
}

func itemsByKey(m ManifestView) map[string]ManifestItem {
	out := map[string]ManifestItem{}
	for _, it := range m.Items {
		out[it.Kind+"/"+it.ID] = it
	}
	return out
}

func TestManifestNamesTheExactAuthorityOfEveryRuleAndMembership(t *testing.T) {
	e := restoredWithLookalikes(t)
	m := e.manifest()
	byKey := itemsByKey(m)
	ep := e.text(`SELECT id FROM endpoints WHERE slug='local'`)

	rule := func(id string) *ItemDetail {
		t.Helper()
		it, ok := byKey["policy/"+id]
		if !ok || it.Detail == nil {
			t.Fatalf("rule %s has no identifying detail: %+v", id, it)
		}
		return it.Detail
	}
	d := rule("pol-allow")
	if d.Effect != "ALLOW" || d.Operation != "container:logs" || d.Subject == nil || *d.Subject != (NamedRef{Kind: "agent", ID: "bot", Name: "bot"}) ||
		d.Endpoint == nil || d.Endpoint.ID != ep || d.Endpoint.Name != "local" || d.Selector == nil || d.Selector.ID != "sel-web" || d.Selector.NameType != "exact" || d.Selector.ContainerName != "web" {
		t.Fatalf("pol-allow detail: %+v %+v %+v", d, d.Subject, d.Selector)
	}
	deny := rule("pol-deny")
	if deny.Effect != "DENY" || deny.Operation != "container:start" || deny.Subject.Kind != "user" || deny.Subject.ID != "alice" || deny.Selector.ContainerName != "db" {
		t.Fatalf("pol-deny detail: %+v", deny)
	}
	glob := rule("pol-allow-glob")
	if glob.Selector.NameType != "glob" || glob.Selector.ContainerName != "web*" || glob.Selector.ComposeProject != "platform" || glob.Selector.ComposeService != "web" || glob.Selector.ImagePattern != "registry.invalid/web:*" {
		t.Fatalf("selector constraints not shown: %+v", glob.Selector)
	}
	if glob.LogTailMax == nil || *glob.LogTailMax != 500 || glob.StopTimeoutMax != nil {
		t.Fatalf("limits not shown: %+v", glob)
	}

	// Same operation and selector, different subject: the details (and digests) differ by subject only.
	g1, g2 := rule("pol-allow-group"), rule("pol-allow-group-two")
	if g1.Subject.ID != "ops" || g1.Subject.Name != "ops" || g2.Subject.ID != "ops-two" || g2.Subject.Name != "ops " || g1.Operation != g2.Operation || g1.Selector.ID != g2.Selector.ID {
		t.Fatalf("lookalike subjects not distinguished: %+v %+v", g1.Subject, g2.Subject)
	}
	// Every rule has its own digest: nothing the approver reviewed can stand in for another record.
	digests := map[string]string{}
	for key, it := range byKey {
		if it.Digest == "" || len(it.Digest) != 64 {
			t.Fatalf("%s has no digest", key)
		}
		if other, dup := digests[it.Digest]; dup {
			t.Fatalf("%s and %s share a digest", key, other)
		}
		digests[it.Digest] = key
	}

	// Memberships name BOTH the principal and the group, including a similar group name.
	am := byKey["agent_membership/bot:ops"].Detail
	if am == nil || am.Member == nil || am.Group == nil || *am.Member != (NamedRef{Kind: "agent", ID: "bot", Name: "bot"}) || *am.Group != (NamedRef{Kind: "group", ID: "ops", Name: "ops"}) {
		t.Fatalf("agent membership detail: %+v", am)
	}
	am2 := byKey["agent_membership/bot:ops-two"].Detail
	if am2 == nil || am2.Group.ID != "ops-two" || am2.Group.Name != "ops " || am2.Member.ID != "bot" {
		t.Fatalf("lookalike group membership: %+v", am2)
	}
	um := byKey["user_membership/alice:ops"].Detail
	if um == nil || um.Member.Kind != "user" || um.Member.Name != "alice" || um.Group.ID != "ops" {
		t.Fatalf("user membership detail: %+v", um)
	}

	// Names follow the stored ID, never position or name equality: rename the group, reorder nothing.
	e.exec(`UPDATE groups SET name='ops-renamed' WHERE id='ops'`)
	again := itemsByKey(e.manifest())
	if got := again["agent_membership/bot:ops"].Detail.Group; got.ID != "ops" || got.Name != "ops-renamed" {
		t.Fatalf("name not resolved by stable ID: %+v", got)
	}
	if again["agent_membership/bot:ops-two"].Detail.Group.Name != "ops " {
		t.Fatal("a rename of one group changed another group's display")
	}
	if again["agent_membership/bot:ops"].Digest == byKey["agent_membership/bot:ops"].Digest {
		t.Fatal("a changed display name left the digest unchanged")
	}

	// Nothing secret is part of a detail.
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaryEncodings() {
		if contains(raw, c) {
			t.Fatal("manifest leaks credential material")
		}
	}
	for _, forbidden := range []string{"verifier", "token_hash", "ciphertext", "secret", "admin@example.invalid", "encrypted"} {
		if contains(raw, forbidden) {
			t.Fatalf("manifest mentions %q", forbidden)
		}
	}
}

// A record that cannot be resolved falls back to its ID and says so; kinds without a detail have none.
func TestDetailFallsBackToStableIDsWhenARecordIsMissing(t *testing.T) {
	e := restoredWithLookalikes(t)
	var d *ItemDetail
	var none, noPolicy, endpoint *ItemDetail
	err := e.repo.Read(t.Context(), func(q *store.Queries) error {
		var err error
		if d, err = DetailOf(t.Context(), q, "agent_membership", "bot:ghost-group"); err != nil {
			return err
		}
		if none, err = DetailOf(t.Context(), q, "agent_membership", "not-a-pair"); err != nil {
			return err
		}
		if noPolicy, err = DetailOf(t.Context(), q, "policy", "no-such-rule"); err != nil {
			return err
		}
		endpoint, err = DetailOf(t.Context(), q, "endpoint", "x")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || d.Group == nil || !d.Group.Missing || d.Group.Name != "ghost-group" || d.Group.ID != "ghost-group" || d.Member.Missing || d.Member.Name != "bot" {
		t.Fatalf("missing group not flagged with an ID fallback: %+v %+v", d, d.Group)
	}
	if none != nil || noPolicy != nil || endpoint != nil {
		t.Fatalf("details for unknown or detail-less items: %+v %+v %+v", none, noPolicy, endpoint)
	}
}

// An approval that names the digest of what was reviewed is refused as stale when the record changed
// afterwards, changes nothing, and succeeds again with the current digest.
func TestApprovalBoundToAReviewedDigestIsRefusedWhenTheRecordChangedSinceReview(t *testing.T) {
	e := restoredWithLookalikes(t)
	pre := e.manifest()
	byKey := itemsByKey(pre)
	// Approve the dependencies without digests (the API stays usable without them).
	if _, err := e.approve(ItemRef{Kind: "agent", ID: "bot"}, ItemRef{Kind: "group", ID: "ops"}, ItemRef{Kind: "user", ID: "alice"},
		ItemRef{Kind: "endpoint", ID: e.text(`SELECT id FROM endpoints WHERE slug='local'`)}); err != nil {
		t.Fatal(err)
	}
	reviewed := itemsByKey(e.manifest())["agent_membership/bot:ops"]
	if reviewed.Digest == "" || reviewed.Detail == nil {
		t.Fatal("no reviewed digest")
	}
	before := e.snapshot()

	// The group is renamed AFTER the administrator looked: the displayed group no longer matches.
	e.exec(`UPDATE groups SET name='someone-elses-group' WHERE id='ops'`)
	var conflict *ConflictError
	_, err := e.approve(ItemRef{Kind: "agent_membership", ID: "bot:ops", Digest: reviewed.Digest})
	if !errors.As(err, &conflict) || len(conflict.Failures) != 1 || conflict.Failures[0].Reason != "stale_details" {
		t.Fatalf("stale approval: %v", err)
	}
	if e.text(`SELECT state FROM agent_group_memberships WHERE agent_id='bot' AND group_id='ops'`) != "quarantined" {
		t.Fatal("a stale approval activated the membership")
	}
	e.exec(`UPDATE groups SET name='ops' WHERE id='ops'`)
	e.sameExceptControl(before)

	// A digest of ANOTHER record (the similar group's membership) never approves this one.
	other := byKey["agent_membership/bot:ops-two"].Digest
	if _, err = e.approve(ItemRef{Kind: "agent_membership", ID: "bot:ops", Digest: other}); !errors.As(err, &conflict) || conflict.Failures[0].Reason != "stale_details" {
		t.Fatalf("another record's digest: %v", err)
	}
	// A malformed digest is a malformed request.
	for _, bad := range []string{"xyz", "AAAA", reviewed.Digest[:63], reviewed.Digest + "0"} {
		if _, err = e.approve(ItemRef{Kind: "agent_membership", ID: "bot:ops", Digest: bad}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("digest %q: %v", bad, err)
		}
	}
	// Duplicate record IDs with different digests are still a duplicate.
	if _, err = e.approve(ItemRef{Kind: "agent_membership", ID: "bot:ops", Digest: reviewed.Digest}, ItemRef{Kind: "agent_membership", ID: "bot:ops"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate with and without digest: %v", err)
	}
	// All-or-nothing: one stale entry rolls back the fresh ones in the same request.
	fresh := itemsByKey(e.manifest())["agent_membership/bot:ops"]
	if _, err = e.approve(ItemRef{Kind: "agent_membership", ID: "bot:ops", Digest: fresh.Digest}, ItemRef{Kind: "user", ID: "adm", Digest: "0000000000000000000000000000000000000000000000000000000000000000"}); !errors.As(err, &conflict) {
		t.Fatalf("mixed request: %v", err)
	}
	if e.text(`SELECT state FROM agent_group_memberships WHERE agent_id='bot' AND group_id='ops'`) != "quarantined" {
		t.Fatal("a refused request partially applied")
	}
	// The current digest approves exactly that record.
	res, err := e.approve(ItemRef{Kind: "agent_membership", ID: "bot:ops", Digest: fresh.Digest})
	if err != nil || len(res) != 1 {
		t.Fatalf("current digest: %v %+v", err, res)
	}
	if e.text(`SELECT state FROM agent_group_memberships WHERE agent_id='bot' AND group_id='ops-two'`) != "quarantined" {
		t.Fatal("the similar group's membership was approved as a side effect")
	}
}

// A known-compromised principal stays visible with its reason but is not approvable, and a crafted
// approval is still refused by the server.
func TestACompromisedPrincipalIsShownButNeverSelectableAndStillRefusedByTheServer(t *testing.T) {
	e := restoredWithLookalikes(t)
	e.exec(`UPDATE users SET compromised=1 WHERE id='alice'`)
	alice := itemsByKey(e.manifest())["user/alice"]
	if alice.Approvable || alice.BlockedReason != "compromised" || alice.Detail == nil || !alice.Detail.Compromised || alice.Decision != "pending" {
		t.Fatalf("compromised user must stay listed, flagged and not approvable: %+v", alice)
	}
	if bob := itemsByKey(e.manifest())["user/adm"]; !bob.Approvable || bob.Detail != nil {
		t.Fatalf("an ordinary user must stay approvable without a detail: %+v", bob)
	}
	var conflict *ConflictError
	before := e.snapshot()
	if _, err := e.approve(ItemRef{Kind: "user", ID: "alice", Digest: alice.Digest}); !errors.As(err, &conflict) || conflict.Failures[0].Reason != "compromised" {
		t.Fatalf("crafted approval of a compromised principal: %v", err)
	}
	if _, err := e.approve(ItemRef{Kind: "user", ID: "alice"}); !errors.As(err, &conflict) || conflict.Failures[0].Reason != "compromised" {
		t.Fatalf("crafted approval without a digest: %v", err)
	}
	e.sameExceptControl(before)
}
