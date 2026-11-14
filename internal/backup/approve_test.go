package backup

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func (e *env) approve(refs ...ItemRef) ([]ItemResult, error) {
	e.t.Helper()
	var res []ItemResult
	var inner error
	err := e.repo.Control(e.t.Context(), func(q *store.Queries) error {
		c, err := q.GetInstallationControl(e.t.Context())
		if err != nil {
			return err
		}
		res, inner = Approve(e.t.Context(), q, c, baseTime+10, refs)
		return inner
	}, nil)
	if inner != nil {
		return nil, inner
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (e *env) manifest() ManifestView {
	e.t.Helper()
	var v ManifestView
	var inner error
	if err := e.repo.Read(e.t.Context(), func(q *store.Queries) error { v, inner = Manifest(e.t.Context(), q); return inner }); err != nil && inner == nil {
		e.t.Fatal(err)
	}
	if inner != nil {
		e.t.Fatal(inner)
	}
	return v
}

// restoredInstallation is a fresh same-key installation after a restore and after the host-authorized
// recovery ceremony ended quarantine: the state in which an administrator reviews the manifest.
func restoredInstallation(t *testing.T) *env {
	t.Helper()
	src := newEnv(t, keyHexA)
	src.seed()
	dst := freshSameKey(t)
	dst.mustRestore(src.export(ModeFull))
	dst.leaveQuarantine()
	return dst
}

func TestReapprovalIsRefusedWhileTheInstallationIsQuarantined(t *testing.T) {
	src := newEnv(t, keyHexA)
	src.seed()
	dst := freshSameKey(t)
	dst.mustRestore(src.export(ModeFull))
	before := dst.snapshot()
	if _, err := dst.approve(ItemRef{Kind: "user", ID: "alice"}); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("approve = %v", err)
	}
	dst.sameExceptControl(before)
}

func TestTheManifestShowsEveryPendingRecordAndNoSecret(t *testing.T) {
	e := restoredInstallation(t)
	m := e.manifest()
	if m.RestoreGeneration != 1 || m.Mode != ModeFull || m.Provenance != ProvenanceAuthenticated || m.Approved != 0 || m.Pending == 0 {
		t.Fatalf("manifest header %+v", m)
	}
	kinds := map[string]int{}
	for _, it := range m.Items {
		kinds[it.Kind]++
		if it.Decision != "pending" {
			t.Fatalf("item %+v", it)
		}
		switch it.Kind {
		case "role":
			if it.Approvable || it.BlockedReason != "single_administrator" {
				t.Fatalf("role %+v", it)
			}
		case "address":
			if it.Approvable || it.BlockedReason != "needs_reverification" {
				t.Fatalf("address %+v", it)
			}
		default:
			if !it.Approvable {
				t.Fatalf("%s should be approvable: %+v", it.Kind, it)
			}
		}
	}
	for kind, want := range map[string]int{"endpoint": 1, "user": 2, "group": 1, "agent": 1, "user_membership": 1, "agent_membership": 1, "role": 1, "policy": 2, "address": 1} {
		if kinds[kind] != want {
			t.Fatalf("kind %s: %d, want %d (%v)", kind, kinds[kind], want, kinds)
		}
	}
	if m.InactiveCredentials["authenticators"] != 2 || m.InactiveCredentials["agent_credentials"] != 1 {
		t.Fatalf("inactive credentials %+v", m.InactiveCredentials)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaryEncodings() {
		if contains(raw, c) {
			t.Fatal("manifest leaks credential material")
		}
	}
	for _, forbidden := range []string{"verifier", "token_hash", "ciphertext", "secret", "admin@example.invalid"} {
		if contains(raw, forbidden) {
			t.Fatalf("manifest mentions %q", forbidden)
		}
	}
	// The weaker imported setting is shown next to the effective one.
	for _, it := range m.Items {
		if it.Kind == "user" && it.ID == "alice" && (!contains(it.Imported, "optional") || !contains(it.Effective, "required")) {
			t.Fatalf("alice %+v", it)
		}
	}
}

func TestApprovalActivatesOnlyTheNamedRecordAtTheCurrentGenerations(t *testing.T) {
	e := restoredInstallation(t)
	c := e.controls()
	res, err := e.approve(ItemRef{Kind: "user", ID: "alice"})
	if err != nil || len(res) != 1 || res[0].Result != "approved" {
		t.Fatalf("approve: %v %+v", err, res)
	}
	if e.scalar(`SELECT count(*) FROM users WHERE id='alice' AND state='active' AND credential_generation=? AND authority_generation=?`, c.CredentialGeneration, c.AuthorityGeneration) != 1 {
		t.Fatal("not activated at the current generations")
	}
	if got := e.activeAuthority(); got != 1 {
		t.Fatalf("%d records effective, want exactly the approved user", got)
	}
	m := e.manifest()
	if m.Approved != 1 {
		t.Fatalf("approved %d", m.Approved)
	}
	// The approval grants no credential: alice still has no active authenticator or token.
	if e.scalar(`SELECT count(*) FROM authenticators WHERE state='active'`) != 0 || e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`) != 0 {
		t.Fatal("approval revived a credential")
	}
	// Approving it again is a refusal, not a second grant.
	_, err = e.approve(ItemRef{Kind: "user", ID: "alice"})
	var conflict *ConflictError
	if !errors.As(err, &conflict) || len(conflict.Failures) != 1 || conflict.Failures[0].Reason != "already_approved" {
		t.Fatalf("second approval: %v", err)
	}
}

func TestApprovalFollowsDependenciesAndAPartialReviewStaysDenied(t *testing.T) {
	e := restoredInstallation(t)
	// A rule cannot be approved before the principal it names.
	before := e.snapshot()
	_, err := e.approve(ItemRef{Kind: "policy", ID: "pol-allow"})
	var conflict *ConflictError
	if !errors.As(err, &conflict) || conflict.Failures[0].Reason != "subject_not_active" {
		t.Fatalf("policy before its agent: %v", err)
	}
	e.sameExceptControl(before)
	// An agent needs an approved owner; a membership needs both ends.
	for _, refs := range [][]ItemRef{{{Kind: "agent", ID: "bot"}}, {{Kind: "user_membership", ID: "alice:ops"}}, {{Kind: "agent_membership", ID: "bot:ops"}}} {
		if _, err := e.approve(refs...); !errors.As(err, &conflict) {
			t.Fatalf("%v: %v", refs, err)
		}
	}
	e.sameExceptControl(before)
	// One request may approve a whole chain; dependencies are applied first regardless of order given.
	res, err := e.approve(ItemRef{Kind: "policy", ID: "pol-allow"}, ItemRef{Kind: "agent_membership", ID: "bot:ops"}, ItemRef{Kind: "agent", ID: "bot"},
		ItemRef{Kind: "group", ID: "ops"}, ItemRef{Kind: "user", ID: "alice"}, ItemRef{Kind: "endpoint", ID: e.text(`SELECT id FROM endpoints WHERE slug='local'`)})
	if err != nil || len(res) != 6 {
		t.Fatalf("chain: %v %+v", err, res)
	}
	// The DENY rule and the user membership were not named, so they remain quarantined (a quarantined
	// DENY still blocks in the authorizer).
	if e.text(`SELECT state FROM policies WHERE id='pol-deny'`) != "quarantined" || e.text(`SELECT state FROM user_group_memberships WHERE user_id='alice'`) != "quarantined" {
		t.Fatal("an unnamed record became effective")
	}
	// Still no credential: the agent is approved but holds no token until a new one is issued.
	if e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`) != 0 {
		t.Fatal("agent approval revived a token")
	}
}

func TestApprovalIsAllOrNothingAndRefusesWhatPhaseOneCannotApprove(t *testing.T) {
	e := restoredInstallation(t)
	before := e.snapshot()
	_, err := e.approve(ItemRef{Kind: "user", ID: "alice"}, ItemRef{Kind: "role", ID: "role-adm"}, ItemRef{Kind: "address", ID: "addr-1"}, ItemRef{Kind: "group", ID: "no-such-group"})
	var conflict *ConflictError
	if !errors.As(err, &conflict) || len(conflict.Failures) != 3 {
		t.Fatalf("err %v", err)
	}
	reasons := map[string]string{}
	for _, f := range conflict.Failures {
		reasons[f.Kind] = f.Reason
	}
	if reasons["role"] != "single_administrator" || reasons["address"] != "needs_reverification" || reasons["group"] != "not_in_manifest" {
		t.Fatalf("reasons %v", reasons)
	}
	e.sameExceptControl(before) // alice was NOT activated: the whole request rolled back
	// A compromised account is never approvable by this flow.
	e.exec(`UPDATE users SET compromised=1 WHERE id='alice'`)
	if _, err := e.approve(ItemRef{Kind: "user", ID: "alice"}); !errors.As(err, &conflict) || conflict.Failures[0].Reason != "compromised" {
		t.Fatalf("compromised: %v", err)
	}
}

func TestMalformedApprovalRequestsAreRefusedBeforeAnyLookup(t *testing.T) {
	e := restoredInstallation(t)
	many := make([]ItemRef, MaxApprovalsPerRequest+1)
	for i := range many {
		many[i] = ItemRef{Kind: "user", ID: "u" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))}
	}
	for name, refs := range map[string][]ItemRef{
		"empty":           nil,
		"unknown kind":    {{Kind: "credential", ID: "cred-1"}},
		"kind injection":  {{Kind: "user'; --", ID: "alice"}},
		"bad id":          {{Kind: "user", ID: "../etc"}},
		"empty id":        {{Kind: "user", ID: ""}},
		"bad pair":        {{Kind: "user_membership", ID: "alice"}},
		"duplicate":       {{Kind: "user", ID: "alice"}, {Kind: "user", ID: "alice"}},
		"over the bound":  many,
		"a credential id": {{Kind: "agent_credential", ID: "cred-1"}},
	} {
		if _, err := e.approve(refs...); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestThereIsNoManifestBeforeAnyRestore(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	var inner error
	_ = e.repo.Read(t.Context(), func(q *store.Queries) error { _, inner = Manifest(t.Context(), q); return inner })
	if !errors.Is(inner, ErrNoRestore) {
		t.Fatalf("manifest = %v", inner)
	}
	if _, err := e.approve(ItemRef{Kind: "user", ID: "alice"}); !errors.Is(err, ErrNoRestore) {
		t.Fatalf("approve = %v", err)
	}
}
