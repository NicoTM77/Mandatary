package auth_test

// P1.18.3 acceptance for RESTORE-01/03/05/09/11 over the REAL machine surfaces: the same stack as the P1.17.2 A/B scenario
// (SQLite store, the administrator's session through the real Browser boundary, the real Admin and backup services and routes,
// the shared authz.Authorizer, ops.Service, the REST adapter and the official MCP server driven by the official go-sdk client),
// with the backup service attached. The Docker daemon is the in-memory MockBackend behind a spy that counts every operational
// call before delegating, so "must not reach Docker" is measured. The host recovery ceremony is the REAL one
// (PolicyE2E.RecoveryCeremony, RESTORE-08): a NEW administrator is enrolled with a fresh password and TOTP, nothing the backup
// carried is revived, and the scenarios continue as that new administrator. No Docker socket, container build, real mail or
// secret is involved; this is component and integration evidence over a mock backend, not real Docker and not a NIST/FIPS
// claim.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/auth"
)

// hostRecover runs the real host recovery and switches the world to the NEW administrator's session. The backup administrator's
// cookie, which the restore revoked, stays dead.
func (w *world) hostRecover() auth.RecoveredAdmin {
	w.t.Helper()
	old := w.cookie
	r := w.p.RecoveryCeremony()
	w.cookie, w.csrf = w.p.AdminSession()
	if w.cookie == old {
		w.t.Fatal("the recovery administrator reused the backup administrator's session")
	}
	return r
}

// manifestItem is the slice of a manifest entry the scenario needs.
type manifestItem struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Label      string `json:"label"`
	Origin     string `json:"origin"`
	Decision   string `json:"decision"`
	Approvable bool   `json:"approvable"`
}

func (w *world) manifestItems() []manifestItem {
	w.t.Helper()
	code, body := w.p.Do(http.MethodGet, admin+"/restore/manifest", "", w.cookie, w.csrf)
	if code != http.StatusOK {
		w.t.Fatalf("manifest: %d %s", code, body)
	}
	for _, forbidden := range []string{"verifier", "token_hash", "ciphertext", "secret"} {
		if strings.Contains(body, forbidden) {
			w.t.Fatalf("the manifest mentions %q", forbidden)
		}
	}
	var view struct {
		Items []manifestItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		w.t.Fatal(err)
	}
	return view.Items
}

// approve names records one by one; it returns the HTTP status and body of the single all-or-nothing request.
func (w *world) approve(items ...manifestItem) (int, string) {
	w.t.Helper()
	refs := make([]map[string]string, 0, len(items))
	for _, it := range items {
		refs = append(refs, map[string]string{"kind": it.Kind, "id": it.ID})
	}
	raw, err := json.Marshal(map[string]any{"items": refs})
	if err != nil {
		w.t.Fatal(err)
	}
	return w.p.Do(http.MethodPost, admin+"/restore/approvals", string(raw), w.cookie, w.csrf)
}

func pick(items []manifestItem, keep func(manifestItem) bool) []manifestItem {
	var out []manifestItem
	for _, it := range items {
		if keep(it) {
			out = append(out, it)
		}
	}
	return out
}

// neverOK requires every operation on both containers to be refused over REST and MCP, and no operational call to reach Docker.
func (w *world) neverOK(who, token string) {
	w.t.Helper()
	before := len(w.spy.calls())
	for _, container := range []string{"edge-proxy", "billing-worker"} {
		for _, op := range []string{"status", "config", "logs", "start", "stop", "restart"} {
			if got := w.restOp(token, op, container, ""); got == okOutcome {
				w.t.Errorf("%s: REST %s %s was allowed", who, op, container)
			}
			if got := w.mcpOp(token, op, container, nil); got == okOutcome {
				w.t.Errorf("%s: MCP %s %s was allowed", who, op, container)
			}
		}
	}
	if got := w.spy.calls(); len(got) != before {
		w.t.Fatalf("%s: a refused request reached Docker: %v", who, got[before:])
	}
}

func TestRestoreNeverRevivesAuthorityOverRESTAndMCP(t *testing.T) {
	t.Parallel() // the world owns its repository, clock, authorizer and loopback server
	w := newWorldFrom(t, auth.NewPolicyE2EWithBackup(t))
	A, B := "edge-proxy", "billing-worker"
	_, groupID, agentID, oldToken := w.newAgent("alice", "ops", "ci-runner")
	selector := func(name string) string {
		return `"selector":{"container_name":"` + name + `","compose_project":"platform","compose_service":"` + name + `"}`
	}
	w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:inspect_status","container:logs"],`+selector(A)+`,"log_tail_max":50}`, http.StatusCreated)
	w.both(oldToken, "status", A, okOutcome, "", nil)
	w.both(oldToken, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})

	// RESTORE-01: the backup is taken BEFORE the token is revoked.
	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"full"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	credential := w.p.Text(`SELECT id FROM agent_credentials WHERE agent_id=? AND state='active'`, agentID)
	if c, out := w.adm(http.MethodPost, admin+"/agents/"+agentID+"/credentials/"+credential+"/revoke", `{}`); c >= 300 {
		t.Fatalf("revoke: %d %v", c, out)
	}
	w.both(oldToken, "status", A, unauth, "", nil) // revoked: no longer accepted anywhere

	// RESTORE-03: a rule created AFTER the backup is one the archive cannot know about.
	w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:start"],`+selector(B)+`}`, http.StatusCreated)
	w.both(oldToken, "status", A, unauth, "", nil)

	// The restore: a full backup into the same installation.
	body := `{"archive":` + archive + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	if c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf); c != http.StatusOK {
		t.Fatalf("restore: %d %s", c, out)
	}
	if w.p.Scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("the restore did not leave quarantine in force")
	}

	t.Run("quarantine: the signed-out administrator and the old token reach nothing", func(t *testing.T) {
		if c, _ := w.p.Do(http.MethodGet, admin+"/restore/manifest", "", w.cookie, w.csrf); c != http.StatusUnauthorized && c != http.StatusForbidden {
			t.Fatalf("the administrator's cookie after the restore: %d", c)
		}
		w.neverOK("old token under quarantine", oldToken)
	})

	w.hostRecover() // the REAL host recovery: a NEW administrator, fresh password and TOTP; nothing the backup carried is revived

	t.Run("after the ceremony nothing imported is effective and the old token is still dead", func(t *testing.T) {
		items := w.manifestItems()
		if len(pick(items, func(m manifestItem) bool { return m.Decision == "approved" })) != 0 {
			t.Fatal("the ceremony approved something")
		}
		for _, q := range []string{`SELECT count(*) FROM agents WHERE state='active'`, `SELECT count(*) FROM groups WHERE state='active'`, `SELECT count(*) FROM policies WHERE state='active'`, `SELECT count(*) FROM agent_credentials WHERE state='active'`} {
			if w.p.Scalar(q) != 0 {
				t.Fatalf("effective after the ceremony: %s", q)
			}
		}
		w.neverOK("old token after the ceremony", oldToken)
	})

	items := w.manifestItems()
	identity := pick(items, func(m manifestItem) bool {
		// The BACKUP administrator (id "u") stays inactive after the ceremony and is not part of what these scenarios approve.
		return m.Approvable && m.ID != "u" && (m.Kind == "endpoint" || m.Kind == "user" || m.Kind == "group" || m.Kind == "agent" || m.Kind == "agent_membership" || m.Kind == "user_membership")
	})
	if len(identity) < 4 {
		t.Fatalf("manifest identity records: %+v", items)
	}
	if c, out := w.approve(identity...); c != http.StatusOK {
		t.Fatalf("approving the identities: %d %s", c, out)
	}

	t.Run("approving the agent never revives its old credential", func(t *testing.T) {
		w.neverOK("old token after the agent was approved", oldToken)
		if w.p.Scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`) != 0 {
			t.Fatal("an approval made a credential effective")
		}
	})

	// RESTORE-01 (second half): a NEW token works only with newly approved rules.
	newToken := w.issue(agentID)
	t.Run("a new token is accepted but holds no scope until its rules are approved", func(t *testing.T) {
		w.both(newToken, "status", A, denied, "", nil)
		w.both(newToken, "logs", A, denied, "tail=5", map[string]any{"tail": 5})
		w.neverOK("new token before any rule", newToken)
	})

	rules := pick(items, func(m manifestItem) bool { return m.Kind == "policy" })
	var inspect, logs, retained []manifestItem
	for _, r := range rules {
		switch {
		case r.Origin == "local_retained":
			retained = append(retained, r)
		case strings.Contains(r.Label, "inspect_status"):
			inspect = append(inspect, r)
		case strings.Contains(r.Label, "logs"):
			logs = append(logs, r)
		}
	}
	if len(inspect) != 1 || len(logs) != 1 || len(retained) != 1 {
		t.Fatalf("rules in the manifest: inspect %d logs %d retained %d (%+v)", len(inspect), len(logs), len(retained), rules)
	}

	t.Run("one approved rule grants exactly its operation; unreviewed scope, the post-backup rule and B stay denied", func(t *testing.T) {
		if c, out := w.approve(inspect...); c != http.StatusOK {
			t.Fatalf("approving the status rule: %d %s", c, out)
		}
		w.both(newToken, "status", A, okOutcome, "", nil)
		w.both(newToken, "logs", A, denied, "tail=5", map[string]any{"tail": 5}) // in the file, not yet approved
		w.both(newToken, "status", B, denied, "", nil)
		w.both(newToken, "start", B, denied, "", nil) // created after the backup: retained, never approved
		if w.p.Scalar(`SELECT count(*) FROM policies WHERE state='active'`) != 1 {
			t.Fatal("exactly one rule should be effective")
		}
	})

	t.Run("the retained post-backup rule was kept, not deleted", func(t *testing.T) {
		if got := w.p.Scalar(`SELECT count(*) FROM policies WHERE id=?`, retained[0].ID); got != 1 {
			t.Fatalf("the post-backup rule is gone (%d rows)", got)
		}
	})

	t.Run("approving the second file rule extends the grant by exactly that rule, with its cap", func(t *testing.T) {
		if c, out := w.approve(logs...); c != http.StatusOK {
			t.Fatalf("approving the logs rule: %d %s", c, out)
		}
		w.both(newToken, "logs", A, okOutcome, "tail=5", map[string]any{"tail": 5})
		w.both(newToken, "logs", A, capExceeded, "tail=51", map[string]any{"tail": 51})
		w.both(newToken, "start", B, denied, "", nil)
		w.both(oldToken, "status", A, unauth, "", nil)
	})
}

// ruleIDFor finds a rule of one operation in a create/list response.
func ruleIDFor(t *testing.T, out map[string]any, operation string) string {
	t.Helper()
	for _, r := range out["rules"].([]any) {
		if m := r.(map[string]any); m["operation"] == operation {
			return m["id"].(string)
		}
	}
	t.Fatalf("no %s rule in %v", operation, out)
	return ""
}

// RESTORE-03/09/11: a restriction the file does not know about is never discarded, an imported ALLOW never overwrites a local
// DENY with the same id, and the manifest shows the imported setting beside the one in force. A partially reviewed restore
// still denies: the retained quarantined DENY keeps applying while the approved ALLOW is only effective where nothing denies it.
func TestRestoreNeverDiscardsALocalDenyDuringPartialReview(t *testing.T) {
	t.Parallel()
	w := newWorldFrom(t, auth.NewPolicyE2EWithBackup(t))
	A := "edge-proxy"
	_, groupID, agentID, _ := w.newAgent("alice", "ops", "ci-runner")
	selector := `"selector":{"container_name":"edge-proxy","compose_project":"platform","compose_service":"edge-proxy"}`
	created := w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:inspect_status","container:logs"],`+selector+`,"log_tail_max":50}`, http.StatusCreated)
	statusRule, logsRule := ruleIDFor(t, created, "container:inspect_status"), ruleIDFor(t, created, "container:logs")

	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"full"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	// After the backup: the logs rule becomes a DENY (same id), and a brand-new DENY on status appears. The file knows neither.
	w.must(http.MethodPut, pol+"/rules/"+logsRule, `{"effect":"DENY",`+selector+`}`, http.StatusOK)
	denyOnStatus := w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"DENY","operations":["container:inspect_status"],`+selector+`}`, http.StatusCreated)
	newDeny := ruleIDFor(t, denyOnStatus, "container:inspect_status")

	body := `{"archive":` + archive + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	if c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf); c != http.StatusOK {
		t.Fatalf("restore: %d %s", c, out)
	}
	w.hostRecover()

	var items []struct {
		manifestItem
		Imported  map[string]any `json:"imported"`
		Effective map[string]any `json:"effective"`
	}
	{
		c, raw := w.p.Do(http.MethodGet, admin+"/restore/manifest", "", w.cookie, w.csrf)
		if c != http.StatusOK {
			t.Fatalf("manifest: %d %s", c, raw)
		}
		var view struct {
			Items []struct {
				manifestItem
				Imported  map[string]any `json:"imported"`
				Effective map[string]any `json:"effective"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(raw), &view); err != nil {
			t.Fatal(err)
		}
		items = view.Items
	}
	byID := map[string]manifestItem{}
	for _, it := range items {
		byID[it.ID] = it.manifestItem
		if it.ID != logsRule {
			continue
		}
		if it.Imported["effect"] != "ALLOW" || it.Effective["effect"] != "DENY" || it.Effective["note"] == nil {
			t.Fatalf("the manifest must show the imported ALLOW beside the effective DENY: imported %v effective %v", it.Imported, it.Effective)
		}
	}
	if byID[newDeny].Origin != "local_retained" || byID[statusRule].Origin != "imported" {
		t.Fatalf("origins: new deny %+v, status rule %+v", byID[newDeny], byID[statusRule])
	}
	if w.p.Text(`SELECT effect FROM policies WHERE id=?`, logsRule) != "DENY" {
		t.Fatal("the imported ALLOW overwrote the local DENY")
	}

	identity := pick(manifestItemsOf(items), func(m manifestItem) bool {
		return m.Approvable && m.ID != "u" && (m.Kind == "endpoint" || m.Kind == "user" || m.Kind == "group" || m.Kind == "agent" || m.Kind == "agent_membership" || m.Kind == "user_membership")
	})
	if c, out := w.approve(identity...); c != http.StatusOK {
		t.Fatalf("identities: %d %s", c, out)
	}
	token := w.issue(agentID)
	// Partial review: only the file's status ALLOW is approved. The retained DENY for the same subject, selector and
	// operation is still quarantined and still denies; the logs rule is a DENY and denies.
	if c, out := w.approve(byID[statusRule]); c != http.StatusOK {
		t.Fatalf("approving the status rule: %d %s", c, out)
	}
	w.both(token, "status", A, denied, "", nil)
	w.both(token, "logs", A, denied, "tail=5", map[string]any{"tail": 5})
	if w.p.Scalar(`SELECT count(*) FROM policies WHERE id=? AND state<>'active'`, newDeny) != 1 {
		t.Fatal("the retained DENY must still be quarantined (not approved, not deleted)")
	}
	// Approving the retained DENY too changes nothing for the better: it is a restriction.
	if c, out := w.approve(byID[newDeny], byID[logsRule]); c != http.StatusOK {
		t.Fatalf("approving the restrictions: %d %s", c, out)
	}
	w.both(token, "status", A, denied, "", nil)
	w.both(token, "logs", A, denied, "tail=5", map[string]any{"tail": 5})
}

func manifestItemsOf(items []struct {
	manifestItem
	Imported  map[string]any `json:"imported"`
	Effective map[string]any `json:"effective"`
}) []manifestItem {
	out := make([]manifestItem, 0, len(items))
	for _, it := range items {
		out = append(out, it.manifestItem)
	}
	return out
}
