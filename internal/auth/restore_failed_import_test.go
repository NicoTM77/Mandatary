package auth_test

// P1.18.4 P118-L2 (the failed-import safety reset) and C4-O4 (the authority-change push is
// asserted independently of the safety reset). Both promote reviewer probes of the P1.18
// execution review into permanent tests. The Docker daemon is the in-memory MockBackend:
// component evidence, not a real-daemon test.

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/docker"
)

// A restore whose transition COMMITTED but whose import then failed has already rotated every
// generation and revoked every session, so it must still drop the shared self-protection proof
// (the reviewer's RP-1). Removing the safety reset from that path is killed here; the
// partial import is rolled back and nothing reaches the backend.
func TestAFailedImportAfterTheTransitionStillDropsTheSelfProtectionProofAndReachesNoBackend(t *testing.T) {
	t.Parallel()
	w := newWorldFrom(t, auth.NewPolicyE2EWithBackup(t))
	var resets atomic.Int32
	w.p.Admin.WithSafetyReset(func() {
		resets.Add(1)
		w.az.InvalidateSelfProtection()
	})
	A := "edge-proxy"
	_, groupID, _, oldToken := w.newAgent("alice", "ops", "ci-runner")
	selector := `"selector":{"container_name":"edge-proxy","compose_project":"platform","compose_service":"edge-proxy"}`
	w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:inspect_status"],`+selector+`}`, http.StatusCreated)
	w.both(oldToken, "status", A, okOutcome, "", nil)
	if w.mock.VerificationState() != docker.StateVerified {
		t.Fatal("the fixture backend is not verified before the restore")
	}
	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"full"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	if resets.Load() != 0 {
		t.Fatal("an export reset the safety proof")
	}
	groupsBefore := w.p.Scalar(`SELECT count(*) FROM groups`)
	policiesBefore := w.p.Scalar(`SELECT count(*) FROM policies`)
	callsBefore := len(w.spy.calls())

	// The import fails AFTER the quarantine transition committed (SQLite itself refuses the
	// group row, exactly like the existing HTTP failure test).
	for _, ev := range []string{"INSERT", "UPDATE"} {
		w.p.Exec(`CREATE TRIGGER p1184_fail_group_` + strings.ToLower(ev) + ` BEFORE ` + ev + ` ON groups BEGIN SELECT RAISE(ABORT,'synthetic import failure'); END`)
	}
	body := `{"archive":` + archive + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf)
	if c != http.StatusServiceUnavailable || !strings.Contains(out, `"installation_state":"restore_quarantine"`) {
		t.Fatalf("failed import: %d %s", c, out)
	}
	if strings.Contains(out, "synthetic") {
		t.Fatal("the failure text was reflected")
	}

	// The reset ran exactly once on this path, BEFORE the call returned: the proof is gone.
	if resets.Load() != 1 {
		t.Fatalf("the safety reset ran %d times on a failed import, want 1", resets.Load())
	}
	if w.mock.VerificationState() != docker.StateUnverified {
		t.Fatal("a failed import after the transition left the self-protection proof in place")
	}
	// The partial import was rolled back, the transition (quarantine, ended sessions) stayed.
	if w.p.Scalar(`SELECT count(*) FROM groups`) != groupsBefore || w.p.Scalar(`SELECT count(*) FROM policies`) != policiesBefore {
		t.Fatal("a failed import left partially imported records")
	}
	if w.p.Scalar(`SELECT restore_quarantined FROM installation_control`) != 1 || w.p.Scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 {
		t.Fatal("the transition must stay committed: quarantined, no active session")
	}
	// The previously valid agent is refused on both transports and nothing reaches Docker.
	w.both(oldToken, "status", A, outcome{status: 403, code: "forbidden", reason: "restore_quarantined"}, "", nil)
	if got := w.spy.calls(); len(got) != callsBefore {
		t.Fatalf("a request reached Docker after the failed import: %v", got[callsBefore:])
	}
	// Control: the endpoint inventory without a proof is refused, not served.
	if _, err := w.az.ListEndpointContainers(t.Context(), w.p.EndpointID); err == nil {
		t.Fatal("the endpoint inventory was served without a verified proof")
	}
}

// The notifier contract (C4-O4): the shared authorizer is TOLD about every committed authority
// change (restore, failed-import restore, each reapproval). The safety reset also cancels active
// streams, which used to mask a missing push in the integrated stream mutant; here the push is
// asserted through an INDEPENDENT hook with the safety reset deliberately removed, so only the
// notifier can account for the observation. Both defenses stay.
func TestRestoreAndReapprovalPushAuthorityChangeThroughTheNotifierIndependentlyOfTheSafetyReset(t *testing.T) {
	t.Parallel()
	w := newWorldFrom(t, auth.NewPolicyE2EWithBackup(t))
	var pushes atomic.Int32
	w.p.SetNotify(func(context.Context) error { pushes.Add(1); return nil })
	w.p.Admin.WithSafetyReset(nil) // no reset at all: the notifier alone is under observation

	_, groupID, _, _ := w.newAgent("alice", "ops", "ci-runner")
	selector := `"selector":{"container_name":"edge-proxy","compose_project":"platform","compose_service":"edge-proxy"}`
	w.must(http.MethodPost, pol+"/rules", `{"subject":{"kind":"group","id":"`+groupID+`"},"effect":"ALLOW","operations":["container:inspect_status"],`+selector+`}`, http.StatusCreated)
	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"full"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	if pushes.Load() != 0 {
		// Earlier mutations (setup) may notify; only the DELTA of each step is asserted below.
		pushes.Store(0)
	}
	body := `{"archive":` + archive + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	if c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf); c != http.StatusOK {
		t.Fatalf("restore: %d %s", c, out)
	}
	if pushes.Load() != 1 {
		t.Fatalf("a committed restore pushed %d authority-change notifications, want exactly 1", pushes.Load())
	}

	w.hostRecover()
	before := pushes.Load()
	items := w.manifestItems()
	approvable := pick(items, func(m manifestItem) bool {
		return m.Approvable && m.Kind != "endpoint" && m.Kind != "policy" && m.ID != "u"
	})
	if len(approvable) == 0 {
		t.Fatalf("no approvable identity record in the manifest: %+v", items)
	}
	if c, out := w.approve(approvable...); c != http.StatusOK {
		t.Fatalf("approval: %d %s", c, out)
	}
	if pushes.Load() != before+1 {
		t.Fatalf("a reapproval pushed %d notifications, want exactly 1", pushes.Load()-before)
	}
	// A REFUSED approval changes nothing and pushes nothing.
	before = pushes.Load()
	if c, _ := w.approve(manifestItem{Kind: "principal", ID: "no-such-record"}); c == http.StatusOK {
		t.Fatal("approving an unknown record succeeded")
	}
	if pushes.Load() != before {
		t.Fatal("a refused approval pushed an authority-change notification")
	}
}

// And a failed import is still a committed authority change (the sessions ended and the
// generations rotated), so the notifier is told there too.
func TestAFailedImportPushesTheCommittedAuthorityChange(t *testing.T) {
	t.Parallel()
	w := newWorldFrom(t, auth.NewPolicyE2EWithBackup(t))
	var pushes atomic.Int32
	w.p.SetNotify(func(context.Context) error { pushes.Add(1); return nil })
	w.p.Admin.WithSafetyReset(nil)
	w.newAgent("alice", "ops", "ci-runner")
	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"full"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	for _, ev := range []string{"INSERT", "UPDATE"} {
		w.p.Exec(`CREATE TRIGGER p1184_push_group_` + strings.ToLower(ev) + ` BEFORE ` + ev + ` ON groups BEGIN SELECT RAISE(ABORT,'synthetic import failure'); END`)
	}
	pushes.Store(0)
	body := `{"archive":` + archive + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	if c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf); c != http.StatusServiceUnavailable {
		t.Fatalf("failed import: %d %s", c, out)
	}
	if pushes.Load() != 1 {
		t.Fatalf("a failed import after the transition pushed %d notifications, want exactly 1", pushes.Load())
	}
}
