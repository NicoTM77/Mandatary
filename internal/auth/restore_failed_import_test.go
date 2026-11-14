package auth_test

// P1.18.4 P118-L2 (the failed-import safety reset) and C4-O4 (the authority-change push is
// asserted independently of the safety reset). Both promote reviewer probes of the P1.18
// execution review into permanent tests. The Docker daemon is the in-memory MockBackend:
// component evidence, not a real-daemon test.

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/authz"
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

	// A live lease (an in-flight stream) held by the still-valid agent before the restore: it must have ended when the call returns (round-1 review).
	lease, err := w.az.AcquireLease(t.Context(), authz.AuthorizeRequest{Principal: authz.PrincipalCredentials{AgentToken: oldToken}, EndpointID: w.p.EndpointID, TargetRef: A, Operation: authz.OpContainerInspectStatus})
	if err != nil {
		t.Fatalf("baseline lease: %v", err)
	}
	defer lease.Release()
	if lease.Context().Err() != nil || w.az.ActiveLeaseCount() != 1 {
		t.Fatal("the baseline lease is not live: the check below would prove nothing")
	}

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
	if lease.Context().Err() == nil || w.az.ActiveLeaseCount() != 0 {
		t.Fatalf("a live lease survived the failed import (active leases %d)", w.az.ActiveLeaseCount())
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

// The control for the test above (round-1 review, reviewer mutant MP1): a restore REFUSED before the quarantine transition changed nothing, so it must
// not drop the self-protection proof, end a lease, end the administrator's session or call the safety reset. A clean archive whose origin this
// installation cannot verify, sent without the explicit acknowledgement, is refused by the restore service itself (after the archive was opened,
// before the transition). Calling the reset on that refusal fails this test.
func TestARestoreRefusedBeforeTheTransitionKeepsTheProofTheLeaseAndTheSession(t *testing.T) {
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
	lease, err := w.az.AcquireLease(t.Context(), authz.AuthorizeRequest{Principal: authz.PrincipalCredentials{AgentToken: oldToken}, EndpointID: w.p.EndpointID, TargetRef: A, Operation: authz.OpContainerInspectStatus})
	if err != nil {
		t.Fatalf("baseline lease: %v", err)
	}
	defer lease.Release()
	code, archive := w.p.Do(http.MethodPost, admin+"/backup/export", `{"mode":"clean"}`, w.cookie, w.csrf)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, archive)
	}
	foreign := regexp.MustCompile(`"integrity_hmac":"[^"]*"`).ReplaceAllStringFunc(archive, func(m string) string {
		return `"integrity_hmac":"` + strings.Repeat("A", len(m)-len(`"integrity_hmac":""`)) + `"`
	})
	if foreign == archive {
		t.Fatal("the archive has no integrity tag to replace: the scenario proves nothing")
	}
	sessions := w.p.Scalar(`SELECT count(*) FROM sessions WHERE state='active'`)
	generation := w.p.Scalar(`SELECT restore_generation FROM installation_control`)
	if sessions == 0 {
		t.Fatal("no active session before the refused restore")
	}

	body := `{"archive":` + foreign + `,"confirm":"RESTORE","acknowledge_unauthenticated_provenance":false}`
	c, out := w.p.Do(http.MethodPost, admin+"/restore", body, w.cookie, w.csrf)
	if c == http.StatusOK || c == http.StatusServiceUnavailable || strings.Contains(out, "restore_quarantine") {
		t.Fatalf("an unacknowledged unverifiable archive was not refused before the transition: %d %s", c, out)
	}
	if resets.Load() != 0 {
		t.Fatalf("a restore refused before the transition called the safety reset %d times", resets.Load())
	}
	if w.mock.VerificationState() != docker.StateVerified {
		t.Fatal("a refused restore dropped the self-protection proof")
	}
	if lease.Context().Err() != nil || w.az.ActiveLeaseCount() != 1 {
		t.Fatal("a refused restore ended a live lease")
	}
	if w.p.Scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != sessions || w.p.Scalar(`SELECT restore_generation FROM installation_control`) != generation ||
		w.p.Scalar(`SELECT restore_quarantined FROM installation_control`) != 0 {
		t.Fatal("a refused restore changed the sessions, the generation or the quarantine")
	}
	w.must(http.MethodGet, pol+"/rules", "", http.StatusOK) // the administrator's session is still alive
	w.both(oldToken, "status", A, okOutcome, "", nil)
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
