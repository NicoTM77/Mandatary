package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
)

// P1.18.4 AUTH-10-L1/L2/L3 (P1.10 #192, run440). Every fixture is a real SQLite store, the
// real administrative service and the real shared verifier; random bytes, credentials and
// the notifier are synthetic. Plaintext tokens are DERIVED from scripted random bytes so
// the tests can scan the store, errors and returned values for exactly that canary.

// scriptedDraw makes the next credential's token and identifier deterministic and returns
// the plaintext it will carry. 32 bytes of token material, 16 bytes of identifier.
func (e *adminEnv) scriptedDraw(seed byte) (plaintext []byte) {
	e.t.Helper()
	stream := append(bytes.Repeat([]byte{seed}, 32), bytes.Repeat([]byte{seed ^ 0x5A}, 16)...)
	token, err := newAgentToken(bytes.NewReader(stream[:32]))
	if err != nil {
		e.t.Fatal(err)
	}
	e.a.random = io.MultiReader(bytes.NewReader(stream), rand.Reader) // scripted draw, then real randomness
	return token
}

func (e *adminEnv) credentialByHash(plaintext []byte) (id, state string, overlap *int64) {
	e.t.Helper()
	var o *int64
	if err := e.db.QueryRow(`SELECT id,state,rotation_overlap_until FROM agent_credentials WHERE token_hash=?`, sha(plaintext)).Scan(&id, &state, &o); err != nil {
		e.t.Fatalf("credential lookup: %v", err)
	}
	return id, state, o
}

func (e *adminEnv) liveCount(agent string) int64 {
	return e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state='active'`, agent)
}

func rotationSetup(t *testing.T) (e *adminEnv, agent string, tokenA []byte, a IssuedCredential) {
	t.Helper()
	e = newAdminEnv(t)
	agent = e.agentOwnedBy("bot", e.person("owner"))
	a, tokenA = e.issue(agent, CredentialRequest{})
	return e, agent, tokenA, a
}

var errSyntheticNotifier = errors.New("synthetic notifier failure CANARY-NOTIFY-0123456789")

// AUTH-10-L1 (kills run440 mutant M6: a committed rotation whose notification failed must
// NEVER return the new plaintext) and the notifier-failure part of AUTH-10-L2(a).
func TestRotationNotificationFailureReturnsNoTokenLeavesNoSecretAndKeepsValidSiblings(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, a := rotationSetup(t)
	sibling := e.agentOwnedBy("sibling", e.person("owner2"))
	_, siblingToken := e.issue(sibling, CredentialRequest{})
	siblingBefore := e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state='active'`, sibling)

	newPlain := e.scriptedDraw(0x31)
	e.hook = func(_ context.Context) error { return errSyntheticNotifier }
	start := e.clock.Now().Unix()
	res, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 30 * time.Minute})

	// error: the sanitized unavailable error only
	if !errors.Is(err, ErrAdminUnavailable) {
		t.Fatalf("a failed notification must be reported as unavailable, got %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "synthetic") || strings.Contains(fmt.Sprint(err), "CANARY") {
		t.Fatalf("notifier detail leaked: %v", err)
	}
	// output: nothing from the rotation reaches the caller
	if len(res.New.ExportOnce()) != 0 || res.New.Credential.ID != "" || len(res.RotatedOut) != 0 {
		t.Fatalf("a rotation whose notification failed returned data: %+v", res)
	}
	if strings.Contains(fmt.Sprintf("%v|%+v|%#v|%s", res, res, res, res.New), string(newPlain)) {
		t.Fatal("the new plaintext appears in the formatted result")
	}
	// storage: no plaintext at rest; the durable rotation is intact and fail closed
	if bytes.Contains(e.rawStore(), newPlain) || bytes.Contains(e.rawStore(), tokenA) {
		t.Fatal("a plaintext token reached the store")
	}
	if e.accepted(newPlain) {
		t.Fatal("the undelivered successor is still usable although nobody holds it")
	}
	_, newState, _ := e.credentialByHash(newPlain)
	if newState != "revoked" {
		t.Fatalf("undelivered successor state = %s, want revoked", newState)
	}
	// the in-use predecessor keeps working for exactly its approved window
	_, aState, aOverlap := e.credentialByHash(tokenA)
	if aState != "active" || aOverlap == nil || *aOverlap != start+int64((30*time.Minute)/time.Second) {
		t.Fatalf("predecessor state=%s overlap=%v, want active until %d", aState, aOverlap, start+1800)
	}
	if !e.accepted(tokenA) {
		t.Fatal("the in-use credential lost its grace on a failed notification")
	}
	// valid sibling controls are untouched
	if !e.accepted(siblingToken) || e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state='active'`, sibling) != siblingBefore {
		t.Fatal("an unrelated agent's credential was affected")
	}
	if e.notifications() == 0 {
		t.Fatal("the notifier was never called")
	}
	_ = a
}

// AUTH-10-L2(a): the retry after a notification-failed rotation must not revoke the in-use
// credential and thereby lose its remaining grace.
func TestRetryAfterANotificationFailedRotationKeepsTheInUseCredentialsRemainingGrace(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, _ := rotationSetup(t)
	start := e.clock.Now().Unix()

	e.scriptedDraw(0x41)
	e.hook = func(_ context.Context) error { return errSyntheticNotifier }
	if _, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour}); !errors.Is(err, ErrAdminUnavailable) {
		t.Fatalf("first attempt: %v", err)
	}
	e.hook = nil
	e.advance(20 * time.Minute) // 40 minutes of grace remain
	retryPlain := e.scriptedDraw(0x42)
	res, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 10 * time.Minute})
	if err != nil {
		t.Fatalf("the retry must succeed: %v", err)
	}
	if !bytes.Equal(res.New.ExportOnce(), retryPlain) {
		t.Fatal("the retry did not deliver its own new token")
	}
	// the in-use credential: still live, same original deadline (never extended, not shortened)
	id, state, overlap := e.credentialByHash(tokenA)
	if state != "active" || overlap == nil || *overlap != start+3600 {
		t.Fatalf("in-use credential state=%s overlap=%v, want active until %d (its ORIGINAL window)", state, overlap, start+3600)
	}
	if len(res.RotatedOut) != 1 || res.RotatedOut[0].ID != id || res.RotatedOut[0].OverlapUntil == nil || *res.RotatedOut[0].OverlapUntil != start+3600 {
		t.Fatalf("rotated-out label wrong: %+v", res.RotatedOut)
	}
	if !e.accepted(tokenA) || !e.accepted(retryPlain) {
		t.Fatal("both the in-use credential and the delivered token must be accepted during the remaining grace")
	}
	if n := e.liveCount(agent); n != 2 {
		t.Fatalf("live credentials = %d, want exactly 2", n)
	}
	// boundary: accepted one second before the ORIGINAL end, rejected at it; never revived
	e.advance(40*time.Minute - time.Second)
	if !e.accepted(tokenA) {
		t.Fatal("grace ended early")
	}
	e.advance(time.Second)
	if e.accepted(tokenA) {
		t.Fatal("rotated-out token accepted at its original overlap boundary")
	}
	if !e.accepted(retryPlain) {
		t.Fatal("the delivered token must outlive the overlap")
	}
	e.clock.Advance(24 * time.Hour) // no admin call follows, so the session need not stay fresh
	if e.accepted(tokenA) {
		t.Fatal("an expired rotated-out token was revived")
	}
}

// AUTH-10-L2(b) plus its adversarial controls.
func TestRotationAfterTheSuccessorWasRevokedKeepsTheRemainingGraceAndNeverResurrects(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, _ := rotationSetup(t)
	start := e.clock.Now().Unix()
	first, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	tokenB := first.New.ExportOnce()
	if err := e.a.RevokeCredential(e.t.Context(), e.secret, agent, first.New.Credential.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(15 * time.Minute)
	if e.accepted(tokenB) || !e.accepted(tokenA) {
		t.Fatal("precondition: successor revoked, predecessor still in grace")
	}

	// Replay of the same request while an unnotified/old token is still presented is harmless.
	if e.accepted(tokenB) {
		t.Fatal("revoked token accepted")
	}
	// A conflicting retry shape is still validated first: immediate AND an overlap is invalid.
	if _, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: time.Minute, Immediate: true}); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("immediate with overlap: %v", err)
	}
	if !e.accepted(tokenA) {
		t.Fatal("an invalid request changed state")
	}

	plainC := e.scriptedDraw(0x51)
	second, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 5 * time.Minute})
	if err != nil {
		t.Fatalf("re-rotation: %v", err)
	}
	if !bytes.Equal(second.New.ExportOnce(), plainC) {
		t.Fatal("new token not delivered")
	}
	_, aState, aOverlap := e.credentialByHash(tokenA)
	if aState != "active" || aOverlap == nil || *aOverlap != start+3600 {
		t.Fatalf("predecessor %s/%v, want its original grace until %d (not 5 minutes, not extended)", aState, aOverlap, start+3600)
	}
	if _, bState, _ := e.credentialByHash(tokenB); bState != "revoked" || e.accepted(tokenB) {
		t.Fatal("the explicitly revoked successor was resurrected")
	}
	if !e.accepted(tokenA) || !e.accepted(plainC) || e.liveCount(agent) != 2 {
		t.Fatalf("expected A and C live (2), got live=%d", e.liveCount(agent))
	}

	// Rotating a THIRD time is the approved two-live rule: the credential in overlap goes at once.
	third, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	_ = third.New.ExportOnce()
	if e.accepted(tokenA) || !e.accepted(plainC) || e.liveCount(agent) != 2 {
		t.Fatal("the third rotation must retire the credential in overlap and keep two live")
	}
}

// Immediate mode explicitly removes the grace: that is the administrator's choice, unchanged.
func TestImmediateRotationStillRevokesTheSoleOverlappingCredentialAtOnce(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, _ := rotationSetup(t)
	first, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = first.New.ExportOnce()
	if err := e.a.RevokeCredential(e.t.Context(), e.secret, agent, first.New.Credential.ID); err != nil {
		t.Fatal(err)
	}
	res, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Immediate: true})
	if err != nil {
		t.Fatal(err)
	}
	newToken := res.New.ExportOnce()
	if e.accepted(tokenA) || !e.accepted(newToken) || e.liveCount(agent) != 1 {
		t.Fatal("immediate rotation must revoke the old credential at once and leave exactly the new one")
	}
}

// Boundary expiry, restart (a fresh service over the same durable state), tightened maximum.
func TestSoleOverlappingCredentialRotationHonoursBoundaryExpiryRestartAndTheCurrentMaximum(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, _ := rotationSetup(t)
	start := e.clock.Now().Unix()
	first, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = first.New.ExportOnce()
	if err := e.a.RevokeCredential(e.t.Context(), e.secret, agent, first.New.Credential.ID); err != nil {
		t.Fatal(err)
	}

	// "Restart": a brand-new Admin with a TIGHTER configured maximum (10 min) over the same store.
	tight := DefaultAdminSettings()
	tight.MaxOverlap = 10 * time.Minute
	tight.DefaultOverlap = 5 * time.Minute
	restarted, err := NewAdmin(e.l, tight, e.notify)
	if err != nil {
		t.Fatal(err)
	}
	e.advance(30 * time.Minute) // 90 minutes of grace remain, far above the new maximum
	res, err := restarted.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	_ = res.New.ExportOnce()
	_, _, overlap := e.credentialByHash(tokenA)
	want := e.clock.Now().Unix() + 600
	if overlap == nil || *overlap != want {
		t.Fatalf("overlap %v, want clamped to now+MaxOverlap = %d (never extended, never beyond the configured maximum; original end was %d)", overlap, want, start+7200)
	}
	e.advance(10*time.Minute - time.Second)
	if !e.accepted(tokenA) {
		t.Fatal("grace ended early")
	}
	e.advance(time.Second)
	if e.accepted(tokenA) {
		t.Fatal("accepted at the clamped boundary")
	}

	// Boundary expiry of the sole overlapping credential itself: nothing live => conflict, never a resurrection.
	e2, agent2, tokenA2, _ := rotationSetup(t)
	r2, err := e2.a.RotateCredential(e2.t.Context(), e2.secret, agent2, RotateRequest{Overlap: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.a.RevokeCredential(e2.t.Context(), e2.secret, agent2, r2.New.Credential.ID); err != nil {
		t.Fatal(err)
	}
	e2.advance(time.Minute) // exactly the boundary second: the old token is rejected
	if e2.accepted(tokenA2) {
		t.Fatal("accepted at the boundary second")
	}
	if _, err := e2.a.RotateCredential(e2.t.Context(), e2.secret, agent2, RotateRequest{}); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("nothing live: rotation must conflict, got %v", err)
	}
	if e2.accepted(tokenA2) {
		t.Fatal("a failed rotation revived an expired token")
	}
	if _, err := e2.a.IssueCredential(e2.t.Context(), e2.secret, agent2, CredentialRequest{}); err != nil {
		t.Fatalf("explicit re-issue is the documented path: %v", err)
	}
}

// Concurrency: serialized control transactions never exceed two live credentials and the
// in-use credential's end is never extended, however the retries interleave.
func TestConcurrentRotationsFromTheSoleOverlappingStateKeepTheBoundAndNeverExtendTheGrace(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, _ := rotationSetup(t)
	start := e.clock.Now().Unix()
	first, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_ = first.New.ExportOnce()
	if err := e.a.RevokeCredential(e.t.Context(), e.secret, agent, first.New.Credential.ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: 20 * time.Minute})
			if err == nil {
				_ = res.New.ExportOnce()
			} else if !errors.Is(err, ErrAdminConflict) && !errors.Is(err, ErrAdminUnavailable) {
				t.Errorf("unexpected rotation error: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := e.liveCount(agent); n > 2 {
		t.Fatalf("live credentials = %d, want at most 2", n)
	}
	_, _, overlap := e.credentialByHash(tokenA)
	if overlap != nil && *overlap > start+3600 {
		t.Fatalf("grace extended to %d beyond its original %d", *overlap, start+3600)
	}
}

// Storage fault during the discard: the durable rotation stays, fail closed, and still no plaintext.
func TestFailedNotificationWithAFailedDiscardStillNeverReturnsOrStoresTheToken(t *testing.T) {
	t.Parallel()
	e, agent, tokenA, _ := rotationSetup(t)
	newPlain := e.scriptedDraw(0x61)
	e.hook = func(_ context.Context) error {
		e.l.repo.FailClosed() // the notifier fails AND the store becomes unavailable
		return errSyntheticNotifier
	}
	res, err := e.a.RotateCredential(e.t.Context(), e.secret, agent, RotateRequest{Overlap: time.Hour})
	if !errors.Is(err, ErrAdminUnavailable) || len(res.New.ExportOnce()) != 0 {
		t.Fatalf("got %v / %+v", err, res)
	}
	if bytes.Contains(e.rawStore(), newPlain) || bytes.Contains(e.rawStore(), tokenA) {
		t.Fatal("a plaintext token reached the store")
	}
	if strings.Contains(fmt.Sprint(err), "synthetic") {
		t.Fatal("notifier detail leaked")
	}
}

// AUTH-10-L1 run440 gap: DisableAgent and membership changes whose notification fails.
func TestNotificationFailureAfterDisableAgentAndMembershipChangesKeepsTheDurableChangeAndNoLeaseIsRevived(t *testing.T) {
	t.Parallel()
	h := newAuthzHarness(t)
	ctx := h.t.Context()
	owner, group := h.person("owner"), h.group("team")
	agent := h.agentOwnedBy("bot", owner)
	_, token := h.issue(agent, CredentialRequest{})
	h.allow("group_id", group)
	if err := h.a.AddMember(ctx, h.secret, group, MemberAgent, agent); err != nil {
		t.Fatal(err)
	}
	lease, err := h.az.AcquireLease(ctx, h.request(token))
	if err != nil {
		t.Fatalf("precondition: group-granted agent must hold a lease: %v", err)
	}
	defer lease.Release()

	fail := func(_ context.Context) error { return errSyntheticNotifier }
	check := func(label string, err error) {
		t.Helper()
		if !errors.Is(err, ErrAdminUnavailable) {
			t.Fatalf("%s: notification failure must be the sanitized unavailable error, got %v", label, err)
		}
		if strings.Contains(fmt.Sprint(err), "synthetic") || strings.Contains(fmt.Sprint(err), "CANARY") {
			t.Fatalf("%s: notifier detail leaked: %v", label, err)
		}
	}

	// Membership removal: durable although the authorizer was not told.
	h.hook = fail
	check("RemoveMember", h.a.RemoveMember(ctx, h.secret, group, MemberAgent, agent))
	if h.scalar(`SELECT count(*) FROM agent_group_memberships WHERE agent_id=? AND group_id=? AND state='disabled'`, agent, group) != 1 {
		t.Fatal("RemoveMember was undone by a notifier failure")
	}
	if err := h.authorize(token); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("the removed member kept the group grant after a failed notification: %v", err)
	}
	if err := lease.Revalidate(ctx); err == nil {
		t.Fatal("a stale lease survived revalidation against the durable membership removal")
	}

	// Membership re-addition with a failing notifier: reported, durable, and still no lease grant is revived.
	h.hook = nil
	lease2, err := h.az.AcquireLease(ctx, h.request(token))
	if err == nil {
		lease2.Release()
		t.Fatal("the removed member acquired a lease")
	}
	h.hook = fail
	check("AddMember", h.a.AddMember(ctx, h.secret, group, MemberAgent, agent))
	if h.scalar(`SELECT count(*) FROM agent_group_memberships WHERE agent_id=? AND group_id=? AND state='active'`, agent, group) != 1 {
		t.Fatal("AddMember was rolled back by a notifier failure")
	}
	if lease.Context().Err() == nil {
		t.Fatal("a canceled lease was revived by a membership re-grant")
	}

	// DisableAgent with a failing notifier: credentials revoked and agent disabled durably.
	check("DisableAgent", h.a.DisableAgent(ctx, h.secret, agent))
	if h.accepted(token) {
		t.Fatal("the disabled agent's token is accepted")
	}
	if h.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state!='revoked'`, agent) != 0 || h.scalar(`SELECT count(*) FROM agents WHERE id=? AND state='disabled'`, agent) != 1 {
		t.Fatal("DisableAgent was undone by a notifier failure")
	}
	if err := h.authorize(token); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("a disabled agent's token must be refused, got %v", err)
	}
	if lease3, err := h.az.AcquireLease(ctx, h.request(token)); err == nil {
		lease3.Release()
		t.Fatal("a lease was granted to a disabled agent")
	}
	if lease.Context().Err() == nil {
		t.Fatal("the original lease is alive after the agent was disabled")
	}
}

// AUTH-10-L3: the claim that the schema forbids an active credential behind a non-active
// agent was wrong (migration 00012 has no such trigger, by design). The truth, pinned here:
// SQLite accepts that state and the shared verifier refuses the credential on every request.
func TestCredentialBehindANonActiveAgentIsRejectedByTheVerifierNotByTheSchema(t *testing.T) {
	t.Parallel()
	e, agent, token, _ := rotationSetup(t)
	if !e.accepted(token) {
		t.Fatal("control: the credential must be accepted while the agent is active")
	}
	// No trigger or constraint stops an active credential behind a disabled agent...
	e.exec(`UPDATE agents SET state='disabled' WHERE id=?`, agent)
	if e.scalar(`SELECT count(*) FROM agent_credentials WHERE agent_id=? AND state='active'`, agent) != 1 {
		t.Fatal("setup: the active credential must remain behind the disabled agent")
	}
	// ...so the runtime verifier is the control, and it rejects it.
	if e.accepted(token) {
		t.Fatal("the verifier accepted a credential of a disabled agent")
	}
}

// AUTH-10-L4 (P1.10 #192 Info, carried to P1.18): RemoveMember followed by AddMember is an
// EXPLICIT re-grant of exactly the named principal+group record by the fresh administrator; it
// is never a silent approval of a restored (quarantined) membership. AddMember alone refuses a
// quarantined or stale-generation membership (conflict: reapproval belongs to restore), the
// removal touches only that record, nothing else is unquarantined, the effective authority is
// still decided by the group's own rules, and replays change nothing. The restore UI shows
// principal AND group for the approval of these records (FC4-1).
func TestRemoveThenAddOfARestoredMembershipIsAnExplicitRegrantOfExactlyThatRecord(t *testing.T) {
	t.Parallel()
	h := newAuthzHarness(t)
	ctx := h.t.Context()
	owner := h.person("owner")
	g1, g2 := h.group("shared-name-a"), h.group("shared-name-b")
	m1, m2 := h.agentOwnedBy("member-one", owner), h.agentOwnedBy("member-two", owner)
	_, tok1 := h.issue(m1, CredentialRequest{})
	_, tok2 := h.issue(m2, CredentialRequest{})
	h.allow("group_id", g1)
	for _, m := range []string{m1, m2} {
		if err := h.a.AddMember(ctx, h.secret, g1, MemberAgent, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.a.AddMember(ctx, h.secret, g2, MemberAgent, m1); err != nil {
		t.Fatal(err)
	}
	// Simulate the restore import: every membership is quarantined, the group rule stays as is.
	h.exec(`UPDATE agent_group_memberships SET state='quarantined'`)
	rows := func() string {
		var b strings.Builder
		r, err := h.db.Query(`SELECT agent_id,group_id,state,authority_generation FROM agent_group_memberships ORDER BY agent_id,group_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		for r.Next() {
			var a, g, s string
			var gen int64
			if err := r.Scan(&a, &g, &s, &gen); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%s|%s|%s|%d\n", a, g, s, gen)
		}
		return b.String()
	}
	policiesBefore := h.snapshot()["policies"]
	if err := h.authorize(tok1); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("a quarantined membership granted authority: %v", err)
	}

	// AddMember alone never approves it.
	before := rows()
	if err := h.a.AddMember(ctx, h.secret, g1, MemberAgent, m1); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("AddMember over a quarantined membership must conflict, got %v", err)
	}
	if rows() != before {
		t.Fatal("a refused AddMember changed a membership")
	}

	// Explicit removal disables exactly (m1, g1): the sibling record and the other group's record stay quarantined.
	if err := h.a.RemoveMember(ctx, h.secret, g1, MemberAgent, m1); err != nil {
		t.Fatal(err)
	}
	state := func(agent, group string) string {
		var s string
		if err := h.db.QueryRow(`SELECT state FROM agent_group_memberships WHERE agent_id=? AND group_id=?`, agent, group).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if state(m1, g1) != "disabled" || state(m2, g1) != "quarantined" || state(m1, g2) != "quarantined" {
		t.Fatalf("collateral state change after removal: %q", rows())
	}
	// Replay of the removal is harmless.
	if err := h.a.RemoveMember(ctx, h.secret, g1, MemberAgent, m1); err != nil {
		t.Fatalf("removal replay: %v", err)
	}
	// A different pair with similar IDs (m2 in g2) is its own membership: AddMember may create it as a NEW active record or refuse it, and either
	// outcome is acceptable here. What it must never do is touch the removed (m1, g1) record or the two still-quarantined siblings.
	if err := h.a.AddMember(ctx, h.secret, g2, MemberAgent, m2); err != nil && !errors.Is(err, ErrAdminNotFound) && !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("unrelated pair: %v", err)
	}
	if state(m1, g1) != "disabled" || state(m2, g1) != "quarantined" || state(m1, g2) != "quarantined" {
		t.Fatalf("adding an unrelated pair changed a record that was not named: %q", rows())
	}

	// Explicit re-grant: that one record becomes active at the CURRENT generation.
	if err := h.a.AddMember(ctx, h.secret, g1, MemberAgent, m1); err != nil {
		t.Fatalf("explicit re-grant: %v", err)
	}
	var gen int64
	if err := h.db.QueryRow(`SELECT authority_generation FROM agent_group_memberships WHERE agent_id=? AND group_id=?`, m1, g1).Scan(&gen); err != nil || state(m1, g1) != "active" || gen != 1 {
		t.Fatalf("re-grant did not produce an active current-generation record (state=%s gen=%d err=%v)", state(m1, g1), gen, err)
	}
	if state(m2, g1) != "quarantined" || state(m1, g2) != "quarantined" {
		t.Fatalf("another quarantined record was approved as a side effect: %q", rows())
	}
	if h.snapshot()["policies"] != policiesBefore {
		t.Fatal("a rule changed during a membership re-grant")
	}
	// Effective authority: the re-granted member now gets the group's ACTIVE rule; the member
	// whose record is still quarantined gets nothing.
	if err := h.authorize(tok1); err != nil {
		t.Fatalf("re-granted member refused although the group rule is active: %v", err)
	}
	if err := h.authorize(tok2); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("a still-quarantined member was authorized: %v", err)
	}
	// Replay of the re-grant is a no-op.
	snap := h.snapshot()
	if err := h.a.AddMember(ctx, h.secret, g1, MemberAgent, m1); err != nil {
		t.Fatal(err)
	}
	if h.snapshot()["agent_group_memberships"] != snap["agent_group_memberships"] {
		t.Fatal("replaying the re-grant changed state")
	}

	// A quarantined GROUP RULE is never approved by the membership path.
	h.exec(`UPDATE policies SET state='quarantined'`)
	if err := h.authorize(tok1); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("membership re-grant approved a quarantined rule: %v", err)
	}

	// A stale-generation record is also not silently usable: AddMember conflicts until it is explicitly removed first.
	h.exec(`UPDATE policies SET state='active'`)
	h.exec(`UPDATE agent_group_memberships SET authority_generation=2 WHERE agent_id=? AND group_id=?`, m1, g1)
	if err := h.authorize(tok1); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("a stale-generation membership granted authority: %v", err)
	}
	if err := h.a.AddMember(ctx, h.secret, g1, MemberAgent, m1); !errors.Is(err, ErrAdminConflict) {
		t.Fatalf("stale-generation record: AddMember must conflict, got %v", err)
	}
	if err := h.a.RemoveMember(ctx, h.secret, g1, MemberAgent, m1); err != nil {
		t.Fatal(err)
	}
	if err := h.a.AddMember(ctx, h.secret, g1, MemberAgent, m1); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT authority_generation FROM agent_group_memberships WHERE agent_id=? AND group_id=?`, m1, g1).Scan(&gen); err != nil || gen != 1 {
		t.Fatalf("explicit re-grant must set the current generation, got %d (%v)", gen, err)
	}
}
