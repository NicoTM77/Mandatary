package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18.4 P115-I1: a storage/infrastructure fault inside an authorizer callback
// (transaction begin, VerifyPrincipal, GetEndpoint, policy query) keeps the SAME
// fail-closed public refusal but is NEVER attributed, so the shared operation
// service can never account it as a denial of a verified principal. Logical
// refusals of a verified principal (inactive endpoint, credential revoked during
// acquisition, a real explicit DENY) stay attributed denials.

// hookBackend runs a hook right before the backend resolves a target. byName is
// the Authorize-time resolution (the name or ref the caller sent); byID is the
// immutable-ID resolution of revalidation, so each hook runs between two callbacks.
type hookBackend struct {
	docker.DockerBackend
	byName, byID func()
}

func (b *hookBackend) ResolveTarget(ctx context.Context, ref string) (docker.ContainerSummary, error) {
	if len(ref) == 64 {
		if b.byID != nil {
			b.byID()
		}
	} else if b.byName != nil {
		b.byName()
	}
	return b.DockerBackend.ResolveTarget(ctx, ref)
}

// faultVerifier delegates to the real store verifier except for the n-th call (1-based).
type faultVerifier struct {
	failOn int64
	calls  atomic.Int64
	err    error
}

func (v *faultVerifier) VerifyPrincipal(ctx context.Context, q *store.Queries, c store.InstallationControl, p authz.PrincipalCredentials, now time.Time) (authz.VerifiedPrincipal, error) {
	if v.calls.Add(1) == v.failOn {
		return authz.VerifiedPrincipal{}, v.err
	}
	return authz.NewStoreCredentialVerifier().VerifyPrincipal(ctx, q, c, p, now)
}

type faultCase struct {
	name string
	// arm installs the fault; it receives the env and returns the hooks/verifier to use.
	byName, byID func(e *testEnv)
	verifier     func() *faultVerifier
	// wantAttributed: true for a logical refusal control, false for a storage fault.
	wantAttributed bool
	// wantStatus is the unchanged public shape.
	wantStatus int
	wantReason authz.DenialReason
}

func runFaultCase(t *testing.T, tc faultCase, lease bool) {
	t.Helper()
	e, req := publicationSetup(t)
	hb := &hookBackend{DockerBackend: e.backend}
	if tc.byName != nil {
		hb.byName = func() { tc.byName(e) }
	}
	if tc.byID != nil {
		hb.byID = func() { tc.byID(e) }
	}
	cfg := authz.Config{Repository: e.repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{testLocalEndpointID: hb}}
	if tc.verifier != nil {
		cfg.CredentialVerifier = tc.verifier()
	}
	a, err := authz.NewAuthorizer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	var gotErr error
	if lease {
		var l *authz.Lease
		l, gotErr = a.AcquireLease(context.Background(), req)
		if l != nil {
			l.Release()
		}
	} else {
		_, gotErr = a.Authorize(context.Background(), req)
	}
	if gotErr == nil {
		t.Fatal("a callback fault/refusal must never grant")
	}
	if got := authz.StatusCode(gotErr); got != tc.wantStatus {
		t.Fatalf("status = %d, want %d (%v)", got, tc.wantStatus, gotErr)
	}
	if tc.wantReason != "" && !authz.HasReason(gotErr, tc.wantReason) {
		r, _ := authz.ReasonOf(gotErr)
		t.Fatalf("reason = %q, want %q", r, tc.wantReason)
	}
	attr, ok := authz.AttributionOf(gotErr)
	if ok != tc.wantAttributed {
		t.Fatalf("attribution present=%v want %v (%+v)", ok, tc.wantAttributed, attr)
	}
	if ok && (attr.UserID != testUserID1 || attr.Operation != authz.OpContainerInspectStatus) {
		t.Fatalf("attribution %+v", attr)
	}
	// Sanitized: neither SQL nor the synthetic fault text may leak.
	for _, leak := range []string{"no such table", "SQL", "synthetic", "policies_x", "endpoints_x"} {
		if strings.Contains(gotErr.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, gotErr)
		}
	}
	if got := e.backend.Counters().TotalOperational(); got != 0 {
		t.Fatalf("%d operational attempts", got)
	}
}

func TestAuthorizeCallbackStorageFaultsAreNeverAttributedAsDenials(t *testing.T) {
	cases := []faultCase{
		{name: "transaction-begin-fault", byName: func(e *testEnv) { e.repo.FailClosed() }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDefaultDeny},
		{name: "verifier-generic-error", verifier: func() *faultVerifier { return &faultVerifier{failOn: 1, err: errors.New("synthetic verifier fault")} }, wantStatus: http.StatusUnauthorized},
		{name: "verification-query-fault-sessions", byName: func(e *testEnv) { e.execSQL(`ALTER TABLE sessions RENAME TO sessions_x`) }, wantStatus: http.StatusUnauthorized},
		{name: "get-endpoint-non-norows-fault", byName: func(e *testEnv) { e.execSQL(`ALTER TABLE endpoints RENAME TO endpoints_x`) }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonEndpointInactive},
		{name: "policy-query-fault", byName: func(e *testEnv) { e.execSQL(`ALTER TABLE policies RENAME TO policies_x`) }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDefaultDeny},
		// Logical controls: still true, attributed denials of the verified principal.
		{name: "control-inactive-endpoint-is-a-denial", byName: func(e *testEnv) {
			e.execSQL(`UPDATE endpoints SET state='disabled' WHERE id=?`, string(testLocalEndpointID))
		}, wantAttributed: true, wantStatus: http.StatusForbidden, wantReason: authz.ReasonEndpointInactive},
		{name: "control-explicit-deny-is-a-denial", byName: func(e *testEnv) {
			e.seedPolicy(store.Policy{ID: string(testPolicyID3), UserID: sql.NullString{String: string(testUserID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerInspectStatus), Effect: "DENY"})
		}, wantAttributed: true, wantStatus: http.StatusForbidden, wantReason: authz.ReasonExplicitDeny},
		{name: "control-default-deny-is-a-denial", byName: func(e *testEnv) { e.execSQL(`DELETE FROM policies`) }, wantAttributed: true, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDefaultDeny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runFaultCase(t, tc, false) })
	}
}

func TestLeaseRevalidationCallbackStorageFaultsAreNeverAttributedAsDenials(t *testing.T) {
	cases := []faultCase{
		{name: "mid-callback-verifier-error", verifier: func() *faultVerifier { return &faultVerifier{failOn: 2, err: errors.New("synthetic verifier fault")} }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		{name: "revalidation-verification-query-fault", byID: func(e *testEnv) { e.execSQL(`ALTER TABLE sessions RENAME TO sessions_x`) }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		{name: "revalidation-get-endpoint-non-norows-fault", byID: func(e *testEnv) { e.execSQL(`ALTER TABLE endpoints RENAME TO endpoints_x`) }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		{name: "revalidation-policy-query-fault", byID: func(e *testEnv) { e.execSQL(`ALTER TABLE policies RENAME TO policies_x`) }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		{name: "revalidation-transaction-begin-fault", byID: func(e *testEnv) { e.repo.FailClosed() }, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		// Logical controls during acquisition: a real change of authority IS an attributed denial.
		{name: "control-credential-revoked-during-acquisition", byID: func(e *testEnv) {
			e.execSQL(`UPDATE sessions SET state='revoked', revoked_at=? WHERE id=?`, e.clock.Now().Unix(), string(testSessionID1))
		}, wantAttributed: true, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		{name: "control-explicit-deny-during-acquisition", byID: func(e *testEnv) {
			e.seedPolicy(store.Policy{ID: string(testPolicyID3), UserID: sql.NullString{String: string(testUserID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerInspectStatus), Effect: "DENY"})
		}, wantAttributed: true, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
		{name: "control-endpoint-disabled-during-acquisition", byID: func(e *testEnv) {
			e.execSQL(`UPDATE endpoints SET state='disabled' WHERE id=?`, string(testLocalEndpointID))
		}, wantAttributed: true, wantStatus: http.StatusForbidden, wantReason: authz.ReasonDecisionStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runFaultCase(t, tc, true) })
	}
}
