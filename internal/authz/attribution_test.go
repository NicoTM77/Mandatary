package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.15: the authorizer exposes the secret-free attribution of its outcomes so the
// shared operation service can account them (TD 9.1). These tests pin exactly WHEN
// an attribution exists: only after the principal was verified, and a selector only
// when a policy selector decided the outcome.

func attributionAgentSetup(t *testing.T, ownerGroup bool) (*testEnv, authz.AuthorizeRequest) {
	t.Helper()
	e, human := publicationSetup(t)
	owner := sql.NullString{String: string(testUserID1), Valid: true}
	if ownerGroup {
		e.seedGroup(testGroupID1, "ops", "active", 1)
		owner = sql.NullString{}
	}
	opts := seedAgentOpts{ID: testAgentID1, Name: "bot", OwnerUserID: owner}
	if ownerGroup {
		opts.OwnerGroupID = sql.NullString{String: string(testGroupID1), Valid: true}
	}
	e.seedAgent(opts)
	token := e.seedAgentCredential(seedAgentCredentialOpts{ID: testCredID1, AgentID: testAgentID1})
	e.seedPolicy(store.Policy{ID: string(testPolicyID2), AgentID: sql.NullString{String: string(testAgentID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerInspectStatus), Effect: "ALLOW"})
	human.Principal = authz.PrincipalCredentials{AgentToken: token}
	return e, human
}

func TestDecisionAttributionNamesHumanAndAgentOwner(t *testing.T) {
	e, req := publicationSetup(t)
	dec, err := e.authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	want := authz.Attribution{UserID: testUserID1, EndpointID: testLocalEndpointID, SelectorID: testSelectorID1, Operation: authz.OpContainerInspectStatus}
	if got := dec.Attribution(); got != want {
		t.Fatalf("human attribution %+v, want %+v", got, want)
	}

	e, req = attributionAgentSetup(t, false)
	dec, err = e.authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// An agent owned by a human records BOTH ids so a report can break down by user
	// and by agent (TD 9.1).
	want = authz.Attribution{UserID: testUserID1, AgentID: testAgentID1, EndpointID: testLocalEndpointID, SelectorID: testSelectorID1, Operation: authz.OpContainerInspectStatus}
	if got := dec.Attribution(); got != want {
		t.Fatalf("user-owned agent attribution %+v, want %+v", got, want)
	}

	e, req = attributionAgentSetup(t, true)
	dec, err = e.authorizer.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// A group-owned agent has no owning user: the owner group is NOT a user and is
	// never invented into one.
	want = authz.Attribution{AgentID: testAgentID1, EndpointID: testLocalEndpointID, SelectorID: testSelectorID1, Operation: authz.OpContainerInspectStatus}
	if got := dec.Attribution(); got != want {
		t.Fatalf("group-owned agent attribution %+v, want %+v", got, want)
	}
}

func TestDenialAttributionExistsOnlyAfterTheVerifiedPrincipalAndCarriesTheDecidingSelector(t *testing.T) {
	type tc struct {
		name   string
		reason authz.DenialReason
		setup  func(e *testEnv, req *authz.AuthorizeRequest)
		// wantOK: an attribution must exist; sel is the deciding selector ("" none).
		wantOK bool
		sel    domain.SelectorID
	}
	cases := []tc{
		{"explicit deny names the deny rule's selector", authz.ReasonExplicitDeny, func(e *testEnv, _ *authz.AuthorizeRequest) {
			e.seedPolicy(store.Policy{ID: string(testPolicyID3), UserID: sql.NullString{String: string(testUserID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerInspectStatus), Effect: "DENY"})
		}, true, testSelectorID1},
		{"default deny matched no selector", authz.ReasonDefaultDeny, func(_ *testEnv, req *authz.AuthorizeRequest) {
			req.Operation = authz.OpContainerRestart
			req.RestartOptions = &docker.RestartOptions{}
		}, true, ""},
		{"parameter cap names the capped allow's selector", authz.ReasonParameterCapExceeded, func(e *testEnv, req *authz.AuthorizeRequest) {
			e.seedPolicy(store.Policy{ID: string(testPolicyID3), UserID: sql.NullString{String: string(testUserID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerLogs), Effect: "ALLOW", LogTailMax: sql.NullInt64{Int64: 3, Valid: true}})
			req.Operation = authz.OpContainerLogs
			req.LogOptions = &docker.LogOptions{Tail: 6, Stdout: true, Stderr: true}
		}, true, testSelectorID1},
		{"missing target matched no selector", authz.ReasonTargetMissing, func(_ *testEnv, req *authz.AuthorizeRequest) {
			req.TargetRef = "no-such-container"
		}, true, ""},
		{"invalid parameters matched no selector", authz.ReasonInvalidParameters, func(_ *testEnv, req *authz.AuthorizeRequest) {
			req.Operation = authz.OpContainerLogs
			req.LogOptions = &docker.LogOptions{Tail: 0, Stdout: false, Stderr: false}
		}, true, ""},
		// Before the principal is verified nobody can be attributed.
		{"self-protected precedes authentication", authz.ReasonSelfProtected, func(_ *testEnv, req *authz.AuthorizeRequest) {
			req.TargetRef = "mandatary-self"
		}, false, ""},
		{"unverified safety precedes authentication", authz.ReasonSafetyUnverified, func(e *testEnv, _ *authz.AuthorizeRequest) {
			e.backend.SimulateEventDiscontinuity()
		}, false, ""},
		{"restore quarantine precedes authentication", authz.ReasonRestoreQuarantined, func(e *testEnv, _ *authz.AuthorizeRequest) {
			e.execSQL(`UPDATE installation_control SET restore_quarantined=1 WHERE singleton=1`)
		}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, req := publicationSetup(t)
			c.setup(e, &req)
			_, err := e.authorizer.Authorize(context.Background(), req)
			if !authz.HasReason(err, c.reason) || !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("got %v, want a %s denial", err, c.reason)
			}
			got, ok := authz.AttributionOf(err)
			if ok != c.wantOK {
				t.Fatalf("attribution present=%v, want %v (%+v)", ok, c.wantOK, got)
			}
			if !ok {
				if !reflect.DeepEqual(got, authz.Attribution{}) {
					t.Fatalf("absent attribution must be the zero value: %+v", got)
				}
				return
			}
			want := authz.Attribution{UserID: testUserID1, EndpointID: testLocalEndpointID, SelectorID: c.sel, Operation: req.Operation}
			if got != want {
				t.Fatalf("attribution %+v, want %+v", got, want)
			}
		})
	}
}

func TestUnauthenticatedFailuresAreNeverAttributed(t *testing.T) {
	e, req := publicationSetup(t)
	req.Principal.SessionSecret = []byte("not-the-secret-0123456789abcdef0123456789abcdef")
	_, err := e.authorizer.Authorize(context.Background(), req)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("want 401, got %v", err)
	}
	if _, ok := authz.AttributionOf(err); ok {
		t.Fatal("a failed authentication was attributed to a user")
	}
	// A principal that is valid but under-assured on an AAL2-only call is a 401, not a
	// policy denial: it must not become a denied count either.
	e, req = publicationSetup(t)
	e.execSQL(`UPDATE sessions SET achieved_assurance=1, methods=1 WHERE id=?`, string(testSessionID1))
	e.execSQL(`UPDATE users SET mfa_requirement='optional' WHERE id=?`, string(testUserID1))
	req.RequireAAL2 = true
	_, err = e.authorizer.Authorize(context.Background(), req)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("want 401, got %v", err)
	}
	if _, ok := authz.AttributionOf(err); ok {
		t.Fatal("a 401 under-assurance outcome was attributed")
	}
}

func TestAttributionDoesNotChangeTheDenialContract(t *testing.T) {
	e, req := publicationSetup(t)
	req.Operation = authz.OpContainerRestart
	req.RestartOptions = &docker.RestartOptions{}
	_, err := e.authorizer.Authorize(context.Background(), req)
	if !authz.HasReason(err, authz.ReasonDefaultDeny) || !errors.Is(err, authz.ErrForbidden) || authz.StatusCode(err) != http.StatusForbidden {
		t.Fatalf("sentinel/status/reason changed: %v", err)
	}
	if err.Error() != string(authz.ErrForbidden) {
		t.Fatalf("error text changed: %q", err.Error())
	}
	// Formatting an attributed error in any verb never reveals the identifiers.
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out := fmt.Sprintf(f, err)
		for _, secret := range []string{string(testUserID1), string(testSelectorID1)} {
			if strings.Contains(out, secret) {
				t.Fatalf("format %s of an attributed denial leaks %q: %s", f, secret, out)
			}
		}
	}
	// Wrapping keeps the attribution reachable (errors.As), as the service relies on.
	wrapped := fmt.Errorf("context: %w", err)
	if _, ok := authz.AttributionOf(wrapped); !ok {
		t.Fatal("attribution lost through wrapping")
	}
}

func TestLeaseDecisionCarriesAttribution(t *testing.T) {
	e, req := publicationSetup(t)
	lease, err := e.authorizer.AcquireLease(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got := lease.Decision.Attribution(); got.UserID != testUserID1 || got.SelectorID != testSelectorID1 || got.Operation != authz.OpContainerInspectStatus || got.EndpointID != testLocalEndpointID {
		t.Fatalf("lease attribution %+v", got)
	}
	if got := (authz.Decision{}).Attribution(); got != (authz.Attribution{}) {
		t.Fatalf("zero decision attributes %+v", got)
	}
}
