package authz_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// faultBackend decorates the mock backend. While armed, ResolveTarget by
// immutable ID reports a shared fault; when cancel is set it also aborts the
// caller's context at the same boundary and returns the fault joined with the
// cancellation (an entered request that observed both).
type faultBackend struct {
	docker.DockerBackend
	armed   atomic.Bool
	fault   error
	onFault func()
	mu      sync.Mutex
	cancel  context.CancelFunc
}

func (b *faultBackend) ResolveTarget(ctx context.Context, ref string) (docker.ContainerSummary, error) {
	if b.armed.Load() && len(ref) == 64 {
		if b.onFault != nil {
			b.onFault()
		}
		b.mu.Lock()
		c := b.cancel
		b.mu.Unlock()
		if c != nil {
			c()
			return docker.ContainerSummary{}, errors.Join(b.fault, ctx.Err())
		}
		if b.fault == nil {
			return docker.ContainerSummary{}, ctx.Err()
		}
		return docker.ContainerSummary{}, b.fault
	}
	return b.DockerBackend.ResolveTarget(ctx, ref)
}

// sharedGroupLeases gives Alice and Bob live leases on one shared group ALLOW.
func sharedGroupLeases(t *testing.T, bobSecret []byte, req authz.AuthorizeRequest, a *authz.Authorizer) (alice, bob *authz.Lease, bobReq authz.AuthorizeRequest) {
	t.Helper()
	ctx := context.Background()
	alice, err := a.AcquireLease(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(alice.Release)
	bobReq = req
	bobReq.Principal = authz.PrincipalCredentials{SessionID: testSessionID2, SessionSecret: bobSecret}
	bob, err = a.AcquireLease(ctx, bobReq)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bob.Release)
	return alice, bob, bobReq
}

func seedSharedGroup(t *testing.T, e *testEnv) []byte {
	t.Helper()
	e.seedUser(seedUserOpts{ID: testUserID2, Username: "bob"})
	bobSecret := e.seedSession(seedSessionOpts{ID: testSessionID2, UserID: testUserID2})
	e.seedGroup(testGroupID1, "shared", "active", 1)
	e.seedUserGroupMembership(testUserID1, testGroupID1, "active", 1)
	e.seedUserGroupMembership(testUserID2, testGroupID1, "active", 1)
	e.execSQL(`UPDATE policies SET user_id=NULL,group_id=? WHERE id=?`, string(testGroupID1), string(testPolicyID1))
	return bobSecret
}

// F6: a shared target/backend fault co-observed with the caller's cancellation
// is still a shared fault and must cancel the peer; a pure cancellation with no
// shared fault stays local to the caller.
func TestLeaseSharedFaultNotMaskedByCallerCancellation(t *testing.T) {
	cases := []struct {
		name         string
		fault        error
		unsafe       bool
		cancelCaller bool
		peerCanceled bool
	}{
		{"protected-target/caller-canceled", docker.ErrProtectedTarget, false, true, true},
		{"protected-target/not-canceled", docker.ErrProtectedTarget, false, false, true},
		{"unverified/caller-canceled", docker.ErrUnverified, true, true, true},
		{"unverified/not-canceled", docker.ErrUnverified, true, false, true},
		{"pure-cancel-control", nil, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, req := publicationSetup(t)
			bobSecret := seedSharedGroup(t, e)
			fb := &faultBackend{DockerBackend: e.backend, fault: tc.fault}
			if tc.unsafe {
				fb.onFault = e.backend.InvalidateSafety
			}
			a, err := authz.NewAuthorizer(authz.Config{Repository: e.repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{testLocalEndpointID: fb}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			alice, bob, _ := sharedGroupLeases(t, bobSecret, req, a)

			checkCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelCaller {
				fb.mu.Lock()
				fb.cancel = cancel
				fb.mu.Unlock()
			}
			fb.armed.Store(true)
			if err := alice.Revalidate(checkCtx); !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("alice must be denied: %v", err)
			}
			if alice.Context().Err() == nil {
				t.Error("alice lease not canceled")
			}
			if got := bob.Context().Err() != nil; got != tc.peerCanceled {
				t.Errorf("peer canceled=%v want %v", got, tc.peerCanceled)
			}
		})
	}
}

// cancelAndUnsafeVerifier loses backend safety and cancels the caller after the
// real verifier ran, so only the final publication check can observe both.
type cancelAndUnsafeVerifier struct {
	armed   atomic.Bool
	cancel  context.CancelFunc
	unsafe  func()
	faultOn bool
}

func (v *cancelAndUnsafeVerifier) VerifyPrincipal(ctx context.Context, q *store.Queries, c store.InstallationControl, p authz.PrincipalCredentials, now time.Time) (authz.VerifiedPrincipal, error) {
	r, err := authz.NewStoreCredentialVerifier().VerifyPrincipal(ctx, q, c, p, now)
	if v.armed.Load() {
		if v.faultOn {
			v.unsafe()
		}
		v.cancel()
	}
	return r, err
}

func TestLeaseBackendUnsafeAtPublicationNotMaskedByCancellation(t *testing.T) {
	for _, unsafe := range []bool{true, false} {
		name := map[bool]string{true: "backend-unsafe", false: "pure-cancel-control"}[unsafe]
		t.Run(name, func(t *testing.T) {
			e, req := publicationSetup(t)
			bobSecret := seedSharedGroup(t, e)
			v := &cancelAndUnsafeVerifier{unsafe: e.backend.InvalidateSafety, faultOn: unsafe}
			a, err := authz.NewAuthorizer(authz.Config{Repository: e.repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{testLocalEndpointID: e.backend}, CredentialVerifier: v})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			alice, bob, _ := sharedGroupLeases(t, bobSecret, req, a)
			checkCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v.cancel = cancel
			v.armed.Store(true)
			if err := alice.Revalidate(checkCtx); !errors.Is(err, authz.ErrForbidden) {
				t.Errorf("alice must be denied: %v", err)
			}
			if alice.Context().Err() == nil {
				t.Error("alice lease not canceled")
			}
			if got := bob.Context().Err() != nil; got != unsafe {
				t.Errorf("peer canceled=%v want %v", got, unsafe)
			}
		})
	}
}

// F7: a no-op/unrelated policy notification that overlaps a healthy lease's
// revalidation must not cancel it; a real revocation still does.
func TestLeaseSurvivesOverlappingNoopNotification(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := map[bool]string{false: "noop-notification", true: "real-revocation-control"}[revoke]
		t.Run(name, func(t *testing.T) {
			e, req := publicationSetup(t)
			a, v := gatedAuthorizer(t, e)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			lease, err := a.AcquireLease(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			v.gateAt.Store(v.calls.Load() + 1)
			done := make(chan error, 1)
			go func() { done <- lease.Revalidate(ctx) }()
			select {
			case <-v.entered:
			case <-ctx.Done():
				close(v.release)
				t.Fatalf("barrier not entered (%v)", <-done)
			}
			if revoke {
				e.execSQL(`DELETE FROM policies WHERE id=?`, string(testPolicyID1))
			}
			if err := a.NotifyPolicyChange(ctx); err != nil {
				t.Error(err)
			}
			close(v.release)
			werr := <-done
			if revoke {
				if !errors.Is(werr, authz.ErrForbidden) || lease.Context().Err() == nil {
					t.Errorf("revoked lease must be denied and canceled (err=%v ctx=%v)", werr, lease.Context().Err())
				}
				if _, err := a.Authorize(ctx, req); err == nil {
					t.Error("revoked authority must stay denied")
				}
				return
			}
			if werr != nil || lease.Context().Err() != nil {
				t.Errorf("healthy lease canceled by overlapping no-op notification (err=%v ctx=%v)", werr, lease.Context().Err())
			}
			if _, err := a.Authorize(ctx, req); err != nil {
				t.Errorf("fresh control: %v", err)
			}
		})
	}
}

func TestConcurrentNoopNotificationsKeepHealthyLeases(t *testing.T) {
	e, req := publicationSetup(t)
	ctx := context.Background()
	var leases []*authz.Lease
	for i := 0; i < 3; i++ {
		l, err := e.authorizer.AcquireLease(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
		defer l.Release()
	}
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				_ = e.authorizer.NotifyPolicyChange(ctx)
			}
		}()
	}
	wg.Wait()
	for i, l := range leases {
		if l.Context().Err() != nil {
			t.Errorf("healthy lease %d canceled by no-op notifications", i)
		}
	}
	if got := e.authorizer.ActiveLeaseCount(); got != 3 {
		t.Errorf("active leases=%d want 3", got)
	}
}

// Concurrent real revocation must still cancel every affected lease even while
// no-op notifications race, and an unrelated lease (other target) is kept.
func TestConcurrentRevocationAmongNoopNotificationsStillCancels(t *testing.T) {
	e, req := publicationSetup(t)
	ctx := context.Background()
	var leases []*authz.Lease
	for i := 0; i < 3; i++ {
		l, err := e.authorizer.AcquireLease(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
		defer l.Release()
	}
	e.execSQL(`DELETE FROM policies WHERE id=?`, string(testPolicyID1))
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_ = e.authorizer.NotifyPolicyChange(ctx)
			}
		}()
	}
	wg.Wait()
	for i, l := range leases {
		if l.Context().Err() == nil {
			t.Errorf("revoked lease %d still live", i)
		}
	}
}

// notifyingVerifier keeps advancing the policy epoch during every (outer)
// validation so a retry can never settle: bounded retry must then fail closed
// rather than loop forever or publish a stale result.
type notifyingVerifier struct {
	a     *authz.Authorizer
	calls atomic.Int64
	in    atomic.Bool
}

func (v *notifyingVerifier) VerifyPrincipal(ctx context.Context, q *store.Queries, c store.InstallationControl, p authz.PrincipalCredentials, now time.Time) (authz.VerifiedPrincipal, error) {
	r, err := authz.NewStoreCredentialVerifier().VerifyPrincipal(ctx, q, c, p, now)
	v.calls.Add(1)
	if v.a != nil && v.in.CompareAndSwap(false, true) {
		done := make(chan struct{})
		go func() { defer close(done); _ = v.a.NotifyPolicyChange(context.Background()) }()
		<-done
		v.in.Store(false)
	}
	return r, err
}

func TestEpochChurnExhaustsBoundedRetryFailClosed(t *testing.T) {
	e, req := publicationSetup(t)
	v := &notifyingVerifier{}
	a, err := authz.NewAuthorizer(authz.Config{Repository: e.repo, Clock: e.clock.Now, Backends: map[domain.EndpointID]docker.DockerBackend{testLocalEndpointID: e.backend}, CredentialVerifier: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	v.a = nil
	lease, err := a.AcquireLease(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	v.a = a
	before := v.calls.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = lease.Revalidate(ctx)
	if !errors.Is(err, authz.ErrForbidden) {
		t.Errorf("unsettled epoch must fail closed, got %v", err)
	}
	if lease.Context().Err() == nil {
		t.Error("lease must be canceled on retry exhaustion")
	}
	if n := v.calls.Load() - before; n < 2 || n > 200 {
		t.Errorf("expected bounded re-evaluation (2..200 verifier calls), got %d", n)
	}
	v.a = nil
	if _, err := a.Authorize(ctx, req); err != nil {
		t.Errorf("fresh authorization on settled epoch must succeed: %v", err)
	}
}
