package docker

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// P1.20 review X2: ListContainers returns the FRESH all-state list it reads for the caller, and that list must be
// verified as a whole (self present, deployment binding unique, every ID well formed and unique) before anything is
// returned or kept as authority. The continuity check may be shared; this list never is, and a cached continuity
// check (the 1 s snapshot) must not make the fresh list's own check redundant. The same call is the readiness
// heartbeat (cmd/mandatary verifier.attempt), so a defect that appears only in the fresh list must also revoke the
// proof through that path within one interval.
//
// Each defect is applied to the LAST list request of the call, i.e. after the continuity check (when one is made)
// has already read a healthy inventory. A ListContainers that skips VerifyInventory on its own list therefore
// answers with the defective inventory and leaves the proof standing: the test fails (RED); the adapter as written
// passes (GREEN).

// inventoryDefects mutates the fake daemon's inventory in a way only VerifyInventory notices.
var inventoryDefects = map[string]func(e *cacheEnv){
	"self-missing": func(e *cacheEnv) {
		e.fake.mu.Lock()
		delete(e.fake.containers, string(testSelfID))
		e.fake.mu.Unlock()
	},
	"duplicate-deployment-binding": func(e *cacheEnv) {
		e.fake.putContainer(fakeDaemonContainer{ID: string(testApp2ID), Name: "second", Labels: map[string]string{SelfInstanceUUIDLabelKey: testSelfUUID}})
	},
	"malformed-container-id": func(e *cacheEnv) {
		e.fake.putContainer(fakeDaemonContainer{ID: "malformed", Name: "broken"})
	},
}

// newBoundCacheEnv is a cacheEnv whose identity config carries the deployment binding (the instance UUID the self
// container is labelled with), so the whole-list uniqueness check is active.
func newBoundCacheEnv(t *testing.T, d time.Duration) *cacheEnv {
	t.Helper()
	return newCacheEnv(t, d, func(cfg *SelfIdentityConfig) { cfg.InstanceUUID = testSelfUUID })
}

// defectOnList makes defect appear on the n-th list request of the next call (n counts from now).
func (e *cacheEnv) defectOnList(n int64, defect func(e *cacheEnv)) {
	var lists atomic.Int64
	e.m.setHook(func(kind string, _ *http.Request) error {
		if kind == "list" && lists.Add(1) == n {
			defect(e)
		}
		return nil
	})
}

func TestListContainersVerifiesItsOwnFreshInventory(t *testing.T) {
	modes := []struct {
		name  string
		ttl   time.Duration
		warm  bool  // a continuity snapshot is already valid, so the call reads only its own fresh list
		lists int64 // the fresh list is this list request of the call
	}{
		{"every-caller-checks-itself", 0, false, 2}, // the check's own inventory step, then the fresh list
		{"within-a-cached-continuity-check", ttl, true, 1},
	}
	for _, mode := range modes {
		for name, defect := range inventoryDefects {
			t.Run(mode.name+"/"+name, func(t *testing.T) {
				e := newBoundCacheEnv(t, mode.ttl)
				if mode.warm {
					e.mustResolve() // publishes the snapshot the next call rides on
				}
				e.m.take()
				e.defectOnList(mode.lists, defect)

				items, err := e.a.ListContainers(context.Background())
				if !errors.Is(err, ErrUnverified) {
					t.Fatalf("ListContainers returned %d items and err=%v for an inventory that fails its whole-list check; want ErrUnverified", len(items), err)
				}
				if items != nil {
					t.Fatalf("ListContainers returned %d items from an unverified inventory", len(items))
				}
				if got := e.m.take(); got["list"] != int(mode.lists) {
					t.Fatalf("the defect was not on the call's own fresh list: requests %v", got)
				}
				e.requireRevoked(name, nil)
				if drops := e.rec.all(); len(drops) == 0 || drops[0].Verified || drops[0].Drop.Reason != DropIdentity {
					t.Fatalf("the safety transition is not an identity drop: %+v", drops)
				}
				// Only a fresh VerifySelf restores; the defect is gone from the daemon only if the test removes it, so the
				// proof must not come back by itself.
				if _, err := e.a.ListContainers(context.Background()); !errors.Is(err, ErrUnverified) {
					t.Fatalf("an unverified endpoint answered a later list: %v", err)
				}
			})
		}
	}
}

// The readiness heartbeat is ListContainers under a deadline of its own (cmd/mandatary verifier.attempt). With the
// continuity check cached, a defect in the fresh list must still end readiness on that one heartbeat, and the
// healthy heartbeats before it must neither revoke nor read more than the one fresh list.
func TestHeartbeatListDetectsAFreshInventoryDefectWithinACachedContinuityCheck(t *testing.T) {
	e := newBoundCacheEnv(t, ttl)
	e.mustResolve()
	for i := 0; i < 3; i++ { // healthy heartbeats inside the snapshot: one fresh list each, nothing else
		e.m.take()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := e.a.ListContainers(ctx)
		cancel()
		if err != nil || !e.a.Ready() {
			t.Fatalf("healthy heartbeat %d: err=%v ready=%v", i, err, e.a.Ready())
		}
		if got := e.m.take(); got["list"] != 1 || got["info"] != 0 || got["inspect-self"] != 0 {
			t.Fatalf("heartbeat %d inside the snapshot read %v, want exactly one fresh list", i, got)
		}
	}
	e.defectOnList(1, inventoryDefects["self-missing"])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := e.a.ListContainers(ctx); !errors.Is(err, ErrUnverified) {
		t.Fatalf("the heartbeat accepted a fresh inventory without self: %v", err)
	}
	if e.a.Ready() {
		t.Fatal("readiness survived an inventory that no longer contains self")
	}
	if v, _, _ := e.a.safety.continuitySnapshot(); v {
		t.Fatal("a cached continuity snapshot outlived the revocation")
	}
}
