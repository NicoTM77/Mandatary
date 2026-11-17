package authz_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/system"
)

// P1.20 R2: the bounded continuity freshness (docker.SDKOptions.ContinuityTTL) answers ONE question, "is the
// daemon still the one that was proven?". It never answers an authorization question. Every revocation, policy
// change, quarantine and default deny below must take effect while a fresh continuity check is held.

type sdkDaemon struct {
	mu     sync.Mutex
	reads  map[string]int
	byID   map[string]container.Summary
	daemon string
}

func newSDKDaemon() *sdkDaemon {
	d := &sdkDaemon{reads: map[string]int{}, daemon: "authz-daemon-0001", byID: map[string]container.Summary{}}
	d.byID[string(docker.MockSelfContainerID)] = container.Summary{ID: string(docker.MockSelfContainerID), Names: []string{"/mandatary-self"},
		Labels: map[string]string{docker.SelfLabelKey: docker.SelfLabelValue, docker.SelfInstanceUUIDLabelKey: docker.MockSelfUUID}}
	d.byID[string(testEdgeProxyID)] = container.Summary{ID: string(testEdgeProxyID), Names: []string{"/edge-proxy"}, Labels: map[string]string{}}
	return d
}

func (d *sdkDaemon) read(kind string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reads[kind]
}

func (d *sdkDaemon) RoundTrip(r *http.Request) (*http.Response, error) {
	h := http.Header{"Api-Version": {"1.46"}, "Content-Type": {"application/json"}}
	respond := func(v any) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
	}
	p := r.URL.Path
	if i := strings.Index(p[1:], "/"); strings.HasPrefix(p, "/v") && i >= 0 {
		p = p[1+i:]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case p == "/_ping":
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("OK")), Request: r}, nil
	case p == "/info":
		d.reads["info"]++
		return respond(system.Info{ID: d.daemon})
	case p == "/containers/json":
		d.reads["list"]++
		var out []container.Summary
		for _, c := range d.byID {
			out = append(out, c)
		}
		return respond(out)
	case strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
		d.reads["inspect"]++
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")
		c, ok := d.byID[id]
		if !ok {
			return &http.Response{StatusCode: 404, Header: h, Body: io.NopCloser(strings.NewReader(`{"message":"No such container"}`)), Request: r}, nil
		}
		return respond(container.InspectResponse{ID: c.ID, Created: "2026-11-08T09:00:00Z", Name: c.Names[0],
			State:  &container.State{Status: container.StateRunning, Running: true, StartedAt: "2026-11-08T09:00:01Z"},
			Config: &container.Config{Labels: c.Labels}, HostConfig: &container.HostConfig{NetworkMode: "bridge"}, NetworkSettings: &container.NetworkSettings{}})
	}
	return &http.Response{StatusCode: 404, Header: h, Body: io.NopCloser(strings.NewReader(`{"message":"unexpected"}`)), Request: r}, nil
}

type authzClock struct{ now atomic.Int64 }

func (c *authzClock) Now() time.Time {
	return time.Unix(0, c.now.Load()).Add(time.Hour * 24 * 365 * 56)
}

// continuityEnv replaces the mock backend of the standard authorization fixture with the real SDK adapter over a
// fake daemon, at the production freshness of 1 s, and returns the authorization request of alice's policy.
func continuityEnv(t *testing.T) (*testEnv, authz.AuthorizeRequest, *sdkDaemon, *docker.SDKAdapter) {
	t.Helper()
	e, req := publicationSetup(t)
	d := newSDKDaemon()
	clk := &authzClock{}
	cfg, _ := docker.DefaultMockFixtures(testLocalEndpointID)
	a, err := docker.NewSDKAdapter(docker.SDKOptions{EndpointID: testLocalEndpointID, Transport: d, Identity: cfg, ContinuityTTL: time.Second, Clock: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.VerifySelf(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.authorizer.RegisterBackend(testLocalEndpointID, a); err != nil {
		t.Fatal(err)
	}
	return e, req, d, a
}

func TestContinuitySnapshotNeverAnswersAnAuthorizationQuestion(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"policy-deleted", "restore-quarantine", "default-deny-other-target", "group-membership-disabled"} {
		t.Run(change, func(t *testing.T) {
			e, req, d, a := continuityEnv(t)
			if change == "group-membership-disabled" {
				// the policy reaches alice through a group in this variant
				e.execSQL(`DELETE FROM policies WHERE id = ?`, string(testPolicyID1))
				e.seedGroup(testGroupID1, "devs", "active", 1)
				e.seedUserGroupMembership(testUserID1, testGroupID1, "active", 1)
				e.seedPolicy(store.Policy{ID: string(testPolicyID2), GroupID: sql.NullString{String: string(testGroupID1), Valid: true}, EndpointID: testLocalEndpointID, SelectorID: string(testSelectorID1), Operation: string(authz.OpContainerInspectStatus), Effect: "ALLOW"})
			}
			lease, err := e.authorizer.AcquireLease(ctx, req)
			if err != nil {
				t.Fatalf("positive control: %v", err)
			}
			defer lease.Release()
			if d.read("info") == 0 {
				t.Fatal("the positive control did not reach the daemon")
			}
			infoBefore := d.read("info")

			switch change {
			case "policy-deleted":
				e.execSQL(`DELETE FROM policies WHERE id = ?`, string(testPolicyID1))
			case "restore-quarantine":
				e.execSQL(`UPDATE installation_control SET restore_quarantined = 1 WHERE singleton = 1`)
			case "default-deny-other-target":
				req.TargetRef = "billing-worker" // no selector, no policy
			case "group-membership-disabled":
				e.execSQL(`UPDATE user_group_memberships SET state = 'disabled' WHERE user_id = ? AND group_id = ?`, string(testUserID1), string(testGroupID1))
			}
			if err := e.authorizer.NotifyPolicyChange(ctx); err != nil {
				t.Fatal(err)
			}
			if change != "default-deny-other-target" && lease.Context().Err() == nil {
				t.Fatal("the active lease survived the revocation while a fresh continuity check was held")
			}
			if _, err := e.authorizer.Authorize(ctx, req); !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("the next call was not refused: %v", err)
			}
			if got := d.read("info"); got != infoBefore {
				t.Fatalf("the refusal needed %d more /info reads: it was decided by authorization, not by the daemon", got-infoBefore)
			}
			if !a.Ready() {
				t.Fatal("an authorization refusal must not touch the safety proof")
			}
		})
	}
}

// With nothing revoked the same fresh snapshot does serve the call: the control that makes the tests above meaningful.
func TestContinuitySnapshotServesAnAuthorizedCallWithoutDaemonChecks(t *testing.T) {
	ctx := context.Background()
	e, req, d, _ := continuityEnv(t)
	if _, err := e.authorizer.Authorize(ctx, req); err != nil {
		t.Fatal(err)
	}
	info := d.read("info")
	for i := 0; i < 5; i++ {
		if _, err := e.authorizer.Authorize(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if got := d.read("info"); got != info {
		t.Fatalf("five authorized calls inside the freshness read /info %d more times, want none", got-info)
	}
}
