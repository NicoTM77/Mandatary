package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/system"
)

const (
	testSelfID   ContainerID = "1111111111111111111111111111111111111111111111111111111111111111"
	testPeerID   ContainerID = "2222222222222222222222222222222222222222222222222222222222222222"
	testPeer2ID  ContainerID = "3333333333333333333333333333333333333333333333333333333333333333"
	testApp1ID   ContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testApp2ID   ContainerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testSelfUUID             = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	testAltUUID              = "99999999-8888-4777-8666-555555555555"
)

type fakeDaemonContainer struct {
	ID         string
	Name       string
	Image      string
	State      container.ContainerState
	Status     string
	Created    string
	StartedAt  string
	FinishedAt string
	Labels     map[string]string
	Env        []string
	Cmd        []string
	Entrypoint []string
	Tty        bool
	Logs       []byte
	FollowCh   chan []byte
}

type fakeDaemonTransport struct {
	mu          sync.Mutex
	apiVersion  string
	daemonID    string
	containers  map[string]*fakeDaemonContainer
	failPing    error
	failList    error
	failInspect error
	failOp      error
	lastTail    string
	lastTimeout string
}

func newFakeDaemonTransport() *fakeDaemonTransport {
	return &fakeDaemonTransport{
		apiVersion: "1.46",
		daemonID:   "daemon-uuid-0001",
		containers: make(map[string]*fakeDaemonContainer),
	}
}

func (f *fakeDaemonTransport) putContainer(c fakeDaemonContainer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := c
	if cp.Created == "" {
		cp.Created = "2026-11-08T09:00:00Z"
	}
	if cp.StartedAt == "" {
		cp.StartedAt = "2026-11-08T09:00:01Z"
	}
	if cp.Image == "" {
		cp.Image = "nginx:1.27-alpine"
	}
	if cp.State == "" {
		cp.State = container.StateRunning
	}
	if cp.Status == "" {
		cp.Status = "Up 1 hour"
	}
	labels := make(map[string]string, len(c.Labels))
	for k, v := range c.Labels {
		labels[k] = v
	}
	cp.Labels = labels
	f.containers[c.ID] = &cp
}

func encodeMultiplexedFrame(stream byte, payload []byte) []byte {
	hdr := make([]byte, 8+len(payload))
	hdr[0] = stream
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	copy(hdr[8:], payload)
	return hdr
}

func (f *fakeDaemonTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	apiVer := f.apiVersion
	daemonID := f.daemonID
	failPing := f.failPing
	failList := f.failList
	failInspect := f.failInspect
	failOp := f.failOp
	f.mu.Unlock()

	header := make(http.Header)
	if apiVer != "" {
		header.Set("Api-Version", apiVer)
	}
	header.Set("Content-Type", "application/json")

	path := req.URL.Path
	if strings.HasPrefix(path, "/v") {
		if idx := strings.Index(path[1:], "/"); idx >= 0 {
			path = path[1+idx:]
		}
	}

	if path == "/_ping" {
		if failPing != nil {
			return nil, failPing
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader("OK")),
			Request:    req,
		}, nil
	}

	if path == "/info" {
		if failPing != nil {
			return nil, failPing
		}
		body, _ := json.Marshal(system.Info{ID: daemonID, ServerVersion: "27.3.1"})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	}

	if path == "/version" {
		body, _ := json.Marshal(system.VersionResponse{
			Version:       "27.3.1",
			APIVersion:    apiVer,
			MinAPIVersion: "1.44",
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	}

	if path == "/containers/json" {
		if failList != nil {
			return nil, failList
		}
		f.mu.Lock()
		items := make([]container.Summary, 0, len(f.containers))
		for _, c := range f.containers {
			name := c.Name
			if !strings.HasPrefix(name, "/") {
				name = "/" + name
			}
			items = append(items, container.Summary{
				ID:     c.ID,
				Names:  []string{name},
				Image:  c.Image,
				State:  c.State,
				Status: c.Status,
				Labels: c.Labels,
			})
		}
		f.mu.Unlock()
		body, _ := json.Marshal(items)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	}

	if strings.HasPrefix(path, "/containers/") {
		rest := strings.TrimPrefix(path, "/containers/")
		parts := strings.Split(rest, "/")
		if len(parts) == 2 {
			id := parts[0]
			action := parts[1]

			f.mu.Lock()
			c, ok := f.containers[id]
			f.mu.Unlock()
			if !ok {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     header,
					Body:       io.NopCloser(strings.NewReader(`{"message":"No such container"}`)),
					Request:    req,
				}, nil
			}

			switch action {
			case "json":
				if failInspect != nil {
					return nil, failInspect
				}
				f.mu.Lock()
				name := c.Name
				if !strings.HasPrefix(name, "/") {
					name = "/" + name
				}
				respObj := container.InspectResponse{
					ID:      c.ID,
					Created: c.Created,
					Name:    name,
					Image:   "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					State: &container.State{
						Status:     c.State,
						Running:    c.State == container.StateRunning,
						Paused:     c.State == container.StatePaused,
						Restarting: c.State == container.StateRestarting,
						Dead:       c.State == container.StateDead,
						StartedAt:  c.StartedAt,
						FinishedAt: c.FinishedAt,
					},
					Config: &container.Config{
						Image:      c.Image,
						Labels:     c.Labels,
						Env:        c.Env,
						Cmd:        c.Cmd,
						Entrypoint: c.Entrypoint,
						Tty:        c.Tty,
					},
					HostConfig:      &container.HostConfig{NetworkMode: "bridge"},
					NetworkSettings: &container.NetworkSettings{},
				}
				f.mu.Unlock()
				body, _ := json.Marshal(respObj)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     header,
					Body:       io.NopCloser(bytes.NewReader(body)),
					Request:    req,
				}, nil

			case "logs":
				if failOp != nil {
					return nil, failOp
				}
				f.mu.Lock()
				f.lastTail = req.URL.Query().Get("tail")
				logsData := append([]byte(nil), c.Logs...)
				followCh := c.FollowCh
				f.mu.Unlock()

				if req.URL.Query().Get("follow") == "1" && followCh != nil {
					pr, pw := io.Pipe()
					go func() {
						defer func() { _ = pw.Close() }()
						if len(logsData) > 0 {
							_, _ = pw.Write(logsData)
						}
						for {
							select {
							case <-req.Context().Done():
								return
							case chunk, ok := <-followCh:
								if !ok {
									return
								}
								if _, err := pw.Write(chunk); err != nil {
									return
								}
							}
						}
					}()
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     header,
						Body:       pr,
						Request:    req,
					}, nil
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     header,
					Body:       io.NopCloser(bytes.NewReader(logsData)),
					Request:    req,
				}, nil

			case "start":
				if failOp != nil {
					return nil, failOp
				}
				f.mu.Lock()
				c.State = container.StateRunning
				c.Status = "Up Less than a second"
				f.mu.Unlock()
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     header,
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil

			case "stop":
				if failOp != nil {
					return nil, failOp
				}
				f.mu.Lock()
				f.lastTimeout = req.URL.Query().Get("t")
				c.State = container.StateExited
				c.Status = "Exited (0) Less than a second ago"
				f.mu.Unlock()
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     header,
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil

			case "restart":
				if failOp != nil {
					return nil, failOp
				}
				f.mu.Lock()
				f.lastTimeout = req.URL.Query().Get("t")
				c.State = container.StateRunning
				c.Status = "Up Less than a second"
				f.mu.Unlock()
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     header,
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}
		}
	}

	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(`{"message":"not found"}`)),
		Request:    req,
	}, nil
}

// SELF-01: Missing self-identity -> Startup verification fails closed; backend
// stays UNVERIFIED, readyz is 503 (Ready()==false), and all container operations
// are denied with zero operational SDK calls.
func TestSELF01_MissingIdentityFailsClosedZeroOperationalCalls(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp1ID),
		Name: "app-1",
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID: epID,
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	defer func() { _ = adapter.Close() }()

	if err := adapter.VerifySelf(ctx); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifySelf with missing identity = %v, want %v", err, ErrUnverified)
	}
	if adapter.Ready() || adapter.VerificationState() != StateUnverified {
		t.Fatalf("adapter should remain UNVERIFIED and not ready")
	}

	target := TargetIdentity{EndpointID: epID, ContainerID: testApp1ID}
	if _, err := adapter.InspectStatus(ctx, target); !errors.Is(err, ErrUnverified) {
		t.Errorf("InspectStatus = %v, want %v", err, ErrUnverified)
	}
	if _, err := adapter.InspectConfig(ctx, target); !errors.Is(err, ErrUnverified) {
		t.Errorf("InspectConfig = %v, want %v", err, ErrUnverified)
	}
	if _, err := adapter.Logs(ctx, target, LogOptions{Stdout: true}); !errors.Is(err, ErrUnverified) {
		t.Errorf("Logs = %v, want %v", err, ErrUnverified)
	}
	if err := adapter.Start(ctx, target); !errors.Is(err, ErrUnverified) {
		t.Errorf("Start = %v, want %v", err, ErrUnverified)
	}
	if err := adapter.Stop(ctx, target, StopOptions{}); !errors.Is(err, ErrUnverified) {
		t.Errorf("Stop = %v, want %v", err, ErrUnverified)
	}
	if err := adapter.Restart(ctx, target, RestartOptions{}); !errors.Is(err, ErrUnverified) {
		t.Errorf("Restart = %v, want %v", err, ErrUnverified)
	}

	if got := adapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("TotalOperational() = %d, want 0", got)
	}
}

// SELF-02: Invalid or conflicting explicit ID -> Startup verification fails closed;
// backend stays UNVERIFIED and all container operations are denied.
func TestSELF02_InvalidOrConflictingExplicitIDFailsClosed(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)

	t.Run("malformed explicit ID rejected", func(t *testing.T) {
		tr := newFakeDaemonTransport()
		adapter, err := NewSDKAdapter(SDKOptions{
			EndpointID: epID,
			Transport:  tr,
			Identity: SelfIdentityConfig{
				EndpointID:          epID,
				ExplicitContainerID: "not-a-64-hex-id",
			},
		})
		if err == nil {
			if vErr := adapter.VerifySelf(ctx); !errors.Is(vErr, ErrUnverified) {
				t.Fatalf("VerifySelf with malformed explicit ID = %v, want %v", vErr, ErrUnverified)
			}
		}
	})

	t.Run("explicit ID conflicts with process cgroup evidence", func(t *testing.T) {
		tr := newFakeDaemonTransport()
		tr.putContainer(fakeDaemonContainer{
			ID:     string(testSelfID),
			Name:   "mandatary",
			Labels: map[string]string{SelfLabelKey: SelfLabelValue},
		})
		tr.putContainer(fakeDaemonContainer{
			ID:     string(testPeerID),
			Name:   "mandatary-peer",
			Labels: map[string]string{SelfLabelKey: SelfLabelValue},
		})

		adapter, err := NewSDKAdapter(SDKOptions{
			EndpointID: epID,
			Transport:  tr,
			Identity: SelfIdentityConfig{
				EndpointID:          epID,
				ExplicitContainerID: string(testSelfID),
				EvidenceReader: func(context.Context) (ProcessEvidence, error) {
					return ProcessEvidence{ContainerID: string(testPeerID), Mandatory: true}, nil
				},
			},
		})
		if err != nil {
			t.Fatalf("NewSDKAdapter: %v", err)
		}
		if err := adapter.VerifySelf(ctx); !errors.Is(err, ErrUnverified) {
			t.Fatalf("VerifySelf with conflicting explicit/cgroup ID = %v, want %v", err, ErrUnverified)
		}
		if got := adapter.Counters().TotalOperational(); got != 0 {
			t.Fatalf("TotalOperational() = %d, want 0", got)
		}
	})
}

// SELF-03: Ambiguous or label-only identity -> Startup verification fails closed when
// label-only proof is presented or when process/explicit identity cannot resolve to a
// unique container ID; positive control verifies multi-container io.mandatary.self=true
// peer sets succeed when unique process/explicit identity exists.
func TestSELF03_AmbiguousOrLabelOnlyIdentityAndMultiPeerPositiveControl(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)

	t.Run("label-only proof without process or explicit identity fails closed", func(t *testing.T) {
		tr := newFakeDaemonTransport()
		tr.putContainer(fakeDaemonContainer{
			ID:     string(testSelfID),
			Name:   "mandatary",
			Labels: map[string]string{SelfLabelKey: SelfLabelValue},
		})

		adapter, err := NewSDKAdapter(SDKOptions{
			EndpointID: epID,
			Transport:  tr,
			Identity: SelfIdentityConfig{
				EndpointID: epID,
				EvidenceReader: func(context.Context) (ProcessEvidence, error) {
					return ProcessEvidence{}, nil
				},
			},
		})
		if err != nil {
			t.Fatalf("NewSDKAdapter: %v", err)
		}
		if err := adapter.VerifySelf(ctx); !errors.Is(err, ErrUnverified) {
			t.Fatalf("VerifySelf with label-only proof = %v, want %v", err, ErrUnverified)
		}
		if got := adapter.Counters().TotalOperational(); got != 0 {
			t.Fatalf("TotalOperational() = %d, want 0", got)
		}
	})

	t.Run("multi-peer positive control succeeds when unique cgroup/explicit proof exists", func(t *testing.T) {
		tr := newFakeDaemonTransport()
		tr.putContainer(fakeDaemonContainer{
			ID:     string(testSelfID),
			Name:   "mandatary-primary",
			Labels: map[string]string{SelfLabelKey: SelfLabelValue},
		})
		tr.putContainer(fakeDaemonContainer{
			ID:     string(testPeerID),
			Name:   "mandatary-secondary",
			Labels: map[string]string{SelfLabelKey: SelfLabelValue},
		})
		tr.putContainer(fakeDaemonContainer{
			ID:   string(testApp1ID),
			Name: "nginx-app",
		})

		adapter, err := NewSDKAdapter(SDKOptions{
			EndpointID: epID,
			Transport:  tr,
			Identity: SelfIdentityConfig{
				EndpointID:          epID,
				ExplicitContainerID: string(testSelfID),
				EvidenceReader: func(context.Context) (ProcessEvidence, error) {
					return ProcessEvidence{ContainerID: string(testSelfID)}, nil
				},
			},
		})
		if err != nil {
			t.Fatalf("NewSDKAdapter: %v", err)
		}
		if err := adapter.VerifySelf(ctx); err != nil {
			t.Fatalf("VerifySelf failed on multi-peer positive control: %v", err)
		}
		if !adapter.Ready() || adapter.VerificationState() != StateVerified {
			t.Fatalf("expected VERIFIED and Ready()")
		}
	})
}

// SELF-04: Self-target by ID, name, or list -> Self container is omitted from
// list/discovery/target resolution and denied across all 6 operations with zero
// operational SDK calls.
func TestSELF04_SelfTargetDeniedAndOmittedZeroOperationalCalls(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp1ID),
		Name: "app-1",
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	list, err := adapter.ListContainers(ctx)
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(list) != 1 || list[0].ContainerID != testApp1ID {
		t.Fatalf("ListContainers = %+v, want only non-protected app-1", list)
	}

	if _, err := adapter.ResolveTarget(ctx, "mandatary"); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("ResolveTarget(self name) = %v, want %v", err, ErrProtectedTarget)
	}
	if _, err := adapter.ResolveTarget(ctx, string(testSelfID)); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("ResolveTarget(self ID) = %v, want %v", err, ErrProtectedTarget)
	}

	selfTarget := TargetIdentity{EndpointID: epID, ContainerID: testSelfID}
	if _, err := adapter.InspectStatus(ctx, selfTarget); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("InspectStatus(self) = %v, want %v", err, ErrProtectedTarget)
	}
	if _, err := adapter.InspectConfig(ctx, selfTarget); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("InspectConfig(self) = %v, want %v", err, ErrProtectedTarget)
	}
	if _, err := adapter.Logs(ctx, selfTarget, LogOptions{Stdout: true}); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("Logs(self) = %v, want %v", err, ErrProtectedTarget)
	}
	if err := adapter.Start(ctx, selfTarget); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("Start(self) = %v, want %v", err, ErrProtectedTarget)
	}
	if err := adapter.Stop(ctx, selfTarget, StopOptions{}); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("Stop(self) = %v, want %v", err, ErrProtectedTarget)
	}
	if err := adapter.Restart(ctx, selfTarget, RestartOptions{}); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("Restart(self) = %v, want %v", err, ErrProtectedTarget)
	}

	if got := adapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("TotalOperational() = %d, want 0", got)
	}
}

// SELF-05: Container recreation / daemon change -> Verification resets to UNVERIFIED;
// new identity must be established against current daemon before operations resume.
func TestSELF05_RecreationStaleIDAndDaemonChangeInvalidateProof(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:        string(testSelfID),
		Name:      "mandatary",
		StartedAt: "2026-11-08T09:00:01Z",
		Labels:    map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp1ID),
		Name: "app-1",
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	// Simulate daemon restart / daemon ID change.
	tr.mu.Lock()
	tr.daemonID = "daemon-uuid-0002-restarted"
	tr.mu.Unlock()

	target := TargetIdentity{EndpointID: epID, ContainerID: testApp1ID}
	if _, err := adapter.InspectStatus(ctx, target); !errors.Is(err, ErrUnverified) {
		t.Fatalf("InspectStatus after daemon ID change = %v, want %v", err, ErrUnverified)
	}
	if adapter.VerificationState() != StateUnverified || adapter.Ready() {
		t.Fatalf("expected adapter to transition to UNVERIFIED on daemon change")
	}
	if got := adapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("TotalOperational() = %d, want 0", got)
	}

	// Re-verify against the new daemon, then simulate self-container recreation (StartedAt changes).
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("re-VerifySelf: %v", err)
	}
	tr.putContainer(fakeDaemonContainer{
		ID:        string(testSelfID),
		Name:      "mandatary",
		StartedAt: "2026-11-08T10:30:00Z",
		Labels:    map[string]string{SelfLabelKey: SelfLabelValue},
	})
	if err := adapter.Start(ctx, target); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Start after self StartedAt change = %v, want %v", err, ErrUnverified)
	}
	if adapter.VerificationState() != StateUnverified {
		t.Fatalf("expected StateUnverified after self container recreation")
	}
	if got := adapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("TotalOperational() = %d, want 0", got)
	}
}

// SELF-06: Rename race during execution -> Verified immutable (endpoint_id, container_id)
// continues to execute against the original container ID without re-resolving by mutable name.
func TestSELF06_ImmutableIDDispatchAndDelayedEventPeerCheck(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp1ID),
		Name: "target-app",
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	summary, err := adapter.ResolveTarget(ctx, "target-app")
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if summary.ContainerID != testApp1ID {
		t.Fatalf("resolved ContainerID = %q, want %q", summary.ContainerID, testApp1ID)
	}

	// Simulate rename race: target-app is renamed to old-app, and self container takes target-app name.
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp1ID),
		Name: "old-app",
	})
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "target-app",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})

	target := TargetIdentity{EndpointID: summary.EndpointID, ContainerID: summary.ContainerID}
	status, err := adapter.InspectStatus(ctx, target)
	if err != nil {
		t.Fatalf("InspectStatus by immutable target failed: %v", err)
	}
	if status.ContainerID != testApp1ID || status.Name != "old-app" {
		t.Fatalf("unexpected status after rename: %+v", status)
	}
}

// SELF-07: Mid-flight verification loss -> Active log stream is canceled immediately
// when safety verification is invalidated, and queued/subsequent dispatches are denied.
func TestSELF07_LossOfProofCancelsActiveStreamsAndBlocksDispatch(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	followCh := make(chan []byte, 4)
	followCh <- encodeMultiplexedFrame(1, []byte("line-1\n"))

	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:       string(testApp1ID),
		Name:     "streaming-app",
		FollowCh: followCh,
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	target := TargetIdentity{EndpointID: epID, ContainerID: testApp1ID}
	stream, err := adapter.Logs(ctx, target, LogOptions{Stdout: true, Follow: true, Tail: 10})
	if err != nil {
		t.Fatalf("Logs follow start: %v", err)
	}
	defer func() { _ = stream.Close() }()

	frame, err := stream.Next(ctx)
	if err != nil {
		t.Fatalf("first stream.Next: %v", err)
	}
	if string(frame.Payload) != "line-1\n" {
		t.Fatalf("first frame payload = %q, want %q", string(frame.Payload), "line-1\n")
	}

	doneCh := make(chan error, 1)
	go func() {
		_, nErr := stream.Next(ctx)
		doneCh <- nErr
	}()

	adapter.InvalidateSafety()

	select {
	case sErr := <-doneCh:
		if sErr == nil {
			t.Fatal("expected active log stream to terminate with error upon InvalidateSafety")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active log stream was not canceled after InvalidateSafety")
	}

	opsBefore := adapter.Counters().TotalOperational()
	if err := adapter.Restart(ctx, target, RestartOptions{}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Restart after InvalidateSafety = %v, want %v", err, ErrUnverified)
	}
	if got := adapter.Counters().TotalOperational(); got != opsBefore {
		t.Fatalf("operational calls incremented after InvalidateSafety: %d -> %d", opsBefore, got)
	}
}

// SELF-08: Multi-instance peer protection & delayed event protection -> Both own instance
// and all io.mandatary.* labeled peers are denied; newly created peer not yet in cached
// protected set is caught by pre-dispatch target metadata check with zero operational calls.
func TestSELF08_MultiInstancePeerSetAndDelayedEventProtection(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary-1",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testPeerID),
		Name:   "mandatary-2",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if err := adapter.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	// Peer present at VerifySelf time is immediately rejected.
	peer1Target := TargetIdentity{EndpointID: epID, ContainerID: testPeerID}
	if err := adapter.Stop(ctx, peer1Target, StopOptions{}); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("Stop(peer1) = %v, want %v", err, ErrProtectedTarget)
	}

	// Simulate newly created peer2 appearing before event listener updates cached set.
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testPeer2ID),
		Name:   "mandatary-3-new",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	peer2Target := TargetIdentity{EndpointID: epID, ContainerID: testPeer2ID}
	if err := adapter.Stop(ctx, peer2Target, StopOptions{}); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("Stop(newly created peer2) = %v, want %v", err, ErrProtectedTarget)
	}
	if got := adapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("TotalOperational() = %d, want 0", got)
	}
}

// SELF-09: Backup/restore / fresh instance starts UNVERIFIED -> New backend never starts
// VERIFIED from static config or fixture state until VerifySelf succeeds against runtime proof.
func TestSELF09_StartsUnverifiedNoPersistedOrRestoredProof(t *testing.T) {
	epID := mustEndpointID(t)
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	tr.putContainer(fakeDaemonContainer{
		ID:   string(testApp1ID),
		Name: "app-1",
	})

	adapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID:          epID,
			ExplicitContainerID: string(testSelfID),
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				return ProcessEvidence{ContainerID: string(testSelfID)}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter: %v", err)
	}
	if adapter.Ready() || adapter.VerificationState() != StateUnverified {
		t.Fatalf("newly constructed SDKAdapter must start UNVERIFIED")
	}
	if _, err := adapter.ListContainers(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("ListContainers before VerifySelf = %v, want %v", err, ErrUnverified)
	}

	idCfg, fixtures := DefaultMockFixtures(epID)
	mock, err := NewMockBackend(MockOptions{
		EndpointID: epID,
		Identity:   idCfg,
		Containers: fixtures,
	})
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if mock.Ready() || mock.VerificationState() != StateUnverified {
		t.Fatalf("newly constructed MockBackend must start UNVERIFIED until VerifySelf is called")
	}
}

// SELF-10: Shared safety state under concurrent reads, target resolution, and invalidation.
func TestSELF10_SharedSafetyStateConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	idCfg, fixtures := DefaultMockFixtures(epID)
	mock, err := NewMockBackend(MockOptions{
		EndpointID: epID,
		Identity:   idCfg,
		Containers: fixtures,
	})
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if err := mock.VerifySelf(ctx); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_, _ = mock.ListContainers(ctx)
				_, _ = mock.ResolveTarget(ctx, "mandatary-self")
				_ = mock.Ready()
				_ = mock.VerificationState()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			mock.InvalidateSafety()
			_ = mock.VerifySelf(ctx)
		}
	}()
	wg.Wait()
}

// SELF-11: Private cgroup namespace -> When cgroupns=private hides the container ID
// in /proc/self/cgroup, deployment instance-UUID binding (MANDATARY_SELF_INSTANCE_UUID +
// io.mandatary.self.instance-uuid) proves unique self-identity; missing or duplicate UUID
// fails closed.
func TestSELF11_PrivateCgroupInstanceUUIDBindingAndOverlap(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)

	t.Run("private cgroup namespace with unique instance UUID and explicit ID succeeds", func(t *testing.T) {
		tr := newFakeDaemonTransport()
		tr.putContainer(fakeDaemonContainer{
			ID:   string(testSelfID),
			Name: "mandatary",
			Labels: map[string]string{
				SelfLabelKey:             SelfLabelValue,
				SelfInstanceUUIDLabelKey: testSelfUUID,
			},
		})
		tr.putContainer(fakeDaemonContainer{
			ID:   string(testPeerID),
			Name: "mandatary-peer",
			Labels: map[string]string{
				SelfLabelKey:             SelfLabelValue,
				SelfInstanceUUIDLabelKey: testAltUUID,
			},
		})

		adapter, err := NewSDKAdapter(SDKOptions{
			EndpointID: epID,
			Transport:  tr,
			Identity: SelfIdentityConfig{
				EndpointID:          epID,
				ExplicitContainerID: string(testSelfID),
				InstanceUUID:        testSelfUUID,
				EvidenceReader: func(context.Context) (ProcessEvidence, error) {
					return ProcessEvidence{PrivateCgroupNS: true}, nil
				},
			},
		})
		if err != nil {
			t.Fatalf("NewSDKAdapter: %v", err)
		}
		if err := adapter.VerifySelf(ctx); err != nil {
			t.Fatalf("VerifySelf with private cgroup + instance UUID failed: %v", err)
		}
		if !adapter.Ready() {
			t.Fatal("expected adapter Ready() == true")
		}
	})

	t.Run("duplicate instance UUID across two containers fails closed", func(t *testing.T) {
		tr := newFakeDaemonTransport()
		tr.putContainer(fakeDaemonContainer{
			ID:   string(testSelfID),
			Name: "mandatary-1",
			Labels: map[string]string{
				SelfLabelKey:             SelfLabelValue,
				SelfInstanceUUIDLabelKey: testSelfUUID,
			},
		})
		tr.putContainer(fakeDaemonContainer{
			ID:   string(testPeerID),
			Name: "mandatary-2-clone",
			Labels: map[string]string{
				SelfLabelKey:             SelfLabelValue,
				SelfInstanceUUIDLabelKey: testSelfUUID,
			},
		})

		adapter, err := NewSDKAdapter(SDKOptions{
			EndpointID: epID,
			Transport:  tr,
			Identity: SelfIdentityConfig{
				EndpointID:          epID,
				ExplicitContainerID: string(testSelfID),
				InstanceUUID:        testSelfUUID,
				EvidenceReader: func(context.Context) (ProcessEvidence, error) {
					return ProcessEvidence{PrivateCgroupNS: true}, nil
				},
			},
		})
		if err != nil {
			t.Fatalf("NewSDKAdapter: %v", err)
		}
		if err := adapter.VerifySelf(ctx); !errors.Is(err, ErrUnverified) {
			t.Fatalf("VerifySelf with duplicate instance UUID = %v, want %v", err, ErrUnverified)
		}
		if got := adapter.Counters().TotalOperational(); got != 0 {
			t.Fatalf("TotalOperational() = %d, want 0", got)
		}
	})
}

// SELF-12: Stopped/created/paused/restarting/dead peer protection -> Protected set
// enumeration uses all=true so non-running peers in any state are hidden and denied.
func TestSELF12_AllStateProtectedPeersDeniedAndHidden(t *testing.T) {
	ctx := context.Background()
	epID := mustEndpointID(t)
	states := []container.ContainerState{
		container.StateCreated,
		container.StateRunning,
		container.StatePaused,
		container.StateRestarting,
		container.StateRemoving,
		container.StateExited,
		container.StateDead,
	}

	for _, st := range states {
		t.Run("peer_state_"+string(st), func(t *testing.T) {
			tr := newFakeDaemonTransport()
			tr.putContainer(fakeDaemonContainer{
				ID:     string(testSelfID),
				Name:   "mandatary",
				State:  container.StateRunning,
				Labels: map[string]string{SelfLabelKey: SelfLabelValue},
			})
			tr.putContainer(fakeDaemonContainer{
				ID:     string(testPeerID),
				Name:   "mandatary-peer-" + string(st),
				State:  st,
				Labels: map[string]string{SelfLabelKey: SelfLabelValue},
			})
			tr.putContainer(fakeDaemonContainer{
				ID:    string(testApp1ID),
				Name:  "app-1",
				State: container.StateExited,
			})

			adapter, err := NewSDKAdapter(SDKOptions{
				EndpointID: epID,
				Transport:  tr,
				Identity: SelfIdentityConfig{
					EndpointID:          epID,
					ExplicitContainerID: string(testSelfID),
					EvidenceReader: func(context.Context) (ProcessEvidence, error) {
						return ProcessEvidence{ContainerID: string(testSelfID)}, nil
					},
				},
			})
			if err != nil {
				t.Fatalf("NewSDKAdapter: %v", err)
			}
			if err := adapter.VerifySelf(ctx); err != nil {
				t.Fatalf("VerifySelf: %v", err)
			}

			items, err := adapter.ListContainers(ctx)
			if err != nil {
				t.Fatalf("ListContainers: %v", err)
			}
			for _, item := range items {
				if item.ContainerID == testPeerID || item.ContainerID == testSelfID {
					t.Fatalf("protected container %s in state %s leaked into ListContainers", item.ContainerID, st)
				}
			}

			peerTarget := TargetIdentity{EndpointID: epID, ContainerID: testPeerID}
			if err := adapter.Start(ctx, peerTarget); !errors.Is(err, ErrProtectedTarget) {
				t.Fatalf("Start(peer in state %s) = %v, want %v", st, err, ErrProtectedTarget)
			}
			if got := adapter.Counters().TotalOperational(); got != 0 {
				t.Fatalf("TotalOperational() = %d, want 0", got)
			}
		})
	}
}

// SELF-13: Native mock mode isolation -> MockBackend operates strictly in-memory even if
// DOCKER_HOST or MANDATARY_DOCKER_SOCKET is set in the environment, and SDKAdapter rejects
// nil Transport so it can never implicitly dial a host socket.
func TestSELF13_MockIsolationAndNoImplicitSocketAccess(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("MANDATARY_DOCKER_SOCKET", "/var/run/docker.sock")

	epID := mustEndpointID(t)
	if _, err := NewSDKAdapter(SDKOptions{EndpointID: epID, Transport: nil}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewSDKAdapter with nil Transport = %v, want %v", err, ErrInvalidConfig)
	}

	idCfg, fixtures := DefaultMockFixtures(epID)
	mock, err := NewMockBackend(MockOptions{
		EndpointID: epID,
		Identity:   idCfg,
		Containers: fixtures,
	})
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if err := mock.VerifySelf(context.Background()); err != nil {
		t.Fatalf("mock.VerifySelf: %v", err)
	}
	containers, err := mock.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("mock.ListContainers: %v", err)
	}
	if len(containers) == 0 {
		t.Fatal("expected non-empty mock containers list")
	}
	for _, c := range containers {
		if c.ContainerID == idCfg.ExplicitContainerIDAsContainerID() {
			t.Fatalf("mock self container must be omitted from ListContainers")
		}
	}

	// Native real-Docker dev mode without explicit MANDATARY_SELF_CONTAINER_ID when a
	// mandatary container is running on the host must fail closed (no native exemption).
	tr := newFakeDaemonTransport()
	tr.putContainer(fakeDaemonContainer{
		ID:     string(testSelfID),
		Name:   "mandatary",
		Labels: map[string]string{SelfLabelKey: SelfLabelValue},
	})
	nativeAdapter, err := NewSDKAdapter(SDKOptions{
		EndpointID: epID,
		Transport:  tr,
		Identity: SelfIdentityConfig{
			EndpointID: epID,
			EvidenceReader: func(context.Context) (ProcessEvidence, error) {
				// Native host process has no container ID in /proc/self/cgroup.
				return ProcessEvidence{}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSDKAdapter(native): %v", err)
	}
	if err := nativeAdapter.VerifySelf(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("native dev mode without explicit ID VerifySelf = %v, want %v", err, ErrUnverified)
	}
	if err := nativeAdapter.Stop(context.Background(), TargetIdentity{EndpointID: epID, ContainerID: testSelfID}, StopOptions{}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("native dev mode Stop(mandatary) = %v, want %v", err, ErrUnverified)
	}
	if got := nativeAdapter.Counters().TotalOperational(); got != 0 {
		t.Fatalf("native dev mode TotalOperational() = %d, want 0", got)
	}
}

func (c SelfIdentityConfig) ExplicitContainerIDAsContainerID() ContainerID {
	return ContainerID(c.ExplicitContainerID)
}

func TestParseCgroupContainerID(t *testing.T) {
	validID := string(testSelfID)

	tests := []struct {
		name      string
		content   string
		wantID    ContainerID
		wantPriv  bool
		wantError bool
	}{
		{
			name:    "cgroup v2 docker scope",
			content: "0::/system.slice/docker-" + validID + ".scope\n",
			wantID:  testSelfID,
		},
		{
			name:    "cgroup v1 multiple controllers same container ID",
			content: "12:memory:/docker/" + validID + "\n11:cpu,cpuacct:/docker/" + validID + "\n",
			wantID:  testSelfID,
		},
		{
			name:     "cgroup v2 private namespace root",
			content:  "0::/\n",
			wantPriv: true,
		},
		{
			name:      "conflicting container IDs in cgroup text",
			content:   "12:memory:/docker/" + validID + "\n11:cpu:/docker/" + string(testPeerID) + "\n",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, priv, err := ParseCgroupContainerID(tc.content)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != tc.wantID || priv != tc.wantPriv {
				t.Fatalf("got (id=%q, priv=%v), want (id=%q, priv=%v)", id, priv, tc.wantID, tc.wantPriv)
			}
		})
	}
}
