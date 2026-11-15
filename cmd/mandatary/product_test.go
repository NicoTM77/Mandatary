package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/config"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/logging"
)

// P1.19 composition: the Docker-backed surface is built only from an explicit setting, verifies its own
// identity afresh before it is ready, and never reaches a daemon the operator did not name. The SELF cases
// run the REAL SDK adapter against an in-process fake Docker daemon on a unix socket (no real daemon,
// no container build); the real-daemon equivalents run in the isolated image acceptance (scripts/image-acceptance).

const (
	instanceUUID = "7a1c3b52-9d44-4b0e-8f21-5c6d7e8f9a0b"
	selfFullID   = "5e1f0a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7"
	peerFullID   = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	otherFullID  = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

type fakeContainer struct {
	id     string
	labels map[string]string
}

// fakeDaemon is a minimal Docker Engine API answering exactly the calls self-verification makes, and
// counting every OPERATIONAL call (anything beyond ping/info/list/inspect-for-proof).
type fakeDaemon struct {
	mu          sync.Mutex
	apiVersion  string
	containers  []fakeContainer
	dropPings   bool
	operational atomic.Int64
	requests    atomic.Int64
	path        string
}

func newFakeDaemon(t *testing.T, containers ...fakeContainer) *fakeDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "fd")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDaemon{apiVersion: "1.52", containers: containers, path: filepath.Join(dir, "d.sock")}
	ln, err := net.Listen("unix", d.path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: d, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = os.RemoveAll(dir) })
	return d
}

func (d *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.requests.Add(1)
	d.mu.Lock()
	version, containers, drop := d.apiVersion, append([]fakeContainer(nil), d.containers...), d.dropPings
	d.mu.Unlock()
	w.Header().Set("Api-Version", version)
	w.Header().Set("Ostype", "linux")
	w.Header().Set("Content-Type", "application/json")
	if drop {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	p := r.URL.Path
	if i := strings.Index(p, "/containers/"); i >= 0 && strings.HasPrefix(p, "/v") {
		p = p[strings.Index(p[1:], "/")+1:]
	}
	switch {
	case p == "/_ping":
		if drop {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "OK")
	case p == "/info" || strings.HasSuffix(p, "/info"):
		_ = json.NewEncoder(w).Encode(map[string]any{"ID": "FAKE-DAEMON-0001"})
	case strings.HasSuffix(p, "/containers/json"):
		out := make([]map[string]any, 0, len(containers))
		for _, c := range containers {
			out = append(out, map[string]any{"Id": c.id, "Names": []string{"/" + c.id[:12]}, "Labels": c.labels, "State": "running"})
		}
		_ = json.NewEncoder(w).Encode(out)
	case strings.Contains(p, "/containers/") && strings.HasSuffix(p, "/json"):
		for _, c := range containers {
			if strings.Contains(p, "/containers/"+c.id+"/") {
				_ = json.NewEncoder(w).Encode(map[string]any{"Id": c.id, "Created": "2026-01-01T00:00:00Z", "State": map[string]any{"StartedAt": "2026-01-01T00:00:01Z"}, "Config": map[string]any{"Labels": c.labels}})
				return
			}
		}
		http.Error(w, `{"message":"no such container"}`, http.StatusNotFound)
	default:
		d.operational.Add(1) // start/stop/restart/logs/anything else: must stay zero in these tests
		http.Error(w, `{"message":"unexpected"}`, http.StatusNotFound)
	}
}

func selfLabels(uuid string) map[string]string {
	l := map[string]string{docker.SelfLabelKey: docker.SelfLabelValue}
	if uuid != "" {
		l[docker.SelfInstanceUUIDLabelKey] = uuid
	}
	return l
}

func privateCgroup(context.Context) (docker.ProcessEvidence, error) {
	return docker.ProcessEvidence{PrivateCgroupNS: true}, nil
}

// syncBuffer is a log sink the verification goroutine and the test may touch concurrently.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type composed struct {
	h       http.Handler
	p       *product
	logs    *syncBuffer
	fixture *cliFixture
}

func composeFor(t *testing.T, values map[string]string, opts productOptions) *composed {
	t.Helper()
	f := newCLIFixture(t)
	logs := &syncBuffer{}
	logger, err := logging.New(logs, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key}
	for k, v := range values {
		env[k] = v
	}
	c, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	repo, err := openConfiguredRepository(t.Context(), func(k string) string { return env[k] }, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	old := verifyInterval
	verifyInterval = 20 * time.Millisecond
	t.Cleanup(func() { verifyInterval = old })
	p, ok := composeProduct(t.Context(), logger, c, repo, opts)
	if !ok {
		t.Fatal("composition refused a valid deployment")
	}
	out := &composed{p: p, logs: logs, fixture: f}
	if p != nil {
		t.Cleanup(p.stop)
		out.h = api.Compose(p.rest, p.mcp, http.NotFoundHandler())
	} else {
		out.h = api.Compose(nil, nil, http.NotFoundHandler())
	}
	return out
}

func (c *composed) get(path string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://mandatary.example.invalid"+path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func (c *composed) ready() (int, bool) {
	w := c.get("/api/v1/readyz")
	var body struct{ Ready bool }
	_ = json.NewDecoder(w.Body).Decode(&body)
	return w.Code, body.Ready
}

func (c *composed) waitReady(t *testing.T, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ready := c.ready(); ready == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, ready := c.ready()
	t.Fatalf("readiness never became %v (last %d %v)", want, code, ready)
}

func TestNoDockerSurfaceIsComposedUnlessConfigured(t *testing.T) {
	c := composeFor(t, nil, productOptions{evidence: privateCgroup})
	if c.p != nil {
		t.Fatal("a Docker surface appeared without an explicit setting")
	}
	if w := c.get("/api/v1/readyz"); w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured readyz must be the common 404, got %d", w.Code)
	}
}

func TestMockBackendComposesAVerifiedSurfaceWithoutAnySocket(t *testing.T) {
	c := composeFor(t, map[string]string{"MANDATARY_DEV_MOCK_DOCKER": "true"}, productOptions{})
	if code, ready := c.ready(); code != http.StatusOK || !ready {
		t.Fatalf("mock backend must verify before serving: %d %v", code, ready)
	}
	if !strings.Contains(c.logs.String(), logging.DockerMockActive) {
		t.Fatal("the mock backend must announce itself in the log")
	}
	// Admission is still authentication-first: an unauthenticated REST and MCP request is refused.
	if w := c.get("/api/v1/endpoints/local/containers/edge-proxy/status"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated REST request got %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "https://mandatary.example.invalid/mcp", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated MCP request got %d", w.Code)
	}
}

func TestSELFVerifiedWithInstanceBindingIsReadyAndDispatchesNothing(t *testing.T) {
	d := newFakeDaemon(t, fakeContainer{selfFullID, selfLabels(instanceUUID)}, fakeContainer{peerFullID, selfLabels("")}, fakeContainer{otherFullID, map[string]string{"app": "x"}})
	c := composeFor(t, map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + d.path, "MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, productOptions{evidence: privateCgroup})
	if code, ready := c.ready(); code != http.StatusOK || !ready {
		t.Fatalf("SELF-11 positive control: private cgroup + matching binding must verify: %d %v logs=%s", code, ready, c.logs)
	}
	if d.operational.Load() != 0 {
		t.Fatalf("verification made %d operational calls", d.operational.Load())
	}
	if !strings.Contains(c.logs.String(), logging.DockerVerified) {
		t.Fatalf("verified transition not logged: %s", c.logs)
	}
	// No credential exists, so nothing is dispatched even though the backend is verified.
	c.get("/api/v1/endpoints/local/containers/" + otherFullID + "/status")
	if d.operational.Load() != 0 {
		t.Fatal("an unauthenticated request reached the daemon")
	}
}

func TestSELFNegativeCasesKeepReadinessFalseOnTheRealAdapter(t *testing.T) {
	selfOnly := []fakeContainer{{selfFullID, selfLabels(instanceUUID)}}
	for _, tc := range []struct {
		name       string
		containers []fakeContainer
		env        map[string]string
		evidence   docker.ProcessEvidenceReader
		version    string
	}{
		{"SELF-01 no runtime evidence and no binding", selfOnly, nil, privateCgroup, ""},
		{"SELF-03 label without proof of which member is this process", []fakeContainer{{selfFullID, selfLabels("")}}, nil, privateCgroup, ""},
		{"SELF-11 binding UUID not on any member", selfOnly, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": "11111111-2222-4333-8444-555555555555"}, privateCgroup, ""},
		{"SELF-11 duplicate binding (recreation overlap)", []fakeContainer{{selfFullID, selfLabels(instanceUUID)}, {peerFullID, selfLabels(instanceUUID)}}, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, privateCgroup, ""},
		{"SELF-02 explicit ID that is not a member", selfOnly, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID, "MANDATARY_SELF_CONTAINER_ID": otherFullID}, privateCgroup, ""},
		{"SELF-02 partial explicit ID", selfOnly, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID, "MANDATARY_SELF_CONTAINER_ID": selfFullID[:12]}, privateCgroup, ""},
		{"SELF-02 runtime ID conflicts with the binding", selfOnly, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, func(context.Context) (docker.ProcessEvidence, error) {
			return docker.ProcessEvidence{ContainerID: peerFullID}, nil
		}, ""},
		{"mandatory evidence unreadable", selfOnly, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, func(context.Context) (docker.ProcessEvidence, error) {
			return docker.ProcessEvidence{}, docker.ErrUnverified
		}, ""},
		{"SUP-03 daemon API below the 1.44 minimum", selfOnly, map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, privateCgroup, "1.43"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newFakeDaemon(t, tc.containers...)
			if tc.version != "" {
				d.apiVersion = tc.version
			}
			env := map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + d.path}
			for k, v := range tc.env {
				env[k] = v
			}
			c := composeFor(t, env, productOptions{evidence: tc.evidence})
			time.Sleep(120 * time.Millisecond) // several retries: it must never become ready by retrying
			if code, ready := c.ready(); code != http.StatusServiceUnavailable || ready {
				t.Fatalf("readiness must be false: %d %v", code, ready)
			}
			if d.operational.Load() != 0 {
				t.Fatalf("%d operational daemon calls while unverified", d.operational.Load())
			}
			if strings.Contains(c.logs.String(), selfFullID) || strings.Contains(c.logs.String(), d.path) || strings.Contains(c.logs.String(), instanceUUID) {
				t.Fatalf("a deployment identity reached the log: %s", c.logs)
			}
			if !strings.Contains(c.logs.String(), logging.DockerUnverified) {
				t.Fatalf("the unverified state was not logged: %s", c.logs)
			}
			if n := strings.Count(c.logs.String(), logging.DockerUnverified); n != 1 {
				t.Fatalf("the unverified line must appear once per outage, saw %d", n)
			}
		})
	}
}

func TestAnUnreachableSocketNeverPanicsAndRecoversOnlyByFreshVerification(t *testing.T) {
	dir, err := os.MkdirTemp("", "u") // short: a unix socket path is limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	missing := filepath.Join(dir, "absent.sock")
	c := composeFor(t, map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + missing, "MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, productOptions{evidence: privateCgroup})
	if code, ready := c.ready(); code != http.StatusServiceUnavailable || ready {
		t.Fatalf("a missing socket must keep readiness false: %d %v", code, ready)
	}
	// The daemon appears later with a correct identity: only the verification loop may make it ready.
	d := newFakeDaemon(t, fakeContainer{selfFullID, selfLabels(instanceUUID)})
	if err := os.Symlink(d.path, missing); err != nil {
		t.Fatal(err)
	}
	c.waitReady(t, true)
	// The daemon vanishes and returns with the proof dropped (SELF-07): readiness follows the truth.
	d.mu.Lock()
	d.dropPings = true // every request now fails: nothing resets the proof by hand, the heartbeat must notice
	d.mu.Unlock()
	c.waitReady(t, false)
	if !strings.Contains(c.logs.String(), logging.DockerUnverified) {
		t.Fatal("the loss of proof was not logged")
	}
	d.mu.Lock()
	d.dropPings = false
	d.mu.Unlock()
	c.waitReady(t, true)
}

func TestSafetyResetWiredToTheSharedAuthorizerDropsTheProofUntilReverified(t *testing.T) {
	d := newFakeDaemon(t, fakeContainer{selfFullID, selfLabels(instanceUUID)})
	c := composeFor(t, map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + d.path, "MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, productOptions{evidence: privateCgroup})
	c.waitReady(t, true)
	before := d.requests.Load()
	if c.p.safetyReset == nil || c.p.notify == nil || c.p.targets == nil {
		t.Fatal("administrative wiring missing")
	}
	// Drop the proof while the verification loop is stopped, so the dropped state is observable.
	c.p.stop()
	c.p.safetyReset()
	if code, ready := c.ready(); code != http.StatusServiceUnavailable || ready {
		t.Fatalf("restore/reapproval reset left the proof in place: %d %v", code, ready)
	}
	if d.requests.Load() != before {
		t.Fatal("the reset itself must not contact the daemon")
	}
}

func TestOnlyTheConfiguredSocketIsEverDialled(t *testing.T) {
	d := newFakeDaemon(t, fakeContainer{selfFullID, selfLabels(instanceUUID)})
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	c := composeFor(t, map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + d.path, "MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, productOptions{evidence: privateCgroup})
	c.waitReady(t, true)
	if d.requests.Load() == 0 {
		t.Fatal("the configured socket was not used")
	}
}

func TestRunComposesTheSurfaceBehindOneListenerAndStopsItBeforeStorageCloses(t *testing.T) {
	f := newCLIFixture(t)
	var out bytes.Buffer
	values := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key, "MANDATARY_DEV_MOCK_DOCKER": "true", "MANDATARY_LOG_FORMAT": "json"}
	code := run(t.Context(), func(k string) string { return values[k] }, &out, func(s *http.Server) error {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/readyz", nil)
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ready":true`) {
			t.Errorf("readyz through the real handler chain: %d %s", w.Code, w.Body)
		}
		// The static surface is untouched and no operations listener exists.
		w = httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusOK {
			t.Errorf("static root: %d", w.Code)
		}
		return http.ErrServerClosed
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if strings.Contains(out.String(), "docker.sock") {
		t.Fatal("log mentions a socket path")
	}
}

func TestInvalidMockAndSocketTogetherRefusesStartup(t *testing.T) {
	f := newCLIFixture(t)
	var out bytes.Buffer
	values := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key, "MANDATARY_DEV_MOCK_DOCKER": "true", "MANDATARY_DOCKER_SOCKET": "unix:///var/run/docker.sock"}
	served := false
	code := run(t.Context(), func(k string) string { return values[k] }, &out, func(*http.Server) error { served = true; return http.ErrServerClosed })
	if code == 0 || served {
		t.Fatalf("a mock beside a real socket started: %d %v", code, served)
	}
	_ = fmt.Sprint(out)
}

// cgroupEvidence feeds real /proc/self/cgroup text through the product's own parser, so the shapes below
// are the ones the kernel produces rather than hand-built ProcessEvidence values.
func cgroupEvidence(text string) docker.ProcessEvidenceReader {
	return func(context.Context) (docker.ProcessEvidence, error) {
		if text == "" {
			return docker.ProcessEvidence{}, nil // the file is absent (a non-Linux or masked /proc)
		}
		id, private, err := docker.ParseCgroupContainerID(text)
		if err != nil {
			return docker.ProcessEvidence{}, err
		}
		return docker.ProcessEvidence{ContainerID: string(id), PrivateCgroupNS: private}, nil
	}
}

// SELF-13 / S1.4: there is no native real-socket exception. With a real socket, a process that is not
// provably inside a container (no container ID in its cgroup and not the root of a private cgroup
// namespace) must never verify, even when the deployment binding names a labelled member of the daemon's
// inventory: a borrowed binding would otherwise let a host process act as that container.
func TestSELFNativeEvidenceWithARealSocketNeverVerifies(t *testing.T) {
	binding := map[string]string{"MANDATARY_SELF_INSTANCE_UUID": instanceUUID}
	for _, tc := range []struct {
		name, cgroup string
	}{
		{"native cgroup v2 (user slice)", "0::/user.slice/user-1000.slice/session-3.scope\n"},
		{"native cgroup v1 (several hierarchies)", "12:cpu,cpuacct:/user.slice\n11:memory:/user.slice\n1:name=systemd:/user.slice/user-1000.slice\n"},
		{"native cgroup v2 under systemd service", "0::/system.slice/ssh.service\n"},
		{"no /proc/self/cgroup at all", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newFakeDaemon(t, fakeContainer{selfFullID, selfLabels(instanceUUID)})
			env := map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + d.path}
			for k, v := range binding {
				env[k] = v
			}
			c := composeFor(t, env, productOptions{evidence: cgroupEvidence(tc.cgroup)})
			time.Sleep(120 * time.Millisecond) // several retries: it must never become ready by retrying
			if code, ready := c.ready(); code != http.StatusServiceUnavailable || ready {
				t.Fatalf("native evidence must keep readiness false: %d %v", code, ready)
			}
			if d.operational.Load() != 0 {
				t.Fatalf("%d operational daemon calls while unverified", d.operational.Load())
			}
		})
	}
}

// The two accepted shapes stay accepted (positive controls for the test above).
func TestSELFContainerEvidenceWithARealSocketStillVerifies(t *testing.T) {
	for _, tc := range []struct {
		name, cgroup string
	}{
		{"private cgroup namespace root", "0::/\n"},
		{"cgroup v2 path naming the container", "0::/system.slice/docker-" + selfFullID + ".scope\n"},
		{"cgroup v1 path naming the container", "12:cpu:/docker/" + selfFullID + "\n11:memory:/docker/" + selfFullID + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newFakeDaemon(t, fakeContainer{selfFullID, selfLabels(instanceUUID)})
			c := composeFor(t, map[string]string{"MANDATARY_DOCKER_SOCKET": "unix://" + d.path, "MANDATARY_SELF_INSTANCE_UUID": instanceUUID}, productOptions{evidence: cgroupEvidence(tc.cgroup)})
			c.waitReady(t, true)
		})
	}
}
