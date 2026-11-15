package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// P1.19 packaging contract: the listener comes from configuration, the container health
// probe needs no shell or curl, the process stops gracefully on SIGTERM and the build
// identity survives a VCS-free image build.

func TestServerAddressComesFromConfigurationAndDefaultsToLoopback(t *testing.T) {
	for _, tc := range []struct{ env, want string }{{"", "127.0.0.1:8080"}, {":8080", ":8080"}, {"172.20.0.5:9090", "172.20.0.5:9090"}} {
		f := newCLIFixture(t)
		values := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key}
		if tc.env != "" {
			values["MANDATARY_ADMIN_LISTEN_ADDR"] = tc.env
		}
		var got string
		var out bytes.Buffer
		code := run(t.Context(), func(k string) string { return values[k] }, &out, func(s *http.Server) error {
			got = s.Addr
			return http.ErrServerClosed
		})
		if code != 0 || got != tc.want {
			t.Fatalf("env %q: exit %d addr %q (want %q): %s", tc.env, code, got, tc.want, out.String())
		}
	}
}

func TestPhaseFourListenerSettingsRefuseStartupBeforeStorageOrListener(t *testing.T) {
	for _, name := range []string{"MANDATARY_OPS_UI_ENABLED", "MANDATARY_OPS_LISTEN_ADDR"} {
		f := newCLIFixture(t)
		values := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key, name: "true"}
		served := false
		var out bytes.Buffer
		code := run(t.Context(), func(k string) string { return values[k] }, &out, func(*http.Server) error { served = true; return http.ErrServerClosed })
		if code == 0 || served || !strings.Contains(out.String(), "configuration") {
			t.Fatalf("%s: exit %d served=%v: %s", name, code, served, out.String())
		}
	}
}

// healthTarget serves canned liveness/readiness answers on a real loopback socket.
func healthTarget(t *testing.T, root, ready int) (addr string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(root)
		case "/api/v1/readyz":
			w.WriteHeader(ready)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func runHealth(t *testing.T, addr string, extra ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	env := cliEnv{args: append([]string{"healthcheck"}, extra...), getenv: func(k string) string {
		if k == "MANDATARY_ADMIN_LISTEN_ADDR" {
			return addr
		}
		return ""
	}, stdout: &out, stderr: &errOut}
	code := runCLI(env)
	return code, out.String() + errOut.String()
}

func TestHealthcheckLivenessAndReadinessAreDistinct(t *testing.T) {
	if code, out := runHealth(t, healthTarget(t, 200, 503)); code != 0 {
		t.Fatalf("a live process that is not ready must still pass the liveness probe: %d %q", code, out)
	}
	if code, out := runHealth(t, healthTarget(t, 200, 503), "--ready"); code != 1 || !strings.Contains(out, "not ready") {
		t.Fatalf("a 503 readiness answer must fail --ready: %d %q", code, out)
	}
	if code, _ := runHealth(t, healthTarget(t, 200, 404), "--ready"); code != 1 {
		t.Fatalf("an unmounted readiness route (no Docker backend) must fail --ready: %d", code)
	}
	if code, out := runHealth(t, healthTarget(t, 200, 200), "--ready"); code != 0 {
		t.Fatalf("ready must pass: %d %q", code, out)
	}
	if code, _ := runHealth(t, healthTarget(t, 500, 200)); code != 1 {
		t.Fatalf("a failing root must fail liveness: %d", code)
	}
	if code, _ := runHealth(t, healthTarget(t, 302, 200)); code != 1 {
		t.Fatalf("a redirect is not health: %d", code)
	}
}

func TestHealthcheckFailsWhenNothingListensAndRefusesBadInput(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	if code, _ := runHealth(t, addr); code != 1 {
		t.Fatalf("closed port must be unhealthy: %d", code)
	}
	if code, _ := runHealth(t, "not-an-address"); code != 1 {
		t.Fatalf("an invalid configured address must be unhealthy: %d", code)
	}
	for _, args := range [][]string{{"--bogus"}, {"extra"}, {"--ready", "--ready", "x"}} {
		if code, _ := runHealth(t, healthTarget(t, 200, 200), args...); code != 2 {
			t.Fatalf("%v: usage error expected, got %d", args, code)
		}
	}
}

func TestHealthcheckProbesLoopbackWhenTheServerListensOnAllInterfaces(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{{":8080", "127.0.0.1:8080"}, {"0.0.0.0:9", "127.0.0.1:9"}, {"[::]:9", "[::1]:9"}, {"172.20.0.5:9090", "172.20.0.5:9090"}} {
		if got := probeAddress(tc.configured); got != tc.want {
			t.Fatalf("%q: %q want %q", tc.configured, got, tc.want)
		}
	}
}

func TestHealthcheckNeverFollowsRedirectsOrProxies(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	if code, _ := runHealth(t, strings.TrimPrefix(srv.URL, "http://")); code != 1 || hits.Load() != 1 {
		t.Fatalf("redirect followed or proxy used: exit %d hits %d", code, hits.Load())
	}
}

func TestServerStopsGracefullyAndForcesAfterTheGracePeriod(t *testing.T) {
	// A request that finishes inside the grace period is completed, not cut.
	started, release := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "done")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- serveUntilDone(ctx, srv, ln, 5*time.Second) }()
	type result struct {
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err != nil {
			got <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		got <- result{string(b), err}
	}()
	<-started
	cancel()
	select {
	case err := <-served:
		t.Fatalf("returned while a request was in flight: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if r := <-got; r.err != nil || r.body != "done" {
		t.Fatalf("in-flight request cut: %+v", r)
	}
	if err := <-served; err != nil {
		t.Fatalf("graceful stop must report success: %v", err)
	}

	// A handler that never returns is cut at the grace deadline: the process must still exit.
	stuck := make(chan struct{})
	srv2 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(stuck)
		<-r.Context().Done()
	})}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(t.Context())
	served2 := make(chan error, 1)
	go func() { served2 <- serveUntilDone(ctx2, srv2, ln2, 200*time.Millisecond) }()
	go func() {
		if resp, err := http.Get("http://" + ln2.Addr().String() + "/"); err == nil { // the connection is cut on purpose
			_ = resp.Body.Close()
		}
	}()
	<-stuck
	cancel2()
	select {
	case err := <-served2:
		if err != nil {
			t.Fatalf("forced stop must still report success: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stuck handler kept the process alive past the grace period")
	}
}

func TestServeUntilDoneReportsARealListenerFailure(t *testing.T) {
	srv := &http.Server{Handler: http.NotFoundHandler()}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // Serve on a closed listener fails at once with a non-ErrServerClosed error.
	if err := serveUntilDone(t.Context(), srv, ln, time.Second); err == nil {
		t.Fatal("a listener failure was reported as a clean stop")
	}
}

func TestBuildIdentityUsesTheLinkerStampWhenThereIsNoVCSInformation(t *testing.T) {
	old := stampedRevision
	t.Cleanup(func() { stampedRevision = old })
	stampedRevision = "0123456789abcdef0123456789abcdef01234567"
	if got := buildIdentity(); got != "rev:0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("stamp not used: %q", got)
	}
	for _, bad := range []string{strings.Repeat("a", 65), "has space", "new\nline", "XYZ", "rev:abc"} {
		stampedRevision = bad
		if got := buildIdentity(); strings.HasPrefix(got, "rev:") && strings.Contains(got, bad) {
			t.Fatalf("malformed stamp %q was trusted: %q", bad, got)
		}
	}
	stampedRevision = ""
	if got := buildIdentity(); got == "rev:" {
		t.Fatalf("an empty stamp produced an empty revision: %q", got)
	}
}
