package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/NicoTM77/Mandatary/internal/config"
)

// Packaging support (P1.19): a container health probe that needs no shell or curl
// (the image is distroless), and a graceful stop so SIGTERM from `docker stop` lets
// in-flight requests finish and storage close instead of killing the process.

const (
	healthTimeout = 3 * time.Second
	livePath      = "/"
	readyPath     = "/api/v1/readyz"
	// shutdownGrace is shorter than Docker's default 10 s stop timeout, so the process
	// finishes (and closes storage) before the daemon would send SIGKILL.
	shutdownGrace = 8 * time.Second
)

// probeAddress turns the configured listen address into the address to probe: a wildcard
// bind is probed over loopback, a specific address as it is.
func probeAddress(configured string) string {
	host, port, err := net.SplitHostPort(configured)
	if err != nil {
		return configured
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if ip != nil && ip.To4() == nil {
			return net.JoinHostPort("::1", port)
		}
		return net.JoinHostPort("127.0.0.1", port)
	}
	return configured
}

// runHealthcheck implements `mandatary healthcheck [--ready]`. Without --ready it asks the
// process whether it is alive (the static root answers 200). With --ready it asks whether the
// Docker-backed surface is ready: GET /api/v1/readyz must answer 200, so a missing socket,
// unproven self-identity or any other missing safety prerequisite fails. Exit 0 = healthy,
// 1 = unhealthy, 2 = usage. Output is a fixed word; nothing from the response is echoed.
func runHealthcheck(e cliEnv, args []string) int {
	path := livePath
	switch len(args) {
	case 0:
	case 1:
		if args[0] != "--ready" {
			_, _ = fmt.Fprint(e.stderr, cliUsage)
			return 2
		}
		path = readyPath
	default:
		_, _ = fmt.Fprint(e.stderr, cliUsage)
		return 2
	}
	c, err := config.Load(e.getenv)
	if err != nil {
		return e.fail("unhealthy: invalid configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	// No proxy, no redirects: the probe talks to this process only, and a redirect is not health.
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+probeAddress(c.AdminListenAddr)+path, nil)
	if err != nil {
		return e.fail("unhealthy")
	}
	resp, err := client.Do(req)
	if err != nil {
		return e.fail("unhealthy: no answer")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		if path == readyPath {
			return e.fail("not ready")
		}
		return e.fail("unhealthy")
	}
	_, _ = fmt.Fprintln(e.stdout, "ok")
	return 0
}

// serveUntilDone serves on ln until ctx ends, then stops gracefully: no new connections, in-flight
// requests may finish for up to grace, after which remaining connections are closed. A clean or
// forced stop returns nil; a listener failure returns its error. Streams (log follow, MCP) end
// when the authorizer closes, so nothing here waits on them beyond the grace period.
func serveUntilDone(ctx context.Context, srv *http.Server, ln net.Listener, grace time.Duration) error {
	failed := make(chan error, 1)
	go func() { failed <- srv.Serve(ln) }()
	select {
	case err := <-failed:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	stop, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(stop); err != nil {
		_ = srv.Close()
	}
	if err := <-failed; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
