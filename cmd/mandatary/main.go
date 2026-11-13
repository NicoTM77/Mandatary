// Mandatary currently runs a loopback-only development skeleton plus the P1.09
// first-administrator setup surface and its host-local recovery helper.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/NicoTM77/Mandatary/internal/api"
	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/config"
	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/NicoTM77/Mandatary/web"
)

func developmentServer(logger *slog.Logger) *http.Server {
	return developmentServerWith(logger, web.Handler())
}

func developmentServerWith(logger *slog.Logger, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           logging.HTTP(logger, handler),
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

// maintenanceInterval bounds how long an expired generation's plaintext file or
// stale setup session can linger before protected cleanup runs.
const maintenanceInterval = 30 * time.Second

// startSetup wires the setup surface. It returns the handler to serve, a stop
// function (which must run before the repository closes) and ok=false only for an
// invalid operator configuration. It never issues a token on restart, after
// expiry, or when the store is not an eligible empty one; it logs only the
// configured secret-free setup URL.
func startSetup(ctx context.Context, logger *slog.Logger, c config.Config, repo *store.Repository) (http.Handler, func(), bool) {
	static := web.Handler()
	noop := func() {}
	if c.PublicOrigin == "" {
		if pending, err := auth.SetupPending(ctx, repo, time.Now()); err == nil && pending {
			logger.Warn(logging.SetupUnavailable, "reason", "origin_not_configured")
		}
		return static, noop, true
	}
	var lifecycle *auth.Lifecycle
	if c.NoticeRelay != "" {
		l, err := auth.NewLifecycle(repo, auth.NoticeSettings{Origin: c.PublicOrigin, Contact: c.NoticeContact, Sender: c.NoticeSender, Relay: c.NoticeRelay, Mode: c.NoticeTLS})
		if err != nil {
			return nil, noop, false
		}
		lifecycle = l
	}
	setup, err := auth.NewSetup(repo, lifecycle, auth.SetupSettings{Origin: c.PublicOrigin, Build: buildIdentity()})
	if err != nil {
		return nil, noop, false
	}
	result, err := setup.EnsureInitial(ctx)
	if err != nil {
		// Reconciliation/eligibility could not be established (storage, clock or an
		// unsafe reveal directory): no setup surface exists and nothing is issued.
		logger.Error(logging.SetupUnavailable, "reason", "storage")
		return static, noop, true
	}
	switch result.Outcome {
	case "issued", "active":
		url, _ := (auth.SetupSettings{Origin: c.PublicOrigin}).SetupURL()
		logger.Info(logging.SetupAvailable, "setup_url", url, "generation", result.Token.Generation, "expires_at", result.Token.ExpiresAt)
		if lifecycle == nil {
			logger.Warn(logging.SetupNoMail)
		}
	case "rotation_required":
		logger.Warn(logging.SetupUnavailable, "reason", "rotation_required")
	}
	adapter, err := auth.NewSetupHTTP(setup)
	if err != nil {
		return nil, noop, false
	}
	mux := http.NewServeMux()
	mux.Handle(auth.SetupPathPrefix, adapter.Handler())
	mux.Handle("/", static)
	// Account routes exist only when the Lifecycle exists (they need the password
	// and factor services, which are built from the notice settings). Without it
	// nothing is half-mounted: the paths fall through to the static 404/405.
	if lifecycle != nil {
		browser, ok := accountBrowser(lifecycle)
		if !ok {
			return nil, noop, false
		}
		for _, path := range auth.AccountPaths() {
			mux.Handle(path, browser)
		}
	}
	background, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(maintenanceInterval)
		defer ticker.Stop()
		for {
			select {
			case <-background.Done():
				return
			case <-ticker.C:
				maintainOnce(background, setup, lifecycle)
			}
		}
	}()
	return mux, func() { cancel(); wg.Wait() }, true
}

// accountBrowser builds the session service and the browser boundary carrying the
// slice-1 account routes (login, session, logout). WebAuthn is not configured in
// this build, so no security-key login or enrolment path exists (slice 2).
func accountBrowser(lifecycle *auth.Lifecycle) (*auth.Browser, bool) {
	sessions, err := auth.NewSessions(lifecycle, nil, auth.DefaultSessionSettings())
	if err != nil {
		return nil, false
	}
	browser := auth.NewBrowser(sessions)
	if err := auth.RegisterAccountRoutes(browser, sessions); err != nil {
		return nil, false
	}
	return browser, true
}

// maintainOnce performs protected cleanup of expired generations/sessions/files
// and, when notice delivery is configured, one bounded dispatch of pending
// security notices. Failures are not logged with detail; the next tick retries.
func maintainOnce(ctx context.Context, setup *auth.Setup, lifecycle *auth.Lifecycle) {
	_, _ = setup.Reconcile(ctx)
	if lifecycle != nil {
		_, _ = lifecycle.DispatchNotices(ctx, 32)
	}
}

// run returns after closing storage, including on listener failure. Runtime
// input/errors are never printed. The fallback for invalid log settings is a
// fixed JSON error on stdout, before key loading, storage or listener access.
func run(ctx context.Context, getenv func(string) string, stdout io.Writer, serve func(*http.Server) error) int {
	c, err := config.Load(getenv)
	if err != nil {
		fallback, logErr := logging.New(stdout, slog.LevelError, "json")
		if logErr == nil {
			fallback.Error(logging.StartupFailed, "stage", "configuration")
		}
		return 1
	}
	logger, err := logging.New(stdout, c.LogLevel, c.LogFormat)
	if err != nil {
		return 1
	}
	previous := slog.Default()
	slog.SetDefault(logger) // Also redirects standard log.Print through redaction.
	defer slog.SetDefault(previous)
	repository, err := openConfiguredRepository(ctx, getenv, c)
	if err != nil {
		logger.Error(logging.StartupFailed, "stage", "storage")
		return 1
	}
	handler, stopSetup, ok := startSetup(ctx, logger, c, repository)
	if !ok {
		stopSetup()
		_ = repository.Close()
		logger.Error(logging.StartupFailed, "stage", "configuration")
		return 1
	}
	result := 0
	logger.Info(logging.ServerStarted)
	// Reserve /api and /mcp: nothing under them may fall through to the static site or
	// the setup mux. The adapters need an executor (real Docker backend, endpoint
	// registry), which is composed by later rows; until then both answer the common 404.
	handler = api.Compose(nil, nil, handler)
	if err := serve(developmentServerWith(logger, handler)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error(logging.ServerFailed, "stage", "listener")
		result = 1
	}
	stopSetup() // stop background work before the repository closes
	if err := repository.Close(); err != nil {
		logger.Error(logging.StorageCloseFailed)
		result = 1
	}
	return result
}

func main() {
	if len(os.Args) > 1 {
		os.Exit(runCLI(productionCLI(os.Args[1:])))
	}
	os.Exit(run(context.Background(), os.Getenv, os.Stdout, func(s *http.Server) error { return s.ListenAndServe() }))
}
