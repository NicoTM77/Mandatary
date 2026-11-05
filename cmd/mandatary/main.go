// Mandatary currently runs a loopback-only static development skeleton.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/NicoTM77/Mandatary/internal/config"
	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/web"
)

func developmentServer(logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           logging.HTTP(logger, web.Handler()),
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
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
	result := 0
	logger.Info(logging.ServerStarted)
	if err := serve(developmentServer(logger)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error(logging.ServerFailed, "stage", "listener")
		result = 1
	}
	if err := repository.Close(); err != nil {
		logger.Error(logging.StorageCloseFailed)
		result = 1
	}
	return result
}

func main() {
	os.Exit(run(context.Background(), os.Getenv, os.Stdout, func(s *http.Server) error { return s.ListenAndServe() }))
}
