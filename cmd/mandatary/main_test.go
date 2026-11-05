package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
)

func TestRuntimeLoggingAndFailureBoundaries(t *testing.T) {
	const canary = "synthetic-runtime-secret-canary"
	for _, format := range []string{"json", "text"} {
		for _, level := range []string{"debug", "info", "warn", "error"} {
			for _, scenario := range []string{"ok", "config", "key", "storage", "listener"} {
				t.Run(format+"/"+level+"/"+scenario, func(t *testing.T) {
					values := map[string]string{"MANDATARY_DATA_DIR": filepath.Join(t.TempDir(), "data"), "MANDATARY_MASTER_KEY": strings.Repeat("42", 32), "MANDATARY_LOG_LEVEL": level, "MANDATARY_LOG_FORMAT": format}
					switch scenario {
					case "config":
						values["MANDATARY_LOG_LEVEL"] = canary
					case "key":
						values["MANDATARY_MASTER_KEY"] = canary
					case "storage":
						values["MANDATARY_DATA_DIR"] = filepath.Join(t.TempDir(), canary, "missing-parent", "data")
					}
					var output bytes.Buffer
					called := false
					result := run(t.Context(), func(k string) string { return values[k] }, &output, func(s *http.Server) error {
						called = true
						if s.ErrorLog == nil {
							t.Fatal("HTTP server default stderr logging remains enabled")
						}
						s.ErrorLog.Print(canary)
						log.Print(canary)
						slog.Error(canary, "error", errors.New(canary))
						r := httptest.NewRequest(http.MethodGet, "/setup?token="+canary, nil)
						r.Header.Set("Cookie", "session="+canary)
						w := httptest.NewRecorder()
						s.Handler.ServeHTTP(w, r)
						if w.Code != 404 {
							t.Fatal("logging added a product route")
						}
						if scenario == "listener" {
							return errors.New(canary)
						}
						return http.ErrServerClosed
					})
					success := scenario == "ok"
					if (result == 0) != success {
						t.Fatal("incorrect process result")
					}
					if called != (success || scenario == "listener") {
						t.Fatal("invalid startup reached listener")
					}
					if output.Len() == 0 {
						t.Fatal("failure/log bridge not exercised")
					}
					for _, secret := range []string{canary, values["MANDATARY_MASTER_KEY"], values["MANDATARY_DATA_DIR"]} {
						if strings.Contains(output.String(), secret) {
							t.Fatal("runtime diagnostic leaked input")
						}
					}
				})
			}
		}
	}
}

func TestDevelopmentServerHasBoundedIOAndStaticOnlySurface(t *testing.T) {
	logger, err := logging.New(io.Discard, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}
	s := developmentServer(logger)
	if s.Addr != "127.0.0.1:8080" {
		t.Fatalf("development server must bind loopback: %s", s.Addr)
	}
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second || s.WriteTimeout != 10*time.Second || s.IdleTimeout != 60*time.Second {
		t.Fatal("missing bounded HTTP I/O")
	}
	if s.Handler == nil || s.MaxHeaderBytes != 16*1024 {
		t.Fatal("server missing static handler/header bound")
	}
}
