// Package config validates the implemented runtime settings without side effects.
package config

import (
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"unicode"
)

// Config contains no credential material. Master-key loading remains in store.
type Config struct {
	LogLevel  slog.Level
	LogFormat string
	DataDir   string
}

func (Config) String() string       { return "[REDACTED]" }
func (Config) GoString() string     { return "[REDACTED]" }
func (Config) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Load uses strict spellings: an invalid value is never echoed in diagnostics.
// An empty environment value selects the documented default.
func Load(getenv func(string) string) (Config, error) {
	c := Config{LogLevel: slog.LevelInfo, LogFormat: "json", DataDir: "/data"}
	switch getenv("MANDATARY_LOG_LEVEL") {
	case "", "info":
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		return Config{}, errors.New("invalid MANDATARY_LOG_LEVEL")
	}
	switch getenv("MANDATARY_LOG_FORMAT") {
	case "", "json":
	case "text":
		c.LogFormat = "text"
	default:
		return Config{}, errors.New("invalid MANDATARY_LOG_FORMAT")
	}
	if path := getenv("MANDATARY_DATA_DIR"); path != "" {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return Config{}, errors.New("invalid MANDATARY_DATA_DIR")
		}
		c.DataDir = path
	}
	// These settings may not masquerade as implemented security/product controls.
	for _, name := range []string{"MANDATARY_ADMIN_LISTEN_ADDR", "MANDATARY_DOCKER_SOCKET", "MANDATARY_DEV_MOCK_DOCKER", "MANDATARY_OPS_UI_ENABLED", "MANDATARY_OPS_LISTEN_ADDR", "MANDATARY_PASSWORD_HIBP_ENABLED"} {
		if getenv(name) != "" {
			return Config{}, errors.New("runtime setting not available in the development skeleton")
		}
	}
	return c, nil
}
