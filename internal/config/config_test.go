package config

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestDataDirectoryValidationAndFormatting(t *testing.T) {
	for _, path := range []string{"/data/private", "/opt/data/scratch/synthetic-directory-canary"} {
		c, err := Load(func(k string) string {
			if k == "MANDATARY_DATA_DIR" {
				return path
			}
			return ""
		})
		if err != nil || c.DataDir != path {
			t.Fatal("absolute data directory rejected")
		}
		for _, rendered := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.LogValue().String()} {
			if strings.Contains(rendered, path) {
				t.Fatal("configuration formatting leaked data path")
			}
		}
	}
	for _, path := range []string{"relative", "/data/../escape", "/data\ninvalid", "/data\x00invalid"} {
		_, err := Load(func(k string) string {
			if k == "MANDATARY_DATA_DIR" {
				return path
			}
			return ""
		})
		if err == nil || strings.Contains(err.Error(), path) {
			t.Fatal("unsafe data path accepted or echoed")
		}
	}
}

func TestUnavailableSettingsFailClosed(t *testing.T) {
	// Refuse misleading no-op settings; these surfaces belong to later cards.
	for _, name := range []string{"MANDATARY_ADMIN_LISTEN_ADDR", "MANDATARY_DOCKER_SOCKET", "MANDATARY_DEV_MOCK_DOCKER", "MANDATARY_OPS_UI_ENABLED", "MANDATARY_OPS_LISTEN_ADDR", "MANDATARY_PASSWORD_HIBP_ENABLED"} {
		_, err := Load(func(k string) string {
			if k == name {
				return "synthetic-unavailable-setting-canary"
			}
			return ""
		})
		if err == nil || strings.Contains(err.Error(), "synthetic-unavailable-setting-canary") {
			t.Fatal("unavailable configuration was silently accepted or echoed")
		}
	}
}

func TestLoggingConfiguration(t *testing.T) {
	for _, format := range []string{"", "json", "text"} {
		for _, level := range []string{"", "debug", "info", "warn", "error"} {
			t.Run(format+"/"+level, func(t *testing.T) {
				values := map[string]string{"MANDATARY_LOG_FORMAT": format, "MANDATARY_LOG_LEVEL": level}
				c, err := Load(func(k string) string { return values[k] })
				if err != nil {
					t.Fatal("valid logging config denied")
				}
				wantFormat := format
				if wantFormat == "" {
					wantFormat = "json"
				}
				wantLevel := map[string]slog.Level{"": slog.LevelInfo, "debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}[level]
				if c.LogFormat != wantFormat || c.LogLevel != wantLevel || c.DataDir != "/data" {
					t.Fatal("incorrect config defaults or overrides")
				}
			})
		}
	}
	for _, name := range []string{"MANDATARY_LOG_LEVEL", "MANDATARY_LOG_FORMAT"} {
		for _, invalid := range []string{"DEBUG", " info", "trace", "-4", "json\n", "synthetic-config-canary"} {
			_, err := Load(func(k string) string {
				if k == name {
					return invalid
				}
				return ""
			})
			if err == nil {
				t.Fatal("invalid logging config accepted")
			}
			if strings.Contains(fmt.Sprint(err), invalid) {
				t.Fatal("config error echoed invalid value")
			}
		}
	}
}
