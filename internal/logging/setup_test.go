package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Only the secret-free setup URL shape is loggable; every token-bearing or
// otherwise decorated variant is redacted, so the URL cannot become a secret
// channel even through a caller mistake.
func TestSetupURLAdmitsOnlyTheSecretFreeShape(t *testing.T) {
	const canary = "SETUPTOKENCANARYSETUPTOKENCANARYSETUPTOKENCANARY22"
	for _, c := range []struct {
		url  string
		keep bool
	}{
		{"https://mandatary.example.invalid/setup", true},
		{"https://mandatary.example.invalid:8443/setup", true},
		{"https://mandatary.example.invalid/setup?token=" + canary, false},
		{"https://mandatary.example.invalid/setup#" + canary, false},
		{"https://mandatary.example.invalid/setup/" + canary, false},
		{"https://user:" + canary + "@mandatary.example.invalid/setup", false},
		{"https://mandatary.example.invalid/setup?", false},
		{"http://mandatary.example.invalid/setup", false},
		{"https://mandatary.example.invalid/other", false},
		{"https://mandatary.example.invalid/setup " + canary, false},
		{"https://mandatary.example.invalid/setup\r\n" + canary, false},
		{"", false},
	} {
		var out bytes.Buffer
		logger, err := New(&out, slog.LevelInfo, "json")
		if err != nil {
			t.Fatal(err)
		}
		logger.Info(SetupAvailable, "setup_url", c.url, "generation", int64(3), "expires_at", time.Unix(1_800_000_000, 0).UTC())
		got := out.String()
		if strings.Contains(got, canary) {
			t.Fatalf("token leaked for %q: %s", c.url, got)
		}
		if c.keep && !strings.Contains(got, c.url) {
			t.Fatalf("legitimate setup URL was redacted: %s", got)
		}
		if !c.keep && c.url != "" && strings.Contains(got, c.url) {
			t.Fatalf("unsafe URL logged: %s", got)
		}
		if !strings.Contains(got, `"generation":3`) || !strings.Contains(got, SetupAvailable) {
			t.Fatalf("setup event metadata missing: %s", got)
		}
	}
}

func TestSetupReasonAndGenerationAreAllowlisted(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(&out, slog.LevelInfo, "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Warn(SetupUnavailable, "reason", "rotation_required")
	logger.Warn(SetupUnavailable, "reason", "free text with SECRETCANARY")
	logger.Warn(SetupUnavailable, "generation", "SECRETCANARY", "expires_at", "SECRETCANARY")
	logger.Warn(SetupUnavailable, "generation", int64(-1))
	if strings.Contains(out.String(), "SECRETCANARY") {
		t.Fatalf("arbitrary text escaped the allowlist: %s", out.String())
	}
	if !strings.Contains(out.String(), "rotation_required") {
		t.Fatal("allowlisted reason dropped")
	}
	// A message not in the schema is replaced, never emitted verbatim.
	var other bytes.Buffer
	l2, _ := New(&other, slog.LevelInfo, "json")
	l2.Info("initial setup token ABCDEFGH")
	if strings.Contains(other.String(), "ABCDEFGH") {
		t.Fatal("free-form setup message was emitted")
	}
}
