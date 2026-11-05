package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A value with user-controlled formatting must never be evaluated by logging.
type hostileValue struct{ calls *int }

func (h hostileValue) LogValue() slog.Value { *h.calls++; panic("formatter must not run") }
func (h hostileValue) String() string       { *h.calls++; panic("formatter must not run") }

func TestSecretCanariesAllLevelsAndFormats(t *testing.T) {
	canaries := []string{"synthetic-password-canary", "mdt_synthetic-bearer-canary", "synthetic-cookie-canary", "synthetic-totp-canary", "synthetic-recovery-canary", "synthetic-challenge-canary", "synthetic-master-key-canary", "synthetic-env-canary", "synthetic-setup-token-canary"}
	for _, format := range []string{"json", "text"} {
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
			t.Run(format+"/"+level.String(), func(t *testing.T) {
				var output bytes.Buffer
				logger, err := New(&output, slog.LevelDebug, format)
				if err != nil {
					t.Fatal("valid logger denied")
				}
				payload := strings.Join(canaries, " ")
				calls := 0
				attrs := []slog.Attr{
					slog.String("password", canaries[0]), slog.String("authorization", "Bearer "+canaries[1]),
					slog.String("cookie", canaries[2]), slog.String("totp_seed", canaries[3]),
					slog.String("recovery_code", canaries[4]), slog.String("challenge", canaries[5]),
					slog.String("MANDATARY_MASTER_KEY", canaries[6]), slog.Any("environment", []string{"TOKEN=" + canaries[7], "KEY=" + canaries[6]}),
					slog.Any("numeric_otp", 876543), slog.Any("binary", []byte(payload)), slog.Any("nested", map[string]any{"secret": payload}),
					slog.String("setup_url", "https://example.invalid/setup?token="+canaries[8]),
					slog.Any("error", errors.New(payload)), slog.Any("request", map[string]any{"body": payload}),
					slog.String(payload, payload), slog.String("method", payload), slog.Any("status", hostileValue{&calls}),
					slog.Group("http", slog.String("body", payload)), slog.Group(payload, slog.String("method", "GET")),
					slog.Any("arbitrary", hostileValue{&calls}), slog.Any("secret", Secret(payload)),
				}
				logger.LogAttrs(t.Context(), level, payload, attrs...)
				logger.With("password", payload, "opaque", hostileValue{&calls}).WithGroup(payload).LogAttrs(t.Context(), level, payload, attrs...)
				if calls != 0 {
					t.Fatal("logger executed arbitrary user formatting")
				}
				if !strings.Contains(output.String(), "[REDACTED]") {
					t.Fatal("no redaction marker emitted")
				}
				for _, c := range canaries {
					if strings.Contains(output.String(), c) {
						t.Fatal("secret canary escaped logging boundary")
					}
				}
				if strings.Contains(output.String(), "redacted=876543") || strings.Contains(output.String(), `"redacted":876543`) || strings.Contains(output.String(), "numeric_otp") {
					t.Fatal("numeric credential was serialized")
				}
				if format == "json" {
					for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
						var record map[string]any
						if json.Unmarshal([]byte(line), &record) != nil {
							t.Fatal("invalid JSON output")
						}
						if record["level"] != level.String() {
							t.Fatal("incorrect output level")
						}
					}
				} else if !strings.Contains(output.String(), "level="+level.String()) {
					t.Fatal("incorrect text output level")
				}
			})
		}
	}
}

func TestLevelFilteringAndUsefulMetadata(t *testing.T) {
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	for i, threshold := range levels {
		for _, format := range []string{"json", "text"} {
			var output bytes.Buffer
			logger, err := New(&output, threshold, format)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range levels {
				logger.WithGroup("http").With("method", "GET").LogAttrs(t.Context(), level, RequestCompleted, slog.Int("status", 204), slog.Duration("duration", time.Second))
			}
			if strings.Count(output.String(), "\n") != len(levels)-i {
				t.Fatal("incorrect threshold filtering")
			}
			for _, expected := range []string{RequestCompleted, "GET", "204", "duration"} {
				if !strings.Contains(output.String(), expected) {
					t.Fatal("safe operational metadata missing")
				}
			}
		}
	}
	for _, level := range []slog.Level{-5, 5, 123} {
		if _, err := New(&bytes.Buffer{}, level, "json"); err == nil {
			t.Fatal("invalid threshold accepted")
		}
	}
	if _, err := New(&bytes.Buffer{}, slog.LevelInfo, "synthetic-invalid-format"); err == nil {
		t.Fatal("invalid format accepted")
	}
	if _, err := New(nil, slog.LevelInfo, "json"); err == nil {
		t.Fatal("nil destination accepted")
	}
}

func TestSecretTypeAndSeparateControlOutput(t *testing.T) {
	const canary = "synthetic-control-channel-canary"
	secret := Secret(canary)
	for _, text := range []string{fmt.Sprint(secret), fmt.Sprintf("%+v", secret), fmt.Sprintf("%#v", secret), secret.LogValue().String()} {
		if strings.Contains(text, canary) {
			t.Fatal("secret formatting escaped")
		}
	}
	// A synthetic separate sink is not an implementation of the P1.09 host helper.
	// Ordinary logs NEVER get a disclosure exemption, even during control output.
	for _, format := range []string{"json", "text"} {
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
			var ordinary, control, standard bytes.Buffer
			logger, err := New(&ordinary, slog.LevelDebug, format)
			if err != nil {
				t.Fatal(err)
			}
			logger.Log(t.Context(), level, canary, "token", secret)
			options := &slog.HandlerOptions{Level: slog.LevelDebug}
			var standardHandler slog.Handler = slog.NewJSONHandler(&standard, options)
			if format == "text" {
				standardHandler = slog.NewTextHandler(&standard, options)
			}
			slog.New(standardHandler).Log(t.Context(), level, "static event", "secret", secret)
			_, _ = control.WriteString(canary)
			if control.String() != canary || ordinary.Len() == 0 || standard.Len() == 0 || strings.Contains(ordinary.String(), canary) || strings.Contains(standard.String(), canary) {
				t.Fatal("control/log sinks were conflated or secret LogValuer leaked")
			}
		}
	}
}
