package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/logging"
)

// P1.20 R2: an operator can see that the safety proof was lost, why and for how long, and the line cannot carry a secret.
func TestTransitionLoggerNamesReasonStepCauseAndOutage(t *testing.T) {
	var out bytes.Buffer
	logger, err := logging.New(&out, slog.LevelInfo, "json")
	if err != nil {
		t.Fatal(err)
	}
	obs := transitionLogger(logger, nil)
	obs(docker.Transition{Drop: docker.Drop{Reason: docker.DropCheckDeadline, Step: docker.StepInventory, Cause: docker.CauseDeadline, Elapsed: 2100 * time.Millisecond}, Inflight: 31, Streams: 5})
	obs(docker.Transition{Verified: true, Outage: 4200 * time.Millisecond})
	got := out.String()
	for _, want := range []string{
		`"msg":"docker safety proof dropped"`, `"reason":"check_deadline"`, `"step":"inventory"`, `"cause":"deadline"`,
		`"elapsed_ms":2100`, `"inflight":31`, `"streams":5`,
		`"msg":"docker safety proof restored"`, `"outage_ms":4200`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
}

func TestTransitionLoggerCannotCarryARuntimeValue(t *testing.T) {
	const canary = "synthetic-canary-/var/run/docker.sock-token-0123456789abcdef"
	var out bytes.Buffer
	logger, err := logging.New(&out, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}
	// every field a hostile caller could reach is outside the closed vocabularies
	transitionLogger(logger, nil)(docker.Transition{Drop: docker.Drop{Reason: docker.DropReason(canary), Step: docker.DropStep(canary), Cause: docker.DropCause(canary), Elapsed: -time.Second}, Inflight: -5, Streams: -1})
	got := out.String()
	if strings.Contains(got, canary) || strings.Contains(got, "docker.sock") || strings.Contains(got, "token") {
		t.Fatalf("a runtime value reached the log: %s", got)
	}
	if !strings.Contains(got, "docker safety proof dropped") {
		t.Fatalf("the event itself must still be logged: %s", got)
	}
}
