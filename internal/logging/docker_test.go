package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// P1.19: the Docker-backend state transitions are the only new admitted events. Each carries at most a
// fixed reason from a closed list; any other value (a path, an error text, a container ID) is redacted.
func TestDockerBackendEventsAdmitOnlyFixedReasons(t *testing.T) {
	const canary = "synthetic-docker-canary-/var/run/docker.sock-0123456789abcdef"
	for _, msg := range []string{DockerVerified, DockerUnverified, DockerMockActive} {
		for _, reason := range []string{"unreachable", "unsupported_api", "identity"} {
			var out bytes.Buffer
			logger, err := New(&out, slog.LevelInfo, "json")
			if err != nil {
				t.Fatal(err)
			}
			logger.Warn(msg, "reason", reason)
			if got := out.String(); !strings.Contains(got, msg) || !strings.Contains(got, `"reason":"`+reason+`"`) {
				t.Fatalf("%s/%s not admitted: %s", msg, reason, got)
			}
		}
		var out bytes.Buffer
		logger, _ := New(&out, slog.LevelInfo, "json")
		logger.Warn(msg, "reason", canary, "error", canary, "socket", canary)
		got := out.String()
		if strings.Contains(got, canary) || strings.Contains(got, "docker.sock") {
			t.Fatalf("%s leaked a runtime value: %s", msg, got)
		}
	}
	var out bytes.Buffer
	logger, _ := New(&out, slog.LevelInfo, "json")
	logger.Info("docker backend verified " + canary)
	if strings.Contains(out.String(), canary) {
		t.Fatal("an interpolated message was admitted")
	}
}
