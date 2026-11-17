package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// P1.20 R2: the daemon request counters admit one count per closed kind and nothing else.
func TestDockerRequestsEventAdmitsOnlyKindCounts(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(&out, slog.LevelInfo, "json")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info(DockerRequests, "req_ping", int64(1), "req_info", int64(2), "req_list", int64(3), "req_inspect", int64(4), "req_logs", int64(5),
		"req_start", int64(6), "req_stop", int64(7), "req_restart", int64(8), "req_other", int64(9))
	got := out.String()
	for _, want := range []string{`"msg":"docker daemon requests"`, `"req_ping":1`, `"req_info":2`, `"req_list":3`, `"req_inspect":4`, `"req_logs":5`, `"req_start":6`, `"req_stop":7`, `"req_restart":8`, `"req_other":9`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}

	const canary = "synthetic-docker-canary-/var/run/docker.sock-0123456789abcdef"
	out.Reset()
	logger.Info(DockerRequests, "req_info", canary, "req_list", int64(-1), "req_other", int64(1)<<41, "req_"+canary, int64(1), "path", canary, "req_start", 3.5)
	got = out.String()
	if strings.Contains(got, canary) || strings.Contains(got, "docker.sock") || strings.Contains(got, `"req_info":`) || strings.Contains(got, `"req_list":`) || strings.Contains(got, `"req_other":`) || strings.Contains(got, `"req_start":`) {
		t.Fatalf("a value outside the closed vocabulary was admitted: %s", got)
	}
	out.Reset()
	logger.Info("docker daemon requests "+canary, "req_info", int64(1))
	if strings.Contains(out.String(), canary) {
		t.Fatal("an interpolated message was admitted")
	}
}
