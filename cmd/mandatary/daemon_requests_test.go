package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
)

// P1.20 R2: the daemon request counters classify by method and path shape only and log counts, nothing else.
func TestClassifyRequestKinds(t *testing.T) {
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, c := range []struct{ method, path, want string }{
		{"GET", "/_ping", "ping"}, {"HEAD", "/v1.46/_ping", "ping"},
		{"GET", "/v1.46/info", "info"}, {"GET", "/info", "info"},
		{"GET", "/v1.46/containers/json", "list"},
		{"GET", "/v1.46/containers/" + id + "/json", "inspect"},
		{"GET", "/v1.46/containers/" + id + "/logs", "logs"},
		{"POST", "/v1.46/containers/" + id + "/start", "start"},
		{"POST", "/v1.46/containers/" + id + "/stop", "stop"},
		{"POST", "/v1.46/containers/" + id + "/restart", "restart"},
		{"GET", "/v1.46/containers/" + id + "/start", "other"}, // wrong method
		{"DELETE", "/v1.46/containers/" + id, "other"},
		{"GET", "/v1.46/containers//json", "other"},
		{"GET", "/v1.46/images/json", "other"},
		{"GET", "", "other"},
	} {
		if got := classifyRequest(c.method, c.path); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestRequestCountsLogCountsOnly(t *testing.T) {
	var out bytes.Buffer
	logger, err := logging.New(&out, slog.LevelInfo, "json")
	if err != nil {
		t.Fatal(err)
	}
	var c requestCounts
	for _, p := range []string{"/v1.46/info", "/v1.46/info", "/v1.46/containers/json", "/v1.46/secret-path-/var/run/docker.sock"} {
		c.record(&http.Request{Method: "GET", URL: &url.URL{Path: p}})
	}
	c.record(nil)
	c.record(&http.Request{Method: "GET"})
	c.log(logger)
	got := out.String()
	for _, want := range []string{`"msg":"docker daemon requests"`, `"req_info":2`, `"req_list":1`, `"req_other":1`, `"req_ping":0`, `"req_inspect":0`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "docker.sock") || strings.Contains(got, "secret") {
		t.Fatalf("a request path reached the log: %s", got)
	}
	var nilCounts *requestCounts
	nilCounts.log(logger) // no counters (mock): silent, never a panic
	nilCounts.record(&http.Request{Method: "GET", URL: &url.URL{Path: "/info"}})
}

func TestRequestCountsRunLogsPeriodically(t *testing.T) {
	var out syncBuffer
	logger, err := logging.New(&out, slog.LevelInfo, "json")
	if err != nil {
		t.Fatal(err)
	}
	var c requestCounts
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx, logger, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(out.String(), "docker daemon requests") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no periodic counter line")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}
