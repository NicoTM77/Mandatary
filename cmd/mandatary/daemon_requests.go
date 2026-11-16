package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/logging"
)

// Daemon request counters (P1.20, R2). Every request this process sends to the Docker socket is counted by a
// closed kind, so how much work the service puts on the daemon per admitted call is measured, not inferred. The
// counts are totals since the process started, logged as one secret-free line every minute and when the service
// stops. Only counts reach the log: the kind is derived from the method and the path shape, never copied.

// requestKinds is the closed vocabulary, in the order of requestCounts.n.
var requestKinds = [...]string{"ping", "info", "list", "inspect", "logs", "start", "stop", "restart", "other"}

const requestLogInterval = time.Minute

type requestCounts struct {
	n [len(requestKinds)]atomic.Int64
}

// classifyRequest names the kind of one daemon request from its method and path.
func classifyRequest(method, path string) string {
	if strings.HasPrefix(path, "/v") { // the SDK prefixes the negotiated API version
		if i := strings.Index(path[1:], "/"); i >= 0 {
			path = path[1+i:]
		}
	}
	switch {
	case path == "/_ping":
		return "ping"
	case path == "/info" && method == http.MethodGet:
		return "info"
	case path == "/containers/json" && method == http.MethodGet:
		return "list"
	}
	if rest, ok := strings.CutPrefix(path, "/containers/"); ok {
		parts := strings.Split(rest, "/")
		if len(parts) == 2 && parts[0] != "" {
			switch {
			case parts[1] == "json" && method == http.MethodGet:
				return "inspect"
			case parts[1] == "logs" && method == http.MethodGet:
				return "logs"
			case method == http.MethodPost && (parts[1] == "start" || parts[1] == "stop" || parts[1] == "restart"):
				return parts[1]
			}
		}
	}
	return "other"
}

func (c *requestCounts) record(req *http.Request) {
	if c == nil || req == nil || req.URL == nil {
		return
	}
	kind := classifyRequest(req.Method, req.URL.Path)
	for i, k := range requestKinds {
		if k == kind {
			c.n[i].Add(1)
			return
		}
	}
}

// run logs the totals every interval until ctx ends (the final line is logged by the caller at stop).
func (c *requestCounts) run(ctx context.Context, logger *slog.Logger, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.log(logger)
		}
	}
}

// log emits the totals as one line (Info level; counts only).
func (c *requestCounts) log(logger *slog.Logger) {
	if c == nil || logger == nil {
		return
	}
	attrs := make([]any, 0, len(requestKinds))
	for i, k := range requestKinds {
		attrs = append(attrs, "req_"+k, c.n[i].Load())
	}
	logger.Info(logging.DockerRequests, attrs...)
}
