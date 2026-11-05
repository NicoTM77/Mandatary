// Package logging provides a fail-closed slog boundary. Payloads are not logs.
package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
)

const redacted = "[REDACTED]"

// Static events are the only admitted messages. Never interpolate runtime input.
const (
	RequestCompleted   = "request completed"
	RequestPanicked    = "request panicked"
	ServerStarted      = "development server started"
	StartupFailed      = "startup failed"
	ServerFailed       = "server failed"
	StorageCloseFailed = "storage close failed"
)

// secretValue deliberately has no exported plaintext/serialization API. This is
// a formatting guard, not secure memory or the protected host-reveal protocol.
type secretValue struct{ value string }

func Secret(value string) secretValue    { return secretValue{value: value} }
func (secretValue) String() string       { return redacted }
func (secretValue) GoString() string     { return redacted }
func (secretValue) LogValue() slog.Value { return slog.StringValue(redacted) }

// New wraps the standard JSON/text handlers BEFORE they resolve/format values.
// A deny-by-default schema handles arbitrary unknown passwords/short OTPs too;
// pattern matching or a registry of known secrets cannot make that guarantee.
func New(output io.Writer, level slog.Level, format string) (*slog.Logger, error) {
	if output == nil || (level != slog.LevelDebug && level != slog.LevelInfo && level != slog.LevelWarn && level != slog.LevelError) {
		return nil, errors.New("invalid logging settings")
	}
	options := &slog.HandlerOptions{Level: level}
	var next slog.Handler
	switch format {
	case "json":
		next = slog.NewJSONHandler(output, options)
	case "text":
		next = slog.NewTextHandler(output, options)
	default:
		return nil, errors.New("invalid logging settings")
	}
	return slog.New(&handler{next: next}), nil
}

type handler struct {
	next      slog.Handler
	redactAll bool
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}
func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	message := redacted
	switch r.Message {
	case RequestCompleted, RequestPanicked, ServerStarted, StartupFailed, ServerFailed, StorageCloseFailed:
		message = r.Message
	}
	level := r.Level
	switch level {
	case slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError:
	default:
		level = slog.LevelError
	}
	clean := slog.NewRecord(r.Time, level, message, 0)
	r.Attrs(func(a slog.Attr) bool { clean.AddAttrs(sanitize(a, h.redactAll)); return true })
	return h.next.Handle(ctx, clean)
}
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = sanitize(a, h.redactAll)
	}
	return &handler{next: h.next.WithAttrs(clean), redactAll: h.redactAll}
}
func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	deny := h.redactAll || !safeGroup(name)
	if deny {
		name = "redacted"
	}
	return &handler{next: h.next.WithGroup(name), redactAll: deny}
}
func safeGroup(name string) bool { return name == "http" || name == "server" || name == "config" }

// Do not call Value.Resolve, error.Error, String, MarshalJSON, reflection, or
// other user code. Unknown keys also redact: a key/group name can hold a secret.
func sanitize(a slog.Attr, deny bool) slog.Attr {
	if deny {
		return slog.String("redacted", redacted)
	}
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" && !safeGroup(a.Key) {
			return slog.String("redacted", redacted)
		}
		children := a.Value.Group()
		clean := make([]slog.Attr, len(children))
		for i, child := range children {
			clean[i] = sanitize(child, false)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(clean...)}
	}
	switch a.Key {
	case "method":
		if a.Value.Kind() == slog.KindString {
			switch a.Value.String() {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
				return a
			}
		}
	case "status":
		if a.Value.Kind() == slog.KindInt64 && a.Value.Int64() >= 100 && a.Value.Int64() <= 599 {
			return a
		}
	case "duration":
		if a.Value.Kind() == slog.KindDuration && a.Value.Duration() >= 0 {
			return a
		}
	case "stage":
		if a.Value.Kind() == slog.KindString {
			switch a.Value.String() {
			case "configuration", "storage", "listener":
				return a
			}
		}
	}
	return slog.String("redacted", redacted)
}
