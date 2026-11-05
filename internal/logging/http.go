package logging

import (
	"log/slog"
	"net/http"
	"time"
)

// HTTP records bounded operational metadata only: no address, URL, headers,
// cookies, bodies, response payloads or recovered panic/error strings. It does
// not grant authority or implement any product route. Install outside handlers.
func HTTP(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		response := &responseWriter{ResponseWriter: w, status: 200}
		defer func() {
			if p := recover(); p != nil {
				logger.ErrorContext(r.Context(), RequestPanicked)
				// net/http recognizes this fixed sentinel and aborts WITHOUT logging the
				// original panic/stack. After commitment, a replacement 500 is impossible.
				if response.committed || p == http.ErrAbortHandler {
					panic(http.ErrAbortHandler)
				}
				http.Error(response, "internal server error", http.StatusInternalServerError)
			}
			level := slog.LevelInfo
			if response.status >= 500 {
				level = slog.LevelError
			} else if response.status >= 400 {
				level = slog.LevelWarn
			}
			logger.LogAttrs(r.Context(), level, RequestCompleted, slog.String("method", r.Method), slog.Int("status", response.status), slog.Duration("duration", time.Since(started)))
		}()
		next.ServeHTTP(response, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status    int
	committed bool
}

func (w *responseWriter) WriteHeader(status int) {
	if w.committed {
		return
	}
	w.ResponseWriter.WriteHeader(status)
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.status = status
		w.committed = true
	}
}
func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Unwrap preserves ResponseController access to the underlying writer. A flush
// commits an implicit 200; expose FlushError so our bookkeeping stays accurate.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseWriter) FlushError() error {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
