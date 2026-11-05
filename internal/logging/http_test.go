package logging

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestAndErrorPathsNeverLogPayloads(t *testing.T) {
	const canary = "synthetic-request-error-cookie-environment-canary"
	for _, format := range []string{"json", "text"} {
		for _, threshold := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
			for _, scenario := range []string{"success", "error", "panic", "committed-panic"} {
				t.Run(format+"/"+threshold.String()+"/"+scenario, func(t *testing.T) {
					var output bytes.Buffer
					logger, err := New(&output, threshold, format)
					if err != nil {
						t.Fatal(err)
					}
					request := httptest.NewRequest(http.MethodPost, "https://example.invalid/"+canary+"?token="+canary, strings.NewReader(canary))
					request.Host = canary
					request.Header.Set("Authorization", "Bearer "+canary)
					request.Header.Set("Cookie", "session="+canary)
					request.Header.Set("X-Forwarded-Host", canary)
					handler := HTTP(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
							logger.Log(r.Context(), level, canary, "request", r, "error", canary)
						}
						switch scenario {
						case "panic":
							panic(canary)
						case "committed-panic":
							w.WriteHeader(202)
							panic(canary)
						case "error":
							w.Header().Set("Set-Cookie", "session="+canary)
							http.Error(w, "safe failure", 500)
						default:
							w.WriteHeader(204)
						}
					}))
					response := httptest.NewRecorder()
					aborted := false
					func() {
						defer func() {
							if p := recover(); p != nil {
								if p != http.ErrAbortHandler {
									t.Fatal("unsafe panic propagated")
								}
								aborted = true
							}
						}()
						handler.ServeHTTP(response, request)
					}()
					want := 204
					if scenario == "panic" || scenario == "error" {
						want = 500
					}
					if scenario == "committed-panic" {
						want = 202
					}
					if response.Code != want || aborted != (scenario == "committed-panic") {
						t.Fatal("middleware changed response semantics")
					}
					if strings.Contains(output.String(), canary) {
						t.Fatal("request/error/panic leaked secret")
					}
					if scenario == "panic" && strings.Contains(response.Body.String(), canary) {
						t.Fatal("panic leaked to response")
					}
					if output.Len() == 0 {
						t.Fatal("no logging exercised")
					}
				})
			}
		}
	}
}

func TestNativeHTTPTransportUsesRedactedServerErrorLog(t *testing.T) {
	const canary = "synthetic-native-http-panic-canary"
	for _, format := range []string{"json", "text"} {
		var output bytes.Buffer
		logger, err := New(&output, slog.LevelDebug, format)
		if err != nil {
			t.Fatal(err)
		}
		fixture := httptest.NewUnstartedServer(HTTP(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202); panic(canary) })))
		fixture.Config.ErrorLog = slog.NewLogLogger(logger.Handler(), slog.LevelError)
		fixture.Start()
		// An after-commit panic must terminate the transport, not emit its secret or
		// stack in net/http's default stderr logger. This is an isolated loopback HTTP
		// fixture, not a Docker/proxy/deployment qualification.
		response, requestErr := fixture.Client().Get(fixture.URL + "/" + canary)
		if response != nil {
			_ = response.Body.Close()
		}
		fixture.Close()
		if requestErr == nil {
			t.Fatal("committed panic did not abort transport")
		}
		if output.Len() == 0 || strings.Contains(output.String(), canary) {
			t.Fatal("native HTTP error path not redacted")
		}
	}
}

func TestHTTPStatusAndResponseController(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, slog.LevelDebug, "json")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	HTTP(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal("response controller lost underlying support")
		}
		_, _ = w.Write([]byte("public response"))
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Body.String() != "public response" || !response.Flushed || !strings.Contains(output.String(), `"status":200`) {
		t.Fatal("implicit response metadata incorrect")
	}
	// An arbitrary method must not become an access-log injection channel.
	output.Reset()
	HTTP(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(405) })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("synthetic-method-canary", "/", nil))
	if strings.Contains(output.String(), "synthetic-method-canary") || !strings.Contains(output.String(), `"level":"WARN"`) {
		t.Fatal("unsafe method or incorrect error severity")
	}
}
