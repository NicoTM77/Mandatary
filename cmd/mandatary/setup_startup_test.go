package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const startupOrigin = "https://mandatary.example.invalid"

// regexpToken matches any canonical or grouped setup-token shape.
var regexpToken = regexp.MustCompile(`([A-Z2-7]{4}-){12}[A-Z2-7]{4}|[A-Z2-7]{40,}`)

func (f *cliFixture) runServer(origin string, serve func(*http.Server) error) (int, string) {
	f.t.Helper()
	values := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key, "MANDATARY_LOG_LEVEL": "debug", "MANDATARY_LOG_FORMAT": "json"}
	if origin != "" {
		values["MANDATARY_PUBLIC_ORIGIN"] = origin
	}
	var out bytes.Buffer
	if serve == nil {
		serve = func(*http.Server) error { return http.ErrServerClosed }
	}
	code := run(f.t.Context(), func(k string) string { return values[k] }, &out, serve)
	return code, out.String()
}

func logEvents(t *testing.T, raw, message string) []map[string]any {
	t.Helper()
	var found []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}

// First start of an empty installation: exactly one initial generation, the log
// names only the configured secret-free URL, and the token reaches no log.
func TestFirstStartLogsOnlyTheSecretFreeSetupURL(t *testing.T) {
	f := newCLIFixture(t)
	code, out := f.runServer(startupOrigin, nil)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	events := logEvents(t, out, "initial setup available")
	if len(events) != 1 || events[0]["setup_url"] != startupOrigin+"/setup" || events[0]["generation"] != float64(1) {
		t.Fatalf("setup event: %v", events)
	}
	if _, ok := events[0]["expires_at"]; !ok {
		t.Fatal("absolute expiry not logged")
	}
	if len(logEvents(t, out, "setup notice delivery not configured")) != 1 {
		t.Fatal("missing notice-delivery warning")
	}
	if regexpToken.MatchString(out) {
		t.Fatalf("token-shaped value in logs: %s", out)
	}
	// Restart: the SAME live generation is reported; nothing new is minted.
	code, out = f.runServer(startupOrigin, nil)
	events = logEvents(t, out, "initial setup available")
	if code != 0 || len(events) != 1 || events[0]["generation"] != float64(1) {
		t.Fatalf("restart: %d %v", code, events)
	}
	if code = f.run("setup", "status"); code != 0 || strings.Count(f.stdout.String(), "generation ") != 1 {
		t.Fatalf("restart minted a second generation: %q", f.stdout.String())
	}
}

func TestStartupWithoutTrustedOriginIssuesNothing(t *testing.T) {
	f := newCLIFixture(t)
	code, out := f.runServer("", nil)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(logEvents(t, out, "initial setup unavailable")) != 1 || len(logEvents(t, out, "initial setup available")) != 0 {
		t.Fatalf("expected the unavailable warning only: %s", out)
	}
	f.run("setup", "status")
	if strings.Contains(f.stdout.String(), "generation ") {
		t.Fatal("a token was issued without a configured origin")
	}
	if code, _ = f.runServer("http://mandatary.example.invalid", nil); code == 0 {
		t.Fatal("a cleartext origin was accepted")
	}
}

// Through the REAL server handler: the host reveals out of band, the browser
// exchanges over the adapter, and neither the token nor the setup cookie appears
// in any log. The static application is not shadowed.
func TestSetupThroughServerHandlerAndLogHygiene(t *testing.T) {
	f := newCLIFixture(t)
	if code, _ := f.runServer(startupOrigin, nil); code != 0 {
		t.Fatal(code)
	}
	if code := f.run("setup", "reveal"); code != 0 {
		t.Fatal(f.stderr.String())
	}
	token := f.term.token()
	cookieValue := ""
	code, out := f.runServer(startupOrigin, func(s *http.Server) error {
		post := func(path, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "https://mandatary.example.invalid"+path, strings.NewReader(body))
			r.Host = "mandatary.example.invalid"
			r.Header.Set("Origin", startupOrigin)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.Handler.ServeHTTP(w, r)
			return w
		}
		if w := post("/api/v1/setup/exchange", `{"token":"AAAAAAAA"}`); w.Code != http.StatusUnauthorized {
			t.Errorf("wrong token: %d", w.Code)
		}
		w := post("/api/v1/setup/exchange", `{"token":"`+token+`"}`)
		cookies := w.Result().Cookies()
		if w.Code != http.StatusOK || len(cookies) != 1 || !strings.Contains(cookies[0].Name, "setup") {
			t.Errorf("exchange: %d %s", w.Code, w.Body.String())
		} else {
			cookieValue = cookies[0].Value
		}
		ww := httptest.NewRecorder()
		s.Handler.ServeHTTP(ww, httptest.NewRequest(http.MethodGet, "/", nil))
		if ww.Code != http.StatusOK {
			t.Errorf("static root: %d", ww.Code)
		}
		return http.ErrServerClosed
	})
	if code != 0 || cookieValue == "" {
		t.Fatalf("exit %d, cookie %q", code, cookieValue)
	}
	for name, secret := range map[string]string{"token": token, "setup cookie": cookieValue, "submitted fragment": "AAAAAAAA"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s reached the server log", name)
		}
	}
	if regexpToken.MatchString(out) {
		t.Fatalf("token-shaped value in the server log: %s", out)
	}
}
