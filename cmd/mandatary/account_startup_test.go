package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveWith runs the real server composition with extra environment and hands the
// composed root handler to probe. No listener, relay connection or mail is made:
// the relay address is only parsed (a notice dispatch needs a live tick).
func (f *cliFixture) serveWith(extra map[string]string, probe func(h http.Handler)) (int, string) {
	f.t.Helper()
	values := map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key, "MANDATARY_LOG_LEVEL": "debug", "MANDATARY_LOG_FORMAT": "json"}
	for k, v := range extra {
		values[k] = v
	}
	var out bytes.Buffer
	code := run(f.t.Context(), func(k string) string { return values[k] }, &out, func(s *http.Server) error {
		probe(s.Handler)
		return http.ErrServerClosed
	})
	return code, out.String()
}

var mailSettings = map[string]string{
	"MANDATARY_PUBLIC_ORIGIN":  startupOrigin,
	"MANDATARY_SMTP_RELAY":     "relay.example.invalid:465",
	"MANDATARY_SMTP_TLS":       "implicit",
	"MANDATARY_SMTP_SENDER":    "notices@example.invalid",
	"MANDATARY_NOTICE_CONTACT": "security@example.invalid",
}

// unrouted: the static fallback answers 404 for an unknown path and 405 for any
// non-GET method (it answers the method first); either way no service ran.
func unrouted(w *httptest.ResponseRecorder) bool {
	return (w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed) && w.Header().Get("Set-Cookie") == ""
}

func browserPost(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://mandatary.example.invalid"+path, strings.NewReader(body))
	r.Host = "mandatary.example.invalid"
	r.Header.Set("Origin", startupOrigin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// With a trusted origin and a notice relay the real server mounts the account
// routes: a failed password step is the generic 401 (no account signal), the
// document routes serve the shell, and the password never reaches the log.
func TestServerMountsAccountRoutesBehindTheBrowserBoundary(t *testing.T) {
	f := newCLIFixture(t)
	const canary = "synthetic-login-canary-not-a-credential"
	code, out := f.serveWith(mailSettings, func(h http.Handler) {
		w := browserPost(h, "/api/v1/login", `{"username":"nobody","password":"`+canary+`"}`)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "unauthenticated") {
			t.Errorf("login on a fresh installation: %d %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("headers: %v", w.Header())
		}
		// The boundary is the one in front: a foreign origin is refused before the service.
		r := httptest.NewRequest(http.MethodPost, "https://mandatary.example.invalid/api/v1/login", strings.NewReader(`{"username":"a","password":"b"}`))
		r.Host = "mandatary.example.invalid"
		r.Header.Set("Origin", "https://evil.invalid")
		r.Header.Set("Content-Type", "application/json")
		if ww := httptest.NewRecorder(); func() bool { h.ServeHTTP(ww, r); return ww.Code != http.StatusForbidden }() {
			t.Error("a foreign Origin reached the login service")
		}
		// No session: the session read is 401, logout needs CSRF and a session.
		sr := httptest.NewRequest(http.MethodGet, "https://mandatary.example.invalid/api/v1/session", nil)
		sr.Host = "mandatary.example.invalid"
		if ww := httptest.NewRecorder(); func() bool { h.ServeHTTP(ww, sr); return ww.Code != http.StatusUnauthorized }() {
			t.Error("anonymous session read was not 401")
		}
		for _, path := range []string{"/", "/setup", "/login"} {
			ww := httptest.NewRecorder()
			h.ServeHTTP(ww, httptest.NewRequest(http.MethodGet, path, nil))
			if ww.Code != http.StatusOK || !strings.Contains(ww.Body.String(), "<title>Mandatary</title>") {
				t.Errorf("document %s: %d", path, ww.Code)
			}
		}
		// WebAuthn login, step-up and recovery are slice 2: no route exists.
		for _, path := range []string{"/api/v1/login/webauthn", "/api/v1/stepup/password", "/api/v1/recovery"} {
			if ww := browserPost(h, path, `{}`); !unrouted(ww) {
				t.Errorf("%s: %d", path, ww.Code)
			}
		}
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, canary) {
		t.Fatal("the submitted password reached the server log")
	}
}

// Without the notice relay there is no Lifecycle, hence no Sessions: login routes
// do not exist (404), they are never half-mounted. The same holds without a
// trusted origin.
func TestServerWithoutNoticeRelayMountsNoAccountRoutes(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"no relay":  {"MANDATARY_PUBLIC_ORIGIN": startupOrigin},
		"no origin": nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newCLIFixture(t)
			code, out := f.serveWith(extra, func(h http.Handler) {
				for _, path := range []string{"/api/v1/login", "/api/v1/login/totp", "/api/v1/login/no-mfa", "/api/v1/logout"} {
					if w := browserPost(h, path, `{}`); !unrouted(w) {
						t.Errorf("%s: %d", path, w.Code)
					}
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
				if w.Code != http.StatusNotFound {
					t.Errorf("session: %d", w.Code)
				}
			})
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
		})
	}
}
