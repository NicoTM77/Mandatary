package adapters_test

import (
	"net/http"
	"strings"
	"testing"
)

// N63B4-DOC-FACTOR-INVENTORY / PWD-ROUTE-PARITY / OOB-UNSUPPORTED / WALLET-UNSUPPORTED /
// RESTRICTED-UNSUPPORTED / SCOPE-FEDERATION / RECOVERY-NO-SESSION: the machine adapters
// expose no human authentication, factor, recovery, setup, federation or access-request
// surface at all. Every such route and tool is absent (not "denied after a lookup"), with
// and without a valid agent token, and none of them can mint a cookie or a session.
func TestAdapterNamespacesExposeNoHumanAuthenticationFactorRecoverySetupFederationOrAccessRequestSurface(t *testing.T) {
	e := newEnv(t)
	tok := e.token("wildcard")
	var paths []string
	for _, root := range []string{"/api/v1", "/mcp", ""} {
		for _, leaf := range []string{
			"login", "logout", "session", "sessions", "password", "password/reset", "reauth", "step-up", "stepup",
			"totp", "totp/enroll", "webauthn", "webauthn/register", "webauthn/assert", "passkey", "recovery", "recovery/code", "recovery/session",
			"setup", "setup/token", "bootstrap", "mfa", "mfa/reset", "factors", "sms", "voice", "email-otp", "push", "push/approve", "wallet", "otp",
			"oauth/token", "oauth/authorize", "authorize", "token", "tokens", "agents", "agents/tokens", "access-requests", "access-requests/webhook",
			"users", "groups", "policies", "admin", "backup", "restore", "export", "usage",
			".well-known/oauth-authorization-server", ".well-known/openid-configuration", ".well-known/oauth-protected-resource", "oidc/callback", "saml/acs",
		} {
			if root == "" {
				paths = append(paths, "/"+leaf)
			} else {
				paths = append(paths, root+"/"+leaf)
			}
		}
	}
	for _, p := range paths {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			for _, hdr := range []http.Header{nil, bearer(tok)} {
				status, h, body := rawDo(t, e, m, p, hdr, []byte(`{"username":"admin","password":"x","code":"000000"}`))
				if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
					t.Errorf("%s %s (auth=%v): %d %s", m, p, hdr != nil, status, truncate(string(body), 80))
				}
				if len(h.Values("Set-Cookie")) != 0 {
					t.Errorf("%s %s set a cookie", m, p)
				}
			}
		}
	}
	if n := e.spy.total() + e.other.total(); n != 0 {
		t.Fatalf("absent surfaces reached Docker %d times", n)
	}
}

// N63B4-SCOPE-MACHINE / TOKEN-NOT-PRESENCE / S05 (cookie side): a successful Bearer call
// never mints a cookie, session or assurance, never rotates or echoes the token, and the
// human credential classes are not accepted on the machine surface in either direction
// (an agent token is not a session; a session secret is not an agent token).
func TestAgentBearerNeverMintsCookiesSessionsOrAssuranceAndHumanCredentialsAreNotAgentCredentials(t *testing.T) {
	e := newEnv(t)
	tok := e.token("granted")
	for _, c := range []struct{ m, p, body string }{
		{"GET", "/api/v1/endpoints/local/containers/edge-proxy/status", ""},
		{"GET", "/api/v1/endpoints/local/containers/edge-proxy/logs?tail=1", ""},
		{"POST", "/api/v1/endpoints/local/containers/edge-proxy/restart", `{"timeout_seconds":5}`},
		{"POST", "/api/v1/endpoints/local/containers/edge-proxy/stop", ""},
		{"GET", "/api/v1/endpoints/local/containers/edge-proxy/status?bad=1", ""},
		{"GET", "/api/v1/readyz", ""},
	} {
		hdr := bearer(tok)
		if c.body != "" {
			hdr.Set("Content-Type", "application/json")
		}
		status, h, body := rawDo(t, e, c.m, c.p, hdr, []byte(c.body))
		if status == 0 {
			t.Fatal("no status")
		}
		for k := range h {
			lk := strings.ToLower(k)
			if lk == "set-cookie" || strings.HasPrefix(lk, "access-control-") || lk == "x-csrf-token" || lk == "authorization" {
				t.Errorf("%s %s answered with %s", c.m, c.p, k)
			}
		}
		if strings.Contains(string(body), tok) {
			t.Errorf("%s %s echoed the token", c.m, c.p)
		}
	}
	// A human session cookie plus a CSRF token, with NO Bearer, is not machine authority.
	for _, p := range []string{"/api/v1/endpoints/local/containers/edge-proxy/stop", "/api/v1/endpoints/local/containers/edge-proxy/status"} {
		for _, m := range []string{"POST", "GET"} {
			hdr := http.Header{"Cookie": {"mandatary_session=" + aliceSess + "; csrf=x"}, "X-CSRF-Token": {"x"}, "Origin": {}}
			if status, _, _ := rawDo(t, e, m, p, hdr, nil); status != http.StatusUnauthorized && status != http.StatusMethodNotAllowed {
				t.Errorf("%s %s with a session cookie: %d", m, p, status)
			}
		}
	}
	if n := len(e.spy.operationalCalls()); n != 4 { // status, logs, restart, stop: the four authenticated, authorized, valid calls
		t.Fatalf("operational calls = %v", e.spy.operationalCalls())
	}
}
