package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// P1.16.4 WebAuthn over the browser boundary: enrolment, login, step-up, removal and
// recovered registration. A virtual P-256 authenticator signs real ceremonies that
// the REAL WebAuthn service verifies (origin, RP ID, challenge, UP+UV, counter).

type ceremony struct {
	ID      string `json:"id"`
	Options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	} `json:"options"`
}

func decodeCeremonyOptions(t *testing.T, w *httptest.ResponseRecorder) ceremony {
	t.Helper()
	var c ceremony
	mustDecode(t, w.Body.Bytes(), &c)
	if w.Code != http.StatusOK || c.ID == "" || c.Options.PublicKey.Challenge == "" {
		t.Fatalf("ceremony options: %d %s", w.Code, w.Body.String())
	}
	return c
}

func finishBody(t *testing.T, id string, response []byte) string {
	t.Helper()
	return mustJSON(t, map[string]any{"id": id, "response": json.RawMessage(response)})
}

func (h *securityHarness) enrollKeyOverHTTP(s cookieSession, v virtualKey) {
	h.t.Helper()
	c := decodeCeremonyOptions(h.t, h.post(s, AccountKeyBeginPath, nil))
	w := h.do(loginCall{method: "POST", path: AccountKeyFinishPath, cookie: s.cookie, csrf: s.csrf, body: finishBody(h.t, c.ID, v.create(h.t, c.Options.PublicKey.Challenge, sessionTestOrigin, 5))})
	if w.Code != http.StatusNoContent {
		h.t.Fatalf("register key: %d %s", w.Code, w.Body.String())
	}
}

func TestAccountSecurityHTTPWebAuthnEnrolmentLoginStepUpAndRemoval(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.e
	s := h.signIn()
	v := newVirtualKey(t)

	// Enrolment: a response made for another origin, or replayed, never binds.
	c := decodeCeremonyOptions(t, h.post(s, AccountKeyBeginPath, nil))
	foreign := h.do(loginCall{method: "POST", path: AccountKeyFinishPath, cookie: s.cookie, csrf: s.csrf, body: finishBody(t, c.ID, v.create(t, c.Options.PublicKey.Challenge, "https://evil.invalid", 5))})
	if foreign.Code != http.StatusForbidden || errorCode(foreign) != "denied" {
		t.Fatalf("foreign-origin attestation: %d %s", foreign.Code, foreign.Body.String())
	}
	if got := h.inventory(s); len(got.Keys) != 0 {
		t.Fatal("a refused attestation bound a key")
	}
	if w := h.do(loginCall{method: "POST", path: AccountKeyFinishPath, cookie: s.cookie, csrf: s.csrf, body: `{"id":"` + c.ID + `"}`}); w.Code != http.StatusBadRequest {
		t.Fatalf("finish without a response: %d", w.Code)
	}
	announced := h.scalarNotices("authenticator_bound")
	h.enrollKeyOverHTTP(s, v)
	inv := h.inventory(s)
	if len(inv.Keys) != 1 || len(inv.TOTP) != 1 {
		t.Fatalf("inventory: %+v", inv)
	}
	if h.scalarNotices("authenticator_bound") != announced+2 {
		t.Fatal("the new key was not announced to the confirmed addresses")
	}

	// Login with the key: the password step offers it, a UV-less assertion is refused.
	e.clock.Advance(time.Minute)
	login := h.password("synthetic-user", sessionTestPassword)
	pre, _ := issuedCookie(login)
	csrf := decodeLogin(t, login).CSRFToken
	if got := decodeLogin(t, login).Next; strings.Join(got, ",") != "totp,webauthn,no-mfa" {
		t.Fatalf("next steps %v", got)
	}
	beginLogin := func() ceremony {
		return decodeCeremonyOptions(t, h.do(loginCall{method: "POST", path: LoginWebAuthnBeginPath, cookie: pre, csrf: csrf, body: "{}"}))
	}
	noUV := beginLogin()
	w := h.do(loginCall{method: "POST", path: LoginWebAuthnFinishPath, cookie: pre, csrf: csrf, body: finishBody(t, noUV.ID, v.assert(t, noUV.Options.PublicKey.Challenge, sessionTestOrigin, 1, e.nextCounter()))})
	if w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("an assertion without user verification: %d %s", w.Code, w.Body.String())
	}
	if rec := h.do(loginCall{method: "POST", path: LoginWebAuthnBeginPath, cookie: s.cookie, csrf: s.csrf, body: "{}"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a full session opened the login ceremony: %d", rec.Code)
	}
	good := beginLogin()
	w = h.do(loginCall{method: "POST", path: LoginWebAuthnFinishPath, cookie: pre, csrf: csrf, body: finishBody(t, good.ID, v.assert(t, good.Options.PublicKey.Challenge, sessionTestOrigin, 5, e.nextCounter()))})
	if w.Code != http.StatusOK {
		t.Fatalf("login with the key: %d %s", w.Code, w.Body.String())
	}
	keySession := h.adopt(w)
	_, info := h.info(keySession.cookie)
	if info.Assurance != "aal2" || strings.Join(info.Methods, ",") != "webauthn-uv" {
		t.Fatalf("key session: %+v", info)
	}
	// The ceremony cannot be replayed (the capability was consumed).
	if rec := h.do(loginCall{method: "POST", path: LoginWebAuthnFinishPath, cookie: pre, csrf: csrf, body: finishBody(t, good.ID, v.assert(t, good.Options.PublicKey.Challenge, sessionTestOrigin, 5, e.nextCounter()))}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed login ceremony: %d", rec.Code)
	}

	// Step-up with the key after the freshness window: successor session, dead predecessor.
	e.clock.Advance(16 * time.Minute)
	if rec := h.post(keySession, AccountRecoveryCodesPath, nil); rec.Code != http.StatusForbidden || errorCode(rec) != "step_up_required" {
		t.Fatalf("stale key session: %d", rec.Code)
	}
	var offered struct {
		Methods []string `json:"step_up_methods"`
	}
	mustDecode(t, h.get(keySession, SessionPath).Body.Bytes(), &offered)
	if len(offered.Methods) != 1 || offered.Methods[0] != "webauthn" {
		t.Fatalf("a phishing-resistant session was offered %v", offered.Methods)
	}
	if rec := h.post(keySession, StepUpTOTPPath, map[string]string{"password": sessionTestPassword, "code": e.nextCode(h.en)}); rec.Code != http.StatusForbidden {
		t.Fatalf("a TOTP step-up downgraded a phishing-resistant session: %d", rec.Code)
	}
	step := decodeCeremonyOptions(t, h.post(keySession, StepUpKeyBeginPath, nil))
	rec := h.do(loginCall{method: "POST", path: StepUpKeyFinishPath, cookie: keySession.cookie, csrf: keySession.csrf, body: finishBody(t, step.ID, v.assert(t, step.Options.PublicKey.Challenge, sessionTestOrigin, 5, e.nextCounter()))})
	if rec.Code != http.StatusOK {
		t.Fatalf("key step-up: %d %s", rec.Code, rec.Body.String())
	}
	next := h.adopt(rec)
	if next.cookie == keySession.cookie {
		t.Fatal("step-up did not rotate the cookie")
	}
	if rec = h.post(keySession, AccountRecoveryCodesPath, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("predecessor after step-up: %d", rec.Code)
	}
	if rec = h.post(next, AccountRecoveryCodesPath, nil); rec.Code != http.StatusOK {
		t.Fatalf("fresh key session refused: %d", rec.Code)
	}

	// Removal of the key ends the sessions; another factor remains so it is allowed.
	keyID := h.inventory(next).Keys[0].ID
	if rec = h.post(next, AccountKeyRemovePath, map[string]string{"authenticator_id": h.id}); rec.Code != http.StatusForbidden {
		t.Fatalf("a TOTP id was removed through the key route: %d", rec.Code)
	}
	rec = h.post(next, AccountKeyRemovePath, map[string]string{"authenticator_id": keyID})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"signed_out":true`) {
		t.Fatalf("remove key: %d %s", rec.Code, rec.Body.String())
	}
	if r, _ := h.info(next.cookie); r.Code != http.StatusUnauthorized {
		t.Fatalf("a session survived the removal of a key: %d", r.Code)
	}
}

// Recovered registration: the capability (not a session) registers a replacement key,
// ends as completed and issues no session.
func TestRecoveryHTTPRegistersAReplacementKey(t *testing.T) {
	h := newSecurityHarness(t)
	codes := h.savedCodes()
	h.e.clock.Advance(time.Minute)
	_, start, capability := h.startRecovery(codes[0])
	if capability == nil {
		t.Fatal("no capability")
	}
	v := newVirtualKey(t)
	call := func(path, body string) *httptest.ResponseRecorder {
		return h.capDo(capCall{method: "POST", path: path, cookies: []*http.Cookie{capability}, csrf: start.CSRF, body: body})
	}
	if w := h.capDo(capCall{method: "POST", path: RecoveryKeyBeginPath, cookies: []*http.Cookie{capability}, body: "{}"}); w.Code != http.StatusForbidden {
		t.Fatalf("begin without CSRF: %d", w.Code)
	}
	c := decodeCeremonyOptions(t, call(RecoveryKeyBeginPath, "{}"))
	if w := call(RecoveryKeyFinishPath, finishBody(t, c.ID, v.create(t, c.Options.PublicKey.Challenge, "https://evil.invalid", 5))); w.Code != http.StatusForbidden {
		t.Fatalf("foreign-origin attestation: %d", w.Code)
	}
	c = decodeCeremonyOptions(t, call(RecoveryKeyBeginPath, "{}"))
	w := call(RecoveryKeyFinishPath, finishBody(t, c.ID, v.create(t, c.Options.PublicKey.Challenge, sessionTestOrigin, 5)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	if _, cleared, found := cookieNamed(w, RecoveryCookieName); !found || !cleared {
		t.Fatal("the finished capability was not discarded")
	}
	if _, _, found := cookieNamed(w, SessionCookieName); found {
		t.Fatal("recovered registration issued a session")
	}
	if got := h.e.scalar(`SELECT count(*) FROM authenticators WHERE kind='webauthn' AND state='active'`); got != 1 {
		t.Fatalf("%d active keys after recovered registration", got)
	}
}
