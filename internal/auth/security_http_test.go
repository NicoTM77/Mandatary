package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// P1.16.4 account-security routes. Every proof is verified by the REAL services of
// the session fixture (SQLite, Lifecycle, WebAuthn, Sessions); only the clock, the
// origin and the synthetic password are synthetic. Test names avoid the prefixes
// owned by the P1.06/P1.08 crosswalks.

type securityHarness struct {
	*loginHarness
}

type cookieSession struct{ cookie, csrf string }

func newSecurityHarness(t *testing.T) *securityHarness {
	t.Helper()
	e := newSessionEnv(t)
	h := &loginHarness{t: t, e: e, b: NewBrowser(e.s)}
	h.id, h.en = e.mfaAccount()
	if err := RegisterAccountRoutes(h.b, e.s); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSecurityRoutes(h.b, e.s); err != nil {
		t.Fatal(err)
	}
	return &securityHarness{h}
}

// signIn performs the real two-step login over HTTP and returns the AAL2 session.
func (h *securityHarness) signIn() cookieSession {
	h.t.Helper()
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(h.t, w)
	pre, _ := issuedCookie(w)
	body := mustJSON(h.t, map[string]string{"code": h.e.nextCode(h.en)})
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/totp", cookie: pre, csrf: login.CSRFToken, body: body})
	if w.Code != http.StatusOK {
		h.t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
	return h.adopt(w)
}

// lowerSession performs the real password-only login (labelled lower assurance).
func (h *securityHarness) lowerSession() cookieSession {
	h.t.Helper()
	w := h.password("synthetic-user", sessionTestPassword)
	login := decodeLogin(h.t, w)
	if login.Step == "session" { // no second factor on the account: the password step itself is the lower-assurance login
		return h.adopt(w)
	}
	pre, _ := issuedCookie(w)
	w = h.do(loginCall{method: "POST", path: "/api/v1/login/no-mfa", cookie: pre, csrf: login.CSRFToken, body: "{}"})
	if w.Code != http.StatusOK {
		h.t.Fatalf("password-only sign-in: %d %s", w.Code, w.Body.String())
	}
	return h.adopt(w)
}

func (h *securityHarness) adopt(w *httptest.ResponseRecorder) cookieSession {
	h.t.Helper()
	cookie, _ := issuedCookie(w)
	if cookie == "" {
		h.t.Fatal("no session cookie issued")
	}
	rec, info := h.info(cookie)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("session info: %d", rec.Code)
	}
	return cookieSession{cookie: cookie, csrf: info.CSRFToken}
}

func (h *securityHarness) post(s cookieSession, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	raw := "{}"
	if body != nil {
		raw = mustJSON(h.t, body)
	}
	return h.do(loginCall{method: "POST", path: path, cookie: s.cookie, csrf: s.csrf, body: raw})
}

func (h *securityHarness) get(s cookieSession, path string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(loginCall{method: "GET", path: path, cookie: s.cookie})
}

type inventoryBody struct {
	TOTP []struct {
		ID      string `json:"id"`
		AddedAt int64  `json:"added_at"`
		Status  string `json:"status"`
	} `json:"totp"`
	Keys []struct {
		ID string `json:"id"`
	} `json:"keys"`
	MaxKeys       int  `json:"max_keys"`
	WebAuthn      bool `json:"webauthn_available"`
	RecoveryCodes struct {
		Remaining int `json:"remaining"`
	} `json:"recovery_codes"`
	Addresses []AddressView `json:"addresses"`
	MaxAddr   int           `json:"max_addresses"`
	Notices   struct {
		Pending, Failed, Bounced, Quarantined, Protective int64
		Unknown                                           bool
	} `json:"notices"`
}

func (h *securityHarness) inventory(s cookieSession) inventoryBody {
	h.t.Helper()
	w := h.get(s, AccountSecurityPath)
	if w.Code != http.StatusOK {
		h.t.Fatalf("inventory: %d %s", w.Code, w.Body.String())
	}
	var inv inventoryBody
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil {
		h.t.Fatal(err)
	}
	return inv
}

func mustDecode(t *testing.T, raw []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("not JSON: %v %q", err, raw)
	}
}

func errorCode(w *httptest.ResponseRecorder) string {
	var b struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return b.Error
}

// Every slice-2 route carries an explicit policy: authenticator and address
// mutations name their TD §4.3 class, the inventory is a plain read, the login
// ceremony needs a preauth, and recovery routes are anonymous at the boundary (the
// capability is checked by the route itself).
func TestAccountSecurityHTTPRoutePolicies(t *testing.T) {
	h := newSecurityHarness(t)
	want := map[string]RoutePolicy{
		"POST " + StepUpKnowledgePath:       {Require: RequireSession},
		"POST " + StepUpTOTPPath:            {Require: RequireSession},
		"POST " + StepUpKeyBeginPath:        {Require: RequireSession},
		"POST " + StepUpKeyFinishPath:       {Require: RequireSession},
		"POST " + LoginWebAuthnBeginPath:    {Require: RequirePreauth},
		"POST " + LoginWebAuthnFinishPath:   {Require: RequirePreauth},
		"GET " + AccountSecurityPath:        {Require: RequireSession},
		"POST " + AccountTOTPPath:           {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountTOTPConfirmPath:    {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountTOTPRemovePath:     {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountRecoveryCodesPath:  {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountKeyBeginPath:       {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountKeyFinishPath:      {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountKeyRemovePath:      {Require: RequireSession, Sensitive: OpAuthenticatorChange},
		"POST " + AccountAddressPath:        {Require: RequireSession, Sensitive: OpNotificationAddress},
		"POST " + AccountAddressProofPath:   {Require: RequireSession, Sensitive: OpNotificationAddress},
		"POST " + AccountAddressConfirmPath: {Require: RequireSession, Sensitive: OpNotificationAddress},
		"POST " + AccountAddressRemovePath:  {Require: RequireSession, Sensitive: OpNotificationAddress},
		"POST " + RecoveryPath:              {Require: RequireNone},
		"GET " + RecoveryStatePath:          {Require: RequireNone},
		"POST " + RecoveryTOTPPath:          {Require: RequireNone},
		"POST " + RecoveryTOTPConfirmPath:   {Require: RequireNone},
		"POST " + RecoveryKeyBeginPath:      {Require: RequireNone},
		"POST " + RecoveryKeyFinishPath:     {Require: RequireNone},
	}
	got := map[string]RoutePolicy{}
	for _, route := range h.b.Routes() {
		got[route.Pattern] = route.Policy
	}
	for pattern, policy := range want {
		if got[pattern] != policy {
			t.Errorf("%s: policy %+v, want %+v", pattern, got[pattern], policy)
		}
	}
	// Every path in SecurityPaths() is a registered route (no dead mount entry).
	for _, path := range SecurityPaths() {
		found := false
		for pattern := range got {
			if strings.HasSuffix(pattern, " "+path) {
				found = true
			}
		}
		if !found {
			t.Errorf("SecurityPaths lists %s but no route is registered", path)
		}
	}
}

// Without a WebAuthn service no key route exists at all (404), and the rest of the
// slice still works. Nothing is half-mounted.
func TestAccountSecurityHTTPWithoutWebAuthnHasNoKeyRoutes(t *testing.T) {
	e := newSessionEnv(t)
	s, err := NewSessions(e.l, nil, DefaultSessionSettings())
	if err != nil {
		t.Fatal(err)
	}
	h := &loginHarness{t: t, e: e, b: NewBrowser(s)}
	h.id, h.en = e.mfaAccount()
	if err = RegisterAccountRoutes(h.b, s); err != nil {
		t.Fatal(err)
	}
	if err = RegisterSecurityRoutes(h.b, s); err != nil {
		t.Fatal(err)
	}
	for _, route := range h.b.Routes() {
		if strings.Contains(route.Pattern, "webauthn") {
			t.Errorf("WebAuthn route registered without a service: %s", route.Pattern)
		}
	}
	sh := &securityHarness{h}
	session := sh.signIn()
	if w := sh.post(session, AccountKeyBeginPath, nil); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("key route answered %d without a service", w.Code)
	}
	if inv := sh.inventory(session); inv.WebAuthn {
		t.Fatal("inventory claims WebAuthn is available")
	}
}

// The inventory is the account's own state, read-only and secret-free.
func TestAccountSecurityHTTPInventoryIsSecretFree(t *testing.T) {
	h := newSecurityHarness(t)
	s := h.signIn()
	w := h.get(s, AccountSecurityPath)
	inv := h.inventory(s)
	if len(inv.TOTP) != 1 || inv.TOTP[0].ID != h.id || inv.TOTP[0].Status != "active" || len(inv.Keys) != 0 || inv.RecoveryCodes.Remaining != 0 || inv.MaxKeys != 16 || !inv.WebAuthn || inv.MaxAddr != 4 {
		t.Fatalf("inventory: %s", w.Body.String())
	}
	if len(inv.Addresses) != 2 || !inv.Addresses[0].Confirmed || !inv.Addresses[1].Confirmed {
		t.Fatalf("addresses: %+v", inv.Addresses)
	}
	for _, secret := range []string{sessionTestPassword, h.en.secret, s.cookie, "verifier", "encrypted", "public_key"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("inventory leaked %q", secret)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("inventory is cacheable")
	}
	if rec := h.do(loginCall{method: "GET", path: AccountSecurityPath}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous inventory: %d", rec.Code)
	}
	if rec := h.do(loginCall{method: "GET", path: AccountSecurityPath + "?id=1", cookie: s.cookie}); rec.Code != http.StatusNotFound {
		t.Fatalf("query string accepted: %d", rec.Code)
	}
}

// A password-only (lower-assurance) session of an AAL2-capable account cannot change
// factors or addresses and cannot step up with a password alone: no assurance bypass.
func TestAccountSecurityHTTPPasswordOnlySessionCannotChangeSecurity(t *testing.T) {
	h := newSecurityHarness(t)
	low := h.lowerSession()
	if _, info := h.info(low.cookie); info.Assurance != "password-only" || len(info.Methods) != 1 {
		t.Fatalf("session: %+v", info)
	}
	for _, path := range []string{AccountTOTPPath, AccountRecoveryCodesPath, AccountAddressPath, AccountTOTPRemovePath, AccountAddressRemovePath} {
		w := h.post(low, path, map[string]string{"address": "x@example.invalid", "authenticator_id": h.id, "id": "addr1"})
		if w.Code != http.StatusForbidden || errorCode(w) != "step_up_required" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	// A password cannot substitute for the second factor.
	w := h.post(low, StepUpKnowledgePath, map[string]string{"password": sessionTestPassword})
	if w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("password step-up of an AAL2-capable account: %d %s", w.Code, w.Body.String())
	}
	if v, _ := issuedCookie(w); v != "" {
		t.Fatal("a refused step-up issued a cookie")
	}
	if _, info := h.info(low.cookie); len(info.Methods) != 1 || info.Assurance != "password-only" {
		t.Fatalf("session was upgraded: %+v", info)
	}
	// The server offers exactly the proofs it would accept.
	var raw struct {
		Methods []string `json:"step_up_methods"`
	}
	_ = json.Unmarshal(h.get(low, SessionPath).Body.Bytes(), &raw)
	if strings.Join(raw.Methods, ",") != "totp" {
		t.Fatalf("offered step-up methods %v", raw.Methods)
	}
}

// The inventory of an MFA-capable account is not shown to a password-only session. The session itself is
// live (so it is not "unauthenticated"): the refusal is a 403 the page can explain, and nothing is leaked.
func TestAccountSecurityHTTPPasswordOnlySessionGetsNoInventory(t *testing.T) {
	h := newSecurityHarness(t)
	low := h.lowerSession()
	w := h.get(low, AccountSecurityPath)
	if w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("inventory for a password-only session: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "example.invalid") {
		t.Fatal("a refused inventory leaked an address")
	}
	if rec, _ := h.info(low.cookie); rec.Code != http.StatusOK {
		t.Fatalf("the refusal ended the session: %d", rec.Code)
	}
	if w := h.get(h.signIn(), AccountSecurityPath); w.Code != http.StatusOK {
		t.Fatalf("an AAL2 session lost its inventory: %d", w.Code)
	}
}

// An account with no second factor re-verifies with its password; the successor
// session replaces the old one, whose cookie and CSRF token die at once.
func TestAccountSecurityHTTPPasswordStepUpForAnAccountWithoutFactors(t *testing.T) {
	e := newSessionEnv(t)
	h := &loginHarness{t: t, e: e, b: NewBrowser(e.s)}
	if err := RegisterAccountRoutes(h.b, e.s); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSecurityRoutes(h.b, e.s); err != nil {
		t.Fatal(err)
	}
	sh := &securityHarness{h}
	s := sh.lowerSession()
	e.clock.Advance(20 * time.Minute)
	var raw struct {
		Stale   bool     `json:"step_up_required"`
		Methods []string `json:"step_up_methods"`
	}
	_ = json.Unmarshal(sh.get(s, SessionPath).Body.Bytes(), &raw)
	if !raw.Stale || strings.Join(raw.Methods, ",") != "password" {
		t.Fatalf("session info %+v", raw)
	}
	if w := sh.post(s, StepUpKnowledgePath, map[string]string{"password": "not the password"}); w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("wrong password: %d %s", w.Code, w.Body.String())
	}
	if w := sh.do(loginCall{method: "POST", path: StepUpKnowledgePath, cookie: s.cookie, body: `{"password":"x"}`}); w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	w := sh.post(s, StepUpKnowledgePath, map[string]string{"password": sessionTestPassword})
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), sessionTestPassword) {
		t.Fatalf("step-up: %d %s", w.Code, w.Body.String())
	}
	next := sh.adopt(w)
	if next.cookie == s.cookie || next.csrf == s.csrf {
		t.Fatal("step-up did not rotate the cookie and CSRF token")
	}
	if rec, _ := sh.info(s.cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the predecessor cookie survived: %d", rec.Code)
	}
	if rec := sh.post(s, StepUpKnowledgePath, map[string]string{"password": sessionTestPassword}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("predecessor still accepted: %d", rec.Code)
	}
	var fresh struct {
		Stale bool `json:"step_up_required"`
	}
	_ = json.Unmarshal(sh.get(next, SessionPath).Body.Bytes(), &fresh)
	if fresh.Stale {
		t.Fatal("the successor session is still stale")
	}
}

// Step-up with password + TOTP: a stale session is refused by the boundary, a wrong
// or replayed code never rotates anything, and the successor session works while the
// predecessor (and its CSRF token, as in a second tab) is dead.
func TestAccountSecurityHTTPTOTPStepUp(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.e
	s := h.signIn()
	e.clock.Advance(16 * time.Minute)
	w := h.post(s, AccountRecoveryCodesPath, nil)
	if w.Code != http.StatusForbidden || errorCode(w) != "step_up_required" {
		t.Fatalf("stale session: %d %s", w.Code, w.Body.String())
	}
	good := e.nextCode(h.en)
	cases := []struct {
		name string
		body map[string]string
	}{
		{"wrong code", map[string]string{"password": sessionTestPassword, "code": "000000"}},
		{"wrong password", map[string]string{"password": "not the password", "code": good}},
		{"foreign authenticator", map[string]string{"password": sessionTestPassword, "code": good, "authenticator_id": "someone-elses-id"}},
	}
	for _, c := range cases {
		w = h.post(s, StepUpTOTPPath, c.body)
		if w.Code != http.StatusForbidden || errorCode(w) != "denied" {
			t.Fatalf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
		if v, _ := issuedCookie(w); v != "" {
			t.Fatalf("%s issued a cookie", c.name)
		}
	}
	// Unknown fields are refused, never ignored.
	if w = h.post(s, StepUpTOTPPath, map[string]any{"password": sessionTestPassword, "code": good, "assurance": "aal2"}); w.Code != http.StatusBadRequest {
		t.Fatalf("client-asserted assurance field: %d", w.Code)
	}
	good = e.nextCode(h.en)
	w = h.post(s, StepUpTOTPPath, map[string]string{"password": sessionTestPassword, "code": good})
	if w.Code != http.StatusOK {
		t.Fatalf("step-up: %d %s", w.Code, w.Body.String())
	}
	next := h.adopt(w)
	if w = h.post(next, StepUpTOTPPath, map[string]string{"password": sessionTestPassword, "code": good}); w.Code != http.StatusForbidden {
		t.Fatalf("a replayed code was accepted: %d", w.Code)
	}
	// The second tab still holds the predecessor's cookie and CSRF token.
	if w = h.post(s, AccountRecoveryCodesPath, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("predecessor session: %d", w.Code)
	}
	if w = h.post(next, AccountRecoveryCodesPath, nil); w.Code != http.StatusOK {
		t.Fatalf("fresh session refused: %d %s", w.Code, w.Body.String())
	}
}

// TOTP enrolment after sign-in: the seed is shown once, the factor is unusable until
// a code proves it, several factors need an explicit choice at login, and removal
// ends every session (and refuses the last required factor).
func TestAccountSecurityHTTPTOTPLifecycle(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.e
	s := h.signIn()
	w := h.post(s, AccountTOTPPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	var begun struct {
		ID, Secret, Algorithm string
		Digits, Period        int
	}
	var raw map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	begun.ID, _ = raw["authenticator_id"].(string)
	begun.Secret, _ = raw["secret"].(string)
	begun.Algorithm, _ = raw["algorithm"].(string)
	if begun.ID == "" || len(begun.Secret) < 26 || begun.Algorithm != "SHA256" || raw["digits"] != float64(6) || raw["period"] != float64(30) {
		t.Fatalf("begin body: %s", w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the seed response is cacheable")
	}
	// A pending factor is not shown as usable and cannot sign anyone in.
	if inv := h.inventory(s); len(inv.TOTP) != 1 {
		t.Fatalf("pending factor listed: %+v", inv.TOTP)
	}
	second := Enrollment{ID: begun.ID, secret: begun.Secret}
	if w = h.post(s, AccountTOTPConfirmPath, map[string]string{"authenticator_id": begun.ID, "code": "000000"}); w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}
	code := enrollmentCode(t, second, e.clock.Now())
	if w = h.post(s, AccountTOTPConfirmPath, map[string]string{"authenticator_id": begun.ID, "code": code}); w.Code != http.StatusNoContent {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	if w = h.post(s, AccountTOTPConfirmPath, map[string]string{"authenticator_id": begun.ID, "code": code}); w.Code != http.StatusForbidden {
		t.Fatalf("a confirmed enrolment was confirmed again: %d", w.Code)
	}
	if inv := h.inventory(s); len(inv.TOTP) != 2 {
		t.Fatalf("inventory after enrolment: %+v", inv.TOTP)
	}
	if got := h.scalarNotices("authenticator_bound"); got < 2 {
		t.Fatalf("enrolment announced to %d recipients, want every confirmed address", got)
	}

	// Two usable authenticators: the server never guesses which one a code is for.
	e.clock.Advance(31 * time.Second)
	login := h.password("synthetic-user", sessionTestPassword)
	var factors struct {
		Step    string `json:"step"`
		Factors []struct {
			ID string `json:"id"`
		} `json:"totp_factors"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &factors)
	if factors.Step != "factor" || len(factors.Factors) != 2 {
		t.Fatalf("password step: %s", login.Body.String())
	}
	pre, _ := issuedCookie(login)
	csrf := decodeLogin(t, login).CSRFToken
	unnamed := mustJSON(t, map[string]string{"code": enrollmentCode(t, h.en, e.clock.Now())})
	if w = h.do(loginCall{method: "POST", path: LoginTOTPPath, cookie: pre, csrf: csrf, body: unnamed}); w.Code != http.StatusForbidden {
		t.Fatalf("several factors were guessed: %d", w.Code)
	}
	named := mustJSON(t, map[string]string{"code": enrollmentCode(t, h.en, e.clock.Now()), "authenticator_id": h.id})
	if w = h.do(loginCall{method: "POST", path: LoginTOTPPath, cookie: pre, csrf: csrf, body: named}); w.Code != http.StatusOK {
		t.Fatalf("named factor: %d %s", w.Code, w.Body.String())
	}
	fresh := h.adopt(w)

	// Removal: foreign/unknown ids are one refusal; a success ends the session.
	if w = h.post(fresh, AccountTOTPRemovePath, map[string]string{"authenticator_id": "pwd"}); w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("removing the password authenticator: %d %s", w.Code, w.Body.String())
	}
	if w = h.post(fresh, AccountTOTPRemovePath, map[string]string{"authenticator_id": "nope"}); w.Code != http.StatusForbidden {
		t.Fatalf("unknown id: %d", w.Code)
	}
	w = h.post(fresh, AccountTOTPRemovePath, map[string]string{"authenticator_id": begun.ID})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"signed_out":true`) {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if _, cleared := issuedCookie(w); !cleared {
		t.Fatal("removal did not clear the cookie")
	}
	if rec, _ := h.info(fresh.cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session survived the removal of a factor: %d", rec.Code)
	}

	// With mandatory MFA the last remaining factor can never be removed.
	e.exec(`UPDATE users SET mfa_requirement='required'`)
	last := h.signIn()
	if w = h.post(last, AccountTOTPRemovePath, map[string]string{"authenticator_id": h.id}); w.Code != http.StatusForbidden || errorCode(w) != "denied" {
		t.Fatalf("the last required factor was removed: %d %s", w.Code, w.Body.String())
	}
	if rec, _ := h.info(last.cookie); rec.Code != http.StatusOK {
		t.Fatal("a refused removal ended the session")
	}
}

// scalarNotices counts outbox rows of an event type (one row per recipient).
func (h *securityHarness) scalarNotices(event string) int64 {
	h.t.Helper()
	return h.e.scalar(`SELECT count(*) FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id WHERE e.event_type=?`, event)
}

// Recovery codes are issued only on a fresh AAL2 session, shown once, replaced as a
// batch, and never listed again: the inventory only counts them.
func TestAccountSecurityHTTPRecoveryCodesRevealOnce(t *testing.T) {
	h := newSecurityHarness(t)
	s := h.signIn()
	w := h.post(s, AccountRecoveryCodesPath, nil)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var issued struct {
		Codes []string `json:"codes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &issued)
	if len(issued.Codes) != 10 {
		t.Fatalf("issued %d codes", len(issued.Codes))
	}
	inv := h.get(s, AccountSecurityPath)
	for _, code := range issued.Codes {
		if strings.Contains(inv.Body.String(), code) || strings.Contains(inv.Body.String(), strings.Split(code, ".")[1]) {
			t.Fatal("the inventory re-displayed a recovery code")
		}
	}
	if got := h.inventory(s); got.RecoveryCodes.Remaining != 10 {
		t.Fatalf("remaining %d", got.RecoveryCodes.Remaining)
	}
	if h.scalarNotices("recovery_codes_issued") != 2 {
		t.Fatal("the issue was not announced to every confirmed address")
	}
	// Replacement invalidates the old batch: an old code cannot start recovery.
	again := h.post(s, AccountRecoveryCodesPath, nil)
	var replaced struct {
		Codes []string `json:"codes"`
	}
	_ = json.Unmarshal(again.Body.Bytes(), &replaced)
	if again.Code != http.StatusOK || len(replaced.Codes) != 10 || replaced.Codes[0] == issued.Codes[0] {
		t.Fatalf("replace: %d", again.Code)
	}
	old := h.do(loginCall{method: "POST", path: RecoveryPath, body: mustJSON(t, map[string]string{"username": "synthetic-user", "password": sessionTestPassword, "code": issued.Codes[0]})})
	if old.Code != http.StatusForbidden {
		t.Fatalf("a replaced code started recovery: %d", old.Code)
	}
	if h.scalarNotices("recovery_codes_replaced") != 2 {
		t.Fatal("the replacement was not announced")
	}
}

// Every new unsafe route refuses the same forgeries: no/wrong/duplicate CSRF, a
// foreign or missing Origin, cross-site fetch metadata, a form content type and any
// query string, and none of them reaches a service.
func TestAccountSecurityHTTPRejectsForgedRequests(t *testing.T) {
	h := newSecurityHarness(t)
	s := h.signIn()
	paths := []string{StepUpKnowledgePath, StepUpTOTPPath, AccountTOTPPath, AccountTOTPConfirmPath, AccountTOTPRemovePath, AccountRecoveryCodesPath, AccountKeyBeginPath, AccountKeyFinishPath, AccountKeyRemovePath, AccountAddressPath, AccountAddressProofPath, AccountAddressConfirmPath, AccountAddressRemovePath, StepUpKeyBeginPath, StepUpKeyFinishPath}
	for _, path := range paths {
		forged := []loginCall{
			{method: "POST", path: path, cookie: s.cookie, body: "{}"},
			{method: "POST", path: path, cookie: s.cookie, csrf: "AAAA" + s.csrf[4:], body: "{}"},
			{method: "POST", path: path, cookie: s.cookie, csrf: s.csrf, body: "{}", origin: "https://evil.invalid"},
			{method: "POST", path: path, cookie: s.cookie, csrf: s.csrf, body: "{}", noOrigin: true},
			{method: "POST", path: path, cookie: s.cookie, csrf: s.csrf, body: "x=1", contentType: "application/x-www-form-urlencoded"},
		}
		for i, call := range forged {
			w := h.do(call)
			if w.Code < 400 || w.Code == http.StatusServiceUnavailable {
				t.Errorf("%s forgery %d answered %d", path, i, w.Code)
			}
			if v, _ := issuedCookie(w); v != "" {
				t.Errorf("%s forgery %d issued a cookie", path, i)
			}
		}
		if w := h.do(loginCall{method: "POST", path: path + "?x=1", cookie: s.cookie, csrf: s.csrf, body: "{}"}); w.Code != http.StatusNotFound {
			t.Errorf("%s accepted a query string: %d", path, w.Code)
		}
	}
	// Nothing above reached a service: the account is exactly as it was.
	if inv := h.inventory(s); len(inv.TOTP) != 1 || len(inv.Addresses) != 2 || inv.RecoveryCodes.Remaining != 0 {
		t.Fatalf("a forged request changed the account: %+v", inv)
	}
	// Server-asserted fields only: unknown/extra JSON members are refused.
	w := h.post(s, AccountAddressPath, map[string]any{"address": "new@example.invalid", "confirmed": true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a client-asserted confirmed flag was ignored instead of refused: %d", w.Code)
	}
}
