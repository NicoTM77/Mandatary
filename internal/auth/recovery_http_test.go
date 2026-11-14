package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// P1.16.4 restricted recovery over HTTP. The REAL Lifecycle.Recover decides; these
// tests prove the adapter hands out a distinct, narrow capability cookie, keeps the
// session boundary and the capability apart, and never creates a session.

type capCall struct {
	method, path, body string
	cookies            []*http.Cookie
	csrf               string
	origin             string
}

func (h *securityHarness) capDo(c capCall) *httptest.ResponseRecorder {
	h.t.Helper()
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	r := httptest.NewRequest(c.method, "https://example.invalid"+c.path, body)
	for _, cookie := range c.cookies {
		r.AddCookie(cookie)
	}
	if c.csrf != "" {
		r.Header.Set(CSRFHeader, c.csrf)
	}
	if c.method != http.MethodGet {
		origin := c.origin
		if origin == "" {
			origin = sessionTestOrigin
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = sessionTestIP + ":4444"
	w := httptest.NewRecorder()
	h.b.ServeHTTP(w, r)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) (value string, cleared bool, found bool) {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c.Value, c.MaxAge < 0 || c.Value == "", true
		}
	}
	return "", false, false
}

type recoveryStart struct {
	Step            string   `json:"step"`
	CSRF            string   `json:"csrf_token"`
	ExpiresAt       int64    `json:"expires_at"`
	Methods         []string `json:"methods"`
	ReplacementCode string   `json:"replacement_code"`
}

// savedCodes issues the account's recovery batch over HTTP and returns it.
func (h *securityHarness) savedCodes() []string {
	h.t.Helper()
	w := h.post(h.signIn(), AccountRecoveryCodesPath, nil)
	var out struct {
		Codes []string `json:"codes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || len(out.Codes) != 10 {
		h.t.Fatalf("issue: %d", w.Code)
	}
	return out.Codes
}

func (h *securityHarness) startRecovery(code string) (*httptest.ResponseRecorder, recoveryStart, *http.Cookie) {
	h.t.Helper()
	w := h.capDo(capCall{method: "POST", path: RecoveryPath, body: mustJSON(h.t, map[string]string{"username": "synthetic-user", "password": sessionTestPassword, "code": code})})
	var start recoveryStart
	_ = json.Unmarshal(w.Body.Bytes(), &start)
	value, _, found := cookieNamed(w, RecoveryCookieName)
	if !found {
		return w, start, nil
	}
	return w, start, &http.Cookie{Name: RecoveryCookieName, Value: value}
}

func TestRecoveryHTTPSavedCodeThenReplacementAuthenticator(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.e
	codes := h.savedCodes()

	// One public denial: unknown user, wrong password, wrong code and a malformed code.
	bad := []map[string]string{
		{"username": "nobody-at-all", "password": sessionTestPassword, "code": codes[0]},
		{"username": "synthetic-user", "password": "not the password", "code": codes[0]},
		{"username": "synthetic-user", "password": sessionTestPassword, "code": strings.Repeat("0", 64) + "." + strings.Repeat("1", 32)},
		{"username": "synthetic-user", "password": sessionTestPassword, "code": "garbage"},
	}
	var first string
	for i, body := range bad {
		w := h.capDo(capCall{method: "POST", path: RecoveryPath, body: mustJSON(t, body)})
		if w.Code != http.StatusForbidden || errorCode(w) != "denied" {
			t.Fatalf("case %d: %d %s", i, w.Code, w.Body.String())
		}
		if i == 0 {
			first = w.Body.String()
		} else if w.Body.String() != first {
			t.Fatalf("case %d is distinguishable from an unknown user", i)
		}
		if _, _, found := cookieNamed(w, RecoveryCookieName); found {
			t.Fatalf("case %d issued a capability", i)
		}
	}
	// Origin and query are enforced on the anonymous route too.
	if w := h.capDo(capCall{method: "POST", path: RecoveryPath, origin: "https://evil.invalid", body: mustJSON(t, bad[0])}); w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	if w := h.capDo(capCall{method: "POST", path: RecoveryPath + "?code=" + codes[0], body: "{}"}); w.Code != http.StatusNotFound {
		t.Fatalf("query string: %d", w.Code)
	}

	// Accepting a code yields ONLY a capability cookie and one replacement code.
	e.clock.Advance(time.Minute)
	w, start, capability := h.startRecovery(codes[0])
	if w.Code != http.StatusOK || capability == nil || start.Step != "capability" || start.CSRF == "" || len(start.ReplacementCode) == 0 || strings.Join(start.Methods, ",") != "totp,webauthn" {
		t.Fatalf("recovery: %d %s", w.Code, w.Body.String())
	}
	if _, _, found := cookieNamed(w, SessionCookieName); found {
		t.Fatal("recovery issued a session cookie")
	}
	set := w.Header().Get("Set-Cookie")
	for _, attr := range []string{"__Host-mandatary_recovery=", "Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=600"} {
		if !strings.Contains(set, attr) {
			t.Fatalf("recovery cookie lacks %s: %s", attr, set)
		}
	}
	if start.ExpiresAt != e.clock.Now().Unix()+600 {
		t.Fatalf("capability lifetime %d", start.ExpiresAt-e.clock.Now().Unix())
	}
	// The sessions of the account ended when the code was consumed.
	// Capability and session never stand in for each other.
	if rec := h.capDo(capCall{method: "GET", path: SessionPath, cookies: []*http.Cookie{capability}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a capability opened the session route: %d", rec.Code)
	}
	asSession := &http.Cookie{Name: SessionCookieName, Value: capability.Value}
	if rec := h.capDo(capCall{method: "GET", path: SessionPath, cookies: []*http.Cookie{asSession}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a capability presented as a session: %d", rec.Code)
	}
	if rec := h.capDo(capCall{method: "GET", path: RecoveryStatePath, cookies: []*http.Cookie{{Name: RecoveryCookieName, Value: asSession.Value[1:] + "A"}}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a forged capability: %d", rec.Code)
	}
	if rec := h.capDo(capCall{method: "GET", path: AccountSecurityPath, cookies: []*http.Cookie{capability}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a capability opened the inventory: %d", rec.Code)
	}
	if rec := h.capDo(capCall{method: "POST", path: AccountRecoveryCodesPath, cookies: []*http.Cookie{capability}, csrf: start.CSRF, body: "{}"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a capability reached a session mutation: %d", rec.Code)
	}

	// State read, then CSRF on the writes.
	rec := h.capDo(capCall{method: "GET", path: RecoveryStatePath, cookies: []*http.Cookie{capability}})
	var state recoveryStart
	_ = json.Unmarshal(rec.Body.Bytes(), &state)
	if rec.Code != http.StatusOK || state.CSRF != start.CSRF || state.ExpiresAt != start.ExpiresAt {
		t.Fatalf("state: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), start.ReplacementCode) {
		t.Fatal("the state route re-displayed the replacement code")
	}
	if rec = h.capDo(capCall{method: "POST", path: RecoveryTOTPPath, cookies: []*http.Cookie{capability}, body: "{}"}); rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", rec.Code)
	}
	if rec = h.capDo(capCall{method: "POST", path: RecoveryTOTPPath, cookies: []*http.Cookie{capability}, csrf: "AAAA" + start.CSRF[4:], body: "{}"}); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF: %d", rec.Code)
	}
	rec = h.capDo(capCall{method: "POST", path: RecoveryTOTPPath, cookies: []*http.Cookie{capability}, csrf: start.CSRF, body: "{}"})
	var begun map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &begun)
	if rec.Code != http.StatusOK || begun["secret"] == "" || begun["authenticator_id"] == "" {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body.String())
	}
	// One replacement per capability.
	if again := h.capDo(capCall{method: "POST", path: RecoveryTOTPPath, cookies: []*http.Cookie{capability}, csrf: start.CSRF, body: "{}"}); again.Code != http.StatusForbidden {
		t.Fatalf("a second replacement was begun: %d", again.Code)
	}
	replacement := Enrollment{ID: begun["authenticator_id"].(string), secret: begun["secret"].(string)}
	confirm := func(code string) *httptest.ResponseRecorder {
		return h.capDo(capCall{method: "POST", path: RecoveryTOTPConfirmPath, cookies: []*http.Cookie{capability}, csrf: start.CSRF, body: mustJSON(t, map[string]string{"authenticator_id": replacement.ID, "code": code})})
	}
	if rec = confirm("000000"); rec.Code != http.StatusForbidden || errorCode(rec) != "denied" {
		t.Fatalf("wrong replacement code: %d %s", rec.Code, rec.Body.String())
	}
	rec = confirm(enrollmentCode(t, replacement, e.clock.Now()))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"completed"`) {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	if _, cleared, found := cookieNamed(rec, RecoveryCookieName); !found || !cleared {
		t.Fatal("completion did not discard the capability")
	}
	if _, _, found := cookieNamed(rec, SessionCookieName); found {
		t.Fatal("recovery completion issued a session")
	}
	if got := h.capDo(capCall{method: "GET", path: RecoveryStatePath, cookies: []*http.Cookie{capability}}); got.Code != http.StatusUnauthorized {
		t.Fatalf("a finished capability is still live: %d", got.Code)
	}
	if h.scalarNotices("recovery_completed") != 2 || h.scalarNotices("authenticator_replaced") != 2 {
		t.Fatal("recovery was not announced to every confirmed address")
	}

	// The old authenticator is retired; the replacement signs in; spent codes are dead.
	e.clock.Advance(31 * time.Second)
	login := h.password("synthetic-user", sessionTestPassword)
	pre, _ := issuedCookie(login)
	csrf := decodeLogin(t, login).CSRFToken
	oldCode := mustJSON(t, map[string]string{"code": enrollmentCode(t, h.en, e.clock.Now())})
	if got := h.do(loginCall{method: "POST", path: LoginTOTPPath, cookie: pre, csrf: csrf, body: oldCode}); got.Code != http.StatusForbidden {
		t.Fatalf("the retired authenticator still signs in: %d", got.Code)
	}
	newCode := mustJSON(t, map[string]string{"code": enrollmentCode(t, replacement, e.clock.Now().Add(31*time.Second))})
	e.clock.Advance(31 * time.Second)
	if got := h.do(loginCall{method: "POST", path: LoginTOTPPath, cookie: pre, csrf: csrf, body: newCode}); got.Code != http.StatusOK {
		t.Fatalf("the replacement does not sign in: %d %s", got.Code, got.Body.String())
	}
	if again, _, c := h.startRecovery(codes[0]); again.Code != http.StatusForbidden || c != nil {
		t.Fatalf("a consumed saved code started recovery again: %d", again.Code)
	}
	if next, _, c := h.startRecovery(start.ReplacementCode); next.Code != http.StatusOK || c == nil {
		t.Fatalf("the replacement saved code was not usable: %d", next.Code)
	}
}

// A capability ends after ten minutes whatever the page does, and an ended one is
// refused everywhere and its cookie cleared.
func TestRecoveryHTTPCapabilityExpires(t *testing.T) {
	h := newSecurityHarness(t)
	codes := h.savedCodes()
	h.e.clock.Advance(time.Minute)
	_, start, capability := h.startRecovery(codes[1])
	if capability == nil {
		t.Fatal("no capability")
	}
	h.e.clock.Advance(10*time.Minute + time.Second)
	for _, call := range []capCall{
		{method: "GET", path: RecoveryStatePath, cookies: []*http.Cookie{capability}},
		{method: "POST", path: RecoveryTOTPPath, cookies: []*http.Cookie{capability}, csrf: start.CSRF, body: "{}"},
	} {
		w := h.capDo(call)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s after expiry: %d", call.path, w.Code)
		}
		if _, cleared, _ := cookieNamed(w, RecoveryCookieName); !cleared {
			t.Fatalf("%s did not clear the ended capability", call.path)
		}
	}
	// Duplicate capability cookies cannot smuggle a value.
	dup := []*http.Cookie{capability, {Name: RecoveryCookieName, Value: capability.Value}}
	if w := h.capDo(capCall{method: "GET", path: RecoveryStatePath, cookies: dup}); w.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate cookies: %d", w.Code)
	}
}

// P1.18.4 P116-L6: the recovery response is derived from the in-memory result of the very
// transaction that consumed the saved code. A storage read that fails AFTER that commit (the
// recovery capability table made unreadable here, between consumption and response) must not
// lose the one replacement code: the caller still receives the cookie, the capability-derived
// CSRF token, the expiry, the permitted methods and the replacement code, exactly once, and
// every later request consistently resolves the same capability.
func TestRecoveryHTTPResponseNeverNeedsASecondStorageReadAfterTheCodeIsConsumed(t *testing.T) {
	h := newSecurityHarness(t)
	codes := h.savedCodes()
	h.e.clock.Advance(time.Minute)
	reads := 0
	h.e.s.afterRecover = func() {
		reads++
		h.e.exec(`ALTER TABLE recovery_capabilities RENAME TO recovery_capabilities_unreadable`)
	}
	w, start, capability := h.startRecovery(codes[0])
	h.e.s.afterRecover = nil
	h.e.exec(`ALTER TABLE recovery_capabilities_unreadable RENAME TO recovery_capabilities`)
	if reads != 1 {
		t.Fatalf("the post-consumption seam ran %d times", reads)
	}
	if w.Code != http.StatusOK || capability == nil || start.Step != "capability" || start.CSRF == "" || len(start.ReplacementCode) == 0 || strings.Join(start.Methods, ",") != "totp,webauthn" || start.ExpiresAt != h.e.clock.Now().Unix()+600 {
		t.Fatalf("a read fault after consumption lost the replacement code: %d %s", w.Code, w.Body.String())
	}
	if len(strings.Split(w.Body.String(), start.ReplacementCode)) != 2 {
		t.Fatal("the replacement code must appear exactly once")
	}
	// The consumed code is spent, and the capability the response described is the live one.
	if w2, _, c2 := h.startRecovery(codes[0]); w2.Code != http.StatusForbidden || c2 != nil {
		t.Fatalf("a consumed saved code was accepted again: %d", w2.Code)
	}
	rec := h.capDo(capCall{method: "GET", path: RecoveryStatePath, cookies: []*http.Cookie{capability}})
	var state recoveryStart
	_ = json.Unmarshal(rec.Body.Bytes(), &state)
	if rec.Code != http.StatusOK || state.CSRF != start.CSRF || state.ExpiresAt != start.ExpiresAt || strings.Join(state.Methods, ",") != strings.Join(start.Methods, ",") {
		t.Fatalf("the response and the stored capability disagree: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), start.ReplacementCode) {
		t.Fatal("the state route re-displayed the replacement code")
	}
	// No raw secret is persisted: neither the capability cookie value nor the replacement code.
	if bytes.Contains(rawStoreBytes(h.e.t, h.e.db), []byte(start.ReplacementCode)) || bytes.Contains(rawStoreBytes(h.e.t, h.e.db), []byte(capability.Value)) {
		t.Fatal("a raw capability or replacement code reached the store")
	}
}

// A WebAuthn-only account is offered only the WebAuthn method, taken from the same transaction.
func TestRecoveryHTTPMethodsForAWebAuthnOnlyAccountComeFromTheConsumingTransaction(t *testing.T) {
	h := newSecurityHarness(t)
	codes := h.savedCodes()
	h.e.exec(`UPDATE users SET mfa_requirement='webauthn'`)
	h.e.clock.Advance(time.Minute)
	w, start, capability := h.startRecovery(codes[0])
	if w.Code != http.StatusOK || capability == nil || strings.Join(start.Methods, ",") != "webauthn" {
		t.Fatalf("webauthn-only methods: %d %s", w.Code, w.Body.String())
	}
	rec := h.capDo(capCall{method: "GET", path: RecoveryStatePath, cookies: []*http.Cookie{capability}})
	var state recoveryStart
	_ = json.Unmarshal(rec.Body.Bytes(), &state)
	if rec.Code != http.StatusOK || strings.Join(state.Methods, ",") != "webauthn" {
		t.Fatalf("state disagrees: %d %s", rec.Code, rec.Body.String())
	}
}

// rawStoreBytes returns the database, WAL and shm bytes for plaintext-exposure scans.
func rawStoreBytes(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	var all []byte
	var path string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}
