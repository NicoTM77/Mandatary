package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// RESTORE-08 over the real setup HTTP surface: the ceremony the browser drives. The view names the purpose, the response
// bodies never echo a secret, completion issues NO session cookie, and only the ordinary login (password + the NEW authenticator)
// yields a session. The restored administrator's own password and authenticator still cannot sign in.
func TestRestoreRecoveryOverHTTPEndsQuarantineAndIssuesNoSession(t *testing.T) {
	e := newSetupEnv(t)
	e.restoredInstallation()
	if _, err := e.issueRestoreRecovery(); err != nil {
		t.Fatal(err)
	}
	token := e.reveal(PurposeRestoreRecovery, "")
	post := func(path, body, cookie, csrf string) *httptest.ResponseRecorder {
		return e.call(setupCall{method: http.MethodPost, path: SetupPathPrefix + path, body: body, cookie: cookie, csrf: csrf})
	}

	w := post("exchange", `{"token":"`+token+`"}`, "", "")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	view := decode(t, w)
	if view["purpose"] != "restore_recovery" || view["target_user"] != "" {
		t.Fatalf("the exchange view: %v", view)
	}
	cookie, csrf := setupCookieOf(t, w), view["csrf_token"].(string)

	w = post("account", `{"username":"`+recoveryTestUser+`","password":"`+recoveryTestPassword+`","addresses":["`+recoveryTestAddress+`"]}`, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), recoveryTestPassword) {
		t.Fatal("the password was echoed")
	}
	address := decode(t, w)["addresses"].([]any)[0].(map[string]any)["id"].(string)
	if w = post("addresses/proof", `{"address_id":"`+address+`"}`, cookie, csrf); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = post("addresses/confirm", `{"address_id":"`+address+`","proof":"`+e.lastProof()+`"}`, cookie, csrf); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = post("complete", `{}`, cookie, csrf); w.Code == http.StatusOK {
		t.Fatal("completed before a fresh authenticator was proven")
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("a refused completion ended quarantine")
	}
	w = post("totp", `{"algorithm":"SHA256"}`, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	seed := decode(t, w)
	en := Enrollment{ID: seed["authenticator_id"].(string), secret: seed["secret"].(string)}
	e.advance(31 * time.Second)
	if w = post("totp/confirm", `{"code":"`+enrollmentCode(t, en, e.clock.Now())+`"}`, cookie, csrf); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	w = post("complete", `{}`, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if done := decode(t, w); done["purpose"] != "restore_recovery" || done["username"] != recoveryTestUser || done["login_required"] != true {
		t.Fatalf("completion view %v", done)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != SetupCookieName || c.MaxAge >= 0 {
			t.Fatalf("unexpected cookie %q on completion: no session may be issued", c.Name)
		}
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 || e.scalar(`SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("quarantine did not end in the completion, or a session was issued")
	}
	if r := e.call(setupCall{method: http.MethodGet, path: SetupPathPrefix + "session", cookie: cookie}); r.Code != http.StatusNotFound {
		t.Fatalf("the setup surface after completion: %d", r.Code)
	}

	// Only the ordinary login yields a session, and only for the NEW administrator.
	e.advance(31 * time.Second)
	login, err := e.sessions().PasswordLogin(e.ctx(), recoveryTestUser, []byte(recoveryTestPassword), "192.0.2.99")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.sessions().LoginTOTP(e.ctx(), login.Session.Secret(), en.ID, enrollmentCode(t, en, e.clock.Now()), "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	if _, err = e.sessions().PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.98"); err == nil {
		t.Fatal("the restored administrator signed in with its backed-up password")
	}
}
