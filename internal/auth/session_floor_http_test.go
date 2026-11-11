package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// L1: the idle predicate lives in the touching statement too. A row whose idle
// window elapsed between Authenticate's read and its activity write must not be
// revived by that write.
func TestSessionTouchCannotReviveIdleExpiredRow(t *testing.T) { // S06 idle timeout, read/write race
	e := newSessionEnv(t)
	issued := e.passwordOnly()
	created := e.clock.Now()
	calls := 0
	e.l.now = func() time.Time {
		calls++
		if calls == 1 {
			return created.Add(DefaultSessionIdle - time.Second) // read: still inside the idle window
		}
		return created.Add(DefaultSessionIdle) // activity write: the window just elapsed
	}
	if _, err := e.s.Authenticate(t.Context(), issued.Secret(), true); err != ErrDenied {
		t.Fatalf("idle-expired session revived by its own activity write: %v", err)
	}
	if calls != 2 {
		t.Fatalf("race not exercised: %d clock reads (the read must pass, the touch must deny)", calls)
	}
	e.l.now = e.clock.Now
	if got := e.row(issued.Info.ID).Active; got != created.Unix() {
		t.Fatalf("denied touch still advanced last activity to %d", got)
	}
	e.clock.Advance(DefaultSessionIdle)
	if _, err := e.s.Authenticate(t.Context(), issued.Secret(), true); err != ErrDenied {
		t.Fatal("expired session accepted afterwards", err)
	}
}

// L2: a sensitive (mutating) class on a safe method is refused at registration.
// GET skips Origin and CSRF by design, so it must never carry a sensitive write.
func TestSessionSensitiveRoutesRefuseSafeMethods(t *testing.T) { // S05, weaker-route prevention
	e := newSessionEnv(t)
	b := NewBrowser(e.s)
	ok := http.NotFoundHandler()
	for _, op := range SensitiveOperations() {
		if err := b.Handle("GET /safe/"+string(op), RoutePolicy{Require: RequireSession, Sensitive: op}, ok); err == nil {
			t.Fatalf("sensitive class %s registered on a GET route (no Origin/CSRF check)", op)
		}
		if err := b.Handle("POST /safe/"+string(op), RoutePolicy{Require: RequireSession, Sensitive: op}, ok); err != nil {
			t.Fatalf("sensitive class %s refused on POST: %v", op, err)
		}
	}
	if len(b.Routes()) != len(SensitiveOperations()) {
		t.Fatal("refused GET routes entered the inventory")
	}
}

// L3: every sensitive class is exercised through the REAL step-up route, not a
// fresh login, with the weaker-session, expired and pre-step-up-cookie negatives.
func TestSessionSensitiveRoutesActualStepUpOverHTTP(t *testing.T) { // REAUTH-STRENGTH, S07 15-minute step-up, every class
	h := newBrowserHarness(t)
	post := func(path string, q httpReq, body string) *httptest.ResponseRecorder {
		q.method, q.path, q.body = "POST", path, body
		return h.do(q)
	}
	stepUpRequired := func(w *httptest.ResponseRecorder) bool {
		var out struct{ Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code == http.StatusForbidden && out.Error == "step_up_required"
	}
	for _, op := range SensitiveOperations() {
		t.Run(string(op), func(t *testing.T) {
			path, counter := "/t/sensitive/"+string(op), "op:"+string(op)
			before := h.calls0(counter)
			// weaker route/session: a password-only cookie on an AAL2-capable account
			weak := h.e.passwordOnly()
			if w := post(path, httpReq{cookie: encodeSessionCookie(weak.Secret()), csrf: weak.CSRFToken()}, `{}`); !stepUpRequired(w) {
				t.Fatalf("password-only cookie reached %s: %d %s", op, w.Code, w.Body.String())
			}
			// an AAL2 session that has gone stale
			old := h.e.aal2TOTP(h.id, h.en)
			oldCookie, oldCSRF := encodeSessionCookie(old.Secret()), old.CSRFToken()
			h.e.clock.Advance(DefaultStepUpWindow + time.Second)
			if w := post(path, httpReq{cookie: oldCookie, csrf: oldCSRF}, `{}`); !stepUpRequired(w) {
				t.Fatalf("stale AAL2 cookie did not ask for step-up: %d %s", w.Code, w.Body.String())
			}
			if w := h.do(httpReq{method: "GET", path: "/t/read", cookie: oldCookie}); w.Code != 200 {
				t.Fatal("the stale session is still a valid non-sensitive session", w.Code)
			}
			// a failed step-up proves nothing and changes nothing
			bad := fmt.Sprintf(`{"password":%q,"id":%q,"code":"000000"}`, sessionTestPassword, h.id)
			if w := post("/t/stepup/totp", httpReq{cookie: oldCookie, csrf: oldCSRF}, bad); w.Code != 401 {
				t.Fatalf("wrong OTP step-up accepted: %d", w.Code)
			}
			if w := post(path, httpReq{cookie: oldCookie, csrf: oldCSRF}, `{}`); !stepUpRequired(w) {
				t.Fatal("failed step-up refreshed freshness")
			}
			// the real step-up: new proofs, successor cookie
			good := fmt.Sprintf(`{"password":%q,"id":%q,"code":%q}`, sessionTestPassword, h.id, h.e.nextCode(h.en))
			w := post("/t/stepup/totp", httpReq{cookie: oldCookie, csrf: oldCSRF}, good)
			if w.Code != 200 {
				t.Fatalf("real step-up failed: %d %s", w.Code, w.Body.String())
			}
			upCookie := cookieValue(t, w)
			var up struct{ CSRF string }
			_ = json.Unmarshal(w.Body.Bytes(), &up)
			if upCookie == oldCookie || up.CSRF == oldCSRF {
				t.Fatal("step-up did not rotate cookie and CSRF token")
			}
			if w := post(path, httpReq{cookie: oldCookie, csrf: oldCSRF}, `{}`); w.Code != 401 {
				t.Fatalf("pre-step-up cookie still usable: %d", w.Code)
			}
			if h.calls0(counter) != before {
				t.Fatalf("%s handler reached before step-up completed", op)
			}
			// positive: the stepped-up cookie performs the mutation, once
			if w := post(path, httpReq{cookie: upCookie, csrf: up.CSRF}, `{}`); w.Code != 200 {
				t.Fatalf("%s denied after real step-up: %d %s", op, w.Code, w.Body.String())
			}
			if h.calls0(counter) != before+1 {
				t.Fatalf("%s handler count after step-up", op)
			}
			// the window is 15 minutes: after it the same cookie must step up again
			h.e.clock.Advance(DefaultStepUpWindow + time.Second)
			if w := post(path, httpReq{cookie: upCookie, csrf: up.CSRF}, `{}`); !stepUpRequired(w) {
				t.Fatalf("step-up outlived its 15-minute window: %d", w.Code)
			}
			if h.calls0(counter) != before+1 {
				t.Fatalf("%s handler reached with expired step-up", op)
			}
		})
	}
}
