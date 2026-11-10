package auth

import (
	"database/sql"
	"sync"
	"testing"
	"time"
)

const (
	sessionTestPassword = "a unique synthetic public phrase"
	sessionTestOrigin   = "https://example.invalid"
	sessionTestIP       = "192.0.2.10"
	sessionBaseTime     = int64(2000000010)
)

// testClock is the one deterministic clock shared by every service in a fixture.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type sessionEnv struct {
	t     *testing.T
	l     *Lifecycle
	w     *WebAuthnService
	s     *Sessions
	db    *sql.DB
	clock *testClock
	seed  []byte
	// lastSecret lets table-driven invalidation cases reach the session created
	// by the scenario without widening the production API.
	lastSecret []byte
	counter    uint32
}

// newSessionEnv builds a real SQLite repository, lifecycle, WebAuthn and session
// service. The only synthetic pieces are the clock, the origin and the user's
// password; every proof is verified by the real services.
func newSessionEnv(t *testing.T) *sessionEnv {
	t.Helper()
	l, db, seed := lifecycleFixture(t)
	clock := &testClock{now: time.Unix(sessionBaseTime, 0)}
	l.now = clock.Now
	l.notices.Origin = sessionTestOrigin
	w, err := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{sessionTestOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSessions(l, w, DefaultSessionSettings())
	if err != nil {
		t.Fatal(err)
	}
	return &sessionEnv{t: t, l: l, w: w, s: s, db: db, clock: clock, seed: seed}
}

func (e *sessionEnv) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(query, args...); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
}

func (e *sessionEnv) scalar(query string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

// enrollTOTP binds a real TOTP factor using the seeded password-only session.
func (e *sessionEnv) enrollTOTP() (string, Enrollment) { return e.enrollTOTPWith(e.seed) }

func (e *sessionEnv) enrollTOTPWith(session []byte) (string, Enrollment) {
	e.t.Helper()
	en, err := e.l.BeginTOTP(e.t.Context(), session, "SHA256")
	if err != nil {
		e.t.Fatal(err)
	}
	if err = e.l.ConfirmTOTP(e.t.Context(), session, en.ID, enrollmentCode(e.t, en, e.clock.Now()), sessionTestIP); err != nil {
		e.t.Fatal(err)
	}
	return en.ID, en
}

// enrollKey binds a real UV-required virtual P-256 key with the seeded session.
func (e *sessionEnv) enrollKey() (virtualKey, string) { return e.enrollKeyWith(e.seed) }

func (e *sessionEnv) enrollKeyWith(session []byte) (virtualKey, string) {
	e.t.Helper()
	c, err := e.w.BeginRegistration(e.t.Context(), session, false)
	if err != nil {
		e.t.Fatal(err)
	}
	v := newVirtualKey(e.t)
	if err = e.w.FinishRegistration(e.t.Context(), session, c.ID, v.create(e.t, c.Options.Response.Challenge.String(), sessionTestOrigin, 5)); err != nil {
		e.t.Fatal(err)
	}
	return v, c.ID
}

// bothFactors enrolls a key with the password-only seed session, then proves it
// to obtain a genuine AAL2 session which authorises the TOTP binding (a second
// factor on an MFA-capable account needs maximum-assurance evidence).
func (e *sessionEnv) bothFactors() (string, Enrollment, virtualKey, string) {
	e.t.Helper()
	key, keyID := e.enrollKey()
	aal2 := e.aal2Key(key)
	id, en := e.enrollTOTPWith(aal2.Secret())
	return id, en, key, keyID
}

// nextCounter returns the next strictly increasing WebAuthn signature counter.
func (e *sessionEnv) nextCounter() uint32 {
	e.counter++
	return e.counter
}

// retireSeed revokes the fixture's pre-seeded password-only session.
func (e *sessionEnv) retireSeed() {
	e.exec(`UPDATE sessions SET state='revoked',revoked_at=? WHERE id='session'`, sessionBaseTime)
}

// nextCode moves to the next TOTP period (so replay state cannot interfere) and
// returns a valid code for it.
func (e *sessionEnv) nextCode(en Enrollment) string {
	e.t.Helper()
	e.clock.Advance(31 * time.Second)
	return enrollmentCode(e.t, en, e.clock.Now())
}

// aal2TOTP signs in with password + TOTP and returns the AAL2 session.
func (e *sessionEnv) aal2TOTP(id string, en Enrollment) IssuedSession {
	e.t.Helper()
	r, err := e.s.PasswordLogin(e.t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	issued, err := e.s.LoginTOTP(e.t.Context(), r.Session.Secret(), id, e.nextCode(en), sessionTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	return issued
}

// aal2Key signs in with password + UV WebAuthn and returns the AAL2 session.
func (e *sessionEnv) aal2Key(v virtualKey) IssuedSession {
	e.t.Helper()
	r, err := e.s.PasswordLogin(e.t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := e.s.BeginLoginWebAuthn(e.t.Context(), r.Session.Secret())
	if err != nil {
		e.t.Fatal(err)
	}
	issued, err := e.s.LoginWebAuthn(e.t.Context(), r.Session.Secret(), c.ID, v.assert(e.t, c.Options.Response.Challenge.String(), sessionTestOrigin, 5, e.nextCounter()), sessionTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	return issued
}

// passwordOnly signs in with the explicit password-only path (AAL1).
func (e *sessionEnv) passwordOnly() IssuedSession {
	e.t.Helper()
	r, err := e.s.PasswordLogin(e.t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	if r.Session.Info.Assurance == AssurancePreauth {
		issued, err := e.s.LoginWithoutMFA(e.t.Context(), r.Session.Secret())
		if err != nil {
			e.t.Fatal(err)
		}
		return issued
	}
	return r.Session
}

type sessionRow struct {
	Purpose, State           string
	Assurance, Methods       int64
	Phishing                 int64
	Authenticated, Reauth    sql.NullInt64
	Created, Expires, Active int64
}

func (e *sessionEnv) row(id string) sessionRow {
	e.t.Helper()
	var r sessionRow
	err := e.db.QueryRow(`SELECT purpose,state,achieved_assurance,methods,phishing_resistant,authenticated_at,reauthenticated_at,created_at,expires_at,last_activity_at FROM sessions WHERE id=?`, id).
		Scan(&r.Purpose, &r.State, &r.Assurance, &r.Methods, &r.Phishing, &r.Authenticated, &r.Reauth, &r.Created, &r.Expires, &r.Active)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}
