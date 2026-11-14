package auth

// P1.17.2 acceptance hooks: the end-to-end A/B scenario (policy_e2e_test.go, package auth_test) must import
// internal/api and the official MCP client, which import this package, so it lives in the external test
// package. It reuses this package's fixtures through the exports below. Nothing here is product code: the
// fixture session rows are the same normal AAL2 password+TOTP rows Sessions.LoginTOTP issues (see
// adminEnv.aal2Session), and every administrative call in the scenario goes through the real Browser
// boundary and the real Admin service.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

type PolicyE2E struct {
	T          *testing.T
	Repo       *store.Repository
	Clock      *testClock
	Admin      *Admin
	EndpointID domain.EndpointID
	AdminCSRF  string

	env      *adminEnv
	browser  *Browser
	notifier atomic.Pointer[func(context.Context) error]
}

// NewPolicyE2E builds one real repository with an ACTIVE local endpoint and the single administrator holding
// a fresh AAL2 session. The administrative service is wired exactly like a composition root would: its
// notify hook is whatever SetNotify installs (the shared service's NotifyAuthorityChange).
func NewPolicyE2E(t *testing.T) *PolicyE2E {
	t.Helper()
	return newPolicyE2E(t, false)
}

// NewPolicyE2EWithBackup is NewPolicyE2E with the P1.18 backup service attached BEFORE the routes are registered
// (the four backup routes exist only when a service was attached), exactly as a composition root would.
func NewPolicyE2EWithBackup(t *testing.T) *PolicyE2E {
	t.Helper()
	return newPolicyE2E(t, true)
}

func newPolicyE2E(t *testing.T, withBackup bool) *PolicyE2E {
	t.Helper()
	e := newAdminEnv(t)
	p := &PolicyE2E{T: t, env: e, Repo: e.l.repo, Clock: e.clock}
	e.exec(`UPDATE endpoints SET state='active', authority_generation=1 WHERE slug='local'`)
	var id string
	if err := e.db.QueryRow(`SELECT id FROM endpoints WHERE slug='local'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	p.EndpointID = domain.EndpointID(id)
	a, err := NewAdmin(e.l, DefaultAdminSettings(), func(ctx context.Context) error {
		if fn := p.notifier.Load(); fn != nil {
			return (*fn)(ctx)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p.Admin = a
	if withBackup {
		svc, err := backup.New(e.l.repo, "test")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.SetBackup(svc); err != nil {
			t.Fatal(err)
		}
	}
	p.browser = NewBrowser(e.s)
	adapter, err := NewAdminHTTP(a)
	if err != nil {
		t.Fatal(err)
	}
	if err = adapter.Register(p.browser); err != nil {
		t.Fatal(err)
	}
	p.AdminCSRF = csrfToken(e.secret, e.sessID)
	return p
}

func (p *PolicyE2E) SetNotify(fn func(context.Context) error) { p.notifier.Store(&fn) }

// Now is the fixture clock the verifier and the lifecycle share.
func (p *PolicyE2E) Now() time.Time { return p.Clock.Now() }

func (p *PolicyE2E) Exec(query string, args ...any) { p.env.exec(query, args...) }

// Scalar reads one integer from the installation's database (a fixture probe, never a product path).
func (p *PolicyE2E) Scalar(query string, args ...any) int64 { return p.env.scalar(query, args...) }

// Text reads one string from the installation's database.
func (p *PolicyE2E) Text(query string, args ...any) string {
	var out string
	if err := p.env.db.QueryRow(query, args...).Scan(&out); err != nil {
		p.T.Fatal(err)
	}
	return out
}

// RecoveryCeremony runs the REAL host-authorized restore-administrator recovery (S2.2.5, RESTORE-08; see
// recovery_ceremony_fixture_test.go): a NEW administrator with a fresh password and TOTP is enrolled and quarantine ends in
// that one transaction. The backup administrator's account, role, factors and revoked session are NOT revived, and nothing
// else is approved. The fixture then holds the new administrator's AAL2 session instead of the old one: AdminSession and
// AdminCSRF return the NEW cookie and token, so callers must re-read them.
func (p *PolicyE2E) RecoveryCeremony() RecoveredAdmin {
	p.T.Helper()
	r := p.env.hostRecoveryCeremony()
	_, p.AdminCSRF = p.env.signInRecoveryAdmin(r)
	return r
}

// AdminSession is the administrator's cookie value and CSRF token.
func (p *PolicyE2E) AdminSession() (cookie, csrf string) {
	return encodeSessionCookie(p.env.secret), p.AdminCSRF
}

// AdminCredentials is the administrator's human session as the shared authorizer takes it (id + secret).
func (p *PolicyE2E) AdminCredentials() (id string, secret []byte) {
	return p.env.sessID, bytes.Clone(p.env.secret)
}

// OrdinaryUser stores an ACTIVE human account that is NOT the administrator, with a genuine fresh AAL2
// (password + TOTP) session row, and returns the cookie and CSRF token that session would hold. The account
// is what the administrator's "create user" plus a later sign-in produces.
func (p *PolicyE2E) OrdinaryUser(username string) (cookie, csrf string) {
	p.T.Helper()
	e := p.env
	id := "ord-" + strings.ToLower(username)
	e.exec(`INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES(?,?,'active','required',1,1)`, id, username)
	pwd, totp := "pwd-"+id, "totp-"+id
	e.exec(`INSERT INTO authenticators(id,user_id,kind,state,bound_at,credential_generation,password_codepoints,password_format,verifier_hash) VALUES(?,?,'password','active',1,1,30,'mdt-pwd-u17-nfc-cn-v1',randomblob(32))`, pwd, id)
	e.exec(`INSERT INTO authenticators(id,user_id,kind,state,bound_at,credential_generation,encrypted_secret,max_assurance) VALUES(?,?,'totp','active',1,1,randomblob(48),2)`, totp, id)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		p.T.Fatal(err)
	}
	sid := "session-" + id
	now := e.clock.Now().Unix()
	sum := sha256.Sum256(secret)
	cfg := DefaultSessionSettings()
	e.exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,phishing_resistant,authenticated_at,created_at,expires_at,last_activity_at,idle_timeout_seconds,credential_generation,session_generation,state) VALUES(?,?,?,'normal',2,?,0,?,?,?,?,?,1,1,'active')`,
		sid, id, sum[:], evidencePassword|evidenceTOTP, now, now, now+int64(cfg.Absolute/time.Second), now, int64(cfg.Idle/time.Second))
	for _, a := range []string{pwd, totp} {
		e.exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES(?,?,?)`, sid, a, id)
	}
	return encodeSessionCookie(secret), csrfToken(secret, sid)
}

// CountPolicyState is a deterministic dump of every identity, credential and policy table, so a refused
// request can be shown to have changed nothing.
func (p *PolicyE2E) CountPolicyState() string {
	snap := p.env.snapshot()
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\n" + snap[k] + "\n")
	}
	return b.String()
}

// DoBearer sends a request carrying only an Authorization: Bearer header (an agent token) and no session cookie.
func (p *PolicyE2E) DoBearer(method, path, body, token string) (int, string) {
	p.T.Helper()
	r := httptest.NewRequest(method, "https://example.invalid"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	if method != http.MethodGet {
		r.Header.Set("Origin", sessionTestOrigin)
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	p.browser.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// Do sends one request straight to the Browser boundary (no network) with the given cookie and CSRF token.
func (p *PolicyE2E) Do(method, path, body, cookie, csrf string) (int, string) {
	p.T.Helper()
	r := httptest.NewRequest(method, "https://example.invalid"+path, strings.NewReader(body))
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	if method != http.MethodGet {
		if csrf != "" {
			r.Header.Set(CSRFHeader, csrf)
		}
		r.Header.Set("Origin", sessionTestOrigin)
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	p.browser.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}
