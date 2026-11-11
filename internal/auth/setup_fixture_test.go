package auth

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

const (
	setupTestOrigin   = "https://example.invalid"
	setupTestPassword = "synthetic setup passphrase 41"
	setupTestUser     = "first-admin"
	setupTestIP       = "192.0.2.50"
)

// fakeTerminal is the host terminal for protocol tests. It records exactly what a
// human would see; the real-terminal behavior is exercised in cmd/mandatary with
// an actual pty and with pipes/files/redirections.
type fakeTerminal struct {
	mu                  sync.Mutex
	verifyErr, writeErr error
	short               bool
	out                 bytes.Buffer
	verified, writes    int
}

func (f *fakeTerminal) Verify() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified++
	return f.verifyErr
}

func (f *fakeTerminal) WriteSecret(_ context.Context, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	if f.short {
		f.out.Write(data[:len(data)/2])
		return io.ErrShortWrite
	}
	f.out.Write(data)
	return nil
}

var groupedTokenPattern = regexp.MustCompile(`([A-Z2-7]{4}-){12}[A-Z2-7]{4}`)

// token returns the canonical token the human saw, or "" when none was shown.
func (f *fakeTerminal) token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := groupedTokenPattern.FindString(f.out.String())
	return strings.ReplaceAll(m, "-", "")
}

type setupConfig struct {
	mail  bool
	probe *authSyncProbe
}

type setupOption func(*setupConfig)

func withoutMail() setupOption { return func(c *setupConfig) { c.mail = false } }

// withSyncProbe registers the real-SQLite xSync interposer BEFORE the repository
// opens, so a later probe.fail=true makes an actual WAL sync fail.
func withSyncProbe(t *testing.T, out **authSyncProbe) setupOption {
	return func(c *setupConfig) {
		c.probe = installAuthSyncProbe(t)
		*out = c.probe
	}
}

type setupEnv struct {
	t       *testing.T
	dir     string
	key     *store.MasterKey
	cfg     setupConfig
	repo    *store.Repository
	db      *sql.DB
	clock   *testClock
	smtp    *smtpFixture
	l       *Lifecycle
	s       *Setup
	h       *SetupHTTP
	handler http.Handler
}

// newSetupEnv builds a REAL fresh SQLite installation (migrations applied, every
// control generation zero, quarantined) with real services, a real loopback TLS
// SMTP receiver and a deterministic clock. Nothing is pre-activated.
func newSetupEnv(t *testing.T, opts ...setupOption) *setupEnv {
	t.Helper()
	cfg := setupConfig{mail: true}
	for _, o := range opts {
		o(&cfg)
	}
	key, err := store.LoadMasterKey(strings.Repeat("22", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	e := &setupEnv{t: t, dir: filepath.Join(t.TempDir(), "data"), key: key, cfg: cfg, clock: &testClock{now: time.Unix(sessionBaseTime, 0)}}
	if cfg.mail {
		e.smtp = receiver(t, "implicit", "", false, false)
	}
	e.open(false)
	return e
}

// open (re)opens the installation: existing=true models a process restart.
func (e *setupEnv) open(existing bool) {
	e.t.Helper()
	repo, err := store.Open(e.t.Context(), store.Options{DataDir: e.dir, MasterKey: e.key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
	if err != nil {
		e.t.Fatal(err)
	}
	e.repo = repo
	e.t.Cleanup(func() { _ = repo.Close() })
	if e.db == nil {
		db, err := sql.Open("sqlite", filepath.Join(e.dir, "mandatary.db"))
		if err != nil {
			e.t.Fatal(err)
		}
		e.t.Cleanup(func() { _ = db.Close() })
		e.db = db
	}
	e.l, e.s, e.h, e.handler = nil, nil, nil, nil
	if e.cfg.mail {
		l, err := NewLifecycle(repo, NoticeSettings{Origin: setupTestOrigin, Contact: "security@example.invalid", Sender: "notices@example.invalid", Relay: e.smtp.relay, Mode: "implicit", RootCAs: e.smtp.roots})
		if err != nil {
			e.t.Fatal(err)
		}
		l.now = e.clock.Now
		e.l = l
	}
	s, err := NewSetup(repo, e.l, SetupSettings{Origin: setupTestOrigin, Build: "test-build"})
	if err != nil {
		e.t.Fatal(err)
	}
	s.now = e.clock.Now
	e.s = s
	h, err := NewSetupHTTP(s)
	if err != nil {
		e.t.Fatal(err)
	}
	e.h, e.handler = h, h.Handler()
	_ = existing
}

// restart closes the handle and reopens the same installation from disk.
func (e *setupEnv) restart() {
	e.t.Helper()
	if err := e.repo.Close(); err != nil {
		e.t.Fatal(err)
	}
	e.open(true)
}

func (e *setupEnv) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(query, args...); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
}

func (e *setupEnv) scalar(query string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (e *setupEnv) text(query string, args ...any) string {
	e.t.Helper()
	var s sql.NullString
	if err := e.db.QueryRow(query, args...).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return s.String
}

func (e *setupEnv) ctx() context.Context { return e.t.Context() }

func (e *setupEnv) advance(d time.Duration) { e.clock.Advance(d) }

// ensure runs the first-start path and requires a fresh initial generation.
func (e *setupEnv) ensure() EnsureResult {
	e.t.Helper()
	r, err := e.s.EnsureInitial(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// reveal performs a host reveal on a fake terminal and returns the token shown.
func (e *setupEnv) reveal(purpose SetupPurpose, user string) string {
	e.t.Helper()
	term := &fakeTerminal{}
	if _, err := e.s.Reveal(e.ctx(), purpose, user, term); err != nil {
		e.t.Fatal(err)
	}
	token := term.token()
	if token == "" {
		e.t.Fatal("no token shown")
	}
	return token
}

// revealedSession issues (first start), reveals and exchanges: a live setup session.
func (e *setupEnv) revealedSession() SetupSession {
	e.t.Helper()
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	session, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	return session
}

var proofLine = regexp.MustCompile(`Address confirmation code: ([A-Z2-7]{26})`)

// lastProof returns the newest confirmation proof delivered to the receiver.
func (e *setupEnv) lastProof() string {
	e.t.Helper()
	messages := e.smtp.received()
	for i := len(messages) - 1; i >= 0; i-- {
		if m := proofLine.FindStringSubmatch(messages[i]); m != nil {
			return m[1]
		}
	}
	e.t.Fatal("no proof message delivered")
	return ""
}

type firstAdmin struct {
	session   SetupSession
	addresses []SetupAddress
	totp      Enrollment
}

// stage stages the account (two addresses) in a fresh live session.
func (e *setupEnv) stage() firstAdmin {
	e.t.Helper()
	session := e.revealedSession()
	addresses, err := e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"first@example.invalid", "second@example.invalid"}})
	if err != nil {
		e.t.Fatal(err)
	}
	return firstAdmin{session: session, addresses: addresses}
}

// confirmAddress proves control of one staged address through the real mail path.
func (e *setupEnv) confirmAddress(a firstAdmin, i int) {
	e.t.Helper()
	if err := e.s.SendAddressProof(e.ctx(), a.session.Secret(), a.addresses[i].ID); err != nil {
		e.t.Fatal(err)
	}
	if err := e.s.ConfirmAddress(e.ctx(), a.session.Secret(), a.addresses[i].ID, e.lastProof(), setupTestIP); err != nil {
		e.t.Fatal(err)
	}
}

// enrollTOTP begins and proves a real SHA256 TOTP factor.
func (e *setupEnv) enrollTOTP(a *firstAdmin) {
	e.t.Helper()
	en, err := e.s.BeginTOTP(e.ctx(), a.session.Secret(), "SHA256")
	if err != nil {
		e.t.Fatal(err)
	}
	a.totp = en
	if err = e.s.ConfirmTOTP(e.ctx(), a.session.Secret(), enrollmentCode(e.t, en, e.clock.Now()), setupTestIP); err != nil {
		e.t.Fatal(err)
	}
}

// firstAdmin runs the entire ceremony to the final commit.
func (e *setupEnv) firstAdmin() firstAdmin {
	e.t.Helper()
	a := e.stage()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err != nil {
		e.t.Fatal(err)
	}
	return a
}

// sessions builds the normal session service over the same lifecycle (the ordinary
// P1.08 path) so tests can prove a setup capability is not a session.
func (e *setupEnv) sessions() *Sessions {
	e.t.Helper()
	s, err := NewSessions(e.l, nil, DefaultSessionSettings())
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}
