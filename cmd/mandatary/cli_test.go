package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/store"
)

type cliTerminal struct {
	mu        sync.Mutex
	verifyErr error
	out       bytes.Buffer
	writes    int
}

func (c *cliTerminal) Verify() error { return c.verifyErr }
func (c *cliTerminal) WriteSecret(_ context.Context, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.out.Write(data)
	return nil
}

var cliToken = regexp.MustCompile(`([A-Z2-7]{4}-){12}[A-Z2-7]{4}`)

func (c *cliTerminal) token() string {
	return strings.ReplaceAll(cliToken.FindString(c.out.String()), "-", "")
}

type cliFixture struct {
	t        *testing.T
	dir, key string
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	term     *cliTerminal
	dropped  [][2]int
	euid     int
	dropErr  error
}

// newCLIFixture creates a REAL existing store (as the server would have) so the
// helper's "existing store only" guarantee is exercised against real files.
func newCLIFixture(t *testing.T) *cliFixture {
	t.Helper()
	root := t.TempDir()
	f := &cliFixture{t: t, dir: filepath.Join(root, "data"), key: filepath.Join(root, "master.key"), term: &cliTerminal{}, euid: os.Geteuid()}
	hex := strings.Repeat("3c", 32)
	if err := os.WriteFile(f.key, []byte(hex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := store.LoadMasterKey("", f.key)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := store.Open(t.Context(), store.Options{DataDir: f.dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *cliFixture) run(args ...string) int {
	f.t.Helper()
	f.stdout.Reset()
	f.stderr.Reset()
	e := cliEnv{
		args: args,
		getenv: func(k string) string {
			return map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key}[k]
		},
		stdout: &f.stdout, stderr: &f.stderr, euid: f.euid, egid: os.Getegid(),
		drop:     func(uid, gid int) error { f.dropped = append(f.dropped, [2]int{uid, gid}); return f.dropErr },
		terminal: f.term,
	}
	return runCLI(e)
}

func (f *cliFixture) requireNoTokenInOutput() {
	f.t.Helper()
	if cliToken.MatchString(f.stdout.String()+f.stderr.String()) || regexp.MustCompile(`[A-Z2-7]{40,}`).MatchString(f.stdout.String()+f.stderr.String()) {
		f.t.Fatalf("a token-shaped value reached stdout/stderr: %q %q", f.stdout.String(), f.stderr.String())
	}
}

func TestCLIUsageAndRefusals(t *testing.T) {
	f := newCLIFixture(t)
	for name, args := range map[string][]string{
		"no arguments":          {},
		"unknown group":         {"admin", "create"},
		"unknown command":       {"setup", "create-admin"},
		"extra argument":        {"setup", "status", "extra"},
		"password as flag":      {"setup", "status", "--password", "x"},
		"token as flag":         {"setup", "reveal", "--token", "x"},
		"recovery without user": {"recovery", "reveal"},
	} {
		if code := f.run(args...); code != 2 {
			t.Fatalf("%s: exit %d", name, code)
		}
	}
	// restore-admin names no account, is never combined with the MFA-reset flags, and its reveal names no user.
	for name, args := range map[string][]string{
		"restore-admin with a user":         {"recovery", "restore-admin", "--user", "x", "--acknowledge-restore-recovery"},
		"restore-admin with replace":        {"recovery", "restore-admin", "--replace-password", "--acknowledge-restore-recovery"},
		"restore-admin with the MFA flag":   {"recovery", "restore-admin", "--acknowledge-all-factors-lost-risk"},
		"reveal of both purposes":           {"recovery", "reveal", "--user", "x", "--restore-admin"},
		"reveal restore-admin with replace": {"recovery", "reveal", "--restore-admin", "--replace-password"},
		"reset-mfa as restore-admin":        {"recovery", "reset-mfa", "--restore-admin", "--user", "x", "--acknowledge-all-factors-lost-risk"},
	} {
		if code := f.run(args...); code != 2 {
			t.Fatalf("%s: exit %d", name, code)
		}
	}
	if code := f.run("recovery", "restore-admin"); code != 1 || !strings.Contains(f.stderr.String(), "acknowledge-restore-recovery") {
		t.Fatalf("restore-admin without the acknowledgement: %d %q", code, f.stderr.String())
	}
	// A fresh installation was never restored: there is nothing to recover and nothing is issued.
	if code := f.run("recovery", "restore-admin", "--acknowledge-restore-recovery"); code != 1 || !strings.Contains(f.stderr.String(), "refused") {
		t.Fatalf("restore-admin on an installation that was never restored: %d %q", code, f.stderr.String())
	}
	if code := f.run("recovery", "reveal", "--restore-admin"); code != 1 || f.term.writes != 0 {
		t.Fatalf("reveal with no generation: %d", code)
	}
	if code := f.run("recovery", "reset-mfa", "--user", "someone"); code != 1 || !strings.Contains(f.stderr.String(), "acknowledge-all-factors-lost-risk") {
		t.Fatalf("reset-mfa without acknowledgement: %d %q", code, f.stderr.String())
	}
}

// S3.1b step 2: identity handling. Root must name a numeric service identity and
// is dropped BEFORE any key/data/reveal access; no UID/GID 0 is ever accepted.
func TestCLIIdentityHandling(t *testing.T) {
	f := newCLIFixture(t)
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 || gid == 0 {
		t.Fatal("this identity test must run unprivileged: UID/GID 0 is never a valid service identity")
	}
	f.euid = 0
	if code := f.run("setup", "status"); code != 1 || len(f.dropped) != 0 {
		t.Fatalf("root without explicit identity: %d, drops %v", code, f.dropped)
	}
	for _, args := range [][]string{{"--uid", "0", "--gid", "0"}, {"--uid", "1000"}, {"--gid", "1000"}, {"--uid", "-1", "--gid", "5"}, {"--uid", "abc", "--gid", "5"}} {
		if code := f.run(append([]string{"setup", "status"}, args...)...); code == 0 || len(f.dropped) != 0 {
			t.Fatalf("root with %v accepted (drops %v)", args, f.dropped)
		}
	}
	f.dropErr = errors.New("setgid failed")
	if code := f.run("setup", "status", "--uid", strconv.Itoa(uid), "--gid", strconv.Itoa(gid)); code != 1 {
		t.Fatal("a failed privilege drop continued")
	}
	if strings.Contains(f.stderr.String(), "setgid failed") {
		t.Fatal("internal error text reached the operator output")
	}
	f.dropErr = nil
	f.dropped = nil
	if code := f.run("setup", "status", "--uid", strconv.Itoa(uid), "--gid", strconv.Itoa(gid)); code != 0 || len(f.dropped) != 1 || f.dropped[0] != [2]int{uid, gid} {
		t.Fatalf("root with explicit identity: %d %v %q", code, f.dropped, f.stderr.String())
	}
	// Non-root: may only name its own identity; nothing is dropped.
	f.euid, f.dropped = uid, nil
	if code := f.run("setup", "status", "--uid", strconv.Itoa(uid+1)); code == 0 {
		t.Fatal("non-root named a different identity")
	}
	if code := f.run("setup", "status"); code != 0 || len(f.dropped) != 0 {
		t.Fatalf("non-root own identity: %d %v", code, f.dropped)
	}
	f.euid = 0 // a non-root process can never be treated as root-without-drop
}

func TestCLIRefusesMissingOrUnsafeKeyAndStore(t *testing.T) {
	f := newCLIFixture(t)
	good := f.key
	f.key = ""
	if code := f.run("setup", "status"); code != 1 {
		t.Fatal("no key file accepted")
	}
	f.key = good
	if err := os.Chmod(good, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := f.run("setup", "status"); code != 1 {
		t.Fatal("group/world-readable key file accepted")
	}
	if err := os.Chmod(good, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := f.dir
	f.dir = filepath.Join(filepath.Dir(f.dir), "does-not-exist")
	if code := f.run("setup", "status"); code != 1 {
		t.Fatal("missing data directory accepted")
	}
	if _, err := os.Lstat(f.dir); !os.IsNotExist(err) {
		t.Fatal("the helper CREATED a data directory")
	}
	f.dir = missing
	if err := os.Remove(filepath.Join(f.dir, "mandatary.db")); err != nil {
		t.Fatal(err)
	}
	if code := f.run("setup", "status"); code != 1 {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Lstat(filepath.Join(f.dir, "mandatary.db")); !os.IsNotExist(err) {
		t.Fatal("the helper CREATED a database")
	}
	if strings.Contains(f.stderr.String(), f.dir) || strings.Contains(f.stderr.String(), good) {
		t.Fatal("a path was echoed")
	}
}

// The full host protocol through the CLI: rotate issues without printing, reveal
// prints ONLY to the verified terminal, and the status never carries a secret.
func TestCLIIssueRevealStatusProtocol(t *testing.T) {
	f := newCLIFixture(t)
	if code := f.run("setup", "status"); code != 0 || !strings.Contains(f.stdout.String(), "setup eligible: true") {
		t.Fatalf("status: %d %q %q", code, f.stdout.String(), f.stderr.String())
	}
	if code := f.run("setup", "rotate"); code != 0 {
		t.Fatalf("rotate: %d %q", code, f.stderr.String())
	}
	f.requireNoTokenInOutput()
	if f.term.writes != 0 {
		t.Fatal("issue wrote a secret")
	}
	// A pipe/file/other terminal (Verify fails): nothing consumed, nothing shown.
	f.term.verifyErr = errors.New("not a controlling terminal")
	if code := f.run("setup", "reveal"); code != 1 || f.term.writes != 0 {
		t.Fatalf("reveal on an unverified terminal: %d writes=%d", code, f.term.writes)
	}
	f.requireNoTokenInOutput()
	f.term.verifyErr = nil
	if code := f.run("setup", "reveal"); code != 0 {
		t.Fatalf("reveal: %d %q", code, f.stderr.String())
	}
	token := f.term.token()
	if token == "" {
		t.Fatal("the verified terminal did not receive the token")
	}
	if strings.Contains(f.stdout.String(), token) || strings.Contains(f.stderr.String(), token) {
		t.Fatal("token reached stdout/stderr rather than only the terminal channel")
	}
	f.requireNoTokenInOutput()
	if code := f.run("setup", "reveal"); code != 1 {
		t.Fatal("token revealed twice")
	}
	if code := f.run("setup", "status"); code != 0 || !strings.Contains(f.stdout.String(), "state retrieved") {
		t.Fatalf("status after reveal: %q", f.stdout.String())
	}
	f.requireNoTokenInOutput()
	// The token is usable by the service over the same store.
	key, _ := store.LoadMasterKey("", f.key)
	repo, err := store.Open(t.Context(), store.Options{DataDir: f.dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()
	service, err := auth.NewSetup(repo, nil, auth.SetupSettings{Build: buildIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Exchange(t.Context(), token, "192.0.2.5"); err != nil {
		t.Fatalf("the CLI-issued token did not exchange: %v", err)
	}
	// An helper from a different build cannot reveal what this build issued.
	other, err := auth.NewSetup(repo, nil, auth.SetupSettings{Build: "rev:some-other-build"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Issue(t.Context(), auth.IssueRequest{Purpose: auth.PurposeInitialSetup}); err != nil {
		t.Fatal(err)
	}
	term := &cliTerminal{}
	if _, err = service.Reveal(t.Context(), auth.PurposeInitialSetup, "", term); err == nil || term.writes != 0 {
		t.Fatal("a helper from a different build revealed a generation it did not issue")
	}
}

// A concurrent second helper cannot reveal the same generation.
func TestCLIConcurrentRevealDeliversOnce(t *testing.T) {
	f := newCLIFixture(t)
	if code := f.run("setup", "rotate"); code != 0 {
		t.Fatal(code)
	}
	var wg sync.WaitGroup
	terminals := make([]*cliTerminal, 4)
	codes := make([]int, 4)
	for i := range terminals {
		terminals[i] = &cliTerminal{}
	}
	for i := range terminals {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out, errOut bytes.Buffer
			codes[i] = runCLI(cliEnv{
				args: []string{"setup", "reveal"},
				getenv: func(k string) string {
					return map[string]string{"MANDATARY_DATA_DIR": f.dir, "MANDATARY_MASTER_KEY_FILE": f.key}[k]
				},
				stdout: &out, stderr: &errOut, euid: os.Geteuid(), egid: os.Getegid(), drop: func(int, int) error { return nil }, terminal: terminals[i],
			})
		}()
	}
	wg.Wait()
	shown := 0
	for _, term := range terminals {
		if term.token() != "" {
			shown++
		}
	}
	if shown != 1 {
		t.Fatalf("%d helpers displayed the token (exit codes %v)", shown, codes)
	}
}
