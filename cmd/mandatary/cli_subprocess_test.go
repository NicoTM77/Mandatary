//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18.4 AUTH-09-L3: the host helper's exclusive one-time reveal is proven across REAL OS PROCESSES, not only goroutines of one process.
//
// Every child is this test binary re-executed with cliChildEnv set (TestMain dispatches it to cliChildMain). Each child runs the production runCLI
// against the same synthetic temporary installation (a real SQLite store and a throw-away master key file created by the test) with a terminal
// double that appends whatever it is asked to display to a per-child file. The children block on stdin until the parent releases all of them at
// once, so the contention is deterministic (no sleeps, no timing guesses). No real credential, controlling terminal or live helper is involved:
// the "secret" is a synthetic setup token that exists only in a temporary directory removed with the test.
var longToken = regexp.MustCompile(`[A-Z2-7]{40,}`)

const (
	cliChildEnv   = "MANDATARY_TEST_CLI_CHILD"
	cliChildDir   = "MANDATARY_TEST_CLI_DIR"
	cliChildKey   = "MANDATARY_TEST_CLI_KEY"
	cliChildShown = "MANDATARY_TEST_CLI_SHOWN"
	cliChildCrash = "MANDATARY_TEST_CLI_CRASH"
	crashExit     = 77
)

// fileTerminal stands in for the controlling terminal inside a child: Verify succeeds and every WriteSecret is appended to a file the parent reads.
type fileTerminal struct {
	path  string
	crash bool
}

func (f fileTerminal) Verify() error { return nil }
func (f fileTerminal) WriteSecret(_ context.Context, data []byte) error {
	file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(append(append([]byte(nil), data...), '\n'))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if f.crash {
		// The claimant dies right after the secret reached its terminal: nothing after this line (no release, no cleanup) runs in this process.
		os.Exit(crashExit)
	}
	return err
}

// cliChildMain is the body of one child process. It returns the exit code of the production CLI.
func cliChildMain() int {
	var gate [1]byte
	_, _ = io.ReadFull(os.Stdin, gate[:]) // released by the parent writing one byte (or by EOF)
	env := cliEnv{
		args: strings.Fields(os.Getenv(cliChildEnv)),
		getenv: func(k string) string {
			return map[string]string{"MANDATARY_DATA_DIR": os.Getenv(cliChildDir), "MANDATARY_MASTER_KEY_FILE": os.Getenv(cliChildKey)}[k]
		},
		stdout: os.Stdout, stderr: os.Stderr, euid: os.Geteuid(), egid: os.Getegid(),
		drop:     func(int, int) error { return nil },
		terminal: fileTerminal{path: os.Getenv(cliChildShown), crash: os.Getenv(cliChildCrash) != ""},
	}
	return runCLI(env)
}

type childResult struct {
	exit   int
	stdout string
	stderr string
	shown  []string // each token the child's terminal was asked to display
}

type childInstall struct {
	t        *testing.T
	root     string
	dir, key string
	runs     atomic.Int64
}

// newChildInstall creates a synthetic installation exactly as the server would have (a real store, owner = the test user, a throw-away key).
func newChildInstall(t *testing.T) *childInstall {
	t.Helper()
	root := t.TempDir()
	in := &childInstall{t: t, root: root, dir: filepath.Join(root, "data"), key: filepath.Join(root, "master.key")}
	if err := os.WriteFile(in.key, []byte(strings.Repeat("5a", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := store.LoadMasterKey("", in.key)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := store.Open(t.Context(), store.Options{DataDir: in.dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	return in
}

// start launches one child (not yet released) and returns it with its gate.
func (in *childInstall) start(name, args string, crash bool) (*exec.Cmd, io.WriteCloser, *bytes.Buffer, *bytes.Buffer, string) {
	in.t.Helper()
	// Every child has its own file: a name is reused across runs, so a counter keeps one run from reading another run's display.
	shown := filepath.Join(in.root, fmt.Sprintf("shown-%d-%s", in.runs.Add(1), name))
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	cmd.Env = append(os.Environ(), cliChildEnv+"="+args, cliChildDir+"="+in.dir, cliChildKey+"="+in.key, cliChildShown+"="+shown)
	if crash {
		cmd.Env = append(cmd.Env, cliChildCrash+"=1")
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	gate, err := cmd.StdinPipe()
	if err != nil {
		in.t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		in.t.Fatal(err)
	}
	return cmd, gate, &out, &errOut, shown
}

// runAll starts n children with the same arguments, releases them together, and waits for them with a bounded timeout.
func (in *childInstall) runAll(n int, args string, crash bool) []childResult {
	in.t.Helper()
	type running struct {
		cmd       *exec.Cmd
		gate      io.WriteCloser
		out, err  *bytes.Buffer
		shownPath string
	}
	procs := make([]running, n)
	for i := range procs {
		cmd, gate, out, errOut, shown := in.start(strconv.Itoa(i)+"-"+strings.ReplaceAll(args, " ", "_"), args, crash)
		procs[i] = running{cmd: cmd, gate: gate, out: out, err: errOut, shownPath: shown}
	}
	for _, p := range procs { // every child is alive and blocked on its gate before any is released
		_, _ = p.gate.Write([]byte{1})
		_ = p.gate.Close()
	}
	results := make([]childResult, n)
	var wg sync.WaitGroup
	for i, p := range procs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				_ = p.cmd.Wait() // the exit code is read from ProcessState below
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(60 * time.Second):
				_ = p.cmd.Process.Kill()
				<-done
				in.t.Errorf("child %d timed out", i)
			}
			res := childResult{exit: p.cmd.ProcessState.ExitCode(), stdout: p.out.String(), stderr: p.err.String()}
			// The production terminal protocol writes a banner, the token and a footer. What matters is how many TOKENS the process was asked to display.
			if raw, err := os.ReadFile(p.shownPath); err == nil {
				res.shown = append(res.shown, cliToken.FindAllString(string(raw), -1)...)
			}
			results[i] = res
		}()
	}
	wg.Wait()
	return results
}

// one runs a single child to completion.
func (in *childInstall) one(args string, crash bool) childResult {
	in.t.Helper()
	return in.runAll(1, args, crash)[0]
}

func tokenIn(lines []string) string {
	for _, line := range lines {
		if token := cliToken.FindString(line); token != "" {
			return strings.ReplaceAll(token, "-", "")
		}
	}
	return ""
}

func (in *childInstall) exchanges(token string) bool {
	in.t.Helper()
	key, err := store.LoadMasterKey("", in.key)
	if err != nil {
		in.t.Fatal(err)
	}
	repo, err := store.Open(in.t.Context(), store.Options{DataDir: in.dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		in.t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()
	service, err := auth.NewSetup(repo, nil, auth.SetupSettings{Build: buildIdentity()})
	if err != nil {
		in.t.Fatal(err)
	}
	_, err = service.Exchange(in.t.Context(), token, "192.0.2.9")
	return err == nil
}

func requireNoSecretOnStreams(t *testing.T, label string, secrets []string, results ...childResult) {
	t.Helper()
	for i, r := range results {
		combined := r.stdout + r.stderr
		if cliToken.MatchString(combined) || longToken.MatchString(combined) {
			t.Fatalf("%s: child %d printed a token-shaped value on stdout/stderr: %q", label, i, combined)
		}
		for _, secret := range secrets {
			if secret != "" && strings.Contains(combined, secret) {
				t.Fatalf("%s: child %d leaked the secret on stdout/stderr", label, i)
			}
		}
	}
}

func TestSubprocessContendersRevealTheOneTimeSetupTokenToExactlyOneProcess(t *testing.T) {
	in := newChildInstall(t)
	if r := in.one("setup rotate", false); r.exit != 0 || len(r.shown) != 0 {
		t.Fatalf("rotate: exit %d shown %d stderr %q", r.exit, len(r.shown), r.stderr)
	}
	const contenders = 8
	results := in.runAll(contenders, "setup reveal", false)
	var winner childResult
	winners, refused := 0, 0
	for i, r := range results {
		switch {
		case r.exit == 0 && len(r.shown) == 1 && tokenIn(r.shown) != "":
			winners++
			winner = r
		case r.exit != 0 && len(r.shown) == 0:
			refused++
		default:
			t.Fatalf("child %d is neither the single claimant nor a clean refusal: exit %d shown %d stderr %q", i, r.exit, len(r.shown), r.stderr)
		}
	}
	if winners != 1 || refused != contenders-1 {
		t.Fatalf("%d claimants and %d refusals among %d real processes; exactly one claimant is required", winners, refused, contenders)
	}
	token := tokenIn(winner.shown)
	requireNoSecretOnStreams(t, "contention", []string{token}, results...)
	if !in.exchanges(token) {
		t.Fatal("the one displayed token does not work: the claimant must have shown a usable generation")
	}
	// Normal release: once claimed, a later process still cannot reveal it again, and the refusal is the sanitized one.
	again := in.one("setup reveal", false)
	if again.exit == 0 || len(again.shown) != 0 || !strings.Contains(again.stderr, "reveal refused") {
		t.Fatalf("a later process revealed or mis-reported an already claimed generation: exit %d shown %d stderr %q", again.exit, len(again.shown), again.stderr)
	}
}

func TestSubprocessClaimantThatDiesAfterDisplayLeavesNothingToReplayAndRotationRecovers(t *testing.T) {
	in := newChildInstall(t)
	if r := in.one("setup rotate", false); r.exit != 0 {
		t.Fatalf("rotate: %d %q", r.exit, r.stderr)
	}
	// The first process displays the secret and is killed by its own exit before it could release or clean anything up.
	crashed := in.one("setup reveal", true)
	if crashed.exit != crashExit || len(crashed.shown) != 1 || tokenIn(crashed.shown) == "" {
		t.Fatalf("the crash scenario did not happen as designed: exit %d shown %d", crashed.exit, len(crashed.shown))
	}
	first := tokenIn(crashed.shown)
	// Restart: a fresh process must not be able to display it again (no double output), whatever state the dead claimant left behind.
	for i := range 3 {
		restarted := in.one("setup reveal", false)
		if restarted.exit == 0 || len(restarted.shown) != 0 {
			t.Fatalf("restart %d revealed a generation the dead claimant already displayed: exit %d shown %d", i, restarted.exit, len(restarted.shown))
		}
		requireNoSecretOnStreams(t, "restart", []string{first}, restarted)
	}
	// The documented recovery is to rotate: a new generation is issued and shown once to exactly one new process; the old token is superseded.
	if r := in.one("setup rotate", false); r.exit != 0 || len(r.shown) != 0 {
		t.Fatalf("rotate after the crash: %d %q", r.exit, r.stderr)
	}
	results := in.runAll(4, "setup reveal", false)
	shown := 0
	var second string
	for _, r := range results {
		if len(r.shown) > 1 {
			t.Fatal("a process displayed the secret more than once")
		}
		if len(r.shown) == 1 {
			shown++
			second = tokenIn(r.shown)
		}
	}
	if shown != 1 || second == "" || second == first {
		t.Fatalf("after rotation exactly one process must show one new token (shown=%d, same as before=%v)", shown, second == first)
	}
	if !in.exchanges(second) {
		t.Fatal("the rotated token does not work")
	}
	if in.exchanges(first) {
		t.Fatal("the superseded token from the dead claimant still works")
	}
	requireNoSecretOnStreams(t, "rotate", []string{first, second}, results...)
}

func TestSubprocessConcurrentRotateAndRevealNeverShowTwiceAndTheInstallationStaysUsable(t *testing.T) {
	in := newChildInstall(t)
	if r := in.one("setup rotate", false); r.exit != 0 {
		t.Fatal(r.stderr)
	}
	// Rotations and reveals race as separate processes against the same store. Whatever interleaving happens: no process displays more than once, no
	// generation is displayed to two processes, every displayed value is a well-formed setup token and no stream carries a secret.
	jobs := []string{"setup rotate", "setup reveal", "setup rotate", "setup reveal", "setup reveal", "setup rotate"}
	var wg sync.WaitGroup
	results := make([]childResult, len(jobs))
	started := make(chan struct{})
	for i, args := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-started
			results[i] = in.one(args, false)
		}()
	}
	close(started)
	wg.Wait()
	seen := map[string]bool{}
	var tokens []string
	for i, r := range results {
		if len(r.shown) > 1 {
			t.Fatalf("job %d (%s) displayed %d secrets", i, jobs[i], len(r.shown))
		}
		if len(r.shown) == 1 {
			token := tokenIn(r.shown)
			if token == "" {
				t.Fatalf("job %d displayed something that is not a setup token", i)
			}
			if seen[token] {
				t.Fatal("the same generation was displayed to two processes")
			}
			seen[token] = true
			tokens = append(tokens, token)
		}
	}
	requireNoSecretOnStreams(t, "race", tokens, results...)
	// Normal operation afterwards: a fresh rotation and a single reveal still produce one working token, and the race left nothing locked.
	if r := in.one("setup rotate", false); r.exit != 0 {
		t.Fatalf("rotate after the race: %d %q", r.exit, r.stderr)
	}
	after := in.runAll(3, "setup reveal", false)
	shown := 0
	var token string
	for _, r := range after {
		if len(r.shown) == 1 {
			shown++
			token = tokenIn(r.shown)
		}
	}
	if shown != 1 || !in.exchanges(token) {
		t.Fatalf("after the race exactly one process must display one working token (shown=%d)", shown)
	}
	for _, old := range tokens {
		if old == token {
			t.Fatal("a generation displayed before the final rotation was displayed again")
		}
	}
}
