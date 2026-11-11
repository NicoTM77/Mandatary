package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var errInjected = errors.New("injected crash")

func failAt(step string) func(string) error {
	return func(s string) error {
		if s == step {
			return errInjected
		}
		return nil
	}
}

// S3.1a crash matrix. A crash at ANY protocol step leaves a state from which the
// next process start is conservative: the secret is never shown twice, no
// plaintext survives reconciliation, and no token is minted automatically.
func TestRevealCrashMatrix(t *testing.T) {
	for _, c := range []struct {
		step         string
		wantShown    bool // the human may already have seen it (uncertain receipt)
		revealableAt string
	}{
		{"reveal:before-claim", false, "available"},
		{"reveal:after-claim", false, ""},
		{"reveal:before-output", false, ""},
		{"reveal:after-output", true, ""},
		{"reveal:after-unlink", true, ""},
	} {
		t.Run(c.step, func(t *testing.T) {
			e := newSetupEnv(t)
			e.ensure()
			e.s.hook = failAt(c.step)
			term := &fakeTerminal{}
			if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err == nil {
				t.Fatal("injected crash was not surfaced")
			}
			if (term.token() != "") != c.wantShown {
				t.Fatalf("shown=%v want %v", term.token() != "", c.wantShown)
			}
			e.restart() // the crashed process is gone; a new one reconciles at startup
			if r := e.ensure(); c.revealableAt == "available" && r.Outcome != "active" || c.revealableAt == "" && r.Outcome != "rotation_required" {
				t.Fatalf("startup outcome %q", r.Outcome)
			}
			// Nothing was minted by the restart.
			if e.scalar(`SELECT count(*) FROM setup_tokens`) != 1 {
				t.Fatal("restart minted a token")
			}
			names, _ := e.repo.RevealFileNames()
			if c.revealableAt == "" && len(names) != 0 {
				t.Fatal("plaintext survived reconciliation of a non-revealable generation")
			}
			second := &fakeTerminal{}
			_, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", second)
			if c.revealableAt == "available" {
				if err != nil || second.token() == "" {
					t.Fatal("a crash before the claim must not cost the operator the token")
				}
				return
			}
			if err == nil || second.token() != "" {
				t.Fatal("a claimed generation was revealed after a crash")
			}
		})
	}
}

// A crash between exchange commit and file removal can never expose the secret
// again: the token is already consumed, and the leftover file is removed.
func TestExchangeCrashLeavesNoUsableTokenOrPlaintext(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	e.s.hook = failAt("exchange:after-commit")
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("injected crash not surfaced")
	}
	e.restart()
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("token usable twice across a crash")
	}
	if names, _ := e.repo.RevealFileNames(); len(names) != 0 {
		t.Fatal("plaintext remains")
	}
}

// issue:before-file / after-file: a half-issued generation is never revealable.
func TestIssueCrashMatrix(t *testing.T) {
	for _, step := range []string{"issue:before-file", "issue:after-file"} {
		t.Run(step, func(t *testing.T) {
			e := newSetupEnv(t)
			e.s.hook = failAt(step)
			if _, err := e.s.EnsureInitial(e.ctx()); err == nil {
				t.Fatal("injected crash not surfaced")
			}
			e.restart()
			if r := e.ensure(); r.Outcome != "rotation_required" {
				t.Fatalf("restart after a crashed issuance: %q", r.Outcome)
			}
			term := &fakeTerminal{}
			if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err == nil || term.token() != "" {
				t.Fatal("a half-issued generation was revealed")
			}
			if names, _ := e.repo.RevealFileNames(); len(names) != 0 {
				t.Fatal("plaintext of a half-issued generation survived")
			}
			// Explicit host rotation recovers.
			if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err != nil {
				t.Fatal(err)
			}
			e.reveal(PurposeInitialSetup, "")
		})
	}
}

// complete:after-commit: the commit is durable, so the setup is final; a crash
// afterwards cannot reopen it.
func TestCompleteCrashAfterCommitStaysCompleted(t *testing.T) {
	e := newSetupEnv(t)
	a := e.stage()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	e.s.hook = failAt("complete:after-commit")
	_, _ = e.s.Complete(e.ctx(), a.session.Secret())
	e.restart()
	if r := e.ensure(); r.Outcome != "ineligible" {
		t.Fatalf("restart after a committed first administrator: %q", r.Outcome)
	}
	if e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 1 {
		t.Fatal("the committed administrator is missing")
	}
}

// Real SQLite xSync failures: no state transition may be acknowledged that did not
// reach durable storage (SETUP-07 / durability). Exercises the actual WAL commit.
func TestSetupSQLiteSyncFailureIsFailClosed(t *testing.T) {
	for _, operation := range []string{"issue", "reveal", "exchange"} {
		t.Run(operation, func(t *testing.T) {
			var probe *authSyncProbe
			e := newSetupEnv(t, withSyncProbe(t, &probe))
			if operation != "issue" {
				e.ensure()
			}
			var token string
			if operation == "exchange" {
				token = e.reveal(PurposeInitialSetup, "")
			}
			probe.mu.Lock()
			probe.fail = true
			probe.mu.Unlock()
			var err error
			term := &fakeTerminal{}
			switch operation {
			case "issue":
				_, err = e.s.EnsureInitial(e.ctx())
			case "reveal":
				_, err = e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term)
			case "exchange":
				_, err = e.s.Exchange(e.ctx(), token, setupTestIP)
			}
			probe.mu.Lock()
			failed := probe.failed
			probe.fail = false
			probe.mu.Unlock()
			if err == nil {
				t.Fatal("a failed sync was acknowledged")
			}
			if failed == 0 {
				t.Fatal("no actual SQLite xSync failure was injected")
			}
			if operation == "reveal" && term.token() != "" {
				t.Fatal("the secret was displayed although the claim never became durable")
			}
			// The handle is poisoned: nothing further is accepted in this process.
			if _, err = e.s.Exchange(e.ctx(), "A", setupTestIP); err == nil {
				t.Fatal("handle continued after a failed durable write")
			}
			e.restart()
			if _, err = e.s.Reconcile(e.ctx()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// SETUP-05: an unsafe reveal directory consumes nothing and reveals nothing.
func TestUnsafeRevealLayoutFailsClosed(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string, name string){
		"file mode too open": func(t *testing.T, dir, name string) {
			if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"file replaced by symlink": func(t *testing.T, dir, name string) {
			target := filepath.Join(dir, "elsewhere")
			if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked file": func(t *testing.T, dir, name string) {
			if err := os.Link(filepath.Join(dir, name), filepath.Join(dir, "initial_setup-9.token")); err != nil {
				t.Fatal(err)
			}
		},
		"directory mode too open": func(t *testing.T, dir, name string) {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newSetupEnv(t)
			e.ensure()
			dir := filepath.Join(e.dir, "reveal")
			names, _ := e.repo.RevealFileNames()
			mutate(t, dir, names[0])
			term := &fakeTerminal{}
			if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err == nil || term.token() != "" || term.writes != 0 {
				t.Fatal("an unsafe reveal layout produced output")
			}
			if st := e.text(`SELECT state FROM setup_tokens`); st != "available" && st != "claimed" {
				t.Fatalf("state %q", st)
			}
		})
	}
}

// A planted, forged or stale file can never be revealed: it must match the stored
// digest, generation and purpose.
func TestForgedRevealFileIsNeverShown(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	names, _ := e.repo.RevealFileNames()
	p := filepath.Join(e.dir, "reveal", names[0])
	forged := revealContent(1, PurposeInitialSetup, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err := os.WriteFile(p, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	term := &fakeTerminal{}
	if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err == nil || term.token() != "" || term.writes != 0 {
		t.Fatal("a file that does not match the stored digest was shown")
	}
	if names, _ = e.repo.RevealFileNames(); len(names) != 0 {
		t.Fatal("forged plaintext survived")
	}
}
