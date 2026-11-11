package auth

import (
	"os"
	"sync"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// second opens an independent handle on the SAME installation, modelling the host
// helper process running beside the service (separate Repository, separate
// Setup, shared control lock and database).
func (e *setupEnv) second(build string) *Setup {
	e.t.Helper()
	repo, err := store.Open(e.ctx(), store.Options{DataDir: e.dir, MasterKey: e.key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		e.t.Fatalf("second handle: %v", err)
	}
	e.t.Cleanup(func() { _ = repo.Close() })
	s, err := NewSetup(repo, nil, SetupSettings{Build: build})
	if err != nil {
		e.t.Fatal(err)
	}
	s.now = e.clock.Now
	return s
}

// A host helper handle and the service handle race to reveal and exchange the same
// generation: the shared control lock makes the token appear on exactly one
// terminal and yield exactly one session.
func TestHelperAndServiceRaceOnOneGeneration(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	helper := e.second("test-build")
	terminals := []*fakeTerminal{{}, {}, {}, {}}
	var wg sync.WaitGroup
	for i, term := range terminals {
		svc := e.s
		if i%2 == 1 {
			svc = helper
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Reveal(e.ctx(), PurposeInitialSetup, "", term)
		}()
	}
	wg.Wait()
	shown, token := 0, ""
	for _, term := range terminals {
		if tk := term.token(); tk != "" {
			shown++
			token = tk
		}
	}
	if shown != 1 {
		t.Fatalf("%d terminals received the token across two handles", shown)
	}
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		svc := e.s
		if i%2 == 1 {
			svc = helper
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Exchange(e.ctx(), token, setupTestIP); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 || e.scalar(`SELECT count(*) FROM setup_sessions`) != 1 {
		t.Fatalf("%d exchanges succeeded across two handles", wins)
	}
}

// Concurrent rotations from two handles leave exactly one live generation whose
// digest differs from every earlier one, and at most one plaintext file.
func TestConcurrentRotationLeavesOneLiveGeneration(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	helper := e.second("test-build")
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		svc := e.s
		if i%2 == 1 {
			svc = helper
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup})
		}()
	}
	wg.Wait()
	if n := e.scalar(`SELECT count(*) FROM setup_tokens WHERE state IN ('pending','available','claimed','retrieved')`); n != 1 {
		t.Fatalf("%d live generations", n)
	}
	if names, err := e.repo.RevealFileNames(); err != nil || len(names) != 1 {
		t.Fatalf("plaintext files: %v %v", names, err)
	}
	if e.scalar(`SELECT count(DISTINCT digest) FROM setup_tokens`) != e.scalar(`SELECT count(*) FROM setup_tokens`) {
		t.Fatal("a digest was reused")
	}
}

// S3.1b step 1: a helper from a different build refuses to reveal.
func TestHelperFromDifferentBuildCannotReveal(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	other := e.second("a-different-build")
	term := &fakeTerminal{}
	if _, err := other.Reveal(e.ctx(), PurposeInitialSetup, "", term); err == nil || term.token() != "" || term.writes != 0 {
		t.Fatal("a different build revealed the generation")
	}
	if e.text(`SELECT state FROM setup_tokens`) != "available" {
		t.Fatal("the refused helper consumed the generation")
	}
	// The issuing build still can.
	if tk := e.reveal(PurposeInitialSetup, ""); len(tk) != setupTokenChars {
		t.Fatal("issuing build cannot reveal")
	}
}
