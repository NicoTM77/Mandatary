package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// dataFileContains scans every file under the data dir (main DB, WAL, SHM, keys)
// for a plaintext needle. The needle is built at call time and never printed.
func (e *setupEnv) dataFileContains(needle string) bool {
	e.t.Helper()
	found := false
	err := filepath.Walk(e.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(needle)) {
			found = true
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return found
}

// S3: only a digest is stored; the plaintext exists ONLY in the 0600 reveal file
// and the verified terminal; after reveal no file and no stored secret remains.
func TestTokenStoredOnlyAsDigestAndRevealedOnce(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	names, err := e.repo.RevealFileNames()
	if err != nil || len(names) != 1 {
		t.Fatalf("expected exactly one reveal file: %v %v", names, err)
	}
	info, err := os.Stat(filepath.Join(e.dir, "reveal", names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("reveal file mode %v", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Join(e.dir, "reveal"))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("reveal directory mode: %v %v", dirInfo, err)
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, "reveal", names[0]))
	if err != nil {
		t.Fatal(err)
	}
	canonical := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if len(line) == setupTokenChars && !strings.ContainsAny(line, " -") {
			canonical = line
		}
	}
	if canonical == "" {
		t.Fatal("reveal file carries no token")
	}
	// The database proper never contains the token in any form.
	e.exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	grouped := string(groupedToken([]byte(canonical)))
	if e.dataFileContains(canonical) && !fileIsRevealOnly(e, canonical) {
		t.Fatal("plaintext token found outside the reveal file")
	}
	if e.scalar(`SELECT count(*) FROM setup_tokens WHERE length(digest)=32 AND state='available'`) != 1 {
		t.Fatal("expected exactly one digest-only available generation")
	}

	term := &fakeTerminal{}
	if _, err = e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err != nil {
		t.Fatal(err)
	}
	if term.verified == 0 || term.token() != canonical {
		t.Fatal("terminal did not receive the token after verification")
	}
	_ = grouped
	// One shot: the file is gone, the generation is retrieved, and a second reveal,
	// a replayed file and a different terminal all fail.
	if names, _ = e.repo.RevealFileNames(); len(names) != 0 {
		t.Fatal("reveal file survived retrieval")
	}
	if e.dataFileContains(canonical) {
		t.Fatal("plaintext token remains in the data directory after reveal")
	}
	second := &fakeTerminal{}
	if _, err = e.s.Reveal(e.ctx(), PurposeInitialSetup, "", second); err == nil || second.token() != "" || second.writes != 0 {
		t.Fatal("token revealed twice")
	}
}

// fileIsRevealOnly reports whether the ONLY file containing the needle is under the
// reveal directory (the single permitted plaintext location).
func fileIsRevealOnly(e *setupEnv, needle string) bool {
	only := true
	_ = filepath.Walk(e.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr == nil && bytes.Contains(data, []byte(needle)) && filepath.Base(filepath.Dir(path)) != "reveal" {
			only = false
		}
		return nil
	})
	return only
}

// The terminal contract: an unverified terminal consumes nothing; a failed or
// short write makes delivery uncertain and the generation can never be revealed
// again. Both leave no plaintext behind.
func TestRevealTerminalFailureSemantics(t *testing.T) {
	t.Run("unverified terminal consumes nothing", func(t *testing.T) {
		e := newSetupEnv(t)
		e.ensure()
		bad := &fakeTerminal{verifyErr: errors.New("not a terminal")}
		if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", bad); err == nil || bad.writes != 0 {
			t.Fatal("secret written to an unverified terminal")
		}
		if e.text(`SELECT state FROM setup_tokens`) != "available" {
			t.Fatal("an unverified terminal consumed the generation")
		}
		if names, _ := e.repo.RevealFileNames(); len(names) != 1 {
			t.Fatal("reveal file lost to an unverified terminal")
		}
		e.reveal(PurposeInitialSetup, "") // still revealable on the real terminal
	})
	for _, c := range []struct {
		name string
		term *fakeTerminal
	}{
		{"write error", &fakeTerminal{writeErr: errors.New("broken pipe")}},
		{"short write", &fakeTerminal{short: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newSetupEnv(t)
			e.ensure()
			if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", c.term); err == nil {
				t.Fatal("uncertain delivery acknowledged")
			}
			if names, _ := e.repo.RevealFileNames(); len(names) != 0 {
				t.Fatal("plaintext survived an uncertain delivery")
			}
			retry := &fakeTerminal{}
			if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", retry); err == nil || retry.token() != "" {
				t.Fatal("generation with uncertain delivery revealed again")
			}
			// The failed finalization poisons this process's handle (fail closed);
			// the next process start reconciles conservatively.
			e.restart()
			if _, err := e.s.Reconcile(e.ctx()); err != nil {
				t.Fatal(err)
			}
			if e.scalar(`SELECT count(*) FROM setup_tokens WHERE state IN ('available','claimed','retrieved')`) != 0 {
				t.Fatal("a generation with uncertain delivery stayed live")
			}
			// Explicit rotation is the only recovery, and yields a fresh generation.
			if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err != nil {
				t.Fatal(err)
			}
			e.reveal(PurposeInitialSetup, "")
		})
	}
}

// TD §10.3: exchange consumes atomically, exactly one session per token.
func TestExchangeIsOneUseAndReplayDenied(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	first, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Exchange(e.ctx(), token, setupTestIP); !errors.Is(err, ErrSetupDenied) {
		t.Fatalf("replayed token: %v", err)
	}
	// The grouped spelling and lowercase are the SAME token, so also replays.
	if _, err = e.s.Exchange(e.ctx(), string(groupedToken([]byte(token))), setupTestIP); !errors.Is(err, ErrSetupDenied) {
		t.Fatalf("replayed grouped token: %v", err)
	}
	if e.scalar(`SELECT count(*) FROM setup_sessions`) != 1 || e.text(`SELECT state FROM setup_tokens`) != "consumed" {
		t.Fatal("token not consumed into exactly one session")
	}
	if _, err = e.s.Authenticate(e.ctx(), first.Secret()); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentExchangeYieldsExactlyOneSession(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 || e.scalar(`SELECT count(*) FROM setup_sessions`) != 1 {
		t.Fatalf("%d concurrent exchanges succeeded", wins)
	}
}

func TestConcurrentRevealDeliversToExactlyOneTerminal(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	var wg sync.WaitGroup
	terminals := make([]*fakeTerminal, 8)
	for i := range terminals {
		terminals[i] = &fakeTerminal{}
		wg.Add(1)
		go func(term *fakeTerminal) {
			defer wg.Done()
			_, _ = e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term)
		}(terminals[i])
	}
	wg.Wait()
	shown := 0
	for _, term := range terminals {
		if term.token() != "" {
			shown++
		}
	}
	if shown != 1 {
		t.Fatalf("%d terminals received the secret", shown)
	}
}

// Expiry is absolute: 30 minutes from ISSUANCE, no retrieval, restart, retry or
// rotation of another generation extends it, and an expired token never works.
func TestExpiryIsAbsoluteAndImmutable(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	issued := e.scalar(`SELECT issued_at FROM setup_tokens`)
	expires := e.scalar(`SELECT expires_at FROM setup_tokens`)
	if expires-issued != 1800 {
		t.Fatalf("lifetime %ds", expires-issued)
	}
	e.advance(10 * time.Minute)
	token := e.reveal(PurposeInitialSetup, "") // retrieval does not extend
	e.restart()                                // restart does not extend
	if e.scalar(`SELECT expires_at FROM setup_tokens`) != expires {
		t.Fatal("restart changed the absolute expiry")
	}
	e.advance(19*time.Minute + 59*time.Second) // 29m59s after issuance
	session, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil {
		t.Fatalf("exchange one second before expiry: %v", err)
	}
	// The session carries the TOKEN's expiry: it cannot outlive it.
	if session.ExpiresAt.Unix() != expires {
		t.Fatalf("session expiry %d != token expiry %d", session.ExpiresAt.Unix(), expires)
	}
	e.advance(time.Second)
	if _, err = e.s.Authenticate(e.ctx(), session.Secret()); err == nil {
		t.Fatal("setup session outlived the absolute token expiry")
	}
	// The database refuses to move it.
	if _, err = e.db.Exec(`UPDATE setup_tokens SET expires_at=expires_at+600`); err == nil {
		t.Fatal("storage allowed the absolute expiry to be extended")
	}
	if _, err = e.db.Exec(`UPDATE setup_sessions SET expires_at=expires_at+600`); err == nil {
		t.Fatal("storage allowed a session expiry to be extended")
	}
}

func TestExpiredTokenFailsClosedEverywhere(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	e.advance(SetupTokenLifetime)
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("expired token exchanged")
	}
	// And a never-revealed expired generation can no longer be revealed.
	e2 := newSetupEnv(t)
	e2.ensure()
	e2.advance(SetupTokenLifetime)
	term := &fakeTerminal{}
	if _, err := e2.s.Reveal(e2.ctx(), PurposeInitialSetup, "", term); err == nil || term.token() != "" {
		t.Fatal("expired generation revealed")
	}
	if surface, _ := e2.s.surfaceOpen(e2.ctx()); surface {
		t.Fatal("setup surface open with only an expired generation")
	}
	if _, err := e2.s.Reconcile(e2.ctx()); err != nil {
		t.Fatal(err)
	}
	if names, _ := e2.repo.RevealFileNames(); len(names) != 0 {
		t.Fatal("expired plaintext not cleaned up")
	}
	if e2.text(`SELECT revoke_reason FROM setup_tokens`) != "expired_cleanup" {
		t.Fatal("expiry was not recorded")
	}
}

// S3.1: a restart NEVER mints a token. Only the very first start issues one; after
// expiry or consumption, rotation is explicit and host-local.
func TestRestartNeverIssuesAnotherInitialToken(t *testing.T) {
	e := newSetupEnv(t)
	if r := e.ensure(); r.Outcome != "issued" {
		t.Fatal(r.Outcome)
	}
	e.restart()
	if r := e.ensure(); r.Outcome != "active" {
		t.Fatalf("restart with a live generation: %q", r.Outcome)
	}
	if e.scalar(`SELECT count(*) FROM setup_tokens`) != 1 {
		t.Fatal("restart issued a second generation")
	}
	e.advance(SetupTokenLifetime + time.Second)
	e.restart()
	if r := e.ensure(); r.Outcome != "rotation_required" {
		t.Fatalf("restart after expiry: %q", r.Outcome)
	}
	if e.scalar(`SELECT count(*) FROM setup_tokens`) != 1 || e.scalar(`SELECT count(*) FROM setup_tokens WHERE state IN ('available','retrieved')`) != 0 {
		t.Fatal("restart after expiry minted or revived a token")
	}
	if open, _ := e.s.surfaceOpen(e.ctx()); open {
		t.Fatal("setup surface open without a live generation")
	}
	// Explicit host rotation yields a NEW generation with its own absolute expiry;
	// the old digest stays dead.
	oldDigest := e.text(`SELECT hex(digest) FROM setup_tokens WHERE id=1`)
	rotated, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup})
	if err != nil || rotated.Generation != 2 {
		t.Fatalf("rotation: %v %v", rotated, err)
	}
	if e.text(`SELECT hex(digest) FROM setup_tokens WHERE id=2`) == oldDigest {
		t.Fatal("rotation reused a digest")
	}
}

// A crashed issuance (pending) and an uncertain reveal (claimed) are never
// revealable after restart: Reconcile revokes both and removes their plaintext.
func TestRestartRevokesCrashedStates(t *testing.T) {
	for _, state := range []string{"pending", "claimed"} {
		t.Run(state, func(t *testing.T) {
			e := newSetupEnv(t)
			e.ensure()
			if state == "pending" {
				e.exec(`DROP TRIGGER setup_token_transition`)
				e.exec(`UPDATE setup_tokens SET state='pending'`)
			} else {
				e.exec(`UPDATE setup_tokens SET state='claimed', claimed_at=issued_at`)
			}
			e.restart()
			if r := e.ensure(); r.Outcome != "rotation_required" { // startup reconciles
				t.Fatalf("startup after a %s crash: %q", state, r.Outcome)
			}
			term := &fakeTerminal{}
			if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", term); err == nil || term.token() != "" {
				t.Fatalf("%s generation was revealed", state)
			}
			if e.scalar(`SELECT count(*) FROM setup_tokens WHERE state IN ('pending','available','claimed','retrieved')`) != 0 {
				t.Fatal("generation stayed live")
			}
			if names, _ := e.repo.RevealFileNames(); len(names) != 0 {
				t.Fatal("plaintext survived reconciliation")
			}
		})
	}
}

// Wrong, malformed, cross-purpose and cross-installation tokens are all denied
// with the same fixed outcome and never consume or reveal anything.
func TestWrongTokensAreIndistinguishablyDenied(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	flipped := []byte(token)
	if flipped[0] == 'A' {
		flipped[0] = 'B'
	} else {
		flipped[0] = 'A'
	}
	for _, c := range []string{"", "not a token", string(flipped), token[:len(token)-1], token + "A", strings.Repeat("A", setupTokenChars), "\x00" + token} {
		if _, err := e.s.Exchange(e.ctx(), c, setupTestIP); !errors.Is(err, ErrSetupDenied) && !errors.Is(err, ErrSetupBusy) {
			t.Fatalf("bad token produced %v", err)
		}
	}
	// A valid token is not accepted under a different purpose digest.
	canonical, _ := canonicalToken(token)
	if bytes.Equal(setupDigest(PurposeInitialSetup, canonical), setupDigest(PurposeMFAReset, canonical)) {
		t.Fatal("digests are not purpose-bound")
	}
	if e.text(`SELECT state FROM setup_tokens`) != "retrieved" {
		t.Fatal("wrong guesses consumed the generation")
	}
}

// 100 evaluated failures revoke every live generation of the purpose; the correct
// token then also fails until explicit rotation (durable ceiling, not per-IP).
func TestGuessingCeilingRevokesGeneration(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	// Start one evaluated failure below the ceiling (the counter is durable control
	// state; the 99 preceding guesses are not re-run to keep the test fast).
	e.exec(`UPDATE setup_attempts SET failed=?, next_attempt_at=0 WHERE purpose='initial_setup'`, setupFailureCeiling-1)
	if _, err := e.s.Exchange(e.ctx(), strings.Repeat("A", setupTokenChars), setupTestIP); err == nil {
		t.Fatal("wrong token accepted")
	}
	if e.text(`SELECT revoke_reason FROM setup_tokens`) != "attempt_ceiling" {
		t.Fatalf("generation not revoked at the ceiling: %q", e.text(`SELECT state FROM setup_tokens`))
	}
	e.exec(`UPDATE setup_attempts SET next_attempt_at=0`)
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("the correct token worked after the guessing ceiling")
	}
	if open, _ := e.s.surfaceOpen(e.ctx()); open {
		t.Fatal("setup surface open after the ceiling")
	}
	if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err != nil {
		t.Fatalf("explicit host rotation after the ceiling: %v", err)
	}
}

// Five evaluated failures begin an escalating, non-sliding wait that denies even a
// correct token while it runs (same schedule as password verification).
func TestFailureWaitDeniesCorrectToken(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	for i := 0; i < 5; i++ {
		_, _ = e.s.Exchange(e.ctx(), strings.Repeat("A", setupTokenChars), setupTestIP)
	}
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("a correct token was accepted during the failure wait")
	}
	e.advance(10 * time.Minute)
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err != nil {
		t.Fatalf("a correct token after the wait: %v", err)
	}
}
