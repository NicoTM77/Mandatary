package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/auth"
	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// openExisting opens the fixture's store the way the helper does: existing only, never created or migrated.
func (f *cliFixture) openExisting() *store.Repository {
	f.t.Helper()
	key, err := store.LoadMasterKey("", f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	repo, err := store.Open(f.t.Context(), store.Options{DataDir: f.dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = repo.Close() })
	return repo
}

// restoreHostSide performs what the trusted host operator's fresh-instance restore does to the store (S2.2.1): a real
// backup of this installation restored by the host initiator. It leaves the persisted RESTORE quarantine in force.
func (f *cliFixture) restoreHostSide() {
	f.t.Helper()
	repo := f.openExisting()
	svc, err := backup.New(repo, "test")
	if err != nil {
		f.t.Fatal(err)
	}
	allow := func(context.Context, *store.Queries, store.InstallationControl, int64) error { return nil }
	raw, _, err := svc.Export(f.t.Context(), backup.ModeClean, allow)
	if err != nil {
		f.t.Fatal(err)
	}
	verified, err := svc.Verify(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = svc.Restore(f.t.Context(), verified, backup.RestoreOptions{Initiator: backup.InitiatorHost, Authorize: allow}); err != nil {
		f.t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		f.t.Fatal(err)
	}
}

// RESTORE-08 through the helper: the same protocol as every other host ceremony. Issuing prints no secret, the reveal
// goes only to the verified controlling terminal and only once, the token exchanges ONLY as a restore-recovery generation,
// and nothing is issued or shown before a restore produced a quarantine.
func TestCLIRestoreAdministratorRecoveryProtocol(t *testing.T) {
	f := newCLIFixture(t)
	if code := f.run("setup", "status"); code != 0 || !strings.Contains(f.stdout.String(), "restore recovery eligible: false") {
		t.Fatalf("status of a fresh installation: %d %q", code, f.stdout.String())
	}
	f.restoreHostSide()
	if code := f.run("setup", "status"); code != 0 || !strings.Contains(f.stdout.String(), "restore recovery eligible: true") || !strings.Contains(f.stdout.String(), "setup eligible: false") {
		t.Fatalf("status after a restore: %d %q", code, f.stdout.String())
	}
	if code := f.run("recovery", "restore-admin", "--acknowledge-restore-recovery"); code != 0 || !strings.Contains(f.stdout.String(), "restore-administrator recovery generation") {
		t.Fatalf("restore-admin: %d %q %q", code, f.stdout.String(), f.stderr.String())
	}
	f.requireNoTokenInOutput()
	if f.term.writes != 0 {
		t.Fatal("issuing wrote a secret")
	}
	// The other purposes' reveal never shows this generation, and a pipe or file never gets it.
	if code := f.run("setup", "reveal"); code != 1 || f.term.writes != 0 {
		t.Fatalf("an initial-setup reveal exposed a restore-recovery generation: %d", code)
	}
	f.term.verifyErr = errors.New("not a controlling terminal")
	if code := f.run("recovery", "reveal", "--restore-admin"); code != 1 || f.term.writes != 0 {
		t.Fatalf("reveal on an unverified terminal: %d writes=%d", code, f.term.writes)
	}
	f.term.verifyErr = nil
	if code := f.run("recovery", "reveal", "--restore-admin"); code != 0 {
		t.Fatalf("reveal: %d %q", code, f.stderr.String())
	}
	token := f.term.token()
	if token == "" || strings.Contains(f.stdout.String(), token) || strings.Contains(f.stderr.String(), token) {
		t.Fatal("the token must reach only the verified terminal")
	}
	f.requireNoTokenInOutput()
	if code := f.run("recovery", "reveal", "--restore-admin"); code != 1 {
		t.Fatal("the token was revealed twice")
	}
	service, err := auth.NewSetup(f.openExisting(), nil, auth.SetupSettings{Build: buildIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.Exchange(t.Context(), token, "192.0.2.6")
	if err != nil || session.Purpose != auth.PurposeRestoreRecovery {
		t.Fatalf("the helper-issued token did not exchange as a restore recovery: %v %+v", err, session.SetupSessionInfo)
	}
}
