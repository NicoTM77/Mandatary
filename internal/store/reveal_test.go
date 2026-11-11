package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const revealSample = "initial_setup-7.token"

func TestRevealFileLifecycleAndModes(t *testing.T) {
	r, options := openFixture(t)
	if names, err := r.RevealFileNames(); err != nil || len(names) != 0 {
		t.Fatalf("fresh store: %v %v", names, err)
	}
	if err := r.RevealFileWrite(revealSample, []byte("synthetic\n")); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(filepath.Join(options.DataDir, "reveal"))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v %v", dirInfo, err)
	}
	info, err := os.Stat(filepath.Join(options.DataDir, "reveal", revealSample))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", info, err)
	}
	if err = r.RevealFileWrite(revealSample, []byte("again")); err == nil {
		t.Fatal("an existing reveal file was overwritten (O_EXCL)")
	}
	if err = r.RevealFileCheck(revealSample); err != nil {
		t.Fatal(err)
	}
	data, err := r.RevealFileRead(revealSample)
	if err != nil || string(data) != "synthetic\n" {
		t.Fatalf("read: %q %v", data, err)
	}
	if err = r.RevealFileRemove(revealSample); err != nil {
		t.Fatal(err)
	}
	if err = r.RevealFileRemove(revealSample); err != nil {
		t.Fatalf("removing a missing file must be success: %v", err)
	}
	if _, err = r.RevealFileRead(revealSample); err == nil {
		t.Fatal("read after remove")
	}
}

func TestRevealFileNameAndSizeValidation(t *testing.T) {
	r, _ := openFixture(t)
	for _, name := range []string{"", "x", "../initial_setup-1.token", "initial_setup-0.token", "initial_setup-01.token", "initial_setup-1.token.bak", "INITIAL_setup-1.token", "initial_setup-1234567890123456789.token", "initial_setup-1/../x.token", "other-1.token", "initial_setup-1.tok\x00en"} {
		if err := r.RevealFileWrite(name, []byte("x")); err == nil {
			t.Fatalf("name %q accepted for write", name)
		}
		if _, err := r.RevealFileRead(name); err == nil {
			t.Fatalf("name %q accepted for read", name)
		}
		if err := r.RevealFileRemove(name); err == nil {
			t.Fatalf("name %q accepted for remove", name)
		}
	}
	if err := r.RevealFileWrite(revealSample, nil); err == nil {
		t.Fatal("empty content accepted")
	}
	if err := r.RevealFileWrite(revealSample, []byte(strings.Repeat("A", maxRevealBytes+1))); err == nil {
		t.Fatal("oversized content accepted")
	}
	if names, _ := r.RevealFileNames(); len(names) != 0 {
		t.Fatal("a refused write left a file")
	}
}

// A planted or substituted entry is never read, followed, listed silently or deleted.
func TestRevealDirectoryAdversarialEntries(t *testing.T) {
	setup := func(t *testing.T) (*Repository, string) {
		r, options := openFixture(t)
		if err := r.RevealFileWrite(revealSample, []byte("synthetic\n")); err != nil {
			t.Fatal(err)
		}
		return r, filepath.Join(options.DataDir, "reveal")
	}
	t.Run("symlink in place of file", func(t *testing.T) {
		r, dir := setup(t)
		outside := filepath.Join(filepath.Dir(dir), "outside")
		if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(dir, revealSample))
		if err := os.Symlink(outside, filepath.Join(dir, revealSample)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.RevealFileRead(revealSample); err == nil {
			t.Fatal("a symlink was followed")
		}
		if err := r.RevealFileCheck(revealSample); err == nil {
			t.Fatal("a symlink passed the safety check")
		}
		if _, err := os.Stat(outside); err != nil {
			t.Fatal("the symlink target was affected")
		}
	})
	t.Run("loose permissions", func(t *testing.T) {
		r, dir := setup(t)
		if err := os.Chmod(filepath.Join(dir, revealSample), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := r.RevealFileRead(revealSample); err == nil {
			t.Fatal("a group-readable file was read")
		}
		if err := r.RevealFileCheck(revealSample); err == nil {
			t.Fatal("a group-readable file passed the check")
		}
	})
	t.Run("hard link", func(t *testing.T) {
		r, dir := setup(t)
		if err := os.Link(filepath.Join(dir, revealSample), filepath.Join(dir, "mfa_reset-1.token")); err != nil {
			t.Fatal(err)
		}
		if _, err := r.RevealFileRead(revealSample); err == nil {
			t.Fatal("a multiply-linked file was read")
		}
	})
	t.Run("unexpected entry fails closed", func(t *testing.T) {
		r, dir := setup(t)
		if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.RevealFileNames(); err == nil {
			t.Fatal("unexpected content was silently ignored")
		}
		if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
			t.Fatal("unexpected content was deleted")
		}
	})
	t.Run("directory replaced by symlink", func(t *testing.T) {
		r, dir := setup(t)
		elsewhere := filepath.Join(filepath.Dir(dir), "elsewhere")
		if err := os.Mkdir(elsewhere, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, dir); err != nil {
			t.Fatal(err)
		}
		if err := r.RevealFileWrite(revealSample, []byte("synthetic\n")); err == nil {
			t.Fatal("wrote through a symlinked reveal directory")
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Fatal("a file landed in the symlink target")
		}
	})
	t.Run("loose directory mode", func(t *testing.T) {
		r, dir := setup(t)
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := r.RevealFileCheck(revealSample); err == nil {
			t.Fatal("a world-readable reveal directory passed")
		}
		if _, err := r.RevealFileRead(revealSample); err == nil {
			t.Fatal("read from a world-readable reveal directory")
		}
	})
}

// Control and setup state is non-importable local state (S2): the bytes of the
// reveal directory and the setup tables never travel with a logical export. The
// storage layer exposes NO API that maps them.
func TestSetupControlStateIsNotPartOfAnyExportSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, ".sql.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(src))
		for _, forbidden := range []string{"export", "importlogical", "backup"} {
			for _, table := range []string{"setup_tokens", "setup_sessions", "setup_state", "setup_attempts"} {
				if strings.Contains(lower, forbidden) && strings.Contains(lower, table) && name != "models.go" {
					t.Fatalf("%s references both %q and %s", name, forbidden, table)
				}
			}
		}
	}
}
