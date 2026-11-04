package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlDurableCallback(t *testing.T) {
	for _, failure := range []string{"none", "mandatary.db", "mandatary.db-wal", "control.lock", "directory"} {
		t.Run(failure, func(t *testing.T) {
			r, _ := openFixture(t)
			called := 0
			r.syncFile = func(f *os.File) error {
				if f.Name() == failure || (failure == "directory" && f == r.dir) {
					return errors.New("synthetic-sync-error")
				}
				return f.Sync()
			}
			err := r.Control(t.Context(), func(q *Queries) error {
				return q.CreateUser(t.Context(), CreateUserParams{ID: "durable", Username: "durable"})
			}, func() error {
				called++
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
				defer cancel()
				if lock, err := r.lock(ctx); err == nil {
					_ = lock.Close()
					t.Error("durable callback lost coordination lock")
				}
				var count int
				if err := r.readers.QueryRowContext(t.Context(), "SELECT count(*) FROM users WHERE id='durable'").Scan(&count); err != nil || count != 1 {
					t.Error("delivery before durable commit")
				}
				return nil
			})
			if failure == "none" {
				if err != nil || called != 1 {
					t.Fatal("durable callback refused")
				}
			} else if err == nil || called != 0 {
				t.Fatal("failed sync disclosed/acknowledged")
			}
		})
	}
}

// Signal when Control reaches the lock deadline calculation, after its initial
// health check. This establishes a queued writer without timing/sleep guesses.
type lockEntryContext struct {
	context.Context
	entered chan struct{}
}

func (c lockEntryContext) Deadline() (time.Time, bool) {
	select {
	case <-c.entered:
	default:
		close(c.entered)
	}
	return c.Context.Deadline()
}

func TestQueuedControlDeniesAfterUncertainDelivery(t *testing.T) {
	r, _ := openFixture(t)
	inDelivery, failDelivery := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- r.Control(t.Context(), func(*Queries) error { return nil }, func() error {
			close(inDelivery)
			<-failDelivery
			return errors.New("synthetic-uncertain-delivery")
		})
	}()
	<-inDelivery
	entered := make(chan struct{})
	second := make(chan error, 1)
	called := false
	go func() {
		second <- r.Control(lockEntryContext{Context: t.Context(), entered: entered}, func(*Queries) error {
			called = true
			return nil
		}, nil)
	}()
	<-entered
	close(failDelivery)
	if err := <-first; err == nil {
		t.Fatal("uncertain delivery acknowledged")
	}
	if err := <-second; err == nil || called {
		t.Fatal("queued control continued after uncertain delivery")
	}
}

func TestZeroKeyIsInvalid(t *testing.T) {
	options := Options{DataDir: filepath.Join(t.TempDir(), "data"), MasterKey: &MasterKey{}, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}
	if r, err := Open(t.Context(), options); err == nil {
		_ = r.Close()
		t.Fatal("zero-value key accepted")
	}
}

func TestRepositoryRejectsUnsafeStorage(t *testing.T) {
	for _, name := range []string{"mandatary.db", "mandatary.db-wal", "mandatary.db-shm", "control.lock"} {
		for _, attack := range []string{"mode", "symlink", "hardlink", "replace", "remove"} {
			t.Run(name+"/"+attack, func(t *testing.T) {
				r, options := openFixture(t)
				path := filepath.Join(options.DataDir, name)
				switch attack {
				case "remove":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "mode":
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(path, path+".linked"); err != nil {
						t.Fatal(err)
					}
				case "symlink", "replace":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					if attack == "symlink" {
						if err := os.Symlink(path+".old", path); err != nil {
							t.Fatal(err)
						}
					} else {
						if err := os.WriteFile(path, nil, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				calls := 0
				if err := r.Write(t.Context(), func(*Queries) error { calls++; return nil }); err == nil || calls != 0 {
					t.Fatal("unsafe file accepted")
				}
			})
		}
	}
	t.Run("unsafe-directory", func(t *testing.T) {
		r, o := openFixture(t)
		if err := os.Chmod(o.DataDir, 0755); err != nil {
			t.Fatal(err)
		}
		if r.Read(t.Context(), func(*Queries) error { return nil }) == nil {
			t.Fatal("unsafe directory accepted")
		}
	})
	t.Run("aliased-directory", func(t *testing.T) {
		r, o := openFixture(t)
		alias := o.DataDir + "-alias"
		if err := os.Symlink(o.DataDir, alias); err != nil {
			t.Fatal(err)
		}
		o.DataDir = alias
		if bad, err := Open(t.Context(), o); err == nil {
			_ = bad.Close()
			t.Fatal("path alias accepted")
		}
		_ = r.Close()
	})
}

func TestHelperCannotCreateOrMigrate(t *testing.T) {
	options := Options{DataDir: filepath.Join(t.TempDir(), "missing"), MasterKey: testKey(t), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true}
	if r, err := Open(t.Context(), options); err == nil {
		_ = r.Close()
		t.Fatal("helper created installation")
	}
	if _, err := os.Lstat(options.DataDir); !os.IsNotExist(err) {
		t.Fatal("helper left data files")
	}
}

func TestWriterSyncFailureAndLockOrder(t *testing.T) {
	r, _ := openFixture(t)
	// A lock timeout must happen before opening a SQLite transaction. Hold the
	// advisory lock and prove an independent SQLite writer remains available.
	guard, err := r.lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	pending := make(chan error, 1)
	go func() {
		pending <- r.Write(ctx, func(*Queries) error { t.Error("callback ran without lock"); return nil })
	}()
	tx, err := r.writer.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(t.Context(), "INSERT INTO users(id,username) VALUES('lock-probe','lock-probe')"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-pending; err == nil {
		t.Fatal("lock timeout accepted")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	// NORMAL is expressly insufficient for a control acknowledgement.
	if _, err := r.writer.ExecContext(t.Context(), "PRAGMA synchronous=NORMAL"); err != nil {
		t.Fatal(err)
	}
	if err := r.Write(t.Context(), func(*Queries) error { t.Error("unsafe writer ran"); return nil }); err == nil {
		t.Fatal("NORMAL acknowledged")
	}
	if _, err := r.writer.ExecContext(t.Context(), "PRAGMA synchronous=FULL"); err != nil {
		t.Fatal(err)
	}
	r.syncFile = func(*os.File) error { return errors.New("sync-failure-canary") }
	if err := r.Write(t.Context(), func(q *Queries) error {
		return q.CreateUser(t.Context(), CreateUserParams{ID: "sync", Username: "sync"})
	}); err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("sync failure acknowledged or leaked")
	}
	if r.Read(t.Context(), func(*Queries) error { t.Error("poisoned repository read"); return nil }) == nil {
		t.Fatal("uncertain sync kept serving")
	}
}

func TestRepositoryChildWriter(t *testing.T) {
	path := os.Getenv("MANDATARY_TEST_REPOSITORY_PATH")
	if path == "" {
		return
	} // parent test always exercises this child branch
	// The denial probe needs a short deadline; successful schema/key validation
	// under the race detector must not share that timing assumption.
	locked := os.Getenv("MANDATARY_TEST_EXPECT_LOCKED") == "1"
	timeout := 5 * time.Second
	if locked {
		timeout = 150 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	r, err := Open(ctx, Options{DataDir: path, MasterKey: testKey(t), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if locked {
		if err == nil {
			_ = r.Close()
			t.Fatal("helper bypassed service lock")
		}
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal("helper denial did not exercise lock deadline")
		}
		return
	}
	if err != nil {
		t.Fatalf("helper open failed (context=%v): %v", ctx.Err(), err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := r.Write(t.Context(), func(q *Queries) error {
		return q.CreateUser(t.Context(), CreateUserParams{ID: "child", Username: "child"})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceAndHelperSharePersistentLock(t *testing.T) {
	r, o := openFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(locked bool) {
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestRepositoryChildWriter$", "-test.v")
		command.Env = append(os.Environ(), "MANDATARY_TEST_REPOSITORY_PATH="+o.DataDir, "MANDATARY_TEST_EXPECT_LOCKED=0")
		if locked {
			command.Env = append(command.Env, "MANDATARY_TEST_EXPECT_LOCKED=1")
		}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("child writer failed: %s", output)
		}
	}
	if err := r.Write(t.Context(), func(*Queries) error { child(true); return nil }); err != nil {
		t.Fatal(err)
	}
	child(false)
	if err := r.Read(t.Context(), func(q *Queries) error { _, err := q.GetUser(t.Context(), "child"); return err }); err != nil {
		for name, old := range r.sidecarIdentities {
			now, e := os.Stat(filepath.Join(o.DataDir, name))
			t.Logf("sidecar %s exists=%t same-inode=%t", name, e == nil, e == nil && os.SameFile(old, now))
		}
		t.Fatal("helper commit not visible to service", err)
	}
}
