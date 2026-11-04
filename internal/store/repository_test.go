package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/pressly/goose/v3"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openFixture(t *testing.T) (*Repository, Options) {
	t.Helper()
	options := Options{DataDir: filepath.Join(t.TempDir(), "data"), MasterKey: testKey(t), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r, options
}

func TestRepositoryKeyAndEncryptedSMTPPersistence(t *testing.T) {
	r, options := openFixture(t)
	secret := []byte("synthetic-SMTP-password-canary")
	if err := r.PutSMTPSecret(t.Context(), "primary", secret); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mandatary.db", "mandatary.db-wal"} {
		data, err := os.ReadFile(filepath.Join(options.DataDir, name))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, secret) {
			t.Fatal("plaintext persisted")
		}
	}
	options.ExistingOnly = true
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	plain, err := r.SMTPSecret(t.Context(), "primary")
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("encrypted SMTP record lost")
	}
	options.MasterKey, _ = LoadMasterKey(strings.Repeat("43", 32), "")
	if bad, err := Open(t.Context(), options); err == nil {
		_ = bad.Close()
		t.Fatal("wrong key opened existing installation")
	}
	options.MasterKey = nil
	if bad, err := Open(t.Context(), options); err == nil {
		_ = bad.Close()
		t.Fatal("missing key opened installation")
	}
	// Authenticated ciphertext binding is checked on every load, not only startup.
	if _, err := r.writer.ExecContext(t.Context(), "UPDATE smtp_secrets SET ciphertext=zeroblob(length(ciphertext))"); err != nil {
		t.Fatal(err)
	}
	if plain, err := r.SMTPSecret(t.Context(), "primary"); err == nil || plain != nil || strings.Contains(err.Error(), string(secret)) {
		t.Fatal("tampered record disclosed")
	}
}

func TestExistingV1UpgradePreservesRowsAndHelperDoesNotMigrate(t *testing.T) {
	r, o := openFixture(t)
	if err := r.Write(t.Context(), func(q *Queries) error {
		return q.CreateUser(t.Context(), CreateUserParams{ID: "upgrade", Username: "upgrade"})
	}); err != nil {
		t.Fatal(err)
	}
	migrationFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, r.writer, migrationFS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	o.ExistingOnly = true
	if bad, err := Open(t.Context(), o); err == nil {
		_ = bad.Close()
		t.Fatal("helper migrated old schema")
	}
	o.ExistingOnly = false
	r, err = Open(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := r.Read(t.Context(), func(q *Queries) error {
		user, err := q.GetUser(t.Context(), "upgrade")
		if err == nil && user.State != "quarantined" {
			t.Fatal("upgrade activated authority")
		}
		return err
	}); err != nil {
		t.Fatal("upgrade lost records")
	}
}

func TestMissingDatabaseDoesNotResetInstallation(t *testing.T) {
	r, o := openFixture(t)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mandatary.db", "mandatary.db-wal", "mandatary.db-shm"} {
		if err := os.Remove(filepath.Join(o.DataDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if bad, err := Open(t.Context(), o); err == nil {
		_ = bad.Close()
		t.Fatal("missing store automatically reinitialized")
	}
	if _, err := os.Lstat(filepath.Join(o.DataDir, "mandatary.db")); !os.IsNotExist(err) {
		t.Fatal("missing database was recreated")
	}
}

func TestUnrecognizedExistingStoreNeverBecomesFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mandatary.db", "control.lock"} {
		if err := os.WriteFile(filepath.Join(path, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(path, "mandatary.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE unrecognized (id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	options := Options{DataDir: path, MasterKey: testKey(t), OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}
	if r, err := Open(t.Context(), options); err == nil {
		_ = r.Close()
		t.Fatal("missing initial control silently initialized")
	}
}

func TestKeyBindingCannotBeReinitialized(t *testing.T) {
	for _, sql := range []string{"DELETE FROM repository_metadata", "UPDATE repository_metadata SET key_check=zeroblob(length(key_check))", "UPDATE repository_metadata SET installation_id=randomblob(32)"} {
		r, o := openFixture(t)
		if _, err := r.writer.ExecContext(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if bad, err := Open(t.Context(), o); err == nil {
			_ = bad.Close()
			t.Fatal("missing/tampered key binding replaced")
		}
	}
}

func TestAuthorityNeverDefaultsActive(t *testing.T) {
	r, options := openFixture(t)
	expected := Generations{Credential: 1, Session: 1, Authority: 1, Restore: 1}
	calls := 0
	read := func() error { return r.ReadActive(t.Context(), expected, func(*Queries) error { calls++; return nil }) }
	if err := read(); err == nil || calls != 0 {
		t.Fatal("fresh quarantine authorized")
	}
	if _, err := r.writer.ExecContext(t.Context(), `UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0`); err != nil {
		t.Fatal(err)
	}
	if err := read(); err != nil || calls != 1 {
		t.Fatal("current approved fixture refused")
	}
	for _, g := range []Generations{{}, {Credential: 2, Session: 1, Authority: 1, Restore: 1}, {Credential: 1, Session: 2, Authority: 1, Restore: 1}, {Credential: 1, Session: 1, Authority: 2, Restore: 1}, {Credential: 1, Session: 1, Authority: 1, Restore: 2}} {
		if err := r.ReadActive(t.Context(), g, func(*Queries) error { t.Fatal("stale generation called"); return nil }); err == nil {
			t.Fatal("stale/missing generation accepted")
		}
	}
	if _, err := r.writer.ExecContext(t.Context(), `DELETE FROM installation_control`); err != nil {
		t.Fatal(err)
	}
	if err := read(); err == nil || calls != 1 {
		t.Fatal("missing control authorized")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if bad, err := Open(t.Context(), options); err == nil {
		_ = bad.Close()
		t.Fatal("missing control silently recreated")
	}
}

func TestRepositoryRestartConcurrencyAndPragmas(t *testing.T) {
	r, options := openFixture(t)
	if r.writer.Stats().MaxOpenConnections != 1 || r.readers.Stats().MaxOpenConnections < 2 {
		t.Fatal("incorrect pool bounds")
	}
	var version string
	if err := r.readers.QueryRowContext(t.Context(), "SELECT sqlite_version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("embedded SQLite %s on local file fixture", version)
	for _, db := range []*sql.DB{r.writer, r.readers} {
		conn, err := db.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var wal string
		var fk, busy, synchronous int
		if err = conn.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&wal); err != nil {
			t.Fatal(err)
		}
		if err = conn.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatal(err)
		}
		if err = conn.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&busy); err != nil {
			t.Fatal(err)
		}
		if err = conn.QueryRowContext(t.Context(), "PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(err)
		}
		if wal != "wal" || fk != 1 || busy != 5000 || (db == r.writer && synchronous != 2) {
			t.Fatal("unsafe SQLite pragmas")
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.readers.ExecContext(t.Context(), "DELETE FROM users"); err == nil {
		t.Fatal("reader permits mutation")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 40 {
		wg.Go(func() {
			errs <- r.Write(t.Context(), func(q *Queries) error {
				return q.CreateUser(t.Context(), CreateUserParams{ID: fmt.Sprint(i), Username: fmt.Sprintf("user-%d", i)})
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A writer can remain uncommitted while several readers use a stable snapshot.
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Write(t.Context(), func(q *Queries) error {
			if err := q.CreateUser(t.Context(), CreateUserParams{ID: "last", Username: "last"}); err != nil {
				return err
			}
			close(entered) // hold an actual SQLite write, not only a deferred BEGIN
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("writer failed before concurrent reader fixture", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for range 4 {
		wg.Go(func() {
			errs := r.Read(ctx, func(q *Queries) error {
				if _, err := q.GetUser(ctx, "0"); err != nil {
					return err
				}
				if _, err := q.GetUser(ctx, "last"); err != sql.ErrNoRows {
					return fmt.Errorf("reader observed uncommitted writer or failed snapshot")
				}
				return nil
			})
			if errs != nil {
				t.Error(errs)
			}
		})
	}
	wg.Wait()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mandatary.db", "mandatary.db-wal", "mandatary.db-shm", "control.lock"} {
		st, err := os.Stat(filepath.Join(options.DataDir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe/missing storage file", name)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	for i := range 40 {
		if err := r.Read(t.Context(), func(q *Queries) error { _, err := q.GetUser(t.Context(), fmt.Sprint(i)); return err }); err != nil {
			t.Fatal("committed record lost")
		}
	}
	if err := r.Read(t.Context(), func(q *Queries) error { _, err := q.GetUser(t.Context(), "last"); return err }); err != nil {
		t.Fatal("commit concurrent with readers lost on restart")
	}
}
