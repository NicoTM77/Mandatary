package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/pressly/goose/v3"
	sqlite "modernc.org/sqlite"
)

var ErrStorage = errors.New("storage unavailable or unsafe")

//go:embed migrations/*.sql
var migrations embed.FS

// Options uses trusted deployment identities, never IDs inferred from files.
// ExistingOnly is the host-helper boundary: no missing files, creation or
// migration. The later helper must additionally check build/installation ID.
type Options struct {
	DataDir            string
	MasterKey          *MasterKey
	OwnerUID, OwnerGID int
	ExistingOnly       bool
}

type Repository struct {
	writer, readers          *sql.DB
	dir                      *os.File
	path                     string
	uid, gid                 int
	lockIdentity, dbIdentity os.FileInfo
	sidecarIdentities        map[string]os.FileInfo
	lifecycle                sync.RWMutex
	closed                   bool
	poisoned                 atomic.Bool
	syncFile                 func(*os.File) error
	cipher                   *recordCipher
}

func Open(ctx context.Context, options Options) (_ *Repository, result error) {
	if !options.MasterKey.valid() {
		return nil, ErrKey
	}
	if options.OwnerUID != os.Geteuid() || options.OwnerGID != os.Getegid() {
		return nil, ErrStorage
	}
	dir, err := openDataDir(options.DataDir, options.OwnerUID, options.OwnerGID, !options.ExistingOnly)
	if err != nil {
		return nil, ErrStorage
	}
	r := &Repository{dir: dir, path: dir.Name(), uid: options.OwnerUID, gid: options.OwnerGID, syncFile: func(f *os.File) error { return f.Sync() }}
	defer func() {
		if result != nil {
			_ = r.Close()
		}
	}()
	_, statErr := os.Lstat(filepath.Join(r.path, "mandatary.db"))
	fresh := os.IsNotExist(statErr) && !options.ExistingOnly
	if fresh {
		for _, name := range []string{"control.lock", "mandatary.db-wal", "mandatary.db-shm", "mandatary.db-journal"} {
			if _, err := os.Lstat(filepath.Join(r.path, name)); !os.IsNotExist(err) {
				return nil, ErrStorage
			}
		}
	}
	lock, err := r.privateFile("control.lock", fresh)
	if err != nil {
		return nil, ErrStorage
	}
	r.lockIdentity, err = lock.Stat()
	_ = lock.Close()
	if err != nil {
		return nil, ErrStorage
	}
	guard, err := r.lock(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	defer func() {
		if err := guard.Close(); err != nil {
			r.poisoned.Store(true)
			result = ErrStorage
		}
	}()
	file, err := r.privateFile("mandatary.db", fresh)
	if err != nil {
		return nil, ErrStorage
	}
	r.dbIdentity, err = file.Stat()
	_ = file.Close()
	if err != nil || (!fresh && r.dbIdentity.Size() == 0) {
		return nil, ErrStorage
	}
	if err := r.verifyFiles(); err != nil {
		return nil, ErrStorage
	}
	r.writer, err = openPool(r.path, false)
	if err != nil {
		return nil, ErrStorage
	}
	if err := verifyWriter(ctx, r.writer); err != nil {
		return nil, ErrStorage
	}
	migrationFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, ErrStorage
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, r.writer, migrationFS)
	if err != nil {
		return nil, ErrStorage
	}
	current, err := provider.GetDBVersion(ctx)
	if err != nil || current < 0 || current > 2 || (!fresh && current < 1) {
		return nil, ErrStorage
	}
	if !fresh {
		if _, err := New(r.writer).GetInstallationControl(ctx); err != nil {
			return nil, ErrStorage
		}
	}
	if options.ExistingOnly {
		if current != 2 {
			return nil, ErrStorage
		}
	} else if _, err = provider.Up(ctx); err != nil {
		return nil, ErrStorage
	}
	if _, err := New(r.writer).GetInstallationControl(ctx); err != nil {
		return nil, ErrStorage
	}
	if err := r.bindKey(ctx, options.MasterKey, current < 2 && !options.ExistingOnly); err != nil {
		return nil, err
	}
	if err := r.syncFiles(); err != nil {
		return nil, ErrStorage
	}
	r.readers, err = openPool(r.path, true)
	if err != nil || r.readers.PingContext(ctx) != nil {
		return nil, ErrStorage
	}
	r.sidecarIdentities = make(map[string]os.FileInfo)
	for _, name := range []string{"mandatary.db-wal", "mandatary.db-shm"} {
		f, err := r.privateFile(name, false)
		if err != nil {
			return nil, ErrStorage
		}
		st, err := f.Stat()
		_ = f.Close()
		if err != nil {
			return nil, ErrStorage
		}
		r.sidecarIdentities[name] = st
	}
	return r, nil
}

func openPool(path string, reader bool) (*sql.DB, error) {
	parameters := url.Values{}
	parameters.Add("_pragma", "foreign_keys(1)")
	parameters.Add("_pragma", "busy_timeout(5000)")
	if reader {
		parameters.Set("mode", "ro")
		parameters.Add("_pragma", "query_only(1)")
	} else {
		parameters.Set("mode", "rw")
		parameters.Add("_pragma", "journal_mode(WAL)")
		parameters.Add("_pragma", "synchronous(FULL)")
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(path, "mandatary.db"), RawQuery: parameters.Encode()}).String()
	connector, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, ErrStorage
	}
	db := sql.OpenDB(persistentWALConnector{connector})
	if reader {
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(4)
	} else {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	return db, nil
}

// Keep sidecar inodes stable across helper/service connection lifetimes. Without
// PERSIST_WAL, an idle peer can legitimately checkpoint/unlink WAL on close;
// that breaks trusted inode validation and risks split control-file identities.
// Configure every replacement physical connection without process-global hooks.
type persistentWALConnector struct{ driver.Connector }

func (c persistentWALConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	control, ok := conn.(sqlite.FileControl)
	if !ok {
		_ = conn.Close()
		return nil, ErrStorage
	}
	mode, err := control.FileControlPersistWAL("main", 1)
	if err != nil || mode != 1 {
		_ = conn.Close()
		return nil, ErrStorage
	}
	return conn, nil
}

// Checked before migrations and on the physical connection of every write.
func verifyWriter(ctx context.Context, db DBTX) error {
	var mode string
	var sync, fk, busy int
	for _, v := range []struct {
		query string
		out   any
	}{{"PRAGMA journal_mode", &mode}, {"PRAGMA synchronous", &sync}, {"PRAGMA foreign_keys", &fk}, {"PRAGMA busy_timeout", &busy}} {
		if err := db.QueryRowContext(ctx, v.query).Scan(v.out); err != nil {
			return ErrStorage
		}
	}
	if mode != "wal" || sync != 2 || fk != 1 || busy != 5000 {
		return ErrStorage
	}
	return nil
}

// Write serializes all writers (including a separate helper process) on the
// installation's advisory lock BEFORE starting a SQLite transaction. All writes
// use FULL: ordinary NORMAL is allowed by TD, but is not needed by this API.
// A successful callback is not an acknowledgement until commit and sync succeed.
// Callbacks may not disclose secrets/acknowledge success or reenter Repository.
func (r *Repository) Write(ctx context.Context, fn func(*Queries) error) error {
	return r.Control(ctx, fn, nil)
}

// Control retains the shared lock through durable-before-delivery work. The
// afterDurable callback runs ONLY after FULL commit, file and directory sync,
// and identity verification; it must be bounded and must not reenter Repository.
// A failed/uncertain callback poisons this handle: the owning protocol must
// reconcile non-revealable persisted state before reopening/serving again.
func (r *Repository) Control(ctx context.Context, fn func(*Queries) error, afterDurable func() error) (result error) {
	r.lifecycle.RLock()
	defer r.lifecycle.RUnlock()
	if r.closed || r.poisoned.Load() {
		return ErrStorage
	}
	guard, err := r.lock(ctx)
	if err != nil {
		return ErrStorage
	}
	defer func() {
		if err := guard.Close(); err != nil {
			r.poisoned.Store(true)
			result = ErrStorage
		}
	}()
	// Another writer may have failed while this operation waited for the shared
	// lock. Never continue a queued transition through an uncertain handle.
	if r.poisoned.Load() || r.verifyFiles() != nil {
		return ErrStorage
	}
	conn, err := r.writer.Conn(ctx)
	if err != nil {
		return ErrStorage
	}
	defer func() {
		if err := conn.Close(); err != nil {
			r.poisoned.Store(true)
			result = ErrStorage
		}
	}()
	if err := verifyWriter(ctx, conn); err != nil {
		return ErrStorage
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = tx.Rollback() }() // also after commit; ErrTxDone is expected
	q := New(tx)
	if _, err := q.GetInstallationControl(ctx); err != nil {
		return ErrStorage
	}
	if err := fn(q); err != nil {
		return ErrStorage
	}
	if err := tx.Commit(); err != nil {
		r.poisoned.Store(true)
		return ErrStorage
	}
	if err := r.syncFiles(); err != nil {
		r.poisoned.Store(true)
		return ErrStorage
	}
	if err := r.verifyFiles(); err != nil {
		r.poisoned.Store(true)
		return ErrStorage
	}
	if afterDurable != nil {
		if err := afterDurable(); err != nil {
			r.poisoned.Store(true)
			return ErrStorage
		}
	}
	return nil
}

// Read provides a read-only, coherent snapshot, INCLUDING current control state.
// It permits quarantined records for restricted recovery/diagnostics, not active
// authority. Owning auth/authz services must check control and record generations.
func (r *Repository) Read(ctx context.Context, fn func(*Queries) error) error {
	r.lifecycle.RLock()
	defer r.lifecycle.RUnlock()
	if r.closed || r.poisoned.Load() || r.verifyFiles() != nil {
		return ErrStorage
	}
	tx, err := r.readers.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = tx.Rollback() }() // also after commit; ErrTxDone is expected
	q := New(tx)
	if _, err := q.GetInstallationControl(ctx); err != nil {
		return ErrStorage
	}
	if err := fn(q); err != nil {
		return ErrStorage
	}
	if err := tx.Commit(); err != nil {
		return ErrStorage
	}
	return nil
}
func (r *Repository) Close() error {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var failed bool
	for _, db := range []*sql.DB{r.readers, r.writer} {
		if db != nil && db.Close() != nil {
			failed = true
		}
	}
	if r.dir != nil && r.dir.Close() != nil {
		failed = true
	}
	if failed {
		return ErrStorage
	}
	return nil
}
