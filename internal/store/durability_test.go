package store

// This test-only VFS interposes on the pinned modernc SQLite ABI. Production
// contains no unsafe pointers, VFS override, fault switch or deterministic RNG.
// The model retains only xSync-confirmed file images: power-loss reconstruction
// discards unsynced writes. It does NOT qualify real hardware/power-loss behavior.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

type syncProbeFile struct {
	original, methods uintptr
	path              string
}
type syncProbe struct {
	mu      sync.Mutex
	parent  uintptr
	files   map[uintptr]syncProbeFile
	durable map[string][]byte
	fail    bool
	syncs   int
}

var activeSyncProbe *syncProbe

// Same function-value ABI used by the pinned modernc translation's __ccgo_fp.
func probeFP(f any) uintptr { return (*[2]uintptr)(unsafe.Pointer(&f))[1] }

// The translated ABI carries C-allocation addresses as uintptr words. Load the
// word as a pointer (as modernc's __ccgo_up does); never apply Go-heap pointer
// arithmetic or manufacture an address. These allocations are explicitly kept
// alive until SQLite closes the file and the VFS is unregistered.
func probePointer[T any](address uintptr) *T { return *(**T)(unsafe.Pointer(&address)) }

func probeOpen(tls *libc.TLS, vfs, name, file uintptr, flags int32, out uintptr) int32 {
	p := activeSyncProbe
	parent := probePointer[sqlite3.Tsqlite3_vfs](p.parent)
	original := *(*func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{parent.FxOpen}))
	rc := original(tls, p.parent, name, file, flags, out)
	if rc != sqlite3.SQLITE_OK {
		return rc
	}
	f := probePointer[sqlite3.Tsqlite3_file](file)
	methods := libc.Xmalloc(tls, sqlite3.Tsize_t(unsafe.Sizeof(sqlite3.Tsqlite3_io_methods{})))
	if methods == 0 {
		return sqlite3.SQLITE_NOMEM
	}
	*probePointer[sqlite3.Tsqlite3_io_methods](methods) = *probePointer[sqlite3.Tsqlite3_io_methods](f.FpMethods)
	m := probePointer[sqlite3.Tsqlite3_io_methods](methods)
	m.FxSync = probeFP(probeSync)
	m.FxClose = probeFP(probeClose)
	p.mu.Lock()
	p.files[file] = syncProbeFile{original: f.FpMethods, methods: methods, path: libc.GoString(name)}
	p.mu.Unlock()
	f.FpMethods = methods
	return rc
}
func probeClose(tls *libc.TLS, file uintptr) int32 {
	p := activeSyncProbe
	p.mu.Lock()
	entry := p.files[file]
	delete(p.files, file)
	p.mu.Unlock()
	probePointer[sqlite3.Tsqlite3_file](file).FpMethods = entry.original
	method := probePointer[sqlite3.Tsqlite3_io_methods](entry.original).FxClose
	fn := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{method}))
	rc := fn(tls, file)
	libc.Xfree(tls, entry.methods)
	return rc
}
func probeSync(tls *libc.TLS, file uintptr, flags int32) int32 {
	p := activeSyncProbe
	p.mu.Lock()
	entry := p.files[file]
	fail := p.fail && strings.HasSuffix(entry.path, "-wal")
	p.mu.Unlock()
	if fail {
		return sqlite3.SQLITE_IOERR_FSYNC
	}
	method := probePointer[sqlite3.Tsqlite3_io_methods](entry.original).FxSync
	fn := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{method}))
	rc := fn(tls, file, flags)
	if rc == sqlite3.SQLITE_OK {
		data, err := os.ReadFile(entry.path)
		if err != nil {
			return sqlite3.SQLITE_IOERR_READ
		}
		p.mu.Lock()
		p.durable[filepath.Base(entry.path)] = data
		p.syncs++
		p.mu.Unlock()
	}
	return rc
}

func attachSyncProbe(t *testing.T, r *Repository) *syncProbe {
	t.Helper()
	// Start with a real checkpointed durable base, then observe the new writer.
	if _, err := r.writer.ExecContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if err := r.writer.Close(); err != nil {
		t.Fatal(err)
	}
	tls := libc.NewTLS()
	parent := sqlite3.Xsqlite3_vfs_find(tls, 0)
	vfs := libc.Xmalloc(tls, sqlite3.Tsize_t(unsafe.Sizeof(sqlite3.Tsqlite3_vfs{})))
	if parent == 0 || vfs == 0 {
		t.Fatal("VFS unavailable")
	}
	*probePointer[sqlite3.Tsqlite3_vfs](vfs) = *probePointer[sqlite3.Tsqlite3_vfs](parent)
	name, err := libc.CString("mandatary-sync-probe")
	if err != nil {
		t.Fatal(err)
	}
	clone := probePointer[sqlite3.Tsqlite3_vfs](vfs)
	clone.FzName = name
	clone.FxOpen = probeFP(probeOpen)
	p := &syncProbe{parent: parent, files: make(map[uintptr]syncProbeFile), durable: make(map[string][]byte)}
	data, err := os.ReadFile(filepath.Join(r.path, "mandatary.db"))
	if err != nil {
		t.Fatal(err)
	}
	p.durable["mandatary.db"] = data
	activeSyncProbe = p
	if rc := sqlite3.Xsqlite3_vfs_register(tls, vfs, 0); rc != sqlite3.SQLITE_OK {
		t.Fatal("VFS registration failed")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(r.path, "mandatary.db")+"?vfs=mandatary-sync-probe&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	r.writer = db
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Reader connections keep the sidecars on the same inode across this swap.
	t.Cleanup(func() {
		_ = r.Close()
		sqlite3.Xsqlite3_vfs_unregister(tls, vfs)
		libc.Xfree(tls, vfs)
		libc.Xfree(tls, name)
		tls.Close()
		activeSyncProbe = nil
	})
	return p
}

func (p *syncProbe) reconstruct(t *testing.T, options Options) *Repository {
	t.Helper()
	path := filepath.Join(t.TempDir(), "power-loss-image")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	for name, data := range p.durable {
		if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
			p.mu.Unlock()
			t.Fatal(err)
		}
	}
	p.mu.Unlock()
	if err := os.WriteFile(filepath.Join(path, "control.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	options.DataDir = path
	options.ExistingOnly = true
	recovered, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal("sync-image recovery failed", err)
	}
	t.Cleanup(func() { _ = recovered.Close() })
	return recovered
}

func TestSQLiteSyncFailurePreventsAcknowledgement(t *testing.T) {
	r, _ := openFixture(t)
	probe := attachSyncProbe(t, r)
	probe.mu.Lock()
	probe.fail = true
	probe.mu.Unlock()
	disclosed := false
	err := r.Control(t.Context(), func(q *Queries) error {
		return q.CreateUser(t.Context(), CreateUserParams{ID: "sync-fail", Username: "sync-fail"})
	}, func() error { disclosed = true; return nil })
	if err == nil || disclosed || !r.poisoned.Load() {
		t.Fatal("SQLite xSync failure acknowledged")
	}
}

func TestSQLiteFULLSurvivesModeledPersistenceLoss(t *testing.T) {
	r, options := openFixture(t)
	probe := attachSyncProbe(t, r)
	if err := r.Write(t.Context(), func(q *Queries) error {
		return q.CreateUser(t.Context(), CreateUserParams{ID: "full", Username: "full"})
	}); err != nil {
		t.Fatal(err)
	}
	probe.mu.Lock()
	syncs := probe.syncs
	probe.mu.Unlock()
	if syncs == 0 {
		t.Fatal("FULL did not sync WAL")
	}
	recovered := probe.reconstruct(t, options)
	if err := recovered.Read(t.Context(), func(q *Queries) error { _, err := q.GetUser(t.Context(), "full"); return err }); err != nil {
		t.Fatal("acknowledged FULL commit lost")
	}
	// Real adverse control, not a process kill: NORMAL commits without a WAL sync;
	// dropping unsynced bytes loses the record. Repository must never use this path.
	if _, err := r.writer.ExecContext(t.Context(), "PRAGMA synchronous=NORMAL"); err != nil {
		t.Fatal(err)
	}
	probe.mu.Lock()
	before := probe.syncs
	probe.mu.Unlock()
	if _, err := r.writer.ExecContext(t.Context(), "INSERT INTO users(id,username) VALUES('normal','normal')"); err != nil {
		t.Fatal(err)
	}
	probe.mu.Lock()
	after := probe.syncs
	probe.mu.Unlock()
	if after != before {
		t.Fatal("adverse NORMAL control unexpectedly synced")
	}
	lost := probe.reconstruct(t, options)
	if err := lost.Read(context.Background(), func(q *Queries) error {
		if _, err := q.GetUser(t.Context(), "full"); err != nil {
			return err // the recovered image must be readable, not merely denied
		}
		if _, err := q.GetUser(t.Context(), "normal"); err != sql.ErrNoRows {
			t.Fatal("persistence-loss adverse control did not lose unsynced NORMAL write")
		}
		return nil
	}); err != nil {
		t.Fatal("adverse control reconstruction unreadable", err)
	}
}
