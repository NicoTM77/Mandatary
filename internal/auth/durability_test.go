package auth

// Test-only interposition on the locked modernc ABI. No production fault seam,
// unsafe code or VFS replacement is linked into the application. This exercises
// the actual auth -> Control -> SQLite xSync failure boundary, not a mocked repo.
import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

type authSyncFile struct {
	original, methods uintptr
	path              string
}
type authSyncProbe struct {
	mu     sync.Mutex
	parent uintptr
	files  map[uintptr]authSyncFile
	fail   bool
	failed int
}

var activeAuthSync *authSyncProbe

func authFP(f any) uintptr                  { return (*[2]uintptr)(unsafe.Pointer(&f))[1] }
func authPointer[T any](address uintptr) *T { return *(**T)(unsafe.Pointer(&address)) }
func authOpen(tls *libc.TLS, vfs, name, file uintptr, flags int32, out uintptr) int32 {
	p := activeAuthSync
	parent := authPointer[sqlite3.Tsqlite3_vfs](p.parent)
	original := *(*func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{parent.FxOpen}))
	rc := original(tls, p.parent, name, file, flags, out)
	if rc != sqlite3.SQLITE_OK {
		return rc
	}
	f := authPointer[sqlite3.Tsqlite3_file](file)
	methods := libc.Xmalloc(tls, sqlite3.Tsize_t(unsafe.Sizeof(sqlite3.Tsqlite3_io_methods{})))
	if methods == 0 {
		return sqlite3.SQLITE_NOMEM
	}
	*authPointer[sqlite3.Tsqlite3_io_methods](methods) = *authPointer[sqlite3.Tsqlite3_io_methods](f.FpMethods)
	m := authPointer[sqlite3.Tsqlite3_io_methods](methods)
	m.FxSync = authFP(authSync)
	m.FxClose = authFP(authClose)
	p.mu.Lock()
	p.files[file] = authSyncFile{original: f.FpMethods, methods: methods, path: libc.GoString(name)}
	p.mu.Unlock()
	f.FpMethods = methods
	return rc
}
func authClose(tls *libc.TLS, file uintptr) int32 {
	p := activeAuthSync
	p.mu.Lock()
	entry := p.files[file]
	delete(p.files, file)
	p.mu.Unlock()
	authPointer[sqlite3.Tsqlite3_file](file).FpMethods = entry.original
	method := authPointer[sqlite3.Tsqlite3_io_methods](entry.original).FxClose
	fn := *(*func(*libc.TLS, uintptr) int32)(unsafe.Pointer(&struct{ p uintptr }{method}))
	rc := fn(tls, file)
	libc.Xfree(tls, entry.methods)
	return rc
}
func authSync(tls *libc.TLS, file uintptr, flags int32) int32 {
	p := activeAuthSync
	p.mu.Lock()
	entry := p.files[file]
	fail := p.fail && strings.HasSuffix(entry.path, "-wal")
	if fail {
		p.failed++
	}
	p.mu.Unlock()
	if fail {
		return sqlite3.SQLITE_IOERR_FSYNC
	}
	method := authPointer[sqlite3.Tsqlite3_io_methods](entry.original).FxSync
	fn := *(*func(*libc.TLS, uintptr, int32) int32)(unsafe.Pointer(&struct{ p uintptr }{method}))
	return fn(tls, file, flags)
}
func installAuthSyncProbe(t *testing.T) *authSyncProbe {
	t.Helper()
	tls := libc.NewTLS()
	parent := sqlite3.Xsqlite3_vfs_find(tls, 0)
	vfs := libc.Xmalloc(tls, sqlite3.Tsize_t(unsafe.Sizeof(sqlite3.Tsqlite3_vfs{})))
	if parent == 0 || vfs == 0 {
		t.Fatal("VFS unavailable")
	}
	*authPointer[sqlite3.Tsqlite3_vfs](vfs) = *authPointer[sqlite3.Tsqlite3_vfs](parent)
	name, e := libc.CString("mandatary-auth-sync-probe")
	if e != nil {
		t.Fatal(e)
	}
	clone := authPointer[sqlite3.Tsqlite3_vfs](vfs)
	clone.FzName = name
	clone.FxOpen = authFP(authOpen)
	p := &authSyncProbe{parent: parent, files: make(map[uintptr]authSyncFile)}
	activeAuthSync = p
	if rc := sqlite3.Xsqlite3_vfs_register(tls, vfs, 1); rc != sqlite3.SQLITE_OK {
		t.Fatal("VFS registration failed")
	}
	t.Cleanup(func() {
		sqlite3.Xsqlite3_vfs_unregister(tls, vfs)
		sqlite3.Xsqlite3_vfs_register(tls, parent, 1)
		libc.Xfree(tls, vfs)
		libc.Xfree(tls, name)
		tls.Close()
		activeAuthSync = nil
	})
	return p
}
func TestPasswordSQLiteSyncFailureIsFailClosed(t *testing.T) {
	for _, operation := range []string{"failure", "reset", "compromise", "replace"} {
		t.Run(operation, func(t *testing.T) {
			probe := installAuthSyncProbe(t)
			s, _, db := serviceFixture(t)
			execFixture(t, db, `UPDATE authenticators SET failed_attempts=2 WHERE id='pwd'`)
			var observed []byte
			if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); e != nil {
				t.Fatal(e)
			}
			probe.mu.Lock()
			probe.fail = true
			probe.mu.Unlock()
			var e error
			switch operation {
			case "failure":
				_, e = s.Prove(t.Context(), "synthetic-user", []byte("wrong public phrase"), "192.0.2.1")
			case "reset":
				_, e = s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1")
			case "compromise":
				e = s.MarkCompromised(t.Context(), "u")
			case "replace":
				e = s.ReplacePassword(t.Context(), "u", observed, []byte("another uncommon synthetic phrase"))
			}
			if e != ErrDenied {
				t.Fatal("failed sync acknowledged", e)
			}
			probe.mu.Lock()
			failed := probe.failed
			probe.fail = false
			probe.mu.Unlock()
			if failed == 0 {
				t.Fatal("no actual SQLite xSync failure")
			}
			if _, e = s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != ErrDenied {
				t.Fatal("uncertain handle continued acceptance")
			}
			var file string
			if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"mandatary.db", "control.lock"} {
				if _, e := os.Stat(filepath.Join(filepath.Dir(file), name)); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
