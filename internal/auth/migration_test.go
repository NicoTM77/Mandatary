package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/pressly/goose/v3"
)

func TestPasswordRevisionMigrationPreservesInactiveState(t *testing.T) {
	_, r, db := serviceFixture(t)
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id='pwd'`)
	execFixture(t, db, `UPDATE users SET compromised=1 WHERE id='u'`)
	var before []byte
	if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	var file string
	if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	provider, e := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("../store/migrations"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = provider.DownTo(t.Context(), 2); e != nil {
		t.Fatal(e)
	}
	key, e := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if e != nil {
		t.Fatal(e)
	}
	options := store.Options{DataDir: filepath.Dir(file), MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true}
	if helper, e := store.Open(t.Context(), options); e == nil {
		if e := helper.Close(); e != nil {
			t.Error(e)
		}
		t.Fatal("helper migrated old schema")
	}
	if n := scalarFixture(t, db, `SELECT count(*) FROM pragma_table_info('users') WHERE name='password_revision'`); n != 0 {
		t.Fatal("refused helper mutated schema")
	}
	options.ExistingOnly = false
	r, e = store.Open(t.Context(), options)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	var after []byte
	if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&after); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) || scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 99 || scalarFixture(t, db, `SELECT compromised FROM users WHERE id='u'`) != 1 || scalarFixture(t, db, `SELECT password_revision FROM users WHERE id='u'`) != 0 {
		t.Fatal("migration relabelled/reactivated/reset historical state")
	}
	s, e := NewService(r, DefaultPolicy(), "synthetic-host.example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1"); e != ErrDenied {
		t.Fatal("migration reactivated compromised proof")
	}
	execFixture(t, db, `UPDATE users SET password_revision=9223372036854775807 WHERE id='u'`)
	if e = s.MarkCompromised(t.Context(), "u"); e != ErrDenied {
		t.Fatal("revision overflow accepted")
	}
	if _, e = s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != ErrDenied {
		t.Fatal("overflow revived authority")
	}
}
