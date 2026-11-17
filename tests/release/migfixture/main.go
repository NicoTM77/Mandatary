// Command migfixture lowers the schema version of a COPY of a populated Mandatary store with the repository's own
// goose down-migrations, so the release acceptance (tests/release/release.py) can start the release image on data
// that is one schema version behind and prove the in-place forward migration keeps everything.
//
// It is a test tool: built from this repository's locked module, never part of the shipped image, and it operates
// only on the file it is given (a copy made by the harness while the service was stopped). A refused downgrade
// (migration 13 aborts while a usage row with no selector exists) exits non-zero and leaves the data as it was.
//
//	migfixture -db /path/to/copy/mandatary.db -migrations internal/store/migrations -to 13
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "", "path of the SQLite file to lower (a copy)")
	dir := flag.String("migrations", "", "directory with the goose SQL migrations")
	to := flag.Int64("to", -1, "target schema version")
	flag.Parse()
	if *dbPath == "" || *dir == "" || *to < 0 {
		fmt.Fprintln(os.Stderr, "usage: migfixture -db FILE -migrations DIR -to N")
		os.Exit(2)
	}
	if st, err := os.Stat(*dbPath); err != nil || !st.Mode().IsRegular() {
		fmt.Fprintln(os.Stderr, "migfixture: -db must be an existing regular file")
		os.Exit(2)
	}
	db, err := sql.Open("sqlite", "file:"+*dbPath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		fmt.Fprintln(os.Stderr, "migfixture: open:", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS(*dir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "migfixture: provider:", err)
		os.Exit(1)
	}
	ctx := context.Background()
	from, err := p.GetDBVersion(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migfixture: version:", err)
		os.Exit(1)
	}
	_, derr := p.DownTo(ctx, *to)
	now, verr := p.GetDBVersion(ctx)
	if verr != nil {
		fmt.Fprintln(os.Stderr, "migfixture: version:", verr)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"from": from, "to": now, "target": *to, "refused": derr != nil})
	if derr != nil {
		fmt.Fprintln(os.Stderr, "migfixture: downgrade refused:", derr)
		os.Exit(1)
	}
}
