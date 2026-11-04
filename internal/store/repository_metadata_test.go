package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExistingOpenRejectsInvalidMetadataWithoutMutation(t *testing.T) {
	for _, damage := range []struct {
		name, sql string
	}{
		{"missing-table", "DROP TABLE goose_db_version"},
		{"empty", "DELETE FROM goose_db_version"},
		{"missing-zero", "DELETE FROM goose_db_version WHERE version_id=0"},
		{"missing-migration", "DELETE FROM goose_db_version WHERE version_id=1"},
		{"future-version", "UPDATE goose_db_version SET version_id=3 WHERE version_id=2"},
		{"not-applied", "UPDATE goose_db_version SET is_applied=0 WHERE version_id=2"},
		{"duplicate", "INSERT INTO goose_db_version(version_id,is_applied) VALUES(2,1)"},
	} {
		for _, existingOnly := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/helper=%t", damage.name, existingOnly), func(t *testing.T) {
				r, options := openFixture(t)
				if _, err := r.writer.ExecContext(t.Context(), damage.sql); err != nil {
					t.Fatal(err)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				inspector, err := openPool(options.DataDir, true)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = inspector.Close() }()
				before := metadataSnapshot(t, inspector, damage.name != "missing-table")
				options.ExistingOnly = existingOnly
				bad, err := Open(t.Context(), options)
				if err == nil {
					_ = bad.Close()
					t.Error("invalid migration metadata accepted")
				} else if !errors.Is(err, ErrStorage) {
					t.Error("metadata failure was not redacted")
				}
				if after := metadataSnapshot(t, inspector, damage.name != "missing-table"); after != before {
					t.Fatal("refused existing open mutated schema or migration metadata")
				}
			})
		}
	}
}

// Inspect logical schema, SQLite's schema counter and every migration row using
// an independent read-only connection. Even a refused create/drop or zero-row
// repair must be visible, not mistaken for a harmless error return.
func metadataSnapshot(t *testing.T, db *sql.DB, hasMetadata bool) string {
	t.Helper()
	var version int
	if err := db.QueryRowContext(t.Context(), "PRAGMA schema_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	var snapshot strings.Builder
	fmt.Fprintln(&snapshot, version)
	queries := []string{"SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name"}
	if hasMetadata {
		queries = append(queries, "SELECT quote(id),quote(version_id),quote(is_applied),quote(tstamp) FROM goose_db_version ORDER BY id")
	}
	for _, query := range queries {
		rows, err := db.QueryContext(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var a, b, c, d string
			if err := rows.Scan(&a, &b, &c, &d); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			fmt.Fprintf(&snapshot, "%q %q %q %q\n", a, b, c, d)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return snapshot.String()
}
