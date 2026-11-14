package store

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"strings"
)

// SchemaVersion is the migration version this build creates and the only database schema a logical
// backup written by this build describes.
func SchemaVersion() int64 { return currentSchemaVersion }

const backupKeyInfoPrefix = "mandatary/backup/"

// DeriveBackupKey returns a 32-byte subkey bound to this repository's master key, the caller-chosen
// random salt and a purpose string under "mandatary/backup/". The master key itself is never exposed:
// the logical backup service gets distinct integrity and encryption subkeys, and no other purpose
// can be derived through this method. The returned slice belongs to the caller, who clears it.
func (r *Repository) DeriveBackupKey(info string, salt []byte) ([]byte, error) {
	r.lifecycle.RLock()
	defer r.lifecycle.RUnlock()
	if r.closed || r.poisoned.Load() || r.cipher == nil || !strings.HasPrefix(info, backupKeyInfoPrefix) || len(info) > 128 || len(salt) != saltSize {
		return nil, ErrKey
	}
	key, err := hkdf.Key(sha256.New, r.cipher.key.value[:], salt, info, 32)
	if err != nil {
		return nil, ErrKey
	}
	return key, nil
}

// ForeignKeyViolations counts the rows SQLite reports from PRAGMA foreign_key_check inside the
// current transaction. A restore runs it before commit so a structurally inconsistent import can
// never become durable (TD 6.3 post-restore integrity check).
func (q *Queries) ForeignKeyViolations(ctx context.Context) (int, error) {
	rows, err := q.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, ErrStorage
	}
	defer func() { _ = rows.Close() }() // read-only cursor
	n := 0
	for rows.Next() {
		n++
	}
	if rows.Err() != nil {
		return 0, ErrStorage
	}
	return n, nil
}
