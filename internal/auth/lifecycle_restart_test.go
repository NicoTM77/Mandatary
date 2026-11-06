package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

type unavailableEntropy struct{}

func (unavailableEntropy) Read([]byte) (int, error) {
	return 0, errors.New("synthetic entropy failure")
}
func TestAuthenticatorEntropyFailure(t *testing.T) {
	l, _, session := lifecycleFixture(t)
	old := rand.Reader
	rand.Reader = unavailableEntropy{}
	defer func() { rand.Reader = old }()
	if _, err := l.BeginTOTP(t.Context(), session, "SHA256"); err != ErrDenied {
		t.Fatal("entropy failure issued seed")
	}
}
func reopenLifecycle(t *testing.T, l *Lifecycle, db *sql.DB) *Lifecycle {
	t.Helper()
	var path string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := l.repo.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := store.Open(t.Context(), store.Options{DataDir: filepath.Dir(path), MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	next, err := NewLifecycle(r, l.notices)
	if err != nil {
		t.Fatal(err)
	}
	next.now = l.now
	return next
}
func TestTOTPReplaySurvivesRepositoryRestart(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	now := l.now().Add(30 * time.Second)
	l.now = func() time.Time { return now }
	code := enrollmentCode(t, e, now)
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, code, "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	l = reopenLifecycle(t, l, db)
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, code, "192.0.2.3"); err != ErrDenied {
		t.Fatal("restart reset replay state")
	}
	now = now.Add(-30 * time.Second)
	if _, err = l.VerifyTOTP(t.Context(), "u", e.ID, enrollmentCode(t, e, now), "192.0.2.4"); err != ErrDenied {
		t.Fatal("clock rollback reset replay state")
	}
}
func TestRecoveryCodeEntropyHashAndRestart(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	codes := batch.ExportOnce()
	seen := map[string]bool{}
	for _, code := range codes {
		parts := strings.Split(code, ".")
		if len(parts) != 2 || len(parts[0]) != 64 {
			t.Fatal("invalid encoding")
		}
		secret, err := hex.DecodeString(parts[1])
		if err != nil || len(secret) != 16 || seen[code] {
			t.Fatal("entropy length/encoding/collision")
		}
		seen[code] = true
		var verifier []byte
		if err = db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id=?`, parts[0]).Scan(&verifier); err != nil {
			t.Fatal(err)
		}
		expected := sha256.Sum256([]byte(code))
		if !bytes.Equal(verifier, expected[:]) || bytes.Contains(verifier, secret) {
			t.Fatal("verifier not exact hash-only")
		}
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	l = reopenLifecycle(t, l, db)
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.3"); err != ErrDenied {
		t.Fatal("consumed code revived on restart")
	}
	if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[1], "192.0.2.4"); err != nil {
		t.Fatal("independent saved code unavailable", err)
	}
}
func TestProtectiveIntentSurvivesRepairAndRestart(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_notice BEFORE INSERT ON security_notice_outbox BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = l.RevokeTOTP(t.Context(), session, e.ID); err != ErrDenied {
		t.Fatal("uncertain notice acknowledged")
	}
	var pending int
	if err = db.QueryRow(`SELECT count(*) FROM protective_notice_intents WHERE state='pending'`).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("no durable repair marker")
	}
	if _, err = db.Exec(`DROP TRIGGER reject_notice`); err != nil {
		t.Fatal(err)
	}
	l = reopenLifecycle(t, l, db)
	if err = l.expandProtectiveIntents(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = l.expandProtectiveIntents(t.Context()); err != nil {
		t.Fatal("repair was not idempotent")
	}
	var notices int
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id WHERE e.event_type='authenticator_removed'`).Scan(&notices); err != nil || notices != 2 {
		t.Fatal("repair lost/duplicated recipients")
	}
}
