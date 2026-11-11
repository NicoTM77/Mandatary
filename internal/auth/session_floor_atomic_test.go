package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/pressly/goose/v3"
)

// addBoundFactor adds a bound second factor of the fixture user and retires it in
// ONE update, the way the lifecycle statements do. reason nil is the legacy,
// provenance-less revocation.
func addBoundFactor(t *testing.T, exec func(string, ...any), id, kind string, reason any) {
	t.Helper()
	if kind == "totp" {
		exec(`INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,encrypted_secret) VALUES(?,'u','totp','active',1,5,5,x'01')`, id)
	} else {
		exec(`INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,public_key,external_credential_id) VALUES(?,'u','webauthn','active',1,5,5,x'01',?)`, id, []byte(id))
	}
	exec(`UPDATE authenticators SET state='revoked',revoked_at=6,changed_at=6,retirement_reason=? WHERE id=?`, reason, id)
}

// An approved restricted recovery that bound a verified replacement settles the
// ambiguous (legacy/protective) retirements and records its own replacements; it
// never rewrites a deliberate authorised removal.
func TestSessionFloorRecoverySettlesAmbiguousRetirements(t *testing.T) { // E08 recovery, E09
	l, db, session := lifecycleFixture(t)
	exec := func(q string, args ...any) { execFixture(t, db, q, args...) }
	reasonOf := func(id string) string {
		var r *string
		if err := db.QueryRow(`SELECT retirement_reason FROM authenticators WHERE id=?`, id).Scan(&r); err != nil {
			t.Fatal(err)
		}
		if r == nil {
			return "<NULL>"
		}
		return *r
	}
	old, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, old.ID, enrollmentCode(t, old, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE sessions SET achieved_assurance=2,methods=3`)
	exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, old.ID)
	addBoundFactor(t, exec, "legacy-totp", "totp", nil)
	addBoundFactor(t, exec, "protective-key", "webauthn", "protective")
	addBoundFactor(t, exec, "removed-key", "webauthn", "authorized_removal")
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), batch.ExportOnce()[0], "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	capability, _ := recovery.ExportOnce()
	next, err := l.BeginRecoveredTOTP(t.Context(), capability, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is settled until the replacement proof succeeds.
	if got := reasonOf("legacy-totp"); got != "<NULL>" {
		t.Fatal("recovery settled records before a verified replacement", got)
	}
	if err = l.ConfirmRecoveredTOTP(t.Context(), capability, next.ID, enrollmentCode(t, next, l.now()), "192.0.2.3"); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{
		old.ID: retireRecovered, "legacy-totp": retireRecovered, "protective-key": retireRecovered, "removed-key": retireAuthorized,
	} {
		if got := reasonOf(id); got != want {
			t.Fatalf("%s provenance %s, want %s", id, got, want)
		}
	}
	if reasonOf(next.ID) != "<NULL>" {
		t.Fatal("the live replacement acquired a retirement reason")
	}
}

// Failure in the settlement statement rolls the whole recovery completion back:
// no replacement activation, no old-factor revocation, no half-settled floor.
func TestSessionFloorRecoverySettlementIsAtomic(t *testing.T) { // atomic recovery, E08
	l, db, session := lifecycleFixture(t)
	exec := func(q string, args ...any) { execFixture(t, db, q, args...) }
	old, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if err = l.ConfirmTOTP(t.Context(), session, old.ID, enrollmentCode(t, old, l.now()), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE sessions SET achieved_assurance=2,methods=3`)
	exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, old.ID)
	batch, err := l.IssueRecoveryCodes(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), batch.ExportOnce()[0], "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	capability, _ := recovery.ExportOnce()
	next, err := l.BeginRecoveredTOTP(t.Context(), capability, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	exec(`CREATE TRIGGER reject_settlement BEFORE UPDATE ON authenticators WHEN NEW.retirement_reason='recovery_replacement' BEGIN SELECT RAISE(ABORT,'synthetic settlement failure'); END`)
	if err = l.ConfirmRecoveredTOTP(t.Context(), capability, next.ID, enrollmentCode(t, next, l.now()), "192.0.2.3"); err != ErrDenied {
		t.Fatal("recovery acknowledged a failed settlement", err)
	}
	state := func(id string) string {
		var s string
		if err := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if state(old.ID) != "active" || state(next.ID) != "pending" {
		t.Fatalf("partial recovery commit: old=%s replacement=%s", state(old.ID), state(next.ID))
	}
	var cap string
	if err = db.QueryRow(`SELECT state FROM recovery_capabilities`).Scan(&cap); err != nil || cap != "restricted" {
		t.Fatal("capability consumed by a rolled-back completion", cap, err)
	}
	if n := scalarFixture(t, db, `SELECT count(*) FROM authenticators WHERE retirement_reason IS NOT NULL`); n != 0 {
		t.Fatal("provenance committed without the transition", n)
	}
}

// Provenance and revocation are one transaction. A failure after the revoking
// statement leaves neither (and never an authorised-looking record), and the
// account does not return to AAL1 on a half-applied removal.
func TestSessionFloorProvenanceIsAtomicWithRevocation(t *testing.T) { // atomicity / durability E09, E12
	for _, path := range []string{"report", "removal"} {
		t.Run(path, func(t *testing.T) {
			e := newSessionEnv(t)
			id, en := e.mfaAccount()
			fresh := e.aal2TOTP(id, en) // a live session row makes the session-invalidation statement run
			e.exec(`CREATE TRIGGER reject_invalidation BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT,'synthetic invalidation failure'); END`)
			var err error
			if path == "report" {
				err = e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.74")
			} else {
				err = e.l.RevokeTOTP(t.Context(), fresh.Secret(), id)
			}
			if err != ErrDenied {
				t.Fatalf("%s acknowledged although invalidation failed: %v", path, err)
			}
			var state string
			if qe := e.db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, id).Scan(&state); qe != nil || state != "active" || e.retirement(id).Valid {
				t.Fatalf("partial commit: state=%s provenance=%v", state, e.retirement(id))
			}
			e.exec(`DROP TRIGGER reject_invalidation`)
			e.restart()
			e.clock.Advance(time.Second)
			// The factor and its floor are intact after the failed transition: the
			// approved lower-assurance login still exists but carries no authority.
			r, lerr := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.75")
			if lerr != nil || r.Session.Info.Assurance != AssurancePreauth {
				t.Fatalf("login after a failed %s: %v %+v", path, lerr, r.Session.Info)
			}
			e.denyEveryWeakWrite(t, e.plantPasswordOnly(), "after failed "+path)
		})
	}
}

// Real migration: an existing revoked second factor is kept ambiguous (NULL) and
// stays counted; nothing is backfilled; the schema carries the provenance rules.
func TestSessionFloorMigrationNeverBackfillsAmbiguousRetirements(t *testing.T) { // E09: conservative migrated records
	_, r, db := serviceFixture(t)
	execFixture(t, db, `UPDATE users SET mfa_requirement='optional' WHERE id='u'`)
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
	// A pre-10 database: revoked bound factors of every legacy kind, no provenance column.
	if _, e = provider.DownTo(t.Context(), 9); e != nil {
		t.Fatal(e)
	}
	if n := scalarFixture(t, db, `SELECT count(*) FROM pragma_table_info('authenticators') WHERE name='retirement_reason'`); n != 0 {
		t.Fatal("down migration kept the column")
	}
	execFixture(t, db, `INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,encrypted_secret) VALUES('old-totp','u','totp','active',1,5,5,x'01')`)
	execFixture(t, db, `INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,public_key,external_credential_id) VALUES('old-key','u','webauthn','active',1,5,5,x'01',x'02')`)
	execFixture(t, db, `UPDATE authenticators SET state='revoked',revoked_at=6 WHERE id IN ('old-totp','old-key')`)
	key, e := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if e != nil {
		t.Fatal(e)
	}
	options := store.Options{DataDir: filepath.Dir(file), MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()}
	migrated, e := store.Open(t.Context(), options)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := migrated.Close(); e != nil {
			t.Error(e)
		}
	}()
	if n := scalarFixture(t, db, `SELECT count(*) FROM authenticators WHERE id IN ('old-totp','old-key') AND retirement_reason IS NULL`); n != 2 {
		t.Fatal("migration backfilled or guessed a provenance for an existing revocation", n)
	}
	if n := scalarFixture(t, db, `SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'authenticator_retirement_%'`); n != 4 {
		t.Fatal("provenance triggers missing after migration", n)
	}
	var floor, plain int64
	e = migrated.Read(t.Context(), func(q *store.Queries) error {
		c, err := q.GetInstallationControl(t.Context())
		if err != nil {
			return err
		}
		u, err := q.GetUser(t.Context(), "u")
		if err != nil {
			return err
		}
		all, err := q.ListUserAuthenticators(t.Context(), "u")
		if err != nil {
			return err
		}
		floor = assuranceFloor(c, u, false, all)
		var none []store.Authenticator
		for _, a := range all {
			if !isSecondFactor(a) {
				none = append(none, a)
			}
		}
		plain = assuranceFloor(c, u, false, none)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if floor != 2 || plain != 1 {
		t.Fatalf("migrated ambiguous revocations must keep the floor at 2 (got %d); a never-bound account stays 1 (got %d)", floor, plain)
	}
}
