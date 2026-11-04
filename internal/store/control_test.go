package store_test

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
)

func TestControlGenerationAndRevocationStructure(t *testing.T) {
	db, _ := fixture(t)
	exec(t, db, `UPDATE installation_control SET credential_generation=2,session_generation=2,authority_generation=2,restore_generation=2`)
	rejects(t, db, `UPDATE installation_control SET credential_generation=1`)
	rejects(t, db, `UPDATE installation_control SET session_generation=1`)
	rejects(t, db, `UPDATE installation_control SET authority_generation=1`)
	rejects(t, db, `UPDATE installation_control SET restore_generation=1`)
	rejects(t, db, `UPDATE installation_control SET restore_quarantined=NULL`)
	principals(t, db)
	exec(t, db, `INSERT INTO authenticators(id,user_id,kind,verifier_hash,password_codepoints,password_format,bound_at,credential_generation) VALUES ('p','u1','password',x'01',15,'fixture',1,2)`)
	exec(t, db, `UPDATE authenticators SET revoked_at=2 WHERE id='p'`)
	rejects(t, db, `UPDATE authenticators SET state='active' WHERE id='p'`)
}
func TestRetryAndReplayStateSurviveReopen(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	exec(t, db, `INSERT INTO authenticators(id,user_id,kind,last_accepted_totp_step) VALUES ('otp','u1','totp',15),('other','u1','totp',NULL)`)
	// Verify the schema can store bounded atomic authenticator-specific updates.
	// Throttling/proof evaluation/appropriate-strength reset remain P1.05/06/08.
	var wg sync.WaitGroup
	for range 120 {
		wg.Go(func() {
			_, err := db.ExecContext(t.Context(), `UPDATE authenticators SET failed_attempts=failed_attempts+1,state=CASE WHEN failed_attempts+1=retry_ceiling THEN 'disabled' ELSE state END WHERE id='otp' AND failed_attempts<retry_ceiling`)
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	var path string
	var seq int
	var name string
	if err := db.QueryRowContext(t.Context(), `PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatal("fixture is not file-backed")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	}()
	if integer(t, reopened, `SELECT failed_attempts FROM authenticators WHERE id='otp'`) != 100 {
		t.Fatal("durable counter lost")
	}
	if integer(t, reopened, `SELECT last_accepted_totp_step FROM authenticators WHERE id='otp'`) != 15 {
		t.Fatal("replay state lost")
	}
	if integer(t, reopened, `SELECT failed_attempts FROM authenticators WHERE id='other'`) != 0 {
		t.Fatal("independent factor affected")
	}
	if integer(t, reopened, `SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("quarantine lost")
	}
}
