package store_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/pressly/goose/v3"
	sqlite "modernc.org/sqlite"
)

func fixture(t *testing.T) (*sql.DB, *goose.Provider) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "fixture.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	exec(t, db, "PRAGMA foreign_keys = ON")
	p, err := goose.NewProvider(goose.DialectSQLite3, db, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	return db, p
}
func exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatalf("fixture SQL failed: %v", err)
	}
}
func rejects(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), query, args...)
	var constraint *sqlite.Error
	if !errors.As(err, &constraint) || constraint.Code()&255 != 19 {
		t.Fatalf("expected SQLite constraint rejection, got %v", err)
	}
}
func integer(t *testing.T, db *sql.DB, query string) int64 {
	t.Helper()
	var value int64
	if err := db.QueryRowContext(t.Context(), query).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestFreshDownUpMigration(t *testing.T) {
	db, p := fixture(t)
	for range 2 {
		var id, slug string
		if err := db.QueryRowContext(t.Context(), "SELECT id, slug FROM endpoints").Scan(&id, &slug); err != nil {
			t.Fatal(err)
		}
		if _, err := domain.ParseEndpointID(id); err != nil || slug != domain.LocalEndpointSlug {
			t.Fatal("invalid local identity")
		}
		if integer(t, db, "SELECT restore_quarantined FROM installation_control") != 1 {
			t.Fatal("fresh control not quarantined")
		}
		if integer(t, db, "SELECT credential_generation + session_generation + authority_generation + restore_generation FROM installation_control") != 0 {
			t.Fatal("fresh generation active")
		}
		if _, err := p.Down(t.Context()); err != nil {
			t.Fatal(err)
		}
		if integer(t, db, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'goose_db_version'") != 0 {
			t.Fatal("down left application tables")
		}
		if _, err := p.Up(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}
func principals(t *testing.T, db *sql.DB) {
	t.Helper()
	exec(t, db, "INSERT INTO users(id,username) VALUES ('u1','alice'),('u2','bob')")
	exec(t, db, "INSERT INTO groups(id,name) VALUES ('g1','operators')")
}
func TestPrincipalOwnershipAndRoles(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	rejects(t, db, "INSERT INTO agents(id,name) VALUES ('a1','unowned')")
	rejects(t, db, "INSERT INTO agents(id,name,owner_user_id,owner_group_id) VALUES ('a1','both','u1','g1')")
	rejects(t, db, "INSERT INTO agents(id,name,owner_user_id) VALUES ('a1','missing','absent')")
	exec(t, db, "INSERT INTO agents(id,name,owner_user_id) VALUES ('a1','individual','u1')")
	exec(t, db, "INSERT INTO agents(id,name,owner_group_id) VALUES ('a2','service','g1')")
	rejects(t, db, "UPDATE agents SET owner_user_id=NULL WHERE id='a1'")
	rejects(t, db, "DELETE FROM users WHERE id='u1'")
	rejects(t, db, "DELETE FROM groups WHERE id='g1'")
	if integer(t, db, "SELECT count(*) FROM agent_group_memberships") != 0 {
		t.Fatal("ownership implied membership")
	}
	exec(t, db, "INSERT INTO agent_group_memberships(agent_id,group_id) VALUES ('a1','g1')")
	rejects(t, db, "INSERT INTO agent_group_memberships(agent_id,group_id) VALUES ('a1','g1')")
	rejects(t, db, "INSERT INTO user_group_memberships(user_id,group_id) VALUES ('absent','g1')")
	exec(t, db, "INSERT INTO administrative_roles(id,user_id,role) VALUES ('r1','u1','super_admin')")
	exec(t, db, "UPDATE administrative_roles SET state='active',authority_generation=1 WHERE id='r1'")
	rejects(t, db, "INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES ('r2','u2','super_admin','active',1)")
	rejects(t, db, "INSERT INTO administrative_roles(id,user_id,role) VALUES ('r3','u2','unknown')")
	exec(t, db, "INSERT INTO administrative_roles(id,user_id,role,endpoint_id) SELECT 'r2','u2','endpoint_admin',id FROM endpoints")
	rejects(t, db, "UPDATE administrative_roles SET state='active',authority_generation=1 WHERE id='r2'")
	rejects(t, db, "INSERT INTO administrative_roles(id,user_id,role,endpoint_id) SELECT 'r3','u2','super_admin',id FROM endpoints")
}
func TestEndpointScopedSelectorsAndPolicies(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	exec(t, db, "INSERT INTO endpoints(id,slug,name,transport) VALUES ('70000000-0000-4000-8000-000000000002','remote','Remote','ssh')")
	exec(t, db, "INSERT INTO container_selectors(id,endpoint_id,container_name) SELECT 's-'||slug,id,'db' FROM endpoints")
	if integer(t, db, "SELECT count(*) FROM container_selectors WHERE container_name='db'") != 2 {
		t.Fatal("endpoint names collapsed")
	}
	rejects(t, db, "INSERT INTO container_selectors(id,endpoint_id,container_name) VALUES ('bad','missing','db')")
	exec(t, db, "INSERT INTO policies(id,user_id,endpoint_id,selector_id,operation,effect) SELECT 'p1','u1',endpoint_id,id,'container:logs','ALLOW' FROM container_selectors WHERE id='s-local'")
	rejects(t, db, "UPDATE policies SET endpoint_id='70000000-0000-4000-8000-000000000002' WHERE id='p1'")
	rejects(t, db, "UPDATE policies SET effect='allow' WHERE id='p1'")
	rejects(t, db, "UPDATE policies SET group_id='g1' WHERE id='p1'")
	rejects(t, db, "UPDATE policies SET user_id=NULL WHERE id='p1'")
	for _, op := range []string{"container:exec", "endpoint:discover", "raw:proxy", ""} {
		rejects(t, db, "UPDATE policies SET operation=? WHERE id='p1'", op)
	}
	for _, op := range []string{"container:logs", "container:inspect_status", "container:inspect_config", "container:start", "container:stop", "container:restart"} {
		exec(t, db, "UPDATE policies SET operation=?, effect='DENY' WHERE id='p1'", op)
	}
	rejects(t, db, "UPDATE policies SET state='active' WHERE id='p1'")
	exec(t, db, "UPDATE policies SET state='active',authority_generation=1 WHERE id='p1'")
}
func TestAuthenticatorAndSessionStructure(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	exec(t, db, "INSERT INTO authenticators(id,user_id,kind) VALUES ('pwd','u1','password'),('otp','u1','totp'),('key','u1','webauthn'),('code','u1','recovery_code')")
	if integer(t, db, "SELECT count(*) FROM authenticators WHERE state='quarantined' AND credential_generation=0 AND failed_attempts=0") != 4 {
		t.Fatal("credentials not inactive")
	}
	rejects(t, db, "INSERT INTO authenticators(id,user_id,kind) VALUES ('bad','missing','password')")
	rejects(t, db, "INSERT INTO authenticators(id,user_id,kind) VALUES ('bad','u1','email_otp')")
	rejects(t, db, "UPDATE authenticators SET state='active' WHERE id='pwd'")
	rejects(t, db, "UPDATE authenticators SET retry_ceiling=101 WHERE id='otp'")
	rejects(t, db, "UPDATE authenticators SET failed_attempts=-1 WHERE id='otp'")
	exec(t, db, "UPDATE authenticators SET failed_attempts=100,state='disabled' WHERE id='otp'")
	rejects(t, db, "UPDATE authenticators SET state='active',credential_generation=1,bound_at=1 WHERE id='otp'")
	if integer(t, db, "SELECT failed_attempts FROM authenticators WHERE id='key'") != 0 {
		t.Fatal("unrelated authenticator disabled")
	}
	exec(t, db, "UPDATE authenticators SET password_codepoints=14 WHERE id='pwd'")
	rejects(t, db, "UPDATE users SET mfa_requirement='optional' WHERE id='u1'")
	exec(t, db, "UPDATE authenticators SET password_codepoints=15 WHERE id='pwd'")
	exec(t, db, "UPDATE users SET mfa_requirement='optional' WHERE id='u1'")
	rejects(t, db, "UPDATE authenticators SET password_codepoints=14 WHERE id='pwd'")
	rejects(t, db, "UPDATE authenticators SET password_codepoints=7 WHERE id='pwd'")
	rejects(t, db, "UPDATE authenticators SET password_codepoints=129 WHERE id='pwd'")
	exec(t, db, "UPDATE authenticators SET last_accepted_totp_step=17 WHERE id='otp'")
	rejects(t, db, "UPDATE authenticators SET last_accepted_totp_step=16 WHERE id='otp'")
	rejects(t, db, "UPDATE authenticators SET last_accepted_totp_step=NULL WHERE id='otp'")
	rejects(t, db, "UPDATE authenticators SET backup_state=1,backup_eligible=0 WHERE id='key'")
	exec(t, db, "INSERT INTO sessions(id,user_id,secret_hash,purpose,created_at,expires_at,last_activity_at) VALUES ('s1','u1',zeroblob(32),'recovery',1,100,1)")
	if integer(t, db, "SELECT credential_generation+session_generation+achieved_assurance FROM sessions") != 0 {
		t.Fatal("session default upgraded")
	}
	rejects(t, db, "UPDATE sessions SET achieved_assurance=2,methods=3,authenticated_at=1 WHERE id='s1'")
	exec(t, db, "UPDATE sessions SET purpose='normal' WHERE id='s1'")
	rejects(t, db, "UPDATE sessions SET achieved_assurance=2,methods=1,authenticated_at=1 WHERE id='s1'")
	rejects(t, db, "UPDATE sessions SET achieved_assurance=2,methods=16,authenticated_at=1 WHERE id='s1'")
	exec(t, db, "UPDATE sessions SET achieved_assurance=2,methods=3,authenticated_at=1 WHERE id='s1'")
	rejects(t, db, "UPDATE sessions SET phishing_resistant=1 WHERE id='s1'")
	rejects(t, db, "UPDATE sessions SET state='active' WHERE id='s1'")
	rejects(t, db, "UPDATE sessions SET secret_hash=x'00' WHERE id='s1'")
	rejects(t, db, "UPDATE sessions SET expires_at=1 WHERE id='s1'")
	exec(t, db, "INSERT INTO agents(id,name,owner_user_id) VALUES ('a1','bot','u1')")
	exec(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at) VALUES ('token','a1',zeroblob(32),'fixture',1,100)")
	rejects(t, db, "UPDATE agent_credentials SET state='active' WHERE id='token'")
	rejects(t, db, "UPDATE agent_credentials SET token_hash=x'00' WHERE id='token'")
	rejects(t, db, "UPDATE agent_credentials SET expires_at=NULL WHERE id='token'")
	exec(t, db, "UPDATE agent_credentials SET expires_at=NULL,nonexpiring_approved=1 WHERE id='token'")
	exec(t, db, "INSERT INTO auth_challenges(id,user_id,purpose,challenge_hash,issued_at,expires_at) VALUES ('c1','u1','webauthn_assertion',zeroblob(32),1,100)")
	rejects(t, db, "INSERT INTO auth_challenges(id,user_id,purpose,challenge_hash,issued_at,expires_at) VALUES ('c2','u1','login_email',zeroblob(32),1,100)")
}
func TestEndpointConstraints(t *testing.T) {
	db, _ := fixture(t)
	rejects(t, db, "INSERT INTO endpoints(id,slug,name,transport) SELECT id,'other','Other','unix' FROM endpoints")
	rejects(t, db, "INSERT INTO endpoints(id,slug,name,transport) VALUES ('70000000-0000-4000-8000-000000000002','local','Other','unix')")
	rejects(t, db, "INSERT INTO endpoints(id,slug,name,transport) VALUES ('70000000-0000-4000-8000-000000000002','other','Local','unix')")
	for _, id := range []string{"local", "00000000-0000-0000-0000-000000000000", "70000000-0000-4000-8000-00000000000z"} {
		rejects(t, db, "INSERT INTO endpoints(id,slug,name,transport) VALUES (?, 'other','Other','unix')", id)
	}
	exec(t, db, "INSERT INTO endpoints(id,slug,name,transport) VALUES ('70000000-0000-4000-8000-000000000002','remote','Remote','mtls')")
	rejects(t, db, "UPDATE endpoints SET state='active' WHERE slug='remote'")
	rejects(t, db, "UPDATE endpoints SET transport='tcp' WHERE slug='remote'")
}
