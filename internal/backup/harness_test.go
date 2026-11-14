package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

const (
	keyHexA  = "1111111111111111111111111111111111111111111111111111111111111111"
	keyHexB  = "2222222222222222222222222222222222222222222222222222222222222222"
	baseTime = int64(2000000010)
)

var seedBytes = []byte("synthetic-totp-seed-0123456789abcdef")

// env is a real SQLite repository (store.Open) plus a second raw handle for fixtures and assertions.
// Everything cryptographic is real; only the clock and the records are synthetic.
type env struct {
	t    *testing.T
	repo *store.Repository
	db   *sql.DB
	svc  *Service
	dir  string
}

func newEnv(t *testing.T, keyHex string) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	key, err := store.LoadMasterKey(keyHex, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := store.Open(t.Context(), store.Options{DataDir: dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	db, err := sql.Open("sqlite", filepath.Join(dir, "mandatary.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err = db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	svc, err := New(repo, "test-build")
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return time.Unix(baseTime, 0) }
	return &env{t: t, repo: repo, db: db, svc: svc, dir: dir}
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(q, args...); err != nil {
		e.t.Fatalf("%v: %s", err, q)
	}
}

func (e *env) scalar(q string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%v: %s", err, q)
	}
	return n
}

func (e *env) text(q string, args ...any) string {
	e.t.Helper()
	var s sql.NullString
	if err := e.db.QueryRow(q, args...).Scan(&s); err != nil {
		e.t.Fatalf("%v: %s", err, q)
	}
	return s.String
}

// activate marks the installation as an ordinary running one (all generations positive, no quarantine).
func (e *env) activate() {
	e.exec(`UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0`)
	e.exec(`UPDATE endpoints SET state='active',authority_generation=1 WHERE slug='local'`)
}

// seed builds a small but complete installation: one administrator with password and TOTP, a user
// whose stored MFA setting is the weak "optional", a group, an agent with an active token, a
// membership, ALLOW and DENY rules, an address, a live session and some usage.
func (e *env) seed() {
	e.t.Helper()
	e.activate()
	totp, err := e.repo.EncryptSecret("totp", "adm-totp", seedBytes)
	if err != nil {
		e.t.Fatal(err)
	}
	e.exec(`INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES('adm','admin','active','required',1,1),('alice','alice','active','optional',1,1)`)
	e.exec(`INSERT INTO groups(id,name,state,authority_generation) VALUES('ops','ops','active',1)`)
	e.exec(`INSERT INTO agents(id,name,owner_user_id,state,credential_generation,authority_generation) VALUES('bot','bot','alice','active',1,1)`)
	e.exec(`INSERT INTO user_group_memberships(user_id,group_id,state,authority_generation) VALUES('alice','ops','active',1)`)
	e.exec(`INSERT INTO agent_group_memberships(agent_id,group_id,state,authority_generation) VALUES('bot','ops','active',1)`)
	e.exec(`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('role-adm','adm','super_admin','active',1)`)
	ep := e.text(`SELECT id FROM endpoints WHERE slug='local'`)
	e.exec(`INSERT INTO container_selectors(id,endpoint_id,container_name) VALUES('sel-web',?,'web'),('sel-db',?,'db')`, ep, ep)
	e.exec(`INSERT INTO policies(id,agent_id,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES('pol-allow',  'bot', ?, 'sel-web','container:logs','ALLOW','active',1)`, ep)
	e.exec(`INSERT INTO policies(id,user_id,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES('pol-deny','alice', ?, 'sel-db','container:start','DENY','active',1)`, ep)
	e.exec(`INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,verifier_hash,password_codepoints,password_format,max_assurance) VALUES('adm-pwd','adm','password','active',1,100,100,?,30,'synthetic-format',1)`, []byte("synthetic-verifier-do-not-leak-0001"))
	e.exec(`INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,encrypted_secret,totp_algorithm,max_assurance) VALUES('adm-totp','adm','totp','active',1,100,100,?,'SHA256',2)`, totp)
	e.exec(`INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,nonexpiring_approved,credential_generation,state) VALUES('cred-1','bot',?,'mdt_abcd',1999999000,2000999999,0,1,'active')`, bytes.Repeat([]byte{0xAB}, 32))
	e.exec(`INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('addr-1','adm','admin@example.invalid',1,100,100,'active',1)`)
	sum := bytes.Repeat([]byte{0xCD}, 32)
	e.exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,authenticated_at,created_at,expires_at,last_activity_at,credential_generation,session_generation,state) VALUES('sess-1','adm',?,'normal',1,1,?,?,?,?,1,1,'active')`, sum, baseTime, baseTime, baseTime+3600, baseTime)
	e.exec(`INSERT INTO usage_stats_hourly(bucket_start,agent_id,endpoint_id,selector_id,operation,allowed_count) VALUES(?, 'bot', ?, 'sel-web','container:logs',7)`, (baseTime/3600)*3600, ep)
}

func allow(context.Context, *store.Queries, store.InstallationControl, int64) error { return nil }
func refuse(context.Context, *store.Queries, store.InstallationControl, int64) error {
	return errors.New("not authorized")
}

func (e *env) export(mode Mode) []byte {
	e.t.Helper()
	raw, _, err := e.svc.Export(e.t.Context(), mode, allow)
	if err != nil {
		e.t.Fatalf("export %s: %v", mode, err)
	}
	return raw
}

func (e *env) verify(raw []byte) *Verified {
	e.t.Helper()
	v, err := e.svc.Verify(raw)
	if err != nil {
		e.t.Fatalf("verify: %v", err)
	}
	return v
}

func (e *env) restore(raw []byte, init Initiator, ack bool) (Report, error) {
	e.t.Helper()
	v, err := e.svc.Verify(raw)
	if err != nil {
		return Report{}, err
	}
	return e.svc.Restore(e.t.Context(), v, RestoreOptions{Initiator: init, Authorize: allow, AcknowledgeUnauthenticated: ack})
}

func (e *env) mustRestore(raw []byte) Report {
	e.t.Helper()
	r, err := e.restore(raw, InitiatorHost, true)
	if err != nil {
		e.t.Fatalf("restore: %v", err)
	}
	return r
}

// controls returns the live control row.
func (e *env) controls() store.InstallationControl {
	e.t.Helper()
	var c store.InstallationControl
	if err := e.db.QueryRow(`SELECT singleton,credential_generation,session_generation,authority_generation,restore_generation,restore_quarantined FROM installation_control`).
		Scan(&c.Singleton, &c.CredentialGeneration, &c.SessionGeneration, &c.AuthorityGeneration, &c.RestoreGeneration, &c.RestoreQuarantined); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// leaveQuarantine models what the host-authorized recovery ceremony does (it is delivered and tested
// with the ceremony): clear the flag and rotate every generation again.
func (e *env) leaveQuarantine() {
	e.exec(`UPDATE installation_control SET restore_quarantined=0,credential_generation=credential_generation+1,session_generation=session_generation+1,authority_generation=authority_generation+1,restore_generation=restore_generation+1`)
}

func mutate(t *testing.T, raw []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func recordsOf(m map[string]any, kind string) []any {
	return m["scope"].(map[string]any)[kind].([]any)
}

func contains(raw []byte, needle string) bool { return strings.Contains(string(raw), needle) }

func osUID() int { return os.Geteuid() }
func osGID() int { return os.Getegid() }
