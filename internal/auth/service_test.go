package auth

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func serviceFixture(t *testing.T) (*Service, *store.Repository, *sql.DB) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	key, e := store.LoadMasterKey(string(bytes.Repeat([]byte("11"), 32)), "")
	if e != nil {
		t.Fatal(e)
	}
	r, e := store.Open(t.Context(), store.Options{DataDir: dir, MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid()})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	db, e := sql.Open("sqlite", filepath.Join(dir, "mandatary.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, s := range []string{`PRAGMA foreign_keys=ON`, `UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0`, `INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES('u','synthetic-user','active','optional',1,1)`, `INSERT INTO authenticators(id,user_id,kind,state,bound_at,credential_generation,password_codepoints,password_format,verifier_hash) VALUES('pwd','u','password','active',1,1,30,'mdt-pwd-u17-nfc-cn-v1',?)`} {
		var e error
		if s[len(s)-1:] == ")" && bytes.Contains([]byte(s), []byte("verifier_hash")) {
			v, err := HashPassword([]byte("a unique synthetic public phrase"))
			if err != nil {
				t.Fatal(err)
			}
			_, e = db.ExecContext(t.Context(), s, v)
		} else {
			_, e = db.ExecContext(t.Context(), s)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	svc, e := NewService(r, DefaultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	return svc, r, db
}
func TestPasswordServiceProofAndSafeParity(t *testing.T) {
	s, _, db := serviceFixture(t)
	result, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1")
	if e != nil || result.UserID != "u" || result.RequiresMFA {
		t.Fatal("valid password proof denied", e)
	}
	for _, name := range []string{"synthetic-user", "unknown-user"} {
		if _, e := s.Prove(t.Context(), name, []byte("incorrect synthetic public phrase"), "192.0.2.2"); e != ErrDenied {
			t.Fatal("unsafe failure", e)
		}
	}
	var count int
	if e := db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id='pwd'`).Scan(&count); e != nil || count != 1 {
		t.Fatal("actual proof failure not counted", count, e)
	}
	_ = context.Background()
	_ = time.Second
}

func TestPasswordThrottleCeilingRestartAndIndependentFactors(t *testing.T) {
	s, r, db := serviceFixture(t)
	now := time.Unix(2000000000, 0)
	s.now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		if _, e := s.Prove(t.Context(), "synthetic-user", []byte("incorrect public proof"), "192.0.2.1"); e != ErrDenied {
			t.Fatal(e)
		}
		// A pre-verification denial cannot slide the next-attempt deadline or count.
		if i >= 4 {
			var before int64
			_ = db.QueryRow(`SELECT next_attempt_at FROM authenticators WHERE id='pwd'`).Scan(&before)
			for j := 0; j < 3; j++ {
				_, _ = s.Prove(t.Context(), "synthetic-user", []byte("incorrect public proof"), "192.0.2.2")
			}
			var after int64
			_ = db.QueryRow(`SELECT next_attempt_at FROM authenticators WHERE id='pwd'`).Scan(&after)
			if before != after {
				t.Fatal("rejected traffic slid deadline")
			}
		}
		now = now.Add(65 * time.Second)
	}
	var n int
	var state string
	if e := db.QueryRow(`SELECT failed_attempts,state FROM authenticators WHERE id='pwd'`).Scan(&n, &state); e != nil || n != 100 || state != "disabled" {
		t.Fatal("ceiling not durable", n, state, e)
	}
	s2, e := NewService(r, DefaultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s2.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.3"); e != ErrDenied {
		t.Fatal("disabled password accepted")
	}
}
func TestPasswordPendingMFADoesNotResetRetries(t *testing.T) {
	s, _, db := serviceFixture(t)
	for _, query := range []string{`UPDATE users SET mfa_requirement='required' WHERE id='u'`, `UPDATE authenticators SET failed_attempts=4 WHERE id='pwd'`, `INSERT INTO authenticators(id,user_id,kind,failed_attempts) VALUES('other','u','totp',9)`} {
		if _, e := db.Exec(query); e != nil {
			t.Fatal(e)
		}
	}
	p, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1")
	if e != nil || !p.RequiresMFA {
		t.Fatal(e)
	}
	var n int
	_ = db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id='pwd'`).Scan(&n)
	if n != 4 {
		t.Fatal("pending MFA reset password")
	}
	_ = db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id='other'`).Scan(&n)
	if n != 9 {
		t.Fatal("unrelated factor reset")
	}
}
func TestPasswordCompromiseRevokesOnlyAffectedSessionsAndRequiresReplacement(t *testing.T) {
	s, _, db := serviceFixture(t)
	for _, query := range []string{`INSERT INTO users(id,username) VALUES('unrelated','unrelated')`, `INSERT INTO sessions(id,user_id,secret_hash,purpose,created_at,expires_at,last_activity_at) VALUES('affected','u',zeroblob(32),'preauth',1,10,1),('unaffected','unrelated',randomblob(32),'preauth',1,10,1)`} {
		if _, e := db.Exec(query); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.MarkCompromised(t.Context(), "u"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1"); e != ErrDenied {
		t.Fatal("compromised password accepted")
	}
	var state string
	_ = db.QueryRow(`SELECT state FROM sessions WHERE id='affected'`).Scan(&state)
	if state != "revoked" {
		t.Fatal("affected session not revoked")
	}
	_ = db.QueryRow(`SELECT state FROM sessions WHERE id='unaffected'`).Scan(&state)
	if state == "revoked" {
		t.Fatal("unrelated session revoked")
	}
}
func TestPasswordReplacementRejectsUnchangedAndStaleBinding(t *testing.T) {
	s, _, db := serviceFixture(t)
	var verifier []byte
	if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&verifier); e != nil {
		t.Fatal(e)
	}
	if e := s.ReplacePassword(t.Context(), "u", verifier, []byte("a unique synthetic public phrase")); e == nil {
		t.Fatal("unchanged compromised password replaced")
	}
	if e := s.MarkCompromised(t.Context(), "u"); e != nil {
		t.Fatal(e)
	}
	if e := s.ReplacePassword(t.Context(), "u", verifier, []byte("another synthetic uncommon phrase")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("another synthetic uncommon phrase"), "192.0.2.1"); e != nil {
		t.Fatal("replacement not accepted", e)
	}
	if e := s.ReplacePassword(t.Context(), "u", verifier, []byte("stale synthetic uncommon phrase")); e == nil {
		t.Fatal("stale replacement succeeded")
	}
	if _, e := db.Exec(`UPDATE installation_control SET restore_quarantined=1,credential_generation=2,session_generation=2,restore_generation=2`); e != nil {
		t.Fatal(e)
	}
	var current []byte
	_ = db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&current)
	if e := s.ReplacePassword(t.Context(), "u", current, []byte("quarantined synthetic public phrase")); e == nil {
		t.Fatal("restore authority reactivated")
	}
}
func TestPasswordIPFixedWindowAndNAT(t *testing.T) {
	g, e := newTrafficGate()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(2000000000, 0)
	for i := 0; i < 30; i++ {
		if !g.allow("192.0.2.1", now) {
			t.Fatal("early NAT denial")
		}
	}
	for i := 0; i < 100; i++ {
		if g.allow("192.0.2.1", now.Add(59*time.Second)) {
			t.Fatal("IP flood accepted")
		}
	}
	if !g.allow("192.0.2.1", now.Add(time.Minute)) {
		t.Fatal("flood slid NAT window")
	}
	if !g.allow("192.0.2.2", now) {
		t.Fatal("unrelated IP disabled")
	}
	for _, bad := range []string{"", "unknown", "192.0.2.1:80", "fe80::1%eth0"} {
		if g.allow(bad, now) {
			t.Fatal("unchecked peer accepted")
		}
	}
}
