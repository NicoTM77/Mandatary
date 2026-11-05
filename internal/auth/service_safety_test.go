package auth

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

func execFixture(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, e := db.ExecContext(t.Context(), query, args...); e != nil {
		t.Fatal(e)
	}
}
func scalarFixture(t *testing.T, db *sql.DB, query string) int64 {
	t.Helper()
	var n int64
	if e := db.QueryRowContext(t.Context(), query).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func TestPasswordResetOnlyUsableFactor(t *testing.T) {
	for _, factor := range []string{"none", "valid", "expired", "stale", "revoked", "exhausted"} {
		t.Run(factor, func(t *testing.T) {
			s, _, db := serviceFixture(t)
			s.now = func() time.Time { return time.Unix(2000000000, 0) }
			execFixture(t, db, `UPDATE authenticators SET failed_attempts=3 WHERE id='pwd'`)
			if factor != "none" {
				execFixture(t, db, `INSERT INTO authenticators(id,user_id,kind,state,bound_at,credential_generation,failed_attempts,encrypted_secret) VALUES('factor','u','totp','active',1,1,9,x'01')`)
				switch factor {
				case "expired":
					execFixture(t, db, `UPDATE authenticators SET expires_at=1999999999 WHERE id='factor'`)
				case "stale":
					execFixture(t, db, `UPDATE authenticators SET credential_generation=2 WHERE id='factor'`)
				case "revoked":
					execFixture(t, db, `UPDATE authenticators SET revoked_at=1,state='revoked' WHERE id='factor'`)
				case "exhausted":
					execFixture(t, db, `UPDATE authenticators SET failed_attempts=retry_ceiling,state='disabled' WHERE id='factor'`)
				}
			}
			if _, e := s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1"); e != nil {
				t.Fatal(e)
			}
			want := int64(0)
			if factor == "valid" {
				want = 3
			}
			if n := scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`); n != want {
				t.Fatalf("password retries=%d want=%d", n, want)
			}
			if factor != "none" && factor != "exhausted" && scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='factor'`) != 9 {
				t.Fatal("unused factor reset")
			}
		})
	}
}
func TestPasswordSameBindingIncludesLifecycleMetadata(t *testing.T) {
	a := store.Authenticator{ID: "p", UserID: "u", Kind: "password", State: "active", CredentialGeneration: 1, RetryCeiling: 100, VerifierHash: []byte("public verifier")}
	for _, mutate := range []func(*store.Authenticator){
		func(b *store.Authenticator) { b.UserID = "other" }, func(b *store.Authenticator) { b.BoundAt = sql.NullInt64{Int64: 1, Valid: true} }, func(b *store.Authenticator) { b.ExpiresAt = sql.NullInt64{Int64: 1, Valid: true} }, func(b *store.Authenticator) { b.RevokedAt = sql.NullInt64{Int64: 1, Valid: true} }, func(b *store.Authenticator) { b.ChangedAt = sql.NullInt64{Int64: 1, Valid: true} }, func(b *store.Authenticator) { b.RetryCeiling = 99 }, func(b *store.Authenticator) { b.NextAttemptAt = sql.NullInt64{Int64: 1, Valid: true} }, func(b *store.Authenticator) { b.PasswordCodepoints = sql.NullInt64{Int64: 15, Valid: true} },
	} {
		b := a
		mutate(&b)
		if samePassword(a, b) {
			t.Fatal("stale binding comparison omitted lifecycle metadata")
		}
	}
}
func TestPasswordMFAOnlyHistoricalProfileAndNoTruncation(t *testing.T) {
	s, _, db := serviceFixture(t)
	for _, n := range []int{8, 14, 15, 64, 128} {
		raw := []byte(strings.Repeat("😀", n))
		v, e := HashPassword(raw)
		if e != nil {
			t.Fatal(e)
		}
		execFixture(t, db, `UPDATE users SET mfa_requirement='required' WHERE id='u'`)
		execFixture(t, db, `UPDATE authenticators SET verifier_hash=?,password_codepoints=? WHERE id='pwd'`, v, n)
		for _, mfa := range []string{"required", "optional", "webauthn"} {
			if mfa == "optional" && n < 15 {
				if _, e := db.Exec(`UPDATE users SET mfa_requirement='optional' WHERE id='u'`); e == nil {
					t.Fatal("short-password policy downgrade succeeded")
				}
				p, e := s.Prove(t.Context(), "synthetic-user", raw, "192.0.2.1")
				if e != nil || !p.RequiresMFA {
					t.Fatal("rejected downgrade created fallback")
				}
				continue
			}
			execFixture(t, db, `UPDATE users SET mfa_requirement=? WHERE id='u'`, mfa)
			p, e := s.Prove(t.Context(), "synthetic-user", raw, "192.0.2.1")
			if e != nil || p.RequiresMFA != (mfa != "optional") {
				t.Fatalf("n=%d mfa=%s fallback violated", n, mfa)
			}
		}
		wrong := bytes.Clone(raw)
		wrong[len(wrong)-1] ^= 1
		if _, e = s.Prove(t.Context(), "synthetic-user", wrong, "192.0.2.1"); e != ErrDenied {
			t.Fatal("suffix ignored")
		}
	}
	execFixture(t, db, `UPDATE authenticators SET password_format='synthetic-historical-unknown' WHERE id='pwd'`)
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte(strings.Repeat("😀", 128)), "192.0.2.2"); e != ErrDenied {
		t.Fatal("unknown profile guessed")
	}
	if scalarFixture(t, db, `SELECT count(*) FROM authenticators WHERE password_format='synthetic-historical-unknown'`) != 1 {
		t.Fatal("profile silently relabelled")
	}
}
func TestPasswordRealRepositoryRestart(t *testing.T) {
	s, r, db := serviceFixture(t)
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id='pwd'`)
	if _, e := s.Prove(t.Context(), "synthetic-user", []byte("wrong public phrase"), "192.0.2.1"); e != ErrDenied {
		t.Fatal(e)
	}
	var file string
	if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if e := db.Close(); e != nil {
		t.Fatal(e)
	}
	key, e := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(t.Context(), store.Options{DataDir: filepath.Dir(file), MasterKey: key, OwnerUID: os.Geteuid(), OwnerGID: os.Getegid(), ExistingOnly: true})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := reopened.Close(); e != nil {
			t.Error(e)
		}
	}()
	s, e = NewService(reopened, DefaultPolicy(), "synthetic-host.example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.2"); e != ErrDenied {
		t.Fatal("restart revived disabled password")
	}
	if e = reopened.Read(t.Context(), func(q *store.Queries) error {
		a, e := q.GetAuthenticator(t.Context(), "pwd")
		if e == nil && (a.FailedAttempts != 100 || a.State != "disabled") {
			t.Error("restart lost ceiling")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
func TestPasswordConcurrentHandlesCannotOverrunCeiling(t *testing.T) {
	s, r, db := serviceFixture(t)
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id='pwd'`)
	s2, e := NewService(r, DefaultPolicy(), "synthetic-host.example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			<-start
			svc := s
			if i%2 == 0 {
				svc = s2
			}
			if _, e := svc.Prove(t.Context(), "synthetic-user", []byte("wrong public proof"), "192.0.2.1"); e != ErrDenied {
				t.Error("concurrent incorrect proof accepted")
			}
		})
	}
	close(start)
	wg.Wait()
	if scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 100 {
		t.Fatal("concurrent ceiling overrun/lost update")
	}
	if scalarFixture(t, db, `SELECT count(*) FROM authenticators WHERE id='pwd' AND state='disabled'`) != 1 {
		t.Fatal("not disabled")
	}
}
func TestPasswordReplacementRaceDeniesStaleAuthority(t *testing.T) {
	for _, mutation := range []string{`UPDATE authenticators SET state='revoked',revoked_at=1 WHERE id='pwd'`, `UPDATE users SET compromised=1 WHERE id='u'`, `UPDATE authenticators SET changed_at=42 WHERE id='pwd'`, `UPDATE users SET state='disabled' WHERE id='u'`, `UPDATE authenticators SET failed_attempts=100,state='disabled' WHERE id='pwd'`, `UPDATE installation_control SET restore_quarantined=1,credential_generation=2,session_generation=2,restore_generation=2`, `UPDATE authenticators SET password_format='unknown' WHERE id='pwd'`} {
		t.Run(mutation, func(t *testing.T) {
			s, _, db := serviceFixture(t)
			var observed []byte
			if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); e != nil {
				t.Fatal(e)
			}
			s.policy.hibp = newHIBP(roundTrip(func(*http.Request) (*http.Response, error) {
				execFixture(t, db, mutation)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n"))}, nil
			}))
			if e := s.ReplacePassword(t.Context(), "u", observed, []byte("new uncommon synthetic public phrase")); e == nil {
				t.Fatal("stale replacement committed")
			}
			var current []byte
			if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&current); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(observed, current) {
				t.Fatal("denied replacement changed verifier")
			}
		})
	}
}
func TestPasswordControlWriteFailuresNeverAcknowledge(t *testing.T) {
	for _, operation := range []string{"failure", "reset", "compromise", "replace"} {
		t.Run(operation, func(t *testing.T) {
			s, _, db := serviceFixture(t)
			execFixture(t, db, `UPDATE authenticators SET failed_attempts=2 WHERE id='pwd'`)
			var observed []byte
			if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); e != nil {
				t.Fatal(e)
			}
			table := "authenticators"
			if operation == "compromise" {
				table = "sessions"
				execFixture(t, db, `INSERT INTO sessions(id,user_id,secret_hash,purpose,created_at,expires_at,last_activity_at) VALUES('s','u',zeroblob(32),'preauth',1,10,1)`)
			}
			execFixture(t, db, `CREATE TRIGGER refuse_auth BEFORE UPDATE ON `+table+` BEGIN SELECT RAISE(ABORT,'synthetic-write-failure'); END`)
			var e error
			switch operation {
			case "failure":
				_, e = s.Prove(t.Context(), "synthetic-user", []byte("wrong synthetic phrase"), "192.0.2.1")
			case "reset":
				_, e = s.Prove(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), "192.0.2.1")
			case "compromise":
				e = s.MarkCompromised(t.Context(), "u")
			case "replace":
				e = s.ReplacePassword(t.Context(), "u", observed, []byte("new uncommon public phrase"))
			}
			if e != ErrDenied {
				t.Fatal("failed write acknowledged", e)
			}
			if scalarFixture(t, db, `SELECT failed_attempts FROM authenticators WHERE id='pwd'`) != 2 || scalarFixture(t, db, `SELECT compromised FROM users WHERE id='u'`) != 0 {
				t.Fatal("partial transition committed")
			}
		})
	}
}
