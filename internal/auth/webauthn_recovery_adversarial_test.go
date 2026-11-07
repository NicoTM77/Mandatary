package auth

import (
	"crypto/sha256"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// P1.08 owns production preauth issuance. This synthetic record grants no
// achieved assurance and is used only to exercise the component after recovery.
func webPreauth(t *testing.T, db *sql.DB, now int64) []byte {
	t.Helper()
	secret := []byte("fresh synthetic preauth after recovery, not live")
	hash := sha256.Sum256(secret)
	_, e := db.Exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,created_at,expires_at,last_activity_at,credential_generation,session_generation,state) VALUES('fresh-preauth','u',?,'preauth',?,?,?,1,1,'active')`, hash[:], now, now+600, now)
	if e != nil {
		t.Fatal(e)
	}
	return secret
}

func TestWebAuthnRecoveredBindingAdversarialAndAtomic(t *testing.T) {
	for _, name := range []string{"uv", "origin", "wrong-capability", "expired", "rollback", "revoked", "password-revision", "credential-generation", "session-generation", "quarantine", "outbox", "sync"} {
		t.Run(name, func(t *testing.T) {
			var probe *authSyncProbe
			// The real WAL interposer is installed before the repository is opened.
			if name == "sync" {
				probe = installAuthSyncProbe(t)
			}
			w, db, _, capability, old := webRecoveryFixture(t)
			c, e := w.BeginRecoveredRegistration(t.Context(), capability, false)
			if e != nil {
				t.Fatal(e)
			}
			key := newVirtualKey(t)
			flags := byte(5)
			origin := "https://example.invalid"
			switch name {
			case "uv":
				flags = 1
			case "origin":
				origin = "https://evil.invalid"
			case "wrong-capability":
				capability = []byte(strings.Repeat("x", 32))
			case "expired":
				at := w.lifecycle.now().Add(300 * time.Second)
				w.lifecycle.now = func() time.Time { return at }
			case "rollback":
				at := w.lifecycle.now().Add(-time.Second)
				w.lifecycle.now = func() time.Time { return at }
			case "revoked":
				execFixture(t, db, `UPDATE recovery_capabilities SET state='revoked'`)
			case "password-revision":
				execFixture(t, db, `UPDATE users SET password_revision=password_revision+1`)
			case "credential-generation":
				execFixture(t, db, `UPDATE installation_control SET credential_generation=2`)
			case "session-generation":
				execFixture(t, db, `UPDATE installation_control SET session_generation=2`)
			case "quarantine":
				execFixture(t, db, `UPDATE installation_control SET restore_quarantined=1`)
			case "outbox":
				execFixture(t, db, `CREATE TRIGGER reject_recovered_notice BEFORE INSERT ON security_notice_outbox BEGIN SELECT RAISE(ABORT,'synthetic'); END`)
			case "sync":
				probe.mu.Lock()
				probe.fail = true
				probe.mu.Unlock()
			}
			e = w.FinishRecoveredRegistration(t.Context(), capability, c.ID, key.create(t, c.Options.Response.Challenge.String(), origin, flags))
			if probe != nil {
				probe.mu.Lock()
				failed := probe.failed
				probe.fail = false
				probe.mu.Unlock()
				if failed == 0 || !w.lifecycle.repo.FailedClosed() {
					t.Fatal("real sync fault not exercised")
				}
			}
			if e != ErrDenied {
				t.Fatal("unsafe recovered binding accepted")
			}
			if name != "sync" {
				var state string
				if e := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, old).Scan(&state); e != nil || state != "active" {
					t.Fatal("failed recovery revoked old key", e)
				}
				var n int
				if e := db.QueryRow(`SELECT count(*) FROM authenticators WHERE id=?`, c.ID).Scan(&n); e != nil || n != 0 {
					t.Fatal("failed recovery activated key", e)
				}
			}
		})
	}
}

func TestWebAuthnRecoveredBindingConcurrentRestartAndFreshProof(t *testing.T) {
	w, db, _, capability, _ := webRecoveryFixture(t)
	var ceremonies []RegistrationOptions
	var keys []virtualKey
	var responses [][]byte
	for i := 0; i < 2; i++ {
		c, e := w.BeginRecoveredRegistration(t.Context(), capability, false)
		if e != nil {
			t.Fatal(e)
		}
		k := newVirtualKey(t)
		ceremonies = append(ceremonies, c)
		keys = append(keys, k)
		responses = append(responses, k.create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5))
	}
	w.lifecycle = reopenLifecycle(t, w.lifecycle, db)
	results := make(chan int, 2)
	for i := range ceremonies {
		go func() {
			if w.FinishRecoveredRegistration(t.Context(), capability, ceremonies[i].ID, responses[i]) == nil {
				results <- i
			} else {
				results <- -1
			}
		}()
	}
	winner := -1
	for range 2 {
		if i := <-results; i >= 0 {
			if winner >= 0 {
				t.Fatal("two replacements accepted")
			}
			winner = i
		}
	}
	if winner < 0 {
		t.Fatal("no replacement accepted")
	}
	w.lifecycle = reopenLifecycle(t, w.lifecycle, db)
	if e := w.FinishRecoveredRegistration(t.Context(), capability, ceremonies[winner].ID, responses[winner]); e != ErrDenied {
		t.Fatal("restart revived capability")
	}
	session := webPreauth(t, db, w.lifecycle.now().Unix())
	a, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if p, e := w.FinishAssertion(t.Context(), session, a.ID, keys[winner].assert(t, a.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.41"); e != nil || p.AuthenticatorID != ceremonies[winner].ID {
		t.Fatal("replacement key unusable", e)
	}
	var n int
	if e := db.QueryRow(`SELECT count(*) FROM sessions WHERE purpose='normal' AND state='active'`).Scan(&n); e != nil || n != 0 {
		t.Fatal("component proof minted normal session", e)
	}
}
