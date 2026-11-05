package auth

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPasswordReplacementScreensStoredEmail(t *testing.T) {
	s, _, db := serviceFixture(t)
	const email = "public-context@example.invalid"
	execFixture(t, db, `INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('context','u','public-context@example.invalid',1,1,1,'active',1)`)
	var observed []byte
	if err := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplacePassword(t.Context(), "u", observed, []byte(email)); err != ErrBlocked {
		t.Fatal("replacement accepted exact stored verified email", err)
	}
}

func TestPasswordReplacementCompleteTrustedContext(t *testing.T) {
	s, _, db := serviceFixture(t)
	execFixture(t, db, `UPDATE users SET username='contextual-username' WHERE id='u'`)
	execFixture(t, db, `INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('context','u','café-context@example.invalid',1,1,1,'active',1)`)
	var observed []byte
	if err := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"contextual-username", "synthetic-host.example.invalid", "café-context@example.invalid"} {
		for _, suffix := range []string{"", "1", "123", "123!", "!", "password"} {
			t.Run(value+suffix, func(t *testing.T) {
				if err := s.ReplacePassword(t.Context(), "u", observed, []byte(value+suffix)); err != ErrBlocked {
					t.Fatal("whole contextual value/derivative accepted", err)
				}
			})
		}
	}
	// Exact context matching must not become a substring deny or input mutation.
	const phrase = "  café-context@example.invalid contextual-username synthetic-host.example.invalid unusual passphrase  "
	if err := s.ReplacePassword(t.Context(), "u", observed, []byte(phrase)); err != nil {
		t.Fatal("safe containing phrase denied", err)
	}
	if _, err := s.Prove(t.Context(), "contextual-username", []byte(phrase), "192.0.2.1"); err != nil {
		t.Fatal("complete phrase changed during hashing", err)
	}
	if _, err := s.Prove(t.Context(), "contextual-username", []byte(strings.TrimSpace(phrase)), "192.0.2.2"); err != ErrDenied {
		t.Fatal("spaces discarded")
	}
}

func TestPasswordReplacementRechecksAddressSnapshot(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE notification_addresses SET address='new-context@example.invalid',version=2 WHERE id='context'`,
		`UPDATE notification_addresses SET version=2 WHERE id='context'`,
		`UPDATE notification_addresses SET state='revoked',revoked_at=2 WHERE id='context'`,
		`INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('new','u','new-context@example.invalid',1,1,1,'active',1)`,
	} {
		t.Run(mutation, func(t *testing.T) {
			s, _, db := serviceFixture(t)
			execFixture(t, db, `INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('context','u','prior-context@example.invalid',1,1,1,'active',1)`)
			var observed []byte
			if err := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			s.policy.hibp = newHIBP(roundTrip(func(*http.Request) (*http.Response, error) {
				execFixture(t, db, mutation)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n"))}, nil
			}))
			if err := s.ReplacePassword(t.Context(), "u", observed, []byte("new-context@example.invalid")); err != ErrDenied {
				t.Fatal("context changed after screening but replacement acknowledged", err)
			}
			var current []byte
			if err := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&current); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(current, observed) {
				t.Fatal("stale replacement changed verifier")
			}
		})
	}
}

func TestPasswordServiceRequiresDeploymentContext(t *testing.T) {
	_, r, _ := serviceFixture(t)
	for _, host := range []string{"", string([]byte{0xff}), "\u0378"} {
		if _, err := NewService(r, DefaultPolicy(), host); err != ErrDenied {
			t.Fatal("missing/invalid trusted deployment context accepted")
		}
	}
}
