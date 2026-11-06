package auth

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRepeatedCompromiseCannotBeLostDuringReplacement(t *testing.T) {
	s, _, db := serviceFixture(t)
	if e := s.MarkCompromised(t.Context(), "u"); e != nil {
		t.Fatal(e)
	}
	var observed []byte
	if e := db.QueryRow(`SELECT verifier_hash FROM authenticators WHERE id='pwd'`).Scan(&observed); e != nil {
		t.Fatal(e)
	}
	s.policy.hibp = newHIBP(roundTrip(func(*http.Request) (*http.Response, error) {
		if e := s.MarkCompromised(t.Context(), "u"); e != nil {
			t.Fatal(e)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n"))}, nil
	}))
	if e := s.ReplacePassword(t.Context(), "u", observed, []byte("new synthetic uncommon public phrase")); e != ErrDenied {
		t.Fatal("concurrent repeated compromise was cleared", e)
	}
	if scalarFixture(t, db, `SELECT compromised FROM users WHERE id='u'`) != 1 {
		t.Fatal("protective report lost")
	}
}
