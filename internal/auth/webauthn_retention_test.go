package auth

import (
	"testing"
	"time"
)

func TestWebAuthnChallengeCapacityAndRetention(t *testing.T) {
	w, db, session, key, _ := webFixture(t)
	// The consumed registration must not accumulate on the assertion path.
	var old AssertionOptions
	for i := 0; i < 16; i++ {
		c, e := w.BeginAssertion(t.Context(), session)
		if e != nil {
			t.Fatal("capacity rejected early", i, e)
		}
		old = c
	}
	if _, e := w.BeginAssertion(t.Context(), session); e != ErrDenied {
		t.Fatal("unbounded outstanding challenges")
	}
	at := w.lifecycle.now().Add(300 * time.Second)
	w.lifecycle.now = func() time.Time { return at }
	if _, e := w.BeginAssertion(t.Context(), session); e != nil {
		t.Fatal("expired challenges blocked admission", e)
	}
	var n int
	if e := db.QueryRow(`SELECT count(*) FROM auth_challenges`).Scan(&n); e != nil || n != 1 {
		t.Fatal("terminal challenge records accumulated", n, e)
	}
	if _, e := w.FinishAssertion(t.Context(), session, old.ID, key.assert(t, old.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.20"); e != ErrDenied {
		t.Fatal("pruned challenge replay accepted")
	}
}
