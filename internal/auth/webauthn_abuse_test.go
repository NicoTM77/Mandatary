package auth

import (
	"database/sql"
	"sync"
	"testing"
)

func TestWebAuthnWorkAdmissionDeniesWithoutConsuming(t *testing.T) {
	w, db, session, key, _ := webFixture(t)
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	response := key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
	for i := 0; i < cap(webAuthnWork); i++ {
		webAuthnWork <- struct{}{}
	}
	func() {
		defer func() {
			for i := 0; i < cap(webAuthnWork); i++ {
				<-webAuthnWork
			}
		}()
		if _, e := w.BeginAssertion(t.Context(), session); e != ErrDenied {
			t.Fatal("unbounded assertion admission")
		}
		if _, e := w.BeginRegistration(t.Context(), session, false); e != ErrDenied {
			t.Fatal("unbounded binding admission")
		}
		if _, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.20"); e != ErrDenied {
			t.Fatal("unbounded verifier admission")
		}
	}()
	var consumed sql.NullInt64
	if e := db.QueryRow(`SELECT consumed_at FROM auth_challenges WHERE id=?`, c.ID).Scan(&consumed); e != nil || consumed.Valid {
		t.Fatal("admission denial consumed proof", e)
	}
	if _, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.21"); e != nil {
		t.Fatal("work slot not released", e)
	}
}

func TestWebAuthnKeyCapacityIsAtomic(t *testing.T) {
	w, db, session, _, id := webFixture(t)
	webSession(t, db, id)
	for i := 1; i < 15; i++ {
		c, e := w.BeginRegistration(t.Context(), session, false)
		if e != nil {
			t.Fatal(e)
		}
		if e = w.FinishRegistration(t.Context(), session, c.ID, newVirtualKey(t).create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
			t.Fatal(e)
		}
	}
	var ceremonies []RegistrationOptions
	var responses [][]byte
	for i := 0; i < 2; i++ {
		c, e := w.BeginRegistration(t.Context(), session, false)
		if e != nil {
			t.Fatal(e)
		}
		ceremonies = append(ceremonies, c)
		responses = append(responses, newVirtualKey(t).create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5))
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := range ceremonies {
		wg.Go(func() { results <- w.FinishRegistration(t.Context(), session, ceremonies[i].ID, responses[i]) == nil })
	}
	wg.Wait()
	close(results)
	accepted := 0
	for ok := range results {
		if ok {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("capacity race accepted %d, want 1", accepted)
	}
	if _, e := w.BeginRegistration(t.Context(), session, false); e != ErrDenied {
		t.Fatal("unbounded key admission")
	}
	var n int
	if e := db.QueryRow(`SELECT count(*) FROM authenticators WHERE kind='webauthn' AND state='active'`).Scan(&n); e != nil || n != 16 {
		t.Fatal("wrong key capacity", n, e)
	}
	// A full/disabled set must not prevent restricted recovery from replacing
	// it. The committed replacement set is one key, not seventeen.
	batch, e := w.lifecycle.IssueRecoveryCodes(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := w.lifecycle.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), batch.ExportOnce()[0], "192.0.2.52")
	if e != nil {
		t.Fatal(e)
	}
	capability, _ := recovery.ExportOnce()
	c, e := w.BeginRecoveredRegistration(t.Context(), capability, false)
	if e != nil {
		t.Fatal(e)
	}
	if e := w.FinishRecoveredRegistration(t.Context(), capability, c.ID, newVirtualKey(t).create(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5)); e != nil {
		t.Fatal(e)
	}
	if e := db.QueryRow(`SELECT count(*) FROM authenticators WHERE kind='webauthn' AND state='active'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("full-set recovery did not replace keys", n, e)
	}
}
