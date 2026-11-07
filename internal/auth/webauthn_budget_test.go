package auth

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnConcurrentCeilingHasNoSpeculativeProofs(t *testing.T) {
	w, db, session, key, id := webFixture(t)
	other, e := NewWebAuthn(w.lifecycle, WebAuthnSettings{RPID: "example.invalid", Origins: []string{"https://example.invalid"}})
	if e != nil {
		t.Fatal(e)
	}
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id=?`, id)
	var evaluations atomic.Int64
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, service := range []*WebAuthnService{w, other} {
		original := service.verifier.ValidateLogin
		service.verifyLogin = func(user wa.User, data wa.SessionData, response *protocol.ParsedCredentialAssertionData) (*wa.Credential, error) {
			evaluations.Add(1)
			return original(user, data, response)
		}
		c, e := service.BeginAssertion(t.Context(), session)
		if e != nil {
			t.Fatal(e)
		}
		impostor := newVirtualKey(t)
		impostor.id = key.id
		response := impostor.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
		go func() {
			<-start
			_, e := service.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.61")
			results <- e
		}()
	}
	close(start)
	for range 2 {
		if e := <-results; e != ErrDenied {
			t.Fatal("bad proof accepted")
		}
	}
	if evaluations.Load() != 1 {
		t.Fatal("speculative verification exceeded remaining budget", evaluations.Load())
	}
	var failures, intents int
	if e := db.QueryRow(`SELECT failed_attempts FROM authenticators WHERE id=?`, id).Scan(&failures); e != nil || failures != 100 {
		t.Fatal("incorrect durable ceiling", failures, e)
	}
	if e := db.QueryRow(`SELECT count(*) FROM protective_notice_intents WHERE event_type='authenticator_suspended'`).Scan(&intents); e != nil || intents != 1 {
		t.Fatal("incorrect terminal notice", intents, e)
	}
}

func TestWebAuthnVerifiedCandidateMismatchDenied(t *testing.T) {
	w, db, session, key, _ := webFixture(t)
	original := w.verifier.ValidateLogin
	w.verifyLogin = func(user wa.User, data wa.SessionData, response *protocol.ParsedCredentialAssertionData) (*wa.Credential, error) {
		c, e := original(user, data, response)
		// Fault injection after REAL cryptographic verification: a future library
		// state-update drift cannot authorize presealed unverified material.
		if e == nil {
			c.Authenticator.SignCount++
		}
		return c, e
	}
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.62"); e != ErrDenied {
		t.Fatal("candidate mismatch accepted")
	}
	var count int
	if e := db.QueryRow(`SELECT sign_count FROM authenticators WHERE kind='webauthn'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("candidate mismatch persisted", e)
	}
}

func TestWebAuthnChallengeExpiryDuringProofDenies(t *testing.T) {
	w, db, session, key, _ := webFixture(t)
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	at := w.lifecycle.now().Add(300 * time.Second)
	original := w.verifier.ValidateLogin
	w.verifyLogin = func(user wa.User, data wa.SessionData, response *protocol.ParsedCredentialAssertionData) (*wa.Credential, error) {
		result, e := original(user, data, response)
		w.lifecycle.now = func() time.Time { return at }
		return result, e
	}
	if p, e := w.FinishAssertion(t.Context(), session, c.ID, key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1), "192.0.2.63"); e != ErrDenied || p.AuthenticatorID != "" {
		t.Fatal("expired during proof accepted")
	}
	var count int
	if e := db.QueryRow(`SELECT sign_count FROM authenticators WHERE kind='webauthn'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("expired proof advanced key", e)
	}
}
