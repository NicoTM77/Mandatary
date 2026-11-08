package auth

import (
	"bytes"
	"context"
	"testing"
)

func TestWebAuthnCeremonyAndInputBoundaries(t *testing.T) {
	for _, name := range []string{"different-session", "different-account", "registration-purpose", "challenge-envelope-substitution", "consumed", "oversized", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			w, db, session, key, id := webFixture(t)
			c, e := w.BeginAssertion(t.Context(), session)
			if e != nil {
				t.Fatal(e)
			}
			response := key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
			ctx := t.Context()
			switch name {
			case "different-session", "different-account":
				session = webPreauth(t, db, w.lifecycle.now().Unix())
				if name == "different-account" {
					execFixture(t, db, `INSERT INTO users(id,username,state,credential_generation,authority_generation) VALUES('other','other-synthetic','active',1,1)`)
					execFixture(t, db, `UPDATE sessions SET user_id='other' WHERE id='fresh-preauth'`)
				}
			case "registration-purpose":
				webSession(t, db, id)
				r, e := w.BeginRegistration(t.Context(), session, false)
				if e != nil {
					t.Fatal(e)
				}
				c.ID = r.ID
				response = key.assert(t, r.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
			case "challenge-envelope-substitution":
				other, e := w.BeginAssertion(t.Context(), session)
				if e != nil {
					t.Fatal(e)
				}
				execFixture(t, db, `UPDATE webauthn_challenges SET envelope=(SELECT envelope FROM webauthn_challenges WHERE challenge_id=?) WHERE challenge_id=?`, other.ID, c.ID)
			case "consumed":
				if _, e := w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.50"); e != nil {
					t.Fatal(e)
				}
			case "oversized":
				response = bytes.Repeat([]byte{'x'}, 32769)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(t.Context())
				cancel()
			}
			if proof, e := w.FinishAssertion(ctx, session, c.ID, response, "192.0.2.51"); e != ErrDenied || proof.AuthenticatorID != "" {
				t.Fatal("boundary admitted proof")
			}
		})
	}
}
