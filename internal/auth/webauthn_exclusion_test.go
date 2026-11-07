package auth

import (
	"bytes"
	"testing"
)

func TestWebAuthnAdditionalBindingExcludesExistingKey(t *testing.T) {
	w, db, session, key, id := webFixture(t)
	webSession(t, db, id)
	c, e := w.BeginRegistration(t.Context(), session, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Options.Response.CredentialExcludeList) != 1 || !bytes.Equal(c.Options.Response.CredentialExcludeList[0].CredentialID, key.id) {
		t.Fatal("existing key not excluded")
	}
}
