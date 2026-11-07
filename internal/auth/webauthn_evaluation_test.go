package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnProofEvaluationHoldsSharedControl(t *testing.T) {
	w, db, session, key, id := webFixture(t)
	var filename string
	if e := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&filename); e != nil {
		t.Fatal(e)
	}
	lock, e := os.OpenFile(filepath.Join(filepath.Dir(filename), "control.lock"), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = lock.Close() }()
	original := w.verifier.ValidateLogin
	evaluated := 0
	outside := false
	w.verifyLogin = func(user wa.User, data wa.SessionData, response *protocol.ParsedCredentialAssertionData) (*wa.Credential, error) {
		evaluated++
		e := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			outside = true
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		} else if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			t.Fatal(e)
		}
		return original(user, data, response) // Actual protocol/signature verification, never a mocked result.
	}
	execFixture(t, db, `UPDATE authenticators SET failed_attempts=99 WHERE id=?`, id)
	c, e := w.BeginAssertion(t.Context(), session)
	if e != nil {
		t.Fatal(e)
	}
	response := key.assert(t, c.Options.Response.Challenge.String(), "https://example.invalid", 5, 1)
	response = alterResponse(t, response, func(m map[string]any) { m["response"].(map[string]any)["signature"] = b64(bytes.Repeat([]byte{1}, 72)) })
	if _, e = w.FinishAssertion(t.Context(), session, c.ID, response, "192.0.2.60"); e != ErrDenied {
		t.Fatal("invalid signature accepted")
	}
	if evaluated != 1 || outside {
		t.Fatalf("proof evaluations=%d outside_shared_control=%t", evaluated, outside)
	}
	// Terminal budget must deny before another real verifier call.
	c, e = w.BeginAssertion(t.Context(), session)
	if e != ErrDenied {
		t.Fatal("disabled key admitted", e)
	}
	if evaluated != 1 {
		t.Fatal("exhausted key evaluated again")
	}
}
