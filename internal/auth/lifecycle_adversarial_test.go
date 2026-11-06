package auth

import (
	"bytes"
	"database/sql"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTOTPPendingExpiryOwnerAndTamper(t *testing.T) {
	for _, scenario := range []string{"expired", "other-session", "tamper", "quarantine", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e, err := l.BeginTOTP(t.Context(), session, "SHA256")
			if err != nil {
				t.Fatal(err)
			}
			var cipher []byte
			if err = db.QueryRow(`SELECT encrypted_secret FROM authenticators WHERE id=?`, e.ID).Scan(&cipher); err != nil {
				t.Fatal(err)
			}
			seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.secret)
			if err != nil {
				t.Fatal("synthetic provisioning decode failed")
			}
			if bytes.Contains(cipher, seed) || bytes.Contains(cipher, []byte(e.secret)) {
				t.Fatal("seed stored in plaintext")
			}
			switch scenario {
			case "expired":
				at := l.now().Add(600 * time.Second)
				l.now = func() time.Time { return at }
			case "other-session":
				if _, err = db.Exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,created_at,expires_at,last_activity_at) VALUES('other','u',zeroblob(32),'preauth',1,3,1)`); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE totp_pending SET session_id='other' WHERE authenticator_id=?`, e.ID); err != nil {
					t.Fatal(err)
				}
			case "tamper":
				cipher[len(cipher)-1] ^= 1
				if _, err = db.Exec(`UPDATE authenticators SET encrypted_secret=? WHERE id=?`, cipher, e.ID); err != nil {
					t.Fatal(err)
				}
			case "quarantine":
				if _, err = db.Exec(`UPDATE installation_control SET restore_quarantined=1`); err != nil {
					t.Fatal(err)
				}
			case "generation":
				if _, err = db.Exec(`UPDATE installation_control SET credential_generation=2,session_generation=2`); err != nil {
					t.Fatal(err)
				}
			}
			if err = l.ConfirmTOTP(t.Context(), session, e.ID, enrollmentCode(t, e, l.now()), "192.0.2.1"); err != ErrDenied {
				t.Fatal("unsafe pending binding accepted")
			}
			var bound sql.NullInt64
			if err = db.QueryRow(`SELECT bound_at FROM authenticators WHERE id=?`, e.ID).Scan(&bound); err != nil || bound.Valid {
				t.Fatal("denied binding became active")
			}
		})
	}
}

func TestRequiredLastFactorCannotBeRemoved(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
		t.Fatal(err)
	}
	// The trusted fixture, not an application policy-mutation interface.
	if _, err := db.Exec(`UPDATE users SET mfa_requirement='required' WHERE id='u'`); err != nil {
		t.Fatal(err)
	}
	if err := l.RevokeTOTP(t.Context(), session, e.ID); err != ErrDenied {
		t.Fatal("required last factor removed")
	}
}

func TestRecoveredCapabilityDenialsAndNoNormalAuthority(t *testing.T) {
	for _, scenario := range []string{"expired", "webauthn-policy", "quarantine", "generation", "password-revision"} {
		t.Run(scenario, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e := queueBindingNotice(t, l, session)
			if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
				t.Fatal(err)
			}
			batch, err := l.IssueRecoveryCodes(t.Context(), session)
			if err != nil {
				t.Fatal(err)
			}
			codes := batch.ExportOnce()
			result, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.2")
			if err != nil {
				t.Fatal(err)
			}
			cap, _ := result.ExportOnce()
			if _, err = l.IssueRecoveryCodes(t.Context(), cap); err != ErrDenied {
				t.Fatal("recovery-only authority generated list")
			}
			if err = l.RevokeTOTP(t.Context(), cap, e.ID); err != ErrDenied {
				t.Fatal("recovery-only authority removed factor")
			}
			if _, err = l.BeginTOTP(t.Context(), cap, "SHA256"); err != ErrDenied {
				t.Fatal("recovery-only capability became normal authority")
			}
			err = nil
			switch scenario {
			case "expired":
				at := l.now().Add(600 * time.Second)
				l.now = func() time.Time { return at }
			case "webauthn-policy":
				_, err = db.Exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id='u'`)
			case "quarantine":
				_, err = db.Exec(`UPDATE installation_control SET restore_quarantined=1`)
			case "generation":
				_, err = db.Exec(`UPDATE installation_control SET credential_generation=2,session_generation=2`)
			case "password-revision":
				_, err = db.Exec(`UPDATE users SET password_revision=password_revision+1 WHERE id='u'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.BeginRecoveredTOTP(t.Context(), cap, "SHA256"); err != ErrDenied {
				t.Fatal("invalid replacement capability accepted")
			}
		})
	}
}

func TestLifecycleSecretValuesRedactedAndRevealOnce(t *testing.T) {
	l, _, session := lifecycleFixture(t)
	e, err := l.BeginTOTP(t.Context(), session, "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	original := e.secret
	if strings.Contains(fmt.Sprintf("%v %#v", e, e), original) {
		t.Fatal("enrollment formatting leaked seed")
	}
	if len(e.ExportOnce()) == 0 || len(e.ExportOnce()) != 0 {
		t.Fatal("provisioning result not reveal once")
	}
	codes := RecoveryCodes{codes: []string{"synthetic public code canary"}}
	if strings.Contains(fmt.Sprintf("%v %#v", codes, codes), "synthetic public code canary") {
		t.Fatal("saved code formatting leaked")
	}
	if len(codes.ExportOnce()) != 1 || len(codes.ExportOnce()) != 0 {
		t.Fatal("saved-code reveal repeated")
	}
}
