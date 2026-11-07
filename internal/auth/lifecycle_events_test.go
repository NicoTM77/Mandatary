package auth

import (
	"strings"
	"testing"
)

func TestLifecycleEventsReachIndependentTLSReceiver(t *testing.T) {
	for _, ceremony := range []string{"remove", "report", "regenerate", "recover"} {
		t.Run(ceremony, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			f := receiver(t, "implicit", "", false, false)
			l.notices.Relay = f.relay
			l.notices.RootCAs = f.roots
			e := queueBindingNotice(t, l, session)
			if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
				t.Fatal(err)
			}
			expected := []string{"authenticator_bound"}
			switch ceremony {
			case "remove":
				if err := l.RevokeTOTP(t.Context(), session, e.ID); err != nil {
					t.Fatal(err)
				}
				expected = append(expected, "authenticator_removed")
			case "report":
				if err := l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.2"); err != nil {
					t.Fatal(err)
				}
				expected = append(expected, "authenticator_suspended")
			case "regenerate", "recover":
				batch, err := l.IssueRecoveryCodes(t.Context(), session)
				if err != nil {
					t.Fatal(err)
				}
				codes := batch.ExportOnce()
				expected = append(expected, "recovery_codes_issued")
				if ceremony == "regenerate" {
					if _, err = l.IssueRecoveryCodes(t.Context(), session); err != nil {
						t.Fatal(err)
					}
					if _, err = l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.2"); err != ErrDenied {
						t.Fatal("regeneration preserved old batch")
					}
				} else {
					result, err := l.Recover(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), codes[0], "192.0.2.2")
					if err != nil {
						t.Fatal(err)
					}
					cap, _ := result.ExportOnce()
					replacement, err := l.BeginRecoveredTOTP(t.Context(), cap, "SHA256")
					if err != nil {
						t.Fatal(err)
					}
					if err = l.ConfirmRecoveredTOTP(t.Context(), cap, replacement.ID, enrollmentCode(t, replacement, l.now()), "192.0.2.3"); err != nil {
						t.Fatal(err)
					}
					expected = append(expected, "authenticator_replaced", "recovery_completed")
				}
				expected = append(expected, "recovery_codes_replaced")
			}
			count, err := l.DispatchNotices(t.Context(), 32)
			if err != nil || count != len(expected)*2 {
				t.Fatal("lifecycle notices not submitted to every independent destination", count)
			}
			messages := f.received()
			seen := map[string]int{}
			for _, message := range messages {
				if strings.Contains(message, e.secret) || strings.Contains(message, "a unique synthetic public phrase") {
					t.Fatal("lifecycle message leaked a credential")
				}
				for _, event := range expected {
					if strings.Contains(message, "Security event: "+event+"\r\n") {
						seen[event]++
					}
				}
			}
			for _, event := range expected {
				if seen[event] != 2 {
					t.Fatal("event fanout incomplete", event)
				}
			}
		})
	}
}
