package auth

import "testing"

func TestProtectiveFallbackIncidentRemainsVisibleAfterRestart(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	if _, err := db.Exec(`CREATE TRIGGER reject_marker BEFORE INSERT ON protective_notice_intents BEGIN SELECT RAISE(ABORT,'synthetic marker failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.2"); err != ErrDenied {
		t.Fatal("missing marker acknowledged")
	}
	if _, err := db.Exec(`UPDATE security_notice_outbox SET delivery_state='relay-accepted',attempts=1,last_attempt_at=2000000010`); err != nil {
		t.Fatal(err)
	}
	l = reopenLifecycle(t, l, db)
	status, err := l.NoticeHealth(t.Context())
	if err != nil || !status.Degraded || status.Protective != 1 {
		t.Fatal("minimal protective incident disappeared after restart")
	}
}

func TestProtectiveMarkerFailureCannotUndoRevocation(t *testing.T) {
	for _, operation := range []string{"remove", "report"} {
		t.Run(operation, func(t *testing.T) {
			l, db, session := lifecycleFixture(t)
			e := queueBindingNotice(t, l, session)
			if _, err := db.Exec(`UPDATE sessions SET achieved_assurance=2,methods=3`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES('session',?,'u')`, e.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TRIGGER reject_protective_marker BEFORE INSERT ON protective_notice_intents BEGIN SELECT RAISE(ABORT,'synthetic marker failure'); END`); err != nil {
				t.Fatal(err)
			}
			var err error
			if operation == "remove" {
				err = l.RevokeTOTP(t.Context(), session, e.ID)
			} else {
				err = l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.2")
			}
			if err != ErrDenied {
				t.Fatal("missing incident was acknowledged")
			}
			var state string
			if err = db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "revoked" {
				t.Fatal("notice-marker failure reversed protective revocation")
			}
			if err = db.QueryRow(`SELECT state FROM sessions WHERE id='session'`).Scan(&state); err != nil || state != "revoked" {
				t.Fatal("notice-marker failure reversed session invalidation")
			}
			if !l.repo.FailedClosed() {
				t.Fatal("missing incident did not degrade acceptance")
			}
		})
	}
}
