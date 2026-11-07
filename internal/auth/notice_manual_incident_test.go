package auth

import (
	"testing"
)

func TestRecipientlessProtectiveIncidentDoesNotBlockOtherAccounts(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	e := queueBindingNotice(t, l, session)
	// Fixture-only lost destinations: ordinary future address APIs must still
	// prohibit last-address removal. Existing immutable outbox snapshots survive.
	if _, err := db.Exec(`UPDATE notification_addresses SET state='revoked',revoked_at=2000000010`); err != nil {
		t.Fatal(err)
	}
	_ = l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte("a unique synthetic public phrase"), e.ID, "192.0.2.2")
	var recipients, state string
	if err := db.QueryRow(`SELECT recipients FROM protective_notice_intents`).Scan(&recipients); err != nil || recipients != "[]" {
		t.Fatal("missing immutable incident", err)
	}
	if err := db.QueryRow(`SELECT state FROM authenticators WHERE id=?`, e.ID).Scan(&state); err != nil || state != "revoked" {
		t.Fatal("revocation lost", err)
	}
	// Add a different account and current protective work, plus corrupt and empty
	// legacy pending snapshots ahead of it. Invalid incidents must not roll back
	// the valid expansion or keep recurring in automatic batches after restart.
	for _, q := range []string{
		`INSERT INTO users(id,username,state,credential_generation,authority_generation) VALUES('v','synthetic-other','active',1,1)`,
		`INSERT INTO notification_addresses(id,user_id,address,version,created_at,verified_at,state,authority_generation) VALUES('vaddr','v','other@example.invalid',1,1,1,'active',1)`,
		`INSERT INTO protective_notice_intents VALUES('bad-json','u','authenticator_suspended',1,1,'{','pending'),('bad-address','u','authenticator_suspended',1,1,'[{"ID":"addr1","Version":1,"Address":"bad"}]','pending'),('valid-other','v','authenticator_suspended',2000000009,1,'[{"ID":"vaddr","Version":1,"Address":"other@example.invalid"}]','pending')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	l = reopenLifecycle(t, l, db)
	f := receiver(t, "implicit", "", false, false)
	l.notices.Relay, l.notices.RootCAs = f.relay, f.roots
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 3 {
		t.Fatal("manual incidents blocked unrelated delivery", n, err)
	}
	if len(f.received()) != 3 {
		t.Fatal("wrong independent receiver count")
	}
	status, err := l.NoticeHealth(t.Context())
	if err != nil || !status.Degraded || status.Protective != 3 || status.Pending != 0 {
		t.Fatal("manual incidents not visible", status, err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM protective_notice_intents WHERE state='pending'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid work still in automatic expansion", count, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM security_notice_outbox WHERE recipient_snapshot='bad'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid recipients queued", count, err)
	}
	l = reopenLifecycle(t, l, db)
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 0 {
		t.Fatal("restart replayed/reblocked incident", n, err)
	}
	status, err = l.NoticeHealth(t.Context())
	if err != nil || status.Protective != 3 || !status.Degraded {
		t.Fatal("restart lost manual incident visibility", status, err)
	}
	if err = db.QueryRow(`SELECT recipients FROM protective_notice_intents WHERE recipients='[]'`).Scan(&recipients); err != nil || recipients != "[]" {
		t.Fatal("incident silently retargeted", err)
	}
}
