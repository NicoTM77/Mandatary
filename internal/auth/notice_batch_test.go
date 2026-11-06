package auth

import "testing"

func TestExhaustedNoticeDoesNotEndDispatchBatch(t *testing.T) {
	l, db, session := lifecycleFixture(t)
	queueBindingNotice(t, l, session)
	if _, err := db.Exec(`UPDATE security_notice_outbox SET attempts=8,total_attempts=8 WHERE id=(SELECT id FROM security_notice_outbox ORDER BY id LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	f := receiver(t, "implicit", "", false, false)
	l.notices.Relay, l.notices.RootCAs = f.relay, f.roots
	if n, err := l.DispatchNotices(t.Context(), 8); err != nil || n != 1 {
		t.Fatal("exhausted row stopped live recipient", n, err)
	}
	status, err := l.NoticeHealth(t.Context())
	if err != nil || status.Pending != 0 || status.Failed != 1 || len(f.received()) != 1 {
		t.Fatal("batch did not retain failure and deliver healthy work", status, err)
	}
}
