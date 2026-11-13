package store_test

import (
	"database/sql"
	"testing"
)

func notices(t *testing.T, db *sql.DB) {
	t.Helper()
	principals(t, db)
	exec(t, db, `INSERT INTO notification_addresses(id,user_id,address,version,created_at) VALUES ('n1','u1','one@example.invalid',1,1),('n2','u1','two@example.invalid',1,1)`)
	exec(t, db, `INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES ('e1','u1','authenticator_bound',1,100,'fixture-event')`)
}
func TestNoticeFanoutAndSnapshot(t *testing.T) {
	db, _ := fixture(t)
	notices(t, db)
	rejects(t, db, `UPDATE notification_addresses SET state='active' WHERE id='n1'`)
	exec(t, db, `UPDATE notification_addresses SET verified_at=2,state='active',authority_generation=1 WHERE id='n1'`)
	rejects(t, db, `INSERT INTO notification_addresses(id,user_id,address,version,created_at) VALUES ('n3','u1','one@example.invalid',1,1)`)
	exec(t, db, `INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until) SELECT 'o-'||id,'e1',user_id,id,version,address,100 FROM notification_addresses`)
	if integer(t, db, `SELECT count(*) FROM security_notice_outbox WHERE delivery_state='pending' AND dispatch_state='quarantined' AND attempts=0`) != 2 {
		t.Fatal("fanout or inactive defaults wrong")
	}
	rejects(t, db, `UPDATE security_notice_outbox SET address_version=2 WHERE id='o-n1'`)
	rejects(t, db, `UPDATE security_notice_outbox SET recipient_snapshot='other@example.invalid' WHERE id='o-n1'`)
	rejects(t, db, `UPDATE security_notice_outbox SET user_id='u2' WHERE id='o-n1'`)
	rejects(t, db, `INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until) VALUES ('duplicate','e1','u1','n1',1,'one@example.invalid',100)`)
	rejects(t, db, `UPDATE security_notice_outbox SET delivery_state='delivered' WHERE id='o-n1'`)
	exec(t, db, `UPDATE security_notice_outbox SET delivery_state='relay-accepted',attempts=1,last_attempt_at=3 WHERE id='o-n1'`)
	exec(t, db, `INSERT INTO notification_address_proofs(id,user_id,address_id,address_version,purpose,proof_hash,issued_at,expires_at) VALUES ('proof','u1','n2',1,'notification_address_confirmation',zeroblob(32),1,100)`)
	rejects(t, db, `UPDATE notification_address_proofs SET purpose='recovery' WHERE id='proof'`)
	rejects(t, db, `UPDATE notification_address_proofs SET user_id='u2' WHERE id='proof'`)
	exec(t, db, `UPDATE notification_address_proofs SET consumed_at=2 WHERE id='proof'`)
	rejects(t, db, `UPDATE notification_address_proofs SET consumed_at=NULL WHERE id='proof'`)
}
func TestNoticeIntentTransactionRollback(t *testing.T) {
	db, _ := fixture(t)
	notices(t, db)
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(t.Context(), `INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES ('e2','u1','authenticator_bound',2,100,'rollback')`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(t.Context(), `INSERT INTO authenticators(id,user_id,kind,bound_at) VALUES ('new-binding','u1','totp',2)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(t.Context(), `INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until) VALUES ('bad','e2','u1','missing',1,'bad@example.invalid',100)`); err == nil {
		t.Fatal("invalid outbox accepted")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if integer(t, db, `SELECT count(*) FROM security_events WHERE id='e2'`) != 0 || integer(t, db, `SELECT count(*) FROM authenticators WHERE id='new-binding'`) != 0 {
		t.Fatal("partial security transition committed")
	}
	// Ordinary binding must roll back on enqueue failure. This is deliberately
	// NOT a protective revocation: those must not wait for SMTP/outbox service.
	// Positive transaction stores both durable intent and synthetic lifecycle state.
	tx, err = db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES ('e2','u1','authenticator_bound',2,100,'commit')`,
		`INSERT INTO authenticators(id,user_id,kind,bound_at) VALUES ('new-binding','u1','totp',2)`,
		`INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until) SELECT 'ok','e2','u1',id,version,address,100 FROM notification_addresses WHERE id='n1'`,
	} {
		if _, err = tx.ExecContext(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if integer(t, db, `SELECT count(*) FROM security_notice_outbox WHERE event_id='e2'`) != 1 || integer(t, db, `SELECT count(*) FROM authenticators WHERE id='new-binding'`) != 1 {
		t.Fatal("notice intent missing")
	}
}

// P1.15 migration 13 makes the selector optional for a denied outcome only. The
// rebuild must keep every existing row, and a downgrade must refuse to silently drop
// an unmatched denial.
func TestUsageUnmatchedDenialMigrationKeepsRowsAndRefusesLossyDowngrade(t *testing.T) {
	db, p := fixture(t)
	principals(t, db)
	exec(t, db, `INSERT INTO container_selectors(id,endpoint_id,container_name) SELECT 's1',id,'db' FROM endpoints`)
	// Downgrade to the P1.02..P1.10 schema (12), populate it the old way, upgrade again.
	if _, err := p.DownTo(t.Context(), 12); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"usage_stats_hourly", "usage_stats_daily"} {
		exec(t, db, `INSERT INTO `+table+`(bucket_start,user_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count) SELECT 0,'u1',endpoint_id,id,'container:logs',2,3,1 FROM container_selectors`)
	}
	exec(t, db, `INSERT INTO usage_recent_events(id,user_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until) SELECT 'ev','u1',endpoint_id,id,'container:logs','error',1,100 FROM container_selectors`)
	if _, err := p.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"usage_stats_hourly", "usage_stats_daily"} {
		if integer(t, db, `SELECT count(*) FROM `+table+` WHERE allowed_count=2 AND denied_count=3 AND error_count=1 AND selector_id='s1'`) != 1 {
			t.Fatalf("%s rows changed by the rebuild", table)
		}
	}
	if integer(t, db, `SELECT count(*) FROM usage_recent_events WHERE id='ev' AND outcome='error' AND selector_id='s1'`) != 1 {
		t.Fatal("recent event changed by the rebuild")
	}
	// A selector-less DENIED row is representable; the same row as allowed/error is not.
	exec(t, db, `INSERT INTO usage_stats_hourly(bucket_start,user_id,endpoint_id,operation,denied_count) SELECT 3600,'u1',id,'container:logs',4 FROM endpoints`)
	rejects(t, db, `INSERT INTO usage_stats_hourly(bucket_start,user_id,endpoint_id,operation,allowed_count) SELECT 7200,'u1',id,'container:logs',1 FROM endpoints`)
	// The downgrade refuses while an unmatched row exists (no silent loss) ...
	if _, err := p.DownTo(t.Context(), 12); err == nil {
		t.Fatal("downgrade silently discarded an unmatched denial")
	}
	if integer(t, db, `SELECT count(*) FROM usage_stats_hourly WHERE selector_id IS NULL AND denied_count=4`) != 1 {
		t.Fatal("failed downgrade lost the unmatched row")
	}
	// ... and succeeds, keeping the matched rows, once it was removed deliberately.
	exec(t, db, `DELETE FROM usage_stats_hourly WHERE selector_id IS NULL`)
	if _, err := p.DownTo(t.Context(), 12); err != nil {
		t.Fatal(err)
	}
	if integer(t, db, `SELECT count(*) FROM usage_stats_hourly WHERE selector_id='s1' AND allowed_count=2`) != 1 {
		t.Fatal("downgrade lost matched usage")
	}
	if _, err := p.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestUsageStorage(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	exec(t, db, `INSERT INTO agents(id,name,owner_user_id) VALUES ('a1','bot','u1')`)
	exec(t, db, `INSERT INTO container_selectors(id,endpoint_id,container_name) SELECT 's1',id,'db' FROM endpoints`)
	for _, table := range []string{"usage_stats_hourly", "usage_stats_daily"} {
		// Only fixed test-owned table names are interpolated; no untrusted SQL.
		q := `INSERT INTO ` + table + `(bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count) SELECT 0,'u1','a1',endpoint_id,id,'container:logs',2,3,1 FROM container_selectors`
		exec(t, db, q)
		rejects(t, db, q)
		rejects(t, db, `UPDATE `+table+` SET denied_count=-1`)
		rejects(t, db, `UPDATE `+table+` SET endpoint_id='missing'`)
		rejects(t, db, `UPDATE `+table+` SET operation='container:exec'`)
		exec(t, db, `INSERT INTO `+table+`(bucket_start,user_id,endpoint_id,selector_id,operation) SELECT 0,'u2',endpoint_id,id,'container:logs' FROM container_selectors`)
		rejects(t, db, `INSERT INTO `+table+`(bucket_start,user_id,endpoint_id,selector_id,operation) SELECT 0,'u2',endpoint_id,id,'container:logs' FROM container_selectors`)
	}
	exec(t, db, `INSERT INTO usage_recent_events(id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until) SELECT 'ev','u1','a1',endpoint_id,id,'container:logs','error',1,100 FROM container_selectors`)
	rejects(t, db, `UPDATE usage_recent_events SET outcome='success'`)
}
