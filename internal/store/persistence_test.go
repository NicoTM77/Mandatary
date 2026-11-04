package store_test

import (
	"database/sql"
	"os"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/pressly/goose/v3"
)

// Reopening a real file proves ordinary persistence, not WAL/FULL power-loss
// qualification or the future backup service's deliberately narrower scope.
func TestPopulatedMigrationReopenAndDown(t *testing.T) {
	db, _ := fixture(t)
	notices(t, db)
	exec(t, db, `INSERT INTO agents(id,name,owner_group_id) VALUES ('a1','shared','g1')`)
	exec(t, db, `INSERT INTO container_selectors(id,endpoint_id,container_name) SELECT 's1',id,'db' FROM endpoints`)
	for _, table := range []string{"usage_stats_hourly", "usage_stats_daily"} {
		exec(t, db, `INSERT INTO `+table+`(bucket_start,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count) SELECT 0,'a1',endpoint_id,id,'container:logs',2,3,1 FROM container_selectors`)
	}
	exec(t, db, `INSERT INTO usage_recent_events(id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until) SELECT 'recent','a1',endpoint_id,id,'container:logs','denied',1,100 FROM container_selectors`)
	exec(t, db, `INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until) SELECT 'o-'||id,'e1',user_id,id,version,address,100 FROM notification_addresses`)
	exec(t, db, `UPDATE security_notice_outbox SET delivery_state='failed',attempts=2,last_attempt_at=3,next_attempt_at=5,failure_code='temporary' WHERE id='o-n1'`)
	var seq int
	var name, path string
	if err := db.QueryRowContext(t.Context(), `PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen after closing the original pool, with FKs explicitly enabled.
	reopened, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	reopened.SetMaxOpenConns(1)
	exec(t, reopened, "PRAGMA foreign_keys = ON")
	migration, err := goose.NewProvider(goose.DialectSQLite3, reopened, os.DirFS("migrations"))
	if err != nil {
		t.Fatal(err)
	}
	q := store.New(reopened)
	local, err := q.GetLocalEndpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	hourly, err := q.ListHourlyUsage(t.Context(), local.ID)
	if err != nil || len(hourly) != 1 {
		t.Fatalf("hourly persistence: rows=%d err=%v", len(hourly), err)
	}
	if hourly[0].UserID.Valid || hourly[0].AgentID.String != "a1" || hourly[0].AllowedCount != 2 || hourly[0].DeniedCount != 3 || hourly[0].ErrorCount != 1 {
		t.Fatal("group-owned agent attribution/counts lost")
	}
	daily, err := q.ListDailyUsage(t.Context(), local.ID)
	if err != nil || len(daily) != 1 || daily[0].AllowedCount != 2 || daily[0].DeniedCount != 3 || daily[0].ErrorCount != 1 {
		t.Fatal("daily counts lost", err)
	}
	recent, err := q.ListRecentUsage(t.Context(), local.ID)
	if err != nil || len(recent) != 1 || recent[0].Outcome != "denied" {
		t.Fatal("recent event lost", err)
	}
	outbox, err := q.ListNoticeIntents(t.Context(), "e1")
	if err != nil || len(outbox) != 2 || outbox[0].Attempts != 2 || outbox[0].DeliveryState != "failed" || outbox[0].DispatchState != "quarantined" || outbox[0].NextAttemptAt.Int64 != 5 {
		t.Fatal("per-recipient retry state lost or activated", err)
	}
	if _, err := migration.Down(t.Context()); err != nil {
		t.Fatal("populated FK migration down", err)
	}
	if _, err := migration.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if integer(t, reopened, `SELECT count(*) FROM users`) != 0 || integer(t, reopened, `SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("fresh migration inherited old records/authority")
	}
}
