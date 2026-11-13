package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

const (
	usageU1   = "10000000-0000-4000-8000-000000000001"
	usageU2   = "10000000-0000-4000-8000-000000000002"
	usageA1   = "40000000-0000-4000-8000-000000000001"
	usageA2   = "40000000-0000-4000-8000-000000000002" // owned by a group
	usageG1   = "30000000-0000-4000-8000-000000000001"
	usageS1   = "60000000-0000-4000-8000-000000000001"
	usageS2   = "60000000-0000-4000-8000-000000000002"
	usageLogs = "container:logs"
	usageStop = "container:stop"
)

type usageClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *usageClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *usageClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

type usageFixture struct {
	repo  *Repository
	opts  Options
	clock *usageClock
	ep    domain.EndpointID
}

// openUsageFixture opens a real file-backed repository and seeds the principals and
// selectors the usage foreign keys require.
func openUsageFixture(t *testing.T) *usageFixture {
	t.Helper()
	r, opts := openFixture(t)
	f := &usageFixture{repo: r, opts: opts, clock: &usageClock{now: time.Date(2030, 1, 10, 12, 30, 0, 0, time.UTC)}}
	ctx := t.Context()
	local, err := readLocal(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	f.ep = local
	for _, q := range []string{
		fmt.Sprintf(`INSERT INTO users(id,username) VALUES ('%s','alice'),('%s','bob')`, usageU1, usageU2),
		fmt.Sprintf(`INSERT INTO groups(id,name) VALUES ('%s','ops')`, usageG1),
		fmt.Sprintf(`INSERT INTO agents(id,name,owner_user_id) VALUES ('%s','bot','%s')`, usageA1, usageU1),
		fmt.Sprintf(`INSERT INTO agents(id,name,owner_group_id) VALUES ('%s','svc','%s')`, usageA2, usageG1),
		fmt.Sprintf(`INSERT INTO container_selectors(id,endpoint_id,container_name) VALUES ('%s','%s','edge'),('%s','%s','db')`, usageS1, local, usageS2, local),
	} {
		if _, err := r.writer.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func readLocal(ctx context.Context, r *Repository) (domain.EndpointID, error) {
	var id domain.EndpointID
	err := r.Read(ctx, func(q *Queries) error {
		ep, err := q.GetLocalEndpoint(ctx)
		id = ep.ID
		return err
	})
	return id, err
}

func (f *usageFixture) ledger(t *testing.T, cfg UsageConfig) *UsageLedger {
	t.Helper()
	cfg.Clock = f.clock.Now
	l, err := NewUsageLedger(f.repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f *usageFixture) event(user, agent, selector, op string, outcome domain.UsageOutcome) domain.UsageEvent {
	return domain.UsageEvent{UserID: domain.UserID(user), AgentID: domain.AgentID(agent), EndpointID: f.ep, SelectorID: domain.SelectorID(selector), Operation: op, Outcome: outcome}
}

func rollupTotals(t *testing.T, l *UsageLedger, g UsageGranularity) map[string][3]int64 {
	t.Helper()
	rows, err := l.Rollups(t.Context(), g)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][3]int64{}
	for _, r := range rows {
		k := fmt.Sprintf("%d|%s|%s|%s|%s|%s", r.Window.Unix(), r.UserID, r.AgentID, r.EndpointID, r.SelectorID, r.Operation)
		if _, dup := out[k]; dup {
			t.Fatalf("duplicate rollup row %s", k)
		}
		out[k] = [3]int64{r.Allowed, r.Denied, r.Error}
	}
	return out
}

func TestUsageRecordAccumulatesExactHourlyAndDailyTotals(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{})
	hour := time.Date(2030, 1, 10, 12, 0, 0, 0, time.UTC)
	nextHour := hour.Add(time.Hour)
	nextDay := time.Date(2030, 1, 11, 0, 0, 0, 0, time.UTC)

	record := func(at time.Time, e domain.UsageEvent) {
		t.Helper()
		f.clock.Set(at)
		if err := l.RecordUsage(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	// alice (human), alice's bot (user+agent), the group-owned svc (agent only).
	record(hour.Add(1*time.Minute), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed))
	record(hour.Add(2*time.Minute), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed))
	record(hour.Add(3*time.Minute), f.event(usageU1, "", usageS1, usageLogs, domain.UsageError))
	record(hour.Add(4*time.Minute), f.event(usageU1, usageA1, usageS1, usageStop, domain.UsageDenied))
	record(hour.Add(5*time.Minute), f.event("", usageA2, usageS2, usageLogs, domain.UsageAllowed))
	record(nextHour.Add(1*time.Minute), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed))
	record(nextDay.Add(1*time.Minute), f.event(usageU1, "", usageS1, usageLogs, domain.UsageDenied))

	h := func(w time.Time) string { return fmt.Sprint(w.Unix()) }
	gotH := rollupTotals(t, l, UsageHourly)
	wantH := map[string][3]int64{
		h(hour) + "|" + usageU1 + "||" + string(f.ep) + "|" + usageS1 + "|" + usageLogs:                {2, 0, 1},
		h(hour) + "|" + usageU1 + "|" + usageA1 + "|" + string(f.ep) + "|" + usageS1 + "|" + usageStop: {0, 1, 0},
		h(hour) + "||" + usageA2 + "|" + string(f.ep) + "|" + usageS2 + "|" + usageLogs:                {1, 0, 0},
		h(nextHour) + "|" + usageU1 + "||" + string(f.ep) + "|" + usageS1 + "|" + usageLogs:            {1, 0, 0},
		h(nextDay) + "|" + usageU1 + "||" + string(f.ep) + "|" + usageS1 + "|" + usageLogs:             {0, 1, 0},
	}
	if fmt.Sprint(gotH) != fmt.Sprint(wantH) {
		t.Fatalf("hourly\n got %v\nwant %v", gotH, wantH)
	}
	day := time.Date(2030, 1, 10, 0, 0, 0, 0, time.UTC)
	gotD := rollupTotals(t, l, UsageDaily)
	wantD := map[string][3]int64{
		h(day) + "|" + usageU1 + "||" + string(f.ep) + "|" + usageS1 + "|" + usageLogs:                {3, 0, 1},
		h(day) + "|" + usageU1 + "|" + usageA1 + "|" + string(f.ep) + "|" + usageS1 + "|" + usageStop: {0, 1, 0},
		h(day) + "||" + usageA2 + "|" + string(f.ep) + "|" + usageS2 + "|" + usageLogs:                {1, 0, 0},
		h(nextDay) + "|" + usageU1 + "||" + string(f.ep) + "|" + usageS1 + "|" + usageLogs:            {0, 1, 0},
	}
	if fmt.Sprint(gotD) != fmt.Sprint(wantD) {
		t.Fatalf("daily\n got %v\nwant %v", gotD, wantD)
	}
}

func TestUsageUnmatchedDenialHasNoSelectorAndNothingElseMay(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{})
	// A default deny matched no selector: counted, attributed to "no selector".
	for range 2 {
		if err := l.RecordUsage(t.Context(), f.event(usageU1, "", "", usageLogs, domain.UsageDenied)); err != nil {
			t.Fatal(err)
		}
	}
	got := rollupTotals(t, l, UsageHourly)
	if len(got) != 1 {
		t.Fatalf("unmatched denials must roll into ONE row, got %v", got)
	}
	for k, v := range got {
		if !strings.HasSuffix(k, "|"+string(f.ep)+"||"+usageLogs) || v != [3]int64{0, 2, 0} {
			t.Fatalf("row %s = %v", k, v)
		}
	}
	// Allowed and error outcomes always follow an allowing policy; a selector-less one
	// is a caller bug and is refused by the ledger and, independently, by SQL.
	for _, o := range []domain.UsageOutcome{domain.UsageAllowed, domain.UsageError} {
		if err := l.RecordUsage(t.Context(), f.event(usageU1, "", "", usageLogs, o)); err == nil {
			t.Fatalf("%s without a selector accepted", o)
		}
	}
	for _, q := range []string{
		`INSERT INTO usage_stats_hourly(bucket_start,user_id,endpoint_id,operation,allowed_count) VALUES (7200,'` + usageU1 + `','` + string(f.ep) + `','container:logs',1)`,
		`INSERT INTO usage_stats_daily(bucket_start,user_id,endpoint_id,operation,error_count) VALUES (86400,'` + usageU1 + `','` + string(f.ep) + `','container:logs',1)`,
		`INSERT INTO usage_recent_events(id,user_id,endpoint_id,operation,outcome,occurred_at,retain_until) VALUES ('x','` + usageU1 + `','` + string(f.ep) + `','container:logs','allowed',1,10)`,
		// the rollup stays unique for the NULL selector as well
		`INSERT INTO usage_stats_hourly(bucket_start,user_id,endpoint_id,operation,denied_count) VALUES (` + fmt.Sprint(f.clock.Now().Truncate(time.Hour).Unix()) + `,'` + usageU1 + `','` + string(f.ep) + `','container:logs',1)`,
	} {
		if _, err := f.repo.writer.ExecContext(t.Context(), q); err == nil {
			t.Fatalf("SQL accepted %q", q)
		}
	}
}

func TestUsageRejectsInvalidEventsAtomically(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{})
	bad := []struct {
		name string
		e    domain.UsageEvent
	}{
		{"no principal", f.event("", "", usageS1, usageLogs, domain.UsageDenied)},
		{"unknown outcome", f.event(usageU1, "", usageS1, usageLogs, "success")},
		{"empty outcome", f.event(usageU1, "", usageS1, usageLogs, "")},
		{"exec is not an operation", f.event(usageU1, "", usageS1, "container:exec", domain.UsageAllowed)},
		{"empty operation", f.event(usageU1, "", usageS1, "", domain.UsageAllowed)},
		{"bad endpoint", domain.UsageEvent{UserID: usageU1, EndpointID: "local", SelectorID: usageS1, Operation: usageLogs, Outcome: domain.UsageAllowed}},
		{"unknown selector", f.event(usageU1, "", "60000000-0000-4000-8000-0000000000ff", usageLogs, domain.UsageAllowed)},
		{"unknown user", f.event("10000000-0000-4000-8000-0000000000ff", "", usageS1, usageLogs, domain.UsageAllowed)},
		{"unknown agent", f.event(usageU1, "40000000-0000-4000-8000-0000000000ff", usageS1, usageLogs, domain.UsageAllowed)},
	}
	for _, c := range bad {
		if err := l.RecordUsage(t.Context(), c.e); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	for _, table := range []string{"usage_stats_hourly", "usage_stats_daily", "usage_recent_events"} {
		var n int
		if err := f.repo.writer.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s holds %d rows after rejected events (partial write), err=%v", table, n, err)
		}
	}
	if err := l.RecordUsage(nil, f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed)); err == nil { //nolint:staticcheck // nil context is the case under test
		t.Error("nil context accepted")
	}
}

func TestUsageConcurrentIncrementsAreExact(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{RecentEventLimit: 50})
	const workers, each = 8, 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				o := domain.UsageAllowed
				switch w % 3 {
				case 1:
					o = domain.UsageDenied
				case 2:
					o = domain.UsageError
				}
				if err := l.RecordUsage(context.Background(), f.event(usageU1, "", usageS1, usageLogs, o)); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// workers 0,3,6 allowed; 1,4,7 denied; 2,5 error.
	want := [3]int64{3 * each, 3 * each, 2 * each}
	for _, g := range []UsageGranularity{UsageHourly, UsageDaily} {
		got := rollupTotals(t, l, g)
		if len(got) != 1 {
			t.Fatalf("%v: expected one tuple, got %v", g, got)
		}
		for _, v := range got {
			if v != want {
				t.Fatalf("%v: lost or duplicated increments: got %v want %v", g, v, want)
			}
		}
	}
}

func TestUsageSurvivesRestart(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{})
	for _, o := range []domain.UsageOutcome{domain.UsageAllowed, domain.UsageAllowed, domain.UsageDenied, domain.UsageError} {
		if err := l.RecordUsage(t.Context(), f.event(usageU1, usageA1, usageS1, usageLogs, o)); err != nil {
			t.Fatal(err)
		}
	}
	beforeH, beforeD := rollupTotals(t, l, UsageHourly), rollupTotals(t, l, UsageDaily)
	recentBefore, err := l.Recent(t.Context())
	if err != nil || len(recentBefore) != 4 {
		t.Fatalf("recent before restart: %d %v", len(recentBefore), err)
	}
	if err := f.repo.Close(); err != nil {
		t.Fatal(err)
	}
	opts := f.opts
	opts.ExistingOnly = true
	reopened, err := Open(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	l2, err := NewUsageLedger(reopened, UsageConfig{Clock: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if got := rollupTotals(t, l2, UsageHourly); fmt.Sprint(got) != fmt.Sprint(beforeH) {
		t.Fatalf("hourly changed across restart: %v vs %v", got, beforeH)
	}
	if got := rollupTotals(t, l2, UsageDaily); fmt.Sprint(got) != fmt.Sprint(beforeD) {
		t.Fatalf("daily changed across restart: %v vs %v", got, beforeD)
	}
	// Counting resumes on the same rows (no reset, no second row).
	if err := l2.RecordUsage(t.Context(), f.event(usageU1, usageA1, usageS1, usageLogs, domain.UsageAllowed)); err != nil {
		t.Fatal(err)
	}
	for _, v := range rollupTotals(t, l2, UsageHourly) {
		if v != [3]int64{3, 1, 1} {
			t.Fatalf("post-restart increment: %v", v)
		}
	}
	recentAfter, err := l2.Recent(t.Context())
	if err != nil || len(recentAfter) != 5 {
		t.Fatalf("recent after restart: %d %v", len(recentAfter), err)
	}
}

func TestUsageRetentionRemovesOnlyTheSelectedWindows(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{Retention: 48 * time.Hour, DisableAutoPrune: true})
	day := func(d int, hour int) time.Time { return time.Date(2030, 1, d, hour, 15, 0, 0, time.UTC) }
	// now = Jan 10 12:30, retention 48h -> cutoff Jan 8 12:30.
	// A window is removed only when it lies WHOLLY before the cutoff.
	events := []struct {
		at time.Time
		e  domain.UsageEvent
	}{
		{day(8, 10), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed)},      // hour 10:00-11:00 ends before cutoff: removed; day Jan 8 straddles: kept
		{day(8, 11), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed)},      // hour 11:00-12:00 ends before cutoff: removed
		{day(8, 12), f.event(usageU1, "", usageS1, usageLogs, domain.UsageDenied)},       // hour 12:00-13:00 straddles the cutoff: kept
		{day(8, 20), f.event(usageU1, "", usageS1, usageLogs, domain.UsageError)},        // kept
		{day(7, 23), f.event(usageU1, usageA1, usageS2, usageStop, domain.UsageAllowed)}, // day Jan 7 wholly before cutoff: removed (hour too)
		{day(10, 12), f.event("", usageA2, usageS2, usageLogs, domain.UsageAllowed)},     // today: kept
	}
	for _, c := range events {
		f.clock.Set(c.at)
		if err := l.RecordUsage(t.Context(), c.e); err != nil {
			t.Fatal(err)
		}
	}
	hourlyBefore, dailyBefore := rollupTotals(t, l, UsageHourly), rollupTotals(t, l, UsageDaily)
	if len(hourlyBefore) != 6 || len(dailyBefore) != 3 {
		t.Fatalf("setup: %d hourly, %d daily", len(hourlyBefore), len(dailyBefore))
	}

	f.clock.Set(time.Date(2030, 1, 10, 12, 30, 0, 0, time.UTC))
	res, err := l.Prune(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.Hourly != 3 || res.Daily != 1 {
		t.Fatalf("pruned %+v, want hourly 3 (Jan 8 10h, 11h and Jan 7 23h) and daily 1 (Jan 7)", res)
	}
	hourlyAfter, dailyAfter := rollupTotals(t, l, UsageHourly), rollupTotals(t, l, UsageDaily)
	for k, v := range hourlyBefore {
		start := mustUnix(t, k)
		removed := start+3600 <= time.Date(2030, 1, 8, 12, 30, 0, 0, time.UTC).Unix()
		_, kept := hourlyAfter[k]
		if removed == kept {
			t.Errorf("hourly %s removed=%v kept=%v", k, removed, kept)
		}
		if kept && hourlyAfter[k] != v {
			t.Errorf("hourly %s counts changed by retention: %v -> %v", k, v, hourlyAfter[k])
		}
	}
	for k, v := range dailyBefore {
		start := mustUnix(t, k)
		removed := start+86400 <= time.Date(2030, 1, 8, 12, 30, 0, 0, time.UTC).Unix()
		_, kept := dailyAfter[k]
		if removed == kept {
			t.Errorf("daily %s removed=%v kept=%v", k, removed, kept)
		}
		if kept && dailyAfter[k] != v {
			t.Errorf("daily %s counts changed by retention: %v -> %v", k, v, dailyAfter[k])
		}
	}
	// A second pass is a no-op (idempotent), and the surviving counters keep counting.
	if res, err = l.Prune(t.Context()); err != nil || res.Hourly != 0 || res.Daily != 0 {
		t.Fatalf("second prune %+v %v", res, err)
	}
}

func mustUnix(t *testing.T, key string) int64 {
	t.Helper()
	var n int64
	if _, err := fmt.Sscanf(key[:strings.IndexByte(key, '|')], "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUsageRecentEventsAreBoundedByCountAndRetention(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{Retention: 24 * time.Hour, RecentEventLimit: 5, DisableAutoPrune: true})
	start := time.Date(2030, 1, 10, 12, 0, 0, 0, time.UTC)
	for i := range 12 {
		f.clock.Set(start.Add(time.Duration(i) * time.Minute))
		o := domain.UsageAllowed
		if i%2 == 1 {
			o = domain.UsageDenied
		}
		if err := l.RecordUsage(t.Context(), f.event(usageU1, "", usageS1, usageLogs, o)); err != nil {
			t.Fatal(err)
		}
	}
	recent, err := l.Recent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 5 {
		t.Fatalf("ring buffer holds %d, want 5", len(recent))
	}
	for i, ev := range recent { // newest 5 of 12 = minutes 7..11, oldest first
		want := start.Add(time.Duration(7+i) * time.Minute)
		if !ev.OccurredAt.Equal(want) || ev.RetainUntil != want.Add(24*time.Hour) {
			t.Fatalf("event %d: %v retain %v, want %v", i, ev.OccurredAt, ev.RetainUntil, want)
		}
	}
	// The rollups still hold ALL 12: the ring buffer bounds recent events only.
	for _, v := range rollupTotals(t, l, UsageHourly) {
		if v[0]+v[1]+v[2] != 12 {
			t.Fatalf("rollup lost events to the ring buffer: %v", v)
		}
	}
	// Retention drops expired events even when the buffer is not full.
	f.clock.Set(start.Add(24*time.Hour + 9*time.Minute - time.Second)) // retain_until is exclusive: minutes 7,8 expired; 9,10,11 not
	res, err := l.Prune(t.Context())
	if err != nil || res.Recent != 2 {
		t.Fatalf("prune %+v %v, want 2 expired recent events", res, err)
	}
	if recent, err = l.Recent(t.Context()); err != nil || len(recent) != 3 {
		t.Fatalf("recent after retention: %d %v", len(recent), err)
	}
}

func TestUsageEventsCarryNoPayload(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{})
	if err := l.RecordUsage(t.Context(), f.event(usageU1, usageA1, usageS1, usageLogs, domain.UsageAllowed)); err != nil {
		t.Fatal(err)
	}
	// Pin the column sets: a payload column cannot appear without failing this test.
	want := map[string]string{
		"usage_stats_hourly":  "id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count",
		"usage_stats_daily":   "id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count",
		"usage_recent_events": "id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until",
	}
	for table, cols := range want {
		rows, err := f.repo.writer.QueryContext(t.Context(), `SELECT name FROM pragma_table_info('`+table+`') ORDER BY cid`)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			got = append(got, n)
		}
		_ = rows.Close()
		if strings.Join(got, ",") != cols {
			t.Errorf("%s columns %v, want %s", table, got, cols)
		}
	}
}

func TestUsageAutoPruneAppliesRetentionOncePerInterval(t *testing.T) {
	f := openUsageFixture(t)
	l := f.ledger(t, UsageConfig{Retention: 48 * time.Hour})
	old := time.Date(2030, 1, 1, 3, 15, 0, 0, time.UTC)
	f.clock.Set(old)
	if err := l.RecordUsage(t.Context(), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed)); err != nil {
		t.Fatal(err)
	}
	// 30 minutes later: inside the prune interval, nothing is due anyway.
	f.clock.Set(old.Add(30 * time.Minute))
	if err := l.RecordUsage(t.Context(), f.event(usageU1, "", usageS1, usageLogs, domain.UsageAllowed)); err != nil {
		t.Fatal(err)
	}
	// Ten days later the first accounted outcome applies retention itself: the Jan 1
	// windows are gone and only the new outcome remains. Nobody called Prune.
	f.clock.Set(old.Add(10 * 24 * time.Hour))
	if err := l.RecordUsage(t.Context(), f.event(usageU1, "", usageS1, usageLogs, domain.UsageDenied)); err != nil {
		t.Fatal(err)
	}
	got := rollupTotals(t, l, UsageHourly)
	if len(got) != 1 {
		t.Fatalf("auto-prune left %v", got)
	}
	for _, v := range got {
		if v != [3]int64{0, 1, 0} {
			t.Fatalf("surviving counts %v", v)
		}
	}
	if n := len(rollupTotals(t, l, UsageDaily)); n != 1 {
		t.Fatalf("daily rows %d", n)
	}
}

func TestUsageLedgerConfigIsValidatedFailClosed(t *testing.T) {
	f := openUsageFixture(t)
	for name, cfg := range map[string]UsageConfig{
		"retention below minimum": {Retention: time.Minute},
		"retention above maximum": {Retention: 4000 * 24 * time.Hour},
		"negative retention":      {Retention: -time.Hour},
		"limit below minimum":     {RecentEventLimit: -1},
		"limit above maximum":     {RecentEventLimit: 1_000_001},
	} {
		if _, err := NewUsageLedger(f.repo, cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewUsageLedger(nil, UsageConfig{}); err == nil {
		t.Error("nil repository accepted")
	}
	l, err := NewUsageLedger(f.repo, UsageConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if l.Retention() != 90*24*time.Hour || l.RecentEventLimit() != 1000 {
		t.Fatalf("defaults %v %d", l.Retention(), l.RecentEventLimit())
	}
}
