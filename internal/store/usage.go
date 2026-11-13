package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"sync/atomic"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
)

// ErrUsageInvalid: the event or the configuration is not acceptable. It is a fixed,
// secret-free sentinel; the rejected values are never echoed.
var ErrUsageInvalid = errors.New("invalid usage accounting input")

// Usage accounting defaults and bounds (TD 9.1: 90 days default, configurable).
const (
	DefaultUsageRetention   = 90 * 24 * time.Hour
	MinUsageRetention       = time.Hour
	MaxUsageRetention       = 3650 * 24 * time.Hour
	DefaultRecentEventLimit = 1000
	MaxRecentEventLimit     = 1_000_000
	DefaultPruneInterval    = time.Hour
	MinPruneInterval        = time.Minute

	hourSeconds = int64(3600)
	daySeconds  = int64(86400)
)

// usageOperations is the closed permission catalog (internal/ops proves it equals
// authz.AllOperations); SQL CHECK constraints enforce the same set independently.
var usageOperations = map[string]struct{}{
	"container:logs": {}, "container:inspect_status": {}, "container:inspect_config": {},
	"container:start": {}, "container:stop": {}, "container:restart": {},
}

// UsageGranularity selects the hourly or the daily rollup table.
type UsageGranularity int

const (
	UsageHourly UsageGranularity = iota + 1
	UsageDaily
)

// UsageConfig configures a UsageLedger; every zero value selects the documented default.
type UsageConfig struct {
	// Retention is how long rollup windows and recent events are kept (default 90 days).
	Retention time.Duration
	// RecentEventLimit bounds the recent-event ring buffer by count (default 1000).
	RecentEventLimit int
	// PruneInterval is how often a successful RecordUsage also applies retention
	// (default 1h). DisableAutoPrune turns the piggy-backed pruning off; the owner
	// must then call Prune itself.
	PruneInterval    time.Duration
	DisableAutoPrune bool
	// Clock is the accounting clock (default time.Now); tests inject a synthetic one.
	Clock func() time.Time
}

// UsageRollup is one hourly or daily row. Window is the UTC window start. UserID and
// AgentID are empty when not applicable; SelectorID is empty only for a denial that
// matched no selector.
type UsageRollup struct {
	Window     time.Time
	UserID     domain.UserID
	AgentID    domain.AgentID
	EndpointID domain.EndpointID
	SelectorID domain.SelectorID
	Operation  string
	Allowed    int64
	Denied     int64
	Error      int64
}

// UsageRecent is one entry of the bounded recent-event ring buffer.
type UsageRecent struct {
	ID          string
	UserID      domain.UserID
	AgentID     domain.AgentID
	EndpointID  domain.EndpointID
	SelectorID  domain.SelectorID
	Operation   string
	Outcome     domain.UsageOutcome
	OccurredAt  time.Time
	RetainUntil time.Time
}

// UsagePruned reports how many rows one retention pass removed.
type UsagePruned struct{ Hourly, Daily, Recent int64 }

// UsageLedger is the persistent usage accounting service (TD 9.1, P1.15). It is safe
// for concurrent use: every accounted outcome is ONE write transaction that
// increments the hourly and the daily rollup, appends the recent event and trims the
// ring buffer together, so a failure leaves no partial count and concurrent
// outcomes never lose an increment (the writer is the repository's single
// serialized writer).
type UsageLedger struct {
	repo      *Repository
	retention time.Duration
	limit     int
	interval  time.Duration
	auto      bool
	clock     func() time.Time
	lastPrune atomic.Int64 // unix seconds of the last automatic pass (0: never)
}

// NewUsageLedger validates cfg fail-closed.
func NewUsageLedger(repo *Repository, cfg UsageConfig) (*UsageLedger, error) {
	if repo == nil {
		return nil, ErrUsageInvalid
	}
	l := &UsageLedger{repo: repo, retention: cfg.Retention, limit: cfg.RecentEventLimit, interval: cfg.PruneInterval, auto: !cfg.DisableAutoPrune, clock: cfg.Clock}
	if l.retention == 0 {
		l.retention = DefaultUsageRetention
	}
	if l.limit == 0 {
		l.limit = DefaultRecentEventLimit
	}
	if l.interval == 0 {
		l.interval = DefaultPruneInterval
	}
	if l.clock == nil {
		l.clock = time.Now
	}
	if l.retention < MinUsageRetention || l.retention > MaxUsageRetention ||
		l.limit < 1 || l.limit > MaxRecentEventLimit ||
		l.interval < MinPruneInterval {
		return nil, ErrUsageInvalid
	}
	return l, nil
}

// Retention and RecentEventLimit report the effective configuration.
func (l *UsageLedger) Retention() time.Duration { return l.retention }
func (l *UsageLedger) RecentEventLimit() int    { return l.limit }

func validUsageEvent(e domain.UsageEvent) (user, agent, selector sql.NullString, err error) {
	if _, ok := usageOperations[e.Operation]; !ok || !e.Outcome.Valid() {
		return user, agent, selector, ErrUsageInvalid
	}
	if _, perr := domain.ParseEndpointID(string(e.EndpointID)); perr != nil {
		return user, agent, selector, ErrUsageInvalid
	}
	if e.UserID == "" && e.AgentID == "" {
		return user, agent, selector, ErrUsageInvalid
	}
	// Allowed and error outcomes follow an allowing policy, hence a selector.
	if e.SelectorID == "" && e.Outcome != domain.UsageDenied {
		return user, agent, selector, ErrUsageInvalid
	}
	user = sql.NullString{String: string(e.UserID), Valid: e.UserID != ""}
	agent = sql.NullString{String: string(e.AgentID), Valid: e.AgentID != ""}
	selector = sql.NullString{String: string(e.SelectorID), Valid: e.SelectorID != ""}
	return user, agent, selector, nil
}

// RecordUsage accounts one outcome exactly once. It never stores more than the event.
func (l *UsageLedger) RecordUsage(ctx context.Context, e domain.UsageEvent) error {
	if l == nil || ctx == nil {
		return ErrUsageInvalid
	}
	user, agent, selector, err := validUsageEvent(e)
	if err != nil {
		return err
	}
	now := l.clock().UTC()
	at := now.Unix()
	if at < 0 {
		return ErrUsageInvalid
	}
	id, err := domain.NewUUID(rand.Reader)
	if err != nil {
		return ErrStorage
	}
	var inc [3]int64
	switch e.Outcome {
	case domain.UsageAllowed:
		inc[0] = 1
	case domain.UsageDenied:
		inc[1] = 1
	case domain.UsageError:
		inc[2] = 1
	}
	err = l.repo.Write(ctx, func(q *Queries) error {
		if err := q.AddHourlyUsage(ctx, AddHourlyUsageParams{
			BucketStart: at - at%hourSeconds, UserID: user, AgentID: agent, EndpointID: e.EndpointID, SelectorID: selector,
			Operation: e.Operation, AllowedCount: inc[0], DeniedCount: inc[1], ErrorCount: inc[2],
		}); err != nil {
			return err
		}
		if err := q.AddDailyUsage(ctx, AddDailyUsageParams{
			BucketStart: at - at%daySeconds, UserID: user, AgentID: agent, EndpointID: e.EndpointID, SelectorID: selector,
			Operation: e.Operation, AllowedCount: inc[0], DeniedCount: inc[1], ErrorCount: inc[2],
		}); err != nil {
			return err
		}
		if err := q.CreateRecentUsage(ctx, CreateRecentUsageParams{
			ID: id, UserID: user, AgentID: agent, EndpointID: e.EndpointID, SelectorID: selector,
			Operation: e.Operation, Outcome: string(e.Outcome), OccurredAt: at, RetainUntil: at + int64(l.retention/time.Second),
		}); err != nil {
			return err
		}
		_, err := q.TrimRecentUsage(ctx, int64(l.limit))
		return err
	})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return ErrStorage
	}
	l.autoPrune(ctx, at)
	return nil
}

// autoPrune applies retention at most once per interval, best effort: a failure
// is retried by the next accounted outcome and never fails the accounting itself.
func (l *UsageLedger) autoPrune(ctx context.Context, at int64) {
	if !l.auto {
		return
	}
	last := l.lastPrune.Load()
	if last != 0 && at-last < int64(l.interval/time.Second) {
		return
	}
	if !l.lastPrune.CompareAndSwap(last, at) {
		return
	}
	if _, err := l.Prune(ctx); err != nil {
		l.lastPrune.CompareAndSwap(at, last)
	}
}

// Prune removes retention-expired data and nothing else: an hourly (daily) window
// only when the whole window lies before now-Retention, and a recent event only
// once its own retain_until has passed. Counts inside a surviving window are never
// altered. It is idempotent.
func (l *UsageLedger) Prune(ctx context.Context) (UsagePruned, error) {
	var res UsagePruned
	if l == nil || ctx == nil {
		return res, ErrUsageInvalid
	}
	now := l.clock().UTC().Unix()
	cutoff := now - int64(l.retention/time.Second)
	err := l.repo.Write(ctx, func(q *Queries) error {
		var err error
		if res.Hourly, err = q.PruneHourlyUsage(ctx, cutoff-hourSeconds); err != nil {
			return err
		}
		if res.Daily, err = q.PruneDailyUsage(ctx, cutoff-daySeconds); err != nil {
			return err
		}
		res.Recent, err = q.PruneExpiredRecentUsage(ctx, now)
		return err
	})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return UsagePruned{}, cerr
		}
		return UsagePruned{}, ErrStorage
	}
	return res, nil
}

func nullUser(v sql.NullString) domain.UserID    { return domain.UserID(v.String) }
func nullAgent(v sql.NullString) domain.AgentID  { return domain.AgentID(v.String) }
func nullSel(v sql.NullString) domain.SelectorID { return domain.SelectorID(v.String) }

// Rollups returns every row of the selected rollup table in window order.
func (l *UsageLedger) Rollups(ctx context.Context, g UsageGranularity) ([]UsageRollup, error) {
	if l == nil || ctx == nil || (g != UsageHourly && g != UsageDaily) {
		return nil, ErrUsageInvalid
	}
	var out []UsageRollup
	err := l.repo.Read(ctx, func(q *Queries) error {
		if g == UsageHourly {
			rows, err := q.ListAllHourlyUsage(ctx)
			if err != nil {
				return err
			}
			for _, r := range rows {
				out = append(out, UsageRollup{Window: time.Unix(r.BucketStart, 0).UTC(), UserID: nullUser(r.UserID), AgentID: nullAgent(r.AgentID),
					EndpointID: r.EndpointID, SelectorID: nullSel(r.SelectorID), Operation: r.Operation, Allowed: r.AllowedCount, Denied: r.DeniedCount, Error: r.ErrorCount})
			}
			return nil
		}
		rows, err := q.ListAllDailyUsage(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, UsageRollup{Window: time.Unix(r.BucketStart, 0).UTC(), UserID: nullUser(r.UserID), AgentID: nullAgent(r.AgentID),
				EndpointID: r.EndpointID, SelectorID: nullSel(r.SelectorID), Operation: r.Operation, Allowed: r.AllowedCount, Denied: r.DeniedCount, Error: r.ErrorCount})
		}
		return nil
	})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, ErrStorage
	}
	return out, nil
}

// Recent returns the ring buffer, oldest first.
func (l *UsageLedger) Recent(ctx context.Context) ([]UsageRecent, error) {
	if l == nil || ctx == nil {
		return nil, ErrUsageInvalid
	}
	var out []UsageRecent
	err := l.repo.Read(ctx, func(q *Queries) error {
		rows, err := q.ListAllRecentUsage(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, UsageRecent{ID: r.ID, UserID: nullUser(r.UserID), AgentID: nullAgent(r.AgentID), EndpointID: r.EndpointID,
				SelectorID: nullSel(r.SelectorID), Operation: r.Operation, Outcome: domain.UsageOutcome(r.Outcome),
				OccurredAt: time.Unix(r.OccurredAt, 0).UTC(), RetainUntil: time.Unix(r.RetainUntil, 0).UTC()})
		}
		return nil
	})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, ErrStorage
	}
	return out, nil
}
