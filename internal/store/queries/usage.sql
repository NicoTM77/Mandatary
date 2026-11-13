-- P1.15 usage accounting (TD section 9.1). Every statement binds parameters; nothing here
-- stores a request or response payload, only the attribution tuple and counts.

-- name: AddHourlyUsage :exec
INSERT INTO usage_stats_hourly(bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count)
VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT (bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,coalesce(selector_id,''),operation)
DO UPDATE SET allowed_count = allowed_count + excluded.allowed_count,
              denied_count = denied_count + excluded.denied_count,
              error_count = error_count + excluded.error_count;

-- name: AddDailyUsage :exec
INSERT INTO usage_stats_daily(bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count)
VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT (bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,coalesce(selector_id,''),operation)
DO UPDATE SET allowed_count = allowed_count + excluded.allowed_count,
              denied_count = denied_count + excluded.denied_count,
              error_count = error_count + excluded.error_count;

-- name: CreateRecentUsage :exec
INSERT INTO usage_recent_events(id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until)
VALUES (?,?,?,?,?,?,?,?,?);

-- Ring buffer bound: keep the newest ? events (insertion order breaks same-second ties).
-- name: TrimRecentUsage :execrows
DELETE FROM usage_recent_events WHERE rowid IN (
    SELECT rowid FROM usage_recent_events ORDER BY occurred_at DESC, rowid DESC LIMIT -1 OFFSET ?);

-- name: PruneExpiredRecentUsage :execrows
DELETE FROM usage_recent_events WHERE retain_until <= ?;

-- A window is removed only when it lies wholly before the cutoff (bucket_start is
-- the window's first second; the caller passes cutoff minus the window width).
-- name: PruneHourlyUsage :execrows
DELETE FROM usage_stats_hourly WHERE bucket_start <= ?;

-- name: PruneDailyUsage :execrows
DELETE FROM usage_stats_daily WHERE bucket_start <= ?;

-- Reads for rollups and the recent-event ring buffer, stable order.
-- name: ListAllHourlyUsage :many
SELECT * FROM usage_stats_hourly ORDER BY bucket_start,id;

-- name: ListAllDailyUsage :many
SELECT * FROM usage_stats_daily ORDER BY bucket_start,id;

-- name: ListAllRecentUsage :many
SELECT * FROM usage_recent_events ORDER BY occurred_at,rowid;
