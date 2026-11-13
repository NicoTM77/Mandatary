-- +goose Up
-- P1.15 persistent usage accounting. The only schema change: a usage row may carry
-- no selector. TD §9.1 attributes usage to (user, agent, endpoint, selector,
-- operation) and counts a *denied* attempt of an authenticated principal. A default
-- deny, a missing target or a rejected parameter set matched no selector at all, so
-- there is no selector to attribute it to; inventing one (a placeholder selector row
-- that an administrator could later attach policies to) would be worse than NULL.
-- NULL is therefore the explicit "no selector matched" attribution of a DENIED
-- outcome; the application never writes it for allowed or error outcomes (those
-- always follow an allowing policy, hence a selector). The CHECK below enforces that
-- in SQL itself, whatever writer acts.
--
-- Nothing else changes: columns, ranges, foreign keys (a composite foreign key whose
-- selector column is NULL is simply not checked, the SQLite default MATCH SIMPLE) and
-- the unique attribution index (selector NULL is folded to '' like the nullable
-- principal columns, so the rollup stays unique) keep their P1.02 meaning. No usage
-- writer existed before this migration, so the tables are rebuilt empty-safe: rows are
-- copied verbatim. SQLite cannot drop NOT NULL in place, hence the rebuild.
--
-- The rebuild stashes the rows in a TEMP table instead of using ALTER TABLE ... RENAME:
-- every RENAME makes SQLite re-parse the whole main schema, and three of them added
-- about 430 ms (+70%) to every fresh store open under the race detector, which pushed
-- the slowest package of the arm64 CI job over its timeout. A TEMP stash lives outside
-- the main schema, is dropped inside the same goose transaction (so the migration stays
-- atomic) and keeps the verbatim row copy. Nothing references the usage tables, so
-- dropping them is safe with foreign keys enforced.

CREATE TEMP TABLE usage_stats_hourly_old AS SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_hourly;
DROP TABLE usage_stats_hourly;
CREATE TABLE usage_stats_hourly (
    id INTEGER PRIMARY KEY,
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0 AND bucket_start % 3600 = 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    allowed_count INTEGER NOT NULL DEFAULT 0 CHECK (allowed_count >= 0),
    denied_count INTEGER NOT NULL DEFAULT 0 CHECK (denied_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    CHECK (selector_id IS NOT NULL OR (allowed_count = 0 AND error_count = 0)),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO usage_stats_hourly(id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count)
    SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_hourly_old;
DROP TABLE usage_stats_hourly_old;
CREATE UNIQUE INDEX usage_hourly_tuple ON usage_stats_hourly(bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,coalesce(selector_id,''),operation);

CREATE TEMP TABLE usage_stats_daily_old AS SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_daily;
DROP TABLE usage_stats_daily;
CREATE TABLE usage_stats_daily (
    id INTEGER PRIMARY KEY,
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0 AND bucket_start % 86400 = 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    allowed_count INTEGER NOT NULL DEFAULT 0 CHECK (allowed_count >= 0),
    denied_count INTEGER NOT NULL DEFAULT 0 CHECK (denied_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    CHECK (selector_id IS NOT NULL OR (allowed_count = 0 AND error_count = 0)),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO usage_stats_daily(id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count)
    SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_daily_old;
DROP TABLE usage_stats_daily_old;
CREATE UNIQUE INDEX usage_daily_tuple ON usage_stats_daily(bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,coalesce(selector_id,''),operation);

CREATE TEMP TABLE usage_recent_events_old AS SELECT id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until FROM usage_recent_events;
DROP TABLE usage_recent_events;
CREATE TABLE usage_recent_events (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','error')),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    retain_until INTEGER NOT NULL CHECK (retain_until > occurred_at),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    CHECK (selector_id IS NOT NULL OR outcome = 'denied'),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO usage_recent_events(id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until)
    SELECT id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until FROM usage_recent_events_old;
DROP TABLE usage_recent_events_old;
CREATE INDEX usage_events_retention ON usage_recent_events(retain_until);
CREATE INDEX usage_events_order ON usage_recent_events(occurred_at);

-- +goose Down
-- Restoring NOT NULL cannot represent an unmatched denial. The copy below therefore
-- aborts (NOT NULL constraint) while any such row exists: a downgrade never silently
-- discards counts. Purge or migrate them deliberately first.
DROP INDEX usage_events_order;
CREATE TEMP TABLE usage_recent_events_new AS SELECT id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until FROM usage_recent_events;
DROP TABLE usage_recent_events;
CREATE TABLE usage_recent_events (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','error')),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    retain_until INTEGER NOT NULL CHECK (retain_until > occurred_at),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO usage_recent_events(id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until)
    SELECT id,user_id,agent_id,endpoint_id,selector_id,operation,outcome,occurred_at,retain_until FROM usage_recent_events_new;
DROP TABLE usage_recent_events_new;
CREATE INDEX usage_events_retention ON usage_recent_events(retain_until);

CREATE TEMP TABLE usage_stats_daily_new AS SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_daily;
DROP TABLE usage_stats_daily;
CREATE TABLE usage_stats_daily (
    id INTEGER PRIMARY KEY,
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0 AND bucket_start % 86400 = 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    allowed_count INTEGER NOT NULL DEFAULT 0 CHECK (allowed_count >= 0),
    denied_count INTEGER NOT NULL DEFAULT 0 CHECK (denied_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO usage_stats_daily(id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count)
    SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_daily_new;
DROP TABLE usage_stats_daily_new;
CREATE UNIQUE INDEX usage_daily_tuple ON usage_stats_daily(bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,selector_id,operation);

CREATE TEMP TABLE usage_stats_hourly_new AS SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_hourly;
DROP TABLE usage_stats_hourly;
CREATE TABLE usage_stats_hourly (
    id INTEGER PRIMARY KEY,
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0 AND bucket_start % 3600 = 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    allowed_count INTEGER NOT NULL DEFAULT 0 CHECK (allowed_count >= 0),
    denied_count INTEGER NOT NULL DEFAULT 0 CHECK (denied_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO usage_stats_hourly(id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count)
    SELECT id,bucket_start,user_id,agent_id,endpoint_id,selector_id,operation,allowed_count,denied_count,error_count FROM usage_stats_hourly_new;
DROP TABLE usage_stats_hourly_new;
CREATE UNIQUE INDEX usage_hourly_tuple ON usage_stats_hourly(bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,selector_id,operation);
