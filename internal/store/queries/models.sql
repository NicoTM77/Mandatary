-- Structural persistence only. No query here accepts a credential, evaluates
-- policy, approves imported authority, activates an endpoint or sends mail.
-- name: GetLocalEndpoint :one
SELECT * FROM endpoints WHERE slug = 'local';

-- name: GetInstallationControl :one
SELECT * FROM installation_control WHERE singleton = 1;

-- name: CreateUser :exec
INSERT INTO users(id,username) VALUES (?,?);

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: CreateGroup :exec
INSERT INTO groups(id,name) VALUES (?,?);

-- name: CreateAgent :exec
INSERT INTO agents(id,name,owner_user_id,owner_group_id) VALUES (?,?,?,?);

-- name: GetAgent :one
SELECT * FROM agents WHERE id = ?;

-- name: CreateSelector :exec
INSERT INTO container_selectors(id,endpoint_id,container_name,name_is_glob,compose_project,compose_service,image_pattern,pinned_container_id,pinned_image_digest) VALUES (?,?,?,?,?,?,?,?,?);

-- name: ListSelectorsByEndpoint :many
SELECT * FROM container_selectors WHERE endpoint_id = ? ORDER BY id;

-- name: GetAuthenticator :one
SELECT * FROM authenticators WHERE id = ?;

-- name: GetSession :one
SELECT * FROM sessions WHERE id = ?;

-- name: GetMachineRecord :one
SELECT * FROM agent_credentials WHERE id = ?;

-- name: ListPoliciesByEndpoint :many
SELECT * FROM policies WHERE endpoint_id = ? ORDER BY id;

-- name: ListNotificationAddresses :many
SELECT * FROM notification_addresses WHERE user_id = ? ORDER BY id;

-- name: CreateSecurityEvent :exec
INSERT INTO security_events(id,user_id,event_type,occurred_at,retain_until,deduplication_key) VALUES (?,?,?,?,?,?);

-- name: CreateNoticeIntent :exec
INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until) VALUES (?,?,?,?,?,?,?);

-- name: ListNoticeIntents :many
SELECT * FROM security_notice_outbox WHERE event_id = ? ORDER BY id;

-- name: ListHourlyUsage :many
SELECT * FROM usage_stats_hourly WHERE endpoint_id = ? ORDER BY bucket_start,id;

-- name: ListDailyUsage :many
SELECT * FROM usage_stats_daily WHERE endpoint_id = ? ORDER BY bucket_start,id;

-- name: ListRecentUsage :many
SELECT * FROM usage_recent_events WHERE endpoint_id = ? ORDER BY occurred_at,id;

-- name: GetRepositoryMetadata :one
SELECT * FROM repository_metadata WHERE singleton = 1;

-- name: InitializeRepositoryMetadata :exec
INSERT INTO repository_metadata(singleton,installation_id,key_check) VALUES (1,?,?);

-- name: PutSMTPRecord :exec
INSERT INTO smtp_secrets(id,ciphertext) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext;

-- name: GetSMTPRecord :one
SELECT ciphertext FROM smtp_secrets WHERE id = ?;
