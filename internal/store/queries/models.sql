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

-- P1.05 internal proof service. Call only under Repository.Control. These
-- queries do not establish sessions, setup authority or AAL2.
-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = ?;

-- name: GetLocalBinding :one
SELECT * FROM authenticators WHERE user_id = ? AND kind = 'password' AND state = 'active';

-- name: HasStrongerAuthenticator :one
SELECT EXISTS(SELECT 1 FROM authenticators WHERE user_id = sqlc.arg(user_id)
 AND kind IN ('totp','webauthn') AND state = 'active'
 AND credential_generation=sqlc.arg(credential_generation) AND bound_at IS NOT NULL AND revoked_at IS NULL
 AND (expires_at IS NULL OR expires_at>sqlc.arg(now)) AND failed_attempts<retry_ceiling) AS present;

-- name: RecordProofFailure :execrows
UPDATE authenticators SET failed_attempts=failed_attempts+1,
 state=CASE WHEN failed_attempts+1 >= retry_ceiling THEN 'disabled' ELSE state END,
 next_attempt_at=sqlc.arg(next_attempt_at)
WHERE id=sqlc.arg(id) AND kind='password' AND state='active'
 AND failed_attempts=sqlc.arg(observed_failures) AND failed_attempts<retry_ceiling;

-- name: ResetProofFailures :execrows
UPDATE authenticators SET failed_attempts=0,next_attempt_at=NULL
WHERE id=? AND kind='password' AND state='active' AND failed_attempts<retry_ceiling;

-- name: CompromiseUser :execrows
UPDATE users SET compromised=1,password_revision=password_revision+1 WHERE id=? AND state='active';

-- name: RevokeUserSessions :exec
UPDATE sessions SET state='revoked',revoked_at=sqlc.arg(now) WHERE user_id=sqlc.arg(user_id) AND state!='revoked';

-- name: UpdateVerifier :execrows
UPDATE authenticators SET verifier_hash=sqlc.arg(verifier_hash),password_format=sqlc.arg(password_format),password_codepoints=sqlc.arg(password_codepoints),changed_at=sqlc.arg(now),failed_attempts=0,next_attempt_at=NULL
WHERE id=sqlc.arg(id) AND kind='password' AND state='active' AND verifier_hash=sqlc.arg(observed_verifier) AND credential_generation=sqlc.arg(credential_generation);

-- name: ClearCompromiseFlag :execrows
UPDATE users SET compromised=0,password_revision=password_revision+1 WHERE id=? AND state='active';
