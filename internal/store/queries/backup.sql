-- P1.18 logical backup and transactional restore (security-contracts.md S2).
-- Used ONLY by internal/backup, inside Repository.Read (export) or Repository.Control (restore).
-- Nothing here verifies a caller, an archive or a signature, decides policy, issues a credential or
-- approves authority: the service authorizes the initiator inside the same transaction, and every
-- imported record is written INACTIVE ('quarantined', generation 0). No statement may write
-- installation_control except BackupEnterQuarantine (monotonic, quarantine-only); an archive never
-- supplies a state, a generation or a control value.

-- name: BackupListEndpoints :many
SELECT * FROM endpoints ORDER BY id;

-- name: BackupListUserMemberships :many
SELECT * FROM user_group_memberships ORDER BY user_id, group_id;

-- name: BackupListAgentMemberships :many
SELECT * FROM agent_group_memberships ORDER BY agent_id, group_id;

-- name: BackupListRoles :many
SELECT * FROM administrative_roles ORDER BY id;

-- name: BackupListSelectors :many
SELECT * FROM container_selectors ORDER BY id;

-- name: BackupListAddresses :many
SELECT * FROM notification_addresses ORDER BY id;

-- name: BackupListActiveAuthenticators :many
-- Only credentials that could authenticate at export time are carried; pending, disabled and
-- revoked material has no authority and is not exported.
SELECT * FROM authenticators WHERE state = 'active' ORDER BY id;

-- name: BackupListActiveMachineRecords :many
SELECT * FROM agent_credentials WHERE state = 'active' AND revoked_at IS NULL ORDER BY id;

-- name: BackupListWebauthnUsers :many
SELECT * FROM webauthn_users ORDER BY user_id;

-- name: BackupListWebauthnRecords :many
SELECT * FROM webauthn_credentials ORDER BY authenticator_id;

-- name: BackupEnterQuarantine :execrows
-- The availability-changing transition (S2.2.1): quarantine plus a rotation of every live control
-- generation. All four only ever increase (the table trigger forbids regression).
UPDATE installation_control SET restore_quarantined = 1,
    credential_generation = credential_generation + 1, session_generation = session_generation + 1,
    authority_generation = authority_generation + 1, restore_generation = restore_generation + 1
WHERE singleton = 1;

-- name: BackupRevokeAllSessions :exec
UPDATE sessions SET state = 'revoked', revoked_at = max(created_at, CAST(sqlc.arg(now) AS INTEGER)) WHERE state != 'revoked';

-- name: BackupRevokeLiveMachineRecords :exec
-- Final (a revoked credential can never be reactivated): the old token cannot return by any route.
UPDATE agent_credentials SET state = 'revoked', revoked_at = max(issued_at, CAST(sqlc.arg(now) AS INTEGER)) WHERE state != 'revoked';

-- name: BackupQuarantineUsers :exec
UPDATE users SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineGroups :exec
UPDATE groups SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineAgents :exec
UPDATE agents SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineUserMemberships :exec
UPDATE user_group_memberships SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineAgentMemberships :exec
UPDATE agent_group_memberships SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineRoles :exec
UPDATE administrative_roles SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantinePolicies :exec
-- A quarantined DENY still blocks (RESTORE-03, authz); a quarantined ALLOW grants nothing.
UPDATE policies SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineEndpoints :exec
UPDATE endpoints SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineAddresses :exec
UPDATE notification_addresses SET state = 'quarantined' WHERE state = 'active';

-- name: BackupQuarantineAuthenticators :exec
UPDATE authenticators SET state = 'quarantined' WHERE state = 'active';

-- name: BackupRenameUserForImport :exec
UPDATE users SET username = username || '~retired~' || substr(id, 1, 8) WHERE username = sqlc.arg(username) AND id != sqlc.arg(id);

-- name: BackupRenameGroupForImport :exec
UPDATE groups SET name = name || '~retired~' || substr(id, 1, 8) WHERE name = sqlc.arg(name) AND id != sqlc.arg(id);

-- name: BackupRenameAgentForImport :exec
UPDATE agents SET name = name || '~retired~' || substr(id, 1, 8) WHERE name = sqlc.arg(name) AND id != sqlc.arg(id);

-- name: BackupUpsertUser :exec
INSERT INTO users(id, username, state, mfa_requirement, compromised, credential_generation, authority_generation)
VALUES (sqlc.arg(id), sqlc.arg(username), 'quarantined', sqlc.arg(mfa_requirement), sqlc.arg(compromised), 0, 0)
ON CONFLICT(id) DO UPDATE SET username = excluded.username, state = 'quarantined', mfa_requirement = excluded.mfa_requirement,
    compromised = max(users.compromised, excluded.compromised), credential_generation = 0, authority_generation = 0;

-- name: BackupUpsertGroup :exec
INSERT INTO groups(id, name, state, authority_generation) VALUES (sqlc.arg(id), sqlc.arg(name), 'quarantined', 0)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, state = 'quarantined', authority_generation = 0;

-- name: BackupUpsertAgent :exec
INSERT INTO agents(id, name, owner_user_id, owner_group_id, state, credential_generation, authority_generation)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.narg(owner_user_id), sqlc.narg(owner_group_id), 'quarantined', 0, 0)
ON CONFLICT(id) DO UPDATE SET name = excluded.name, owner_user_id = excluded.owner_user_id, owner_group_id = excluded.owner_group_id,
    state = 'quarantined', credential_generation = 0, authority_generation = 0;

-- name: BackupUpsertUserMembership :exec
INSERT INTO user_group_memberships(user_id, group_id, state, authority_generation) VALUES (sqlc.arg(user_id), sqlc.arg(group_id), 'quarantined', 0)
ON CONFLICT(user_id, group_id) DO UPDATE SET state = 'quarantined', authority_generation = 0;

-- name: BackupUpsertAgentMembership :exec
INSERT INTO agent_group_memberships(agent_id, group_id, state, authority_generation) VALUES (sqlc.arg(agent_id), sqlc.arg(group_id), 'quarantined', 0)
ON CONFLICT(agent_id, group_id) DO UPDATE SET state = 'quarantined', authority_generation = 0;

-- name: BackupDeleteCollidingGlobalRole :exec
-- A user holds at most one global role per kind; a different live row for the same (user, role)
-- is dropped so the archived (quarantined) one can take its place. Roles are referenced by nothing.
DELETE FROM administrative_roles WHERE user_id = sqlc.arg(user_id) AND role = sqlc.arg(role) AND endpoint_id IS NULL AND id != sqlc.arg(id);

-- name: BackupDeleteCollidingEndpointRole :exec
DELETE FROM administrative_roles WHERE user_id = sqlc.arg(user_id) AND role = sqlc.arg(role) AND endpoint_id = sqlc.arg(endpoint_id) AND id != sqlc.arg(id);

-- name: BackupUpsertRole :exec
INSERT INTO administrative_roles(id, user_id, role, endpoint_id, state, authority_generation)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(role), sqlc.narg(endpoint_id), 'quarantined', 0)
ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, role = excluded.role, endpoint_id = excluded.endpoint_id,
    state = 'quarantined', authority_generation = 0;

-- name: BackupInsertSelector :exec
INSERT INTO container_selectors(id, endpoint_id, container_name, name_is_glob, compose_project, compose_service, image_pattern, pinned_container_id, pinned_image_digest)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING;

-- name: BackupUpsertPolicy :exec
INSERT INTO policies(id, user_id, group_id, agent_id, endpoint_id, selector_id, operation, effect, state, authority_generation, log_tail_max, stop_timeout_max)
VALUES (sqlc.arg(id), sqlc.narg(user_id), sqlc.narg(group_id), sqlc.narg(agent_id), sqlc.arg(endpoint_id), sqlc.arg(selector_id), sqlc.arg(operation), sqlc.arg(effect), 'quarantined', 0, sqlc.narg(log_tail_max), sqlc.narg(stop_timeout_max))
ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, group_id = excluded.group_id, agent_id = excluded.agent_id,
    endpoint_id = excluded.endpoint_id, selector_id = excluded.selector_id, operation = excluded.operation, effect = excluded.effect,
    state = 'quarantined', authority_generation = 0, log_tail_max = excluded.log_tail_max, stop_timeout_max = excluded.stop_timeout_max;

-- name: BackupInsertAddress :exec
-- Imported contact data is never verified: it stays quarantined until the address is proven again.
INSERT INTO notification_addresses(id, user_id, address, version, created_at, state, authority_generation)
VALUES (?, ?, ?, ?, ?, 'quarantined', 0) ON CONFLICT DO NOTHING;

-- name: BackupInsertAuthenticator :exec
-- Retained for provenance only. state is fixed to 'quarantined' and generation to 0 here, never read
-- from the archive, and failed-attempt/lockout counters start clean (rate-limit buckets are excluded).
INSERT INTO authenticators(id, user_id, kind, state, credential_generation, created_at, bound_at, expires_at, verifier_hash, encrypted_secret, public_key,
    external_credential_id, password_codepoints, password_format, max_assurance, phishing_resistant, retry_ceiling, failed_attempts, last_accepted_totp_step,
    sign_count, backup_eligible, backup_state, user_verified, totp_algorithm)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(kind), 'quarantined', 0, sqlc.arg(created_at), sqlc.narg(bound_at), sqlc.narg(expires_at), sqlc.narg(verifier_hash), sqlc.narg(encrypted_secret), sqlc.narg(public_key),
    sqlc.narg(external_credential_id), sqlc.narg(password_codepoints), sqlc.narg(password_format), sqlc.arg(max_assurance), sqlc.narg(phishing_resistant), sqlc.arg(retry_ceiling), 0, sqlc.narg(last_accepted_totp_step),
    sqlc.narg(sign_count), sqlc.narg(backup_eligible), sqlc.narg(backup_state), sqlc.narg(user_verified), sqlc.narg(totp_algorithm))
ON CONFLICT DO NOTHING;

-- name: BackupInsertMachineRecord :exec
-- Imported token hashes are inactive 'quarantined' rows with their ORIGINAL issue and expiry times: nothing
-- here extends or restarts a lifetime, and no code path ever activates a credential.
INSERT INTO agent_credentials(id, agent_id, token_hash, display_prefix, issued_at, expires_at, nonexpiring_approved, credential_generation, state)
VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'quarantined') ON CONFLICT DO NOTHING;

-- name: BackupInsertWebauthnUser :exec
INSERT INTO webauthn_users(user_id, handle) VALUES (?, ?) ON CONFLICT DO NOTHING;

-- name: BackupInsertWebauthnRecord :exec
INSERT INTO webauthn_credentials(authenticator_id, label, envelope) VALUES (?, ?, ?) ON CONFLICT DO NOTHING;

-- name: BackupCountActiveAuthority :one
-- Post-import invariant: nothing the restore touched may be effective.
SELECT (SELECT count(*) FROM users WHERE state = 'active') + (SELECT count(*) FROM groups WHERE state = 'active')
 + (SELECT count(*) FROM agents WHERE state = 'active') + (SELECT count(*) FROM user_group_memberships WHERE state = 'active')
 + (SELECT count(*) FROM agent_group_memberships WHERE state = 'active') + (SELECT count(*) FROM administrative_roles WHERE state = 'active')
 + (SELECT count(*) FROM policies WHERE state = 'active') + (SELECT count(*) FROM endpoints WHERE state = 'active')
 + (SELECT count(*) FROM notification_addresses WHERE state = 'active') + (SELECT count(*) FROM authenticators WHERE state = 'active')
 + (SELECT count(*) FROM agent_credentials WHERE state = 'active') + (SELECT count(*) FROM sessions WHERE state = 'active') AS active_records;

-- name: InsertRestoreReport :exec
INSERT INTO restore_reports(restore_generation, backup_id, mode, provenance, initiator, restored_at, summary) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: InsertRestoreManifestItem :exec
INSERT INTO restore_manifest(restore_generation, kind, item_id, label, origin, source_state, imported, effective) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: LatestRestoreReport :one
SELECT * FROM restore_reports ORDER BY restore_generation DESC LIMIT 1;

-- name: ListRestoreManifest :many
SELECT * FROM restore_manifest WHERE restore_generation = ? ORDER BY kind, item_id;

-- name: GetRestoreManifestItem :one
SELECT * FROM restore_manifest WHERE restore_generation = ? AND kind = ? AND item_id = ?;

-- name: ApproveRestoreManifestItem :execrows
UPDATE restore_manifest SET decision = 'approved', decided_at = sqlc.arg(now), effective = sqlc.arg(effective)
WHERE restore_generation = sqlc.arg(restore_generation) AND kind = sqlc.arg(kind) AND item_id = sqlc.arg(item_id) AND decision = 'pending';

-- name: BackupActivateUser :execrows
UPDATE users SET state = 'active', credential_generation = sqlc.arg(credential_generation), authority_generation = sqlc.arg(authority_generation)
WHERE id = sqlc.arg(id) AND state = 'quarantined' AND compromised = 0;

-- name: BackupActivateGroup :execrows
UPDATE groups SET state = 'active', authority_generation = sqlc.arg(authority_generation) WHERE id = sqlc.arg(id) AND state = 'quarantined';

-- name: BackupActivateAgent :execrows
UPDATE agents SET state = 'active', credential_generation = sqlc.arg(credential_generation), authority_generation = sqlc.arg(authority_generation)
WHERE id = sqlc.arg(id) AND state = 'quarantined';

-- name: BackupActivateUserMembership :execrows
UPDATE user_group_memberships SET state = 'active', authority_generation = sqlc.arg(authority_generation)
WHERE user_id = sqlc.arg(user_id) AND group_id = sqlc.arg(group_id) AND state = 'quarantined';

-- name: BackupActivateAgentMembership :execrows
UPDATE agent_group_memberships SET state = 'active', authority_generation = sqlc.arg(authority_generation)
WHERE agent_id = sqlc.arg(agent_id) AND group_id = sqlc.arg(group_id) AND state = 'quarantined';

-- name: BackupActivatePolicy :execrows
UPDATE policies SET state = 'active', authority_generation = sqlc.arg(authority_generation) WHERE id = sqlc.arg(id) AND state = 'quarantined';

-- name: BackupActivateEndpoint :execrows
UPDATE endpoints SET state = 'active', authority_generation = sqlc.arg(authority_generation)
WHERE id = sqlc.arg(id) AND state = 'quarantined' AND slug = 'local' AND transport = 'unix';

-- name: BackupListQuarantinedUsers :many
SELECT * FROM users WHERE state = 'quarantined' ORDER BY id;

-- name: BackupListQuarantinedGroups :many
SELECT * FROM groups WHERE state = 'quarantined' ORDER BY id;

-- name: BackupListQuarantinedAgents :many
SELECT * FROM agents WHERE state = 'quarantined' ORDER BY id;

-- name: BackupListQuarantinedUserMemberships :many
SELECT * FROM user_group_memberships WHERE state = 'quarantined' ORDER BY user_id, group_id;

-- name: BackupListQuarantinedAgentMemberships :many
SELECT * FROM agent_group_memberships WHERE state = 'quarantined' ORDER BY agent_id, group_id;

-- name: BackupListQuarantinedRoles :many
SELECT * FROM administrative_roles WHERE state = 'quarantined' ORDER BY id;

-- name: BackupListQuarantinedPolicies :many
SELECT * FROM policies WHERE state = 'quarantined' ORDER BY id;

-- name: BackupListQuarantinedAddresses :many
SELECT * FROM notification_addresses WHERE state = 'quarantined' ORDER BY id;

-- name: BackupCountInactiveRecords :one
SELECT (SELECT count(*) FROM authenticators WHERE state = 'quarantined') AS authenticators,
       (SELECT count(*) FROM agent_credentials WHERE state = 'quarantined') AS agent_credentials;
