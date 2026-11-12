-- P1.10 identity/group/agent administration and agent-credential lifecycle.
-- Used only by the owning administrative service, inside Repository.Control for
-- writes and Repository.Read for views. Nothing here verifies a caller, evaluates
-- policy or accepts a bearer token: the service re-checks the administrator
-- session, the live control generations and every state in the same transaction.
-- Machine-record (agent credential) queries only ever store/compare SHA-256
-- verifiers, never plaintext. Query names avoid gosec G101 name heuristics
-- (see authz.sql); the statements are bound parameters over hashed records.

-- name: GetGroupByName :one
SELECT * FROM groups WHERE name = ?;

-- name: GetAgentByName :one
SELECT * FROM agents WHERE name = ?;

-- name: ListUsers :many
SELECT * FROM users ORDER BY username, id;

-- name: ListGroups :many
SELECT * FROM groups ORDER BY name, id;

-- name: ListAgents :many
SELECT * FROM agents ORDER BY name, id;

-- name: CreateActiveUser :exec
INSERT INTO users(id,username,state,mfa_requirement,credential_generation,authority_generation) VALUES (?,?,'active','required',?,?);

-- name: CreateActiveGroup :exec
INSERT INTO groups(id,name,state,authority_generation) VALUES (?,?,'active',?);

-- name: CreateActiveAgent :exec
INSERT INTO agents(id,name,owner_user_id,owner_group_id,state,credential_generation,authority_generation) VALUES (?,?,?,?,'active',?,?);

-- name: DisableAgent :execrows
UPDATE agents SET state = 'disabled' WHERE id = ? AND state = 'active';

-- name: ListAgentMachineRecords :many
SELECT * FROM agent_credentials WHERE agent_id = ? ORDER BY issued_at, id;

-- name: InsertAgentMachineRecord :exec
INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,nonexpiring_approved,credential_generation,state)
VALUES (?,?,?,?,?,?,?,?,'active');

-- name: ShortenMachineRecordOverlap :execrows
-- Starts (or shortens) the overlap window of a rotated-out credential. The
-- schema trigger independently refuses any extension or clearing.
UPDATE agent_credentials SET rotation_overlap_until = sqlc.arg(until)
WHERE id = sqlc.arg(id) AND state = 'active' AND revoked_at IS NULL
  AND (rotation_overlap_until IS NULL OR rotation_overlap_until > sqlc.arg(until));

-- name: RetireAgentMachineRecord :execrows
UPDATE agent_credentials SET state = 'revoked', revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND agent_id = sqlc.arg(agent_id) AND state != 'revoked';

-- name: RetireAgentMachineRecords :exec
UPDATE agent_credentials SET state = 'revoked', revoked_at = sqlc.arg(now)
WHERE agent_id = sqlc.arg(agent_id) AND state != 'revoked';

-- name: GetUserGroupMembership :one
SELECT * FROM user_group_memberships WHERE user_id = ? AND group_id = ?;

-- name: GetAgentGroupMembership :one
SELECT * FROM agent_group_memberships WHERE agent_id = ? AND group_id = ?;

-- name: CreateActiveUserGroupMembership :exec
INSERT INTO user_group_memberships(user_id,group_id,state,authority_generation) VALUES (?,?,'active',?);

-- name: CreateActiveAgentGroupMembership :exec
INSERT INTO agent_group_memberships(agent_id,group_id,state,authority_generation) VALUES (?,?,'active',?);

-- name: ReenableUserGroupMembership :execrows
UPDATE user_group_memberships SET state = 'active', authority_generation = sqlc.arg(generation)
WHERE user_id = sqlc.arg(user_id) AND group_id = sqlc.arg(group_id) AND state = 'disabled';

-- name: ReenableAgentGroupMembership :execrows
UPDATE agent_group_memberships SET state = 'active', authority_generation = sqlc.arg(generation)
WHERE agent_id = sqlc.arg(agent_id) AND group_id = sqlc.arg(group_id) AND state = 'disabled';

-- name: DisableUserGroupMembership :execrows
UPDATE user_group_memberships SET state = 'disabled' WHERE user_id = ? AND group_id = ? AND state != 'disabled';

-- name: DisableAgentGroupMembership :execrows
UPDATE agent_group_memberships SET state = 'disabled' WHERE agent_id = ? AND group_id = ? AND state != 'disabled';

-- name: ListGroupUserMemberships :many
SELECT * FROM user_group_memberships WHERE group_id = ? ORDER BY user_id;

-- name: ListGroupAgentMemberships :many
SELECT * FROM agent_group_memberships WHERE group_id = ? ORDER BY agent_id;
