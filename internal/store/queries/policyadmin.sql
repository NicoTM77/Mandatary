-- P1.17 policy, selector and identity-lifecycle administration.
-- Used only by the administrative service (internal/auth), inside Repository.Control for writes
-- and Repository.Read for views. Nothing here verifies a caller or evaluates policy: the service
-- re-checks the fresh administrator session, the live control generations and every referenced
-- state in the same transaction, and the shared authorizer re-evaluates every request. Every
-- statement is guarded by the state it expects, so a stale view can never move a row it did not read.

-- name: ListAllPolicies :many
SELECT * FROM policies ORDER BY id;

-- name: CreateActivePolicy :exec
INSERT INTO policies(id,user_id,group_id,agent_id,endpoint_id,selector_id,operation,effect,state,authority_generation,log_tail_max,stop_timeout_max)
VALUES (?,?,?,?,?,?,?,?,'active',?,?,?);

-- name: FindSelector :one
-- Exact structural match (NULL-safe), so identical rules share one immutable selector row.
SELECT * FROM container_selectors
WHERE endpoint_id = sqlc.arg(endpoint_id) AND container_name = sqlc.arg(container_name) AND name_is_glob = sqlc.arg(name_is_glob)
  AND compose_project IS sqlc.narg(compose_project) AND compose_service IS sqlc.narg(compose_service)
  AND image_pattern IS sqlc.narg(image_pattern) AND pinned_container_id IS sqlc.narg(pinned_container_id)
  AND pinned_image_digest IS sqlc.narg(pinned_image_digest)
ORDER BY id LIMIT 1;

-- name: CountEquivalentPolicies :one
-- The same subject, selector, operation and effect again is a duplicate (excluding the rule being edited).
SELECT count(*) FROM policies
WHERE user_id IS sqlc.narg(user_id) AND group_id IS sqlc.narg(group_id) AND agent_id IS sqlc.narg(agent_id)
  AND endpoint_id = sqlc.arg(endpoint_id) AND selector_id = sqlc.arg(selector_id)
  AND operation = sqlc.arg(operation) AND effect = sqlc.arg(effect) AND id != sqlc.arg(except_id);

-- name: UpdatePolicyRule :execrows
-- Effect, selector and ceilings of an existing rule. Subject, operation and state are fixed by this
-- statement: editing never enables a disabled rule and never re-approves a stale or restored one (the
-- service refuses a rule whose generation is not current before calling it).
UPDATE policies SET effect = sqlc.arg(effect), selector_id = sqlc.arg(selector_id), log_tail_max = sqlc.arg(log_tail_max),
  stop_timeout_max = sqlc.arg(stop_timeout_max)
WHERE id = sqlc.arg(id) AND state IN ('active','disabled') AND authority_generation = sqlc.arg(generation);

-- name: SetPolicyEnabled :execrows
-- A rule left over from an earlier authority generation is never revived: it can only be deleted.
UPDATE policies SET state = 'active' WHERE id = sqlc.arg(id) AND state = 'disabled' AND authority_generation = sqlc.arg(generation);

-- name: SetPolicyDisabled :execrows
UPDATE policies SET state = 'disabled' WHERE id = ? AND state = 'active';

-- name: DeletePolicy :execrows
DELETE FROM policies WHERE id = ?;

-- name: DisableUserAccount :execrows
UPDATE users SET state = 'disabled' WHERE id = ? AND state = 'active';

-- name: EnableUserAccount :execrows
UPDATE users SET state = 'active' WHERE id = sqlc.arg(id) AND state = 'disabled' AND compromised = 0
  AND credential_generation = sqlc.arg(credential_generation) AND authority_generation = sqlc.arg(authority_generation);

-- name: DisableGroupRecord :execrows
UPDATE groups SET state = 'disabled' WHERE id = ? AND state = 'active';

-- name: EnableGroupRecord :execrows
UPDATE groups SET state = 'active' WHERE id = sqlc.arg(id) AND state = 'disabled' AND authority_generation = sqlc.arg(authority_generation);

-- name: DeleteDisabledGroupUserMemberships :exec
DELETE FROM user_group_memberships WHERE group_id = ? AND state = 'disabled';

-- name: DeleteDisabledGroupAgentMemberships :exec
DELETE FROM agent_group_memberships WHERE group_id = ? AND state = 'disabled';

-- name: DeleteGroupRecord :execrows
DELETE FROM groups WHERE id = ?;

-- name: EnableAgentRecord :execrows
UPDATE agents SET state = 'active' WHERE id = sqlc.arg(id) AND state = 'disabled'
  AND credential_generation = sqlc.arg(credential_generation) AND authority_generation = sqlc.arg(authority_generation);

-- name: SetAgentOwner :execrows
UPDATE agents SET owner_user_id = sqlc.narg(owner_user_id), owner_group_id = sqlc.narg(owner_group_id) WHERE id = sqlc.arg(id) AND state != 'quarantined';
