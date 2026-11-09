-- P1.11 authorization and selector evaluation queries.
-- name: GetEndpoint :one
SELECT * FROM endpoints WHERE id = ?;

-- name: GetAgentCredentialByHash :one
SELECT * FROM agent_credentials WHERE token_hash = ?;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = ?;

-- name: ListUserGroupMembershipsWithGroups :many
SELECT
    m.user_id,
    m.group_id,
    m.state AS membership_state,
    m.authority_generation AS membership_authority_generation,
    g.name AS group_name,
    g.state AS group_state,
    g.authority_generation AS group_authority_generation
FROM user_group_memberships m
JOIN groups g ON g.id = m.group_id
WHERE m.user_id = ?
ORDER BY m.group_id;

-- name: ListAgentGroupMembershipsWithGroups :many
SELECT
    m.agent_id,
    m.group_id,
    m.state AS membership_state,
    m.authority_generation AS membership_authority_generation,
    g.name AS group_name,
    g.state AS group_state,
    g.authority_generation AS group_authority_generation
FROM agent_group_memberships m
JOIN groups g ON g.id = m.group_id
WHERE m.agent_id = ?
ORDER BY m.group_id;

-- name: ListUserAdministrativeRoles :many
SELECT * FROM administrative_roles WHERE user_id = ? ORDER BY id;

-- name: GetContainerSelector :one
SELECT * FROM container_selectors WHERE id = ?;

-- name: GetPolicy :one
SELECT * FROM policies WHERE id = ?;

-- name: ListEndpointOperationPoliciesWithSelectors :many
SELECT
    p.id AS policy_id,
    p.user_id,
    p.group_id,
    p.agent_id,
    p.endpoint_id,
    p.selector_id,
    p.operation,
    p.effect,
    p.state AS policy_state,
    p.authority_generation AS policy_authority_generation,
    p.log_tail_max,
    p.stop_timeout_max,
    s.endpoint_id AS selector_endpoint_id,
    s.container_name,
    s.name_is_glob,
    s.compose_project,
    s.compose_service,
    s.image_pattern,
    s.pinned_container_id,
    s.pinned_image_digest
FROM policies p
JOIN container_selectors s ON s.id = p.selector_id
WHERE p.endpoint_id = sqlc.arg(endpoint_id)
  AND p.operation = sqlc.arg(operation)
ORDER BY p.id;

-- name: ListPoliciesWithSelectorsForEndpoint :many
SELECT
    p.id AS policy_id,
    p.user_id,
    p.group_id,
    p.agent_id,
    p.endpoint_id,
    p.selector_id,
    p.operation,
    p.effect,
    p.state AS policy_state,
    p.authority_generation AS policy_authority_generation,
    p.log_tail_max,
    p.stop_timeout_max,
    s.endpoint_id AS selector_endpoint_id,
    s.container_name,
    s.name_is_glob,
    s.compose_project,
    s.compose_service,
    s.image_pattern,
    s.pinned_container_id,
    s.pinned_image_digest
FROM policies p
JOIN container_selectors s ON s.id = p.selector_id
WHERE p.endpoint_id = sqlc.arg(endpoint_id)
ORDER BY p.id;
