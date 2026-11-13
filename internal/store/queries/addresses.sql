-- Post-setup notification-address management (P1.16.4). Setup stages addresses
-- at version 1 only; an address that is revoked and later added again needs a
-- higher version because (user_id,address,version) is unique.

-- name: CreateManagedAddress :exec
INSERT INTO notification_addresses(id,user_id,address,version,created_at) VALUES (?,?,?,?,?);

-- name: CreateManagedAddressProof :exec
INSERT INTO notification_address_proofs(id,user_id,address_id,address_version,purpose,proof_hash,issued_at,expires_at,credential_generation)
VALUES (?,?,?,?,'notification_address_confirmation',?,?,?,0);

-- name: RevokeManagedAddress :execrows
UPDATE notification_addresses SET state = 'revoked', revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state IN ('quarantined','active');
