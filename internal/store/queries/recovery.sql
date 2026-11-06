-- name: CreateRecoveryBatch :exec
INSERT INTO recovery_batches(id,user_id,credential_generation,state,created_at) VALUES(?,?,?,'active',?);

-- name: GetActiveRecoveryBatch :one
SELECT * FROM recovery_batches WHERE user_id=? AND state='active';

-- name: RevokeRecoveryBatches :exec
UPDATE recovery_batches SET state='revoked' WHERE user_id=? AND state!='revoked';

-- name: RevokeRecoveryCodes :exec
UPDATE authenticators SET state='revoked',revoked_at=sqlc.arg(now),changed_at=sqlc.arg(now) WHERE user_id=sqlc.arg(user_id) AND kind='recovery_code' AND state!='revoked';

-- name: CreateRecoveryCode :exec
INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,verifier_hash,max_assurance,recovery_batch_id) VALUES(?,?,'recovery_code','active',?,?,?, ?,0,?);

-- name: RecoveryFailure :execrows
UPDATE recovery_batches SET failures=failures+1,state=CASE WHEN failures+1>=100 THEN 'disabled' ELSE state END,next_attempt_at=sqlc.arg(next_attempt_at) WHERE id=sqlc.arg(id) AND state='active' AND failures<100;

-- name: ConsumeRecoveryCode :execrows
UPDATE authenticators SET state='revoked',revoked_at=sqlc.arg(now),changed_at=sqlc.arg(now) WHERE id=sqlc.arg(id) AND kind='recovery_code' AND state='active' AND revoked_at IS NULL;

-- name: RevokeRecoveryCapabilities :exec
UPDATE recovery_capabilities SET state='revoked' WHERE user_id=? AND state!='revoked';

-- name: CreateRecoveryCapability :exec
INSERT INTO recovery_capabilities(id,user_id,secret_hash,credential_generation,session_generation,password_revision,created_at,expires_at,state) VALUES(?,?,?,?,?,?,?,?,'restricted');

-- name: SelectRecoveryReplacement :execrows
UPDATE recovery_capabilities SET replacement_authenticator_id=sqlc.arg(authenticator_id) WHERE id=sqlc.arg(id) AND state='restricted' AND replacement_authenticator_id IS NULL;

-- name: FinishRecoveryCapability :execrows
UPDATE recovery_capabilities SET state='bound' WHERE id=sqlc.arg(id) AND state='restricted' AND replacement_authenticator_id=sqlc.arg(authenticator_id);

-- name: GetRecoveryCapability :one
SELECT * FROM recovery_capabilities WHERE secret_hash=?;
