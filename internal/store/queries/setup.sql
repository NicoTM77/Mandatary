-- P1.09 setup/recovery control plane. Call ONLY under Repository.Control (writes) or
-- Repository.Read (reads) from the owning auth setup service. No query here
-- accepts a plaintext token, decides policy, issues a normal session or sends mail.
-- name: GetSetupState :one
SELECT * FROM setup_state WHERE singleton = 1;

-- name: AdvanceSetupClock :execrows
UPDATE setup_state SET clock_high_water = sqlc.arg(now) WHERE singleton = 1 AND clock_high_water <= sqlc.arg(now);

-- name: MarkInitialSetupIssued :exec
UPDATE setup_state SET initial_issued = 1 WHERE singleton = 1;

-- name: MarkSetupCompleted :execrows
UPDATE setup_state SET completed_at = sqlc.arg(now) WHERE singleton = 1 AND completed_at IS NULL;

-- name: CountSetupBlockers :one
-- Empty-store test: every table that could carry prior authority, excluding the
-- inert staged administrator of a live setup session and the seeded local endpoint.
SELECT (SELECT count(*) FROM users WHERE id NOT IN (SELECT staged_user_id FROM setup_sessions WHERE staged_user_id IS NOT NULL))
 + (SELECT count(*) FROM groups) + (SELECT count(*) FROM agents) + (SELECT count(*) FROM agent_credentials)
 + (SELECT count(*) FROM policies) + (SELECT count(*) FROM container_selectors)
 + (SELECT count(*) FROM administrative_roles) + (SELECT count(*) FROM sessions)
 + (SELECT count(*) FROM security_events) + (SELECT count(*) FROM usage_stats_hourly)
 + (SELECT count(*) FROM usage_stats_daily) + (SELECT count(*) FROM usage_recent_events)
 + (SELECT count(*) FROM endpoints WHERE state != 'quarantined') AS blockers;

-- name: CreateSetupGeneration :one
INSERT INTO setup_tokens(purpose,target_user_id,installation_id,build_identity,digest,state,issued_at,expires_at,replace_password,risk_acknowledged)
VALUES (?,?,?,?,?,'pending',?,?,?,?) RETURNING id;

-- name: GetSetupGeneration :one
SELECT * FROM setup_tokens WHERE id = ?;

-- name: GetSetupGenerationByDigest :one
SELECT * FROM setup_tokens WHERE digest IN (sqlc.arg(first), sqlc.arg(second));

-- name: ListLiveSetupGenerations :many
SELECT * FROM setup_tokens WHERE state IN ('pending','available','claimed','retrieved') ORDER BY id;

-- name: ListRecentSetupGenerations :many
SELECT * FROM setup_tokens ORDER BY id DESC LIMIT 8;

-- name: MakeSetupGenerationAvailable :execrows
UPDATE setup_tokens SET state = 'available' WHERE id = ? AND state = 'pending';

-- name: ClaimSetupGeneration :execrows
UPDATE setup_tokens SET state = 'claimed', claimed_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND state = 'available' AND expires_at > sqlc.arg(now);

-- name: FinishSetupGenerationReveal :execrows
UPDATE setup_tokens SET state = 'retrieved', retrieved_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND state = 'claimed';

-- name: ConsumeSetupGeneration :execrows
UPDATE setup_tokens SET state = 'consumed', consumed_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND state = 'retrieved' AND expires_at > sqlc.arg(now);

-- name: RevokeSetupGeneration :execrows
UPDATE setup_tokens SET state = 'revoked', revoked_at = sqlc.arg(now), revoke_reason = CAST(sqlc.arg(reason) AS TEXT)
WHERE id = sqlc.arg(id) AND state IN ('pending','available','claimed','retrieved');

-- name: GetSetupAttempts :one
SELECT * FROM setup_attempts WHERE purpose = ?;

-- name: RecordSetupFailure :execrows
UPDATE setup_attempts SET failed = failed + 1, next_attempt_at = sqlc.arg(next_attempt_at) WHERE purpose = sqlc.arg(purpose) AND failed < 100;

-- name: ResetSetupAttempts :exec
UPDATE setup_attempts SET failed = 0, next_attempt_at = 0 WHERE purpose = ?;

-- name: CreateSetupSession :exec
INSERT INTO setup_sessions(id,token_id,purpose,target_user_id,secret_hash,created_at,expires_at) VALUES (?,?,?,?,?,?,?);

-- name: GetSetupSessionByHash :one
SELECT * FROM setup_sessions WHERE secret_hash = ?;

-- name: GetSetupSession :one
SELECT * FROM setup_sessions WHERE id = ?;

-- name: ListLiveSetupSessions :many
SELECT * FROM setup_sessions WHERE state = 'active' ORDER BY id;

-- name: ListSetupSessionsByStagedUser :many
SELECT * FROM setup_sessions WHERE staged_user_id = ? ORDER BY id;

-- name: EndSetupSession :execrows
UPDATE setup_sessions SET state = CAST(sqlc.arg(to_state) AS TEXT), ended_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND state = 'active';

-- name: StageSetupUser :execrows
UPDATE setup_sessions SET staged_user_id = sqlc.arg(user_id), staged_verifier = sqlc.arg(verifier), staged_password_format = sqlc.arg(format), staged_password_codepoints = sqlc.arg(codepoints)
WHERE id = sqlc.arg(id) AND state = 'active' AND purpose = 'initial_setup' AND staged_user_id IS NULL AND staged_verifier IS NULL;

-- name: StageSetupVerifier :execrows
UPDATE setup_sessions SET staged_verifier = sqlc.arg(verifier), staged_password_format = sqlc.arg(format), staged_password_codepoints = sqlc.arg(codepoints)
WHERE id = sqlc.arg(id) AND state = 'active' AND purpose = 'mfa_reset' AND staged_verifier IS NULL;

-- name: SetSetupTOTP :execrows
UPDATE setup_sessions SET totp_authenticator_id = sqlc.arg(authenticator_id), totp_proven_at = NULL
WHERE id = sqlc.arg(id) AND state = 'active' AND totp_authenticator_id IS NULL;

-- name: MarkSetupTOTPProven :execrows
UPDATE setup_sessions SET totp_proven_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND state = 'active' AND totp_authenticator_id = sqlc.arg(authenticator_id) AND totp_proven_at IS NULL;

-- name: RecordSetupProofFailure :execrows
UPDATE setup_sessions SET proof_failures = proof_failures + 1, proof_next_attempt_at = sqlc.arg(next_attempt_at)
WHERE id = sqlc.arg(id) AND state = 'active' AND proof_failures < 100;

-- name: NoteSetupProofSent :exec
UPDATE setup_sessions SET last_proof_sent_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: ClearSetupStaging :exec
UPDATE setup_sessions SET staged_user_id = NULL, staged_verifier = NULL, staged_password_format = NULL, staged_password_codepoints = NULL,
 totp_authenticator_id = NULL, totp_proven_at = NULL WHERE id = ?;

-- name: CreateStagedUser :exec
INSERT INTO users(id,username,state,mfa_requirement) VALUES (?,?,'quarantined','required');

-- name: CreateStagedAddress :exec
INSERT INTO notification_addresses(id,user_id,address,version,created_at) VALUES (?,?,?,1,?);

-- name: CreateAddressProof :exec
INSERT INTO notification_address_proofs(id,user_id,address_id,address_version,purpose,proof_hash,issued_at,expires_at,credential_generation)
VALUES (?,?,?,1,'notification_address_confirmation',?,?,?,0);

-- name: GetAddressProofByHash :one
SELECT * FROM notification_address_proofs WHERE proof_hash = ?;

-- name: ConsumeAddressProof :execrows
UPDATE notification_address_proofs SET consumed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND issued_at <= sqlc.arg(now) AND expires_at > sqlc.arg(now);

-- name: CountAddressProofs :one
SELECT count(*) FROM notification_address_proofs WHERE user_id = ?;

-- name: ListAddressProofs :many
SELECT * FROM notification_address_proofs WHERE user_id = ? ORDER BY id;

-- name: ListConfirmedStagedAddresses :many
SELECT a.* FROM notification_addresses a WHERE a.user_id = ? AND a.state = 'quarantined'
 AND EXISTS (SELECT 1 FROM notification_address_proofs p WHERE p.address_id = a.id AND p.address_version = a.version AND p.consumed_at IS NOT NULL)
ORDER BY a.id;

-- name: ActivateConfirmedAddress :execrows
UPDATE notification_addresses SET state = 'active', verified_at = sqlc.arg(now), authority_generation = sqlc.arg(generation)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND state = 'quarantined';

-- name: RevokeUnconfirmedAddresses :exec
UPDATE notification_addresses SET state = 'revoked', revoked_at = sqlc.arg(now) WHERE user_id = sqlc.arg(user_id) AND state = 'quarantined';

-- name: UnlockInstallation :execrows
-- Fresh-install activation only: every local control generation is still zero and
-- the installation is still quarantined. It can never regress or re-run.
UPDATE installation_control SET credential_generation = 1, session_generation = 1, authority_generation = 1, restore_generation = 1, restore_quarantined = 0
WHERE singleton = 1 AND credential_generation = 0 AND session_generation = 0 AND authority_generation = 0 AND restore_generation = 0 AND restore_quarantined = 1;

-- name: ActivateStagedAdmin :execrows
UPDATE users SET state = 'active', credential_generation = 1, authority_generation = 1 WHERE id = ? AND state = 'quarantined' AND mfa_requirement = 'required';

-- name: CreateAdminVerifier :exec
INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,changed_at,verifier_hash,password_codepoints,password_format,max_assurance)
VALUES (?,?,'password','active',1,?,?,?,?,?,?,1);

-- name: CreateInitialAdminRole :exec
INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES (?,?,'super_admin','active',1);

-- name: ProveSetupTOTPStep :execrows
UPDATE authenticators SET last_accepted_totp_step = sqlc.arg(step)
WHERE id = sqlc.arg(id) AND kind = 'totp' AND state = 'pending' AND last_accepted_totp_step IS NULL;

-- name: ActivateProvenTOTP :execrows
UPDATE authenticators SET state = 'active', credential_generation = sqlc.arg(generation), bound_at = sqlc.arg(now), changed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND kind = 'totp' AND state = 'pending' AND last_accepted_totp_step IS NOT NULL;

-- name: PurgeSetupTOTPAcceptances :exec
DELETE FROM totp_acceptances WHERE authenticator_id = ?;

-- name: PurgeSetupTOTP :exec
DELETE FROM authenticators WHERE id = ? AND kind = 'totp' AND state IN ('pending','disabled');

-- name: PurgeStagedProofs :exec
DELETE FROM notification_address_proofs WHERE user_id = ?;

-- name: PurgeStagedAddresses :exec
DELETE FROM notification_addresses WHERE user_id = ? AND state IN ('quarantined','revoked');

-- name: PurgeStagedUser :execrows
DELETE FROM users WHERE id = ? AND state = 'quarantined';

-- name: CountStagedAuthenticators :one
SELECT count(*) FROM authenticators WHERE user_id = ?;

-- name: ListUserSetupGenerations :many
SELECT * FROM setup_tokens WHERE target_user_id = ? ORDER BY id;
