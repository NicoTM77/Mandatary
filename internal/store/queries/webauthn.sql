-- WebAuthn service only; all mutations use the shared FULL control writer.
-- name: GetWebAuthnHandle :one
SELECT handle FROM webauthn_users WHERE user_id=?;
-- name: PutWebAuthnHandle :exec
INSERT INTO webauthn_users(user_id,handle) VALUES(?,?) ON CONFLICT(user_id) DO NOTHING;
-- name: PruneWebAuthnChallenges :exec
DELETE FROM auth_challenges WHERE purpose IN ('webauthn_binding','webauthn_assertion')
AND (expires_at<=sqlc.arg(now) OR consumed_at IS NOT NULL)
AND EXISTS (SELECT 1 FROM webauthn_challenges w WHERE w.challenge_id=auth_challenges.id);
-- name: CountWebAuthnChallenges :one
SELECT count(*) FROM auth_challenges WHERE user_id=? AND expires_at>sqlc.arg(now) AND consumed_at IS NULL;
-- name: CreateWebAuthnChallenge :exec
INSERT INTO auth_challenges(id,user_id,session_id,purpose,challenge_hash,issued_at,expires_at,credential_generation) VALUES(?,?,?,?,?,?,?,?);
-- name: PutWebAuthnChallenge :exec
INSERT INTO webauthn_challenges(challenge_id,envelope) VALUES(?,?);
-- name: GetWebAuthnChallenge :one
SELECT c.*,w.envelope FROM auth_challenges c JOIN webauthn_challenges w ON w.challenge_id=c.id WHERE c.id=?;
-- name: ConsumeWebAuthnChallenge :execrows
UPDATE auth_challenges SET consumed_at=sqlc.arg(now) WHERE id=sqlc.arg(id) AND consumed_at IS NULL AND issued_at<=sqlc.arg(now) AND expires_at>sqlc.arg(now);
-- name: CreateWebAuthnAuthenticator :exec
INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,changed_at,public_key,external_credential_id,max_assurance,phishing_resistant,sign_count,backup_eligible,backup_state,user_verified) VALUES(?,?,'webauthn','active',?,?,?,?,?,?,2,1,?,?,?,1);
-- name: PutWebAuthnCredential :exec
INSERT INTO webauthn_credentials(authenticator_id,label,envelope) VALUES(?,?,?);
-- name: RevokeWebAuthn :execrows
UPDATE authenticators SET state='revoked',revoked_at=sqlc.arg(now),changed_at=sqlc.arg(now) WHERE id=sqlc.arg(id) AND kind='webauthn' AND state IN ('active','disabled') AND revoked_at IS NULL;
-- name: GetWebAuthnCredential :one
SELECT * FROM webauthn_credentials WHERE authenticator_id=?;
-- name: UpdateWebAuthnCredential :execrows
UPDATE webauthn_credentials SET envelope=? WHERE authenticator_id=?;
-- name: AdvanceWebAuthn :execrows
UPDATE authenticators SET sign_count=sqlc.arg(sign_count),backup_state=sqlc.arg(backup_state),changed_at=sqlc.arg(now) WHERE id=sqlc.arg(id) AND state='active' AND kind='webauthn';
-- name: RecordWebAuthnFailure :execrows
UPDATE authenticators SET failed_attempts=failed_attempts+1,state=CASE WHEN failed_attempts+1>=retry_ceiling THEN 'disabled' ELSE state END,
changed_at=CASE WHEN failed_attempts+1>=retry_ceiling THEN sqlc.arg(now) ELSE changed_at END,next_attempt_at=sqlc.arg(next_attempt_at)
WHERE id=sqlc.arg(id) AND kind='webauthn' AND state='active' AND failed_attempts<retry_ceiling;
