-- P1.06 owning lifecycle service only, under Repository.Control.
-- name: GetSessionByHash :one
SELECT * FROM sessions WHERE secret_hash=?;

-- name: ListSessionAuthenticators :many
SELECT a.* FROM authenticators a JOIN session_authenticators s ON a.id=s.authenticator_id WHERE s.session_id=? ORDER BY a.id;

-- name: ListUserAuthenticators :many
SELECT * FROM authenticators WHERE user_id=? ORDER BY id;

-- name: CreatePendingTOTP :exec
INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,encrypted_secret,totp_algorithm,max_assurance,phishing_resistant) VALUES(?,?,'totp','pending',?,?,?, ?,1,0);

-- name: BindPendingTOTP :exec
INSERT INTO totp_pending(authenticator_id,session_id,expires_at) VALUES(?,?,?);

-- name: GetPendingTOTP :one
SELECT * FROM totp_pending WHERE authenticator_id=?;

-- name: ActivateTOTP :execrows
UPDATE authenticators SET state='active',bound_at=sqlc.arg(now),changed_at=sqlc.arg(now),last_accepted_totp_step=sqlc.arg(step) WHERE id=sqlc.arg(id) AND kind='totp' AND state='pending';

-- name: RecordTOTPFailure :execrows
UPDATE authenticators SET failed_attempts=failed_attempts+1,state=CASE WHEN failed_attempts+1>=retry_ceiling THEN 'disabled' ELSE state END,next_attempt_at=sqlc.arg(next_attempt_at)
WHERE id=sqlc.arg(id) AND kind='totp' AND state IN ('active','pending') AND failed_attempts<retry_ceiling;

-- name: RecordTOTPAcceptance :exec
INSERT INTO totp_acceptances(authenticator_id,step,verifier_period,output_hash) VALUES(?,?,?,?);

-- name: HasTOTPReplay :one
SELECT EXISTS(SELECT 1 FROM totp_acceptances WHERE authenticator_id=sqlc.arg(id) AND (step=sqlc.arg(step) OR verifier_period>=sqlc.arg(period) OR (step>=sqlc.arg(earliest) AND output_hash=sqlc.arg(hash)))) AS replay;

-- name: AdvanceTOTPStep :execrows
UPDATE authenticators SET last_accepted_totp_step=sqlc.arg(step) WHERE id=sqlc.arg(id) AND kind='totp' AND state='active' AND (last_accepted_totp_step IS NULL OR last_accepted_totp_step<sqlc.arg(step));

-- name: PruneTOTPAcceptances :exec
DELETE FROM totp_acceptances WHERE authenticator_id=sqlc.arg(id) AND step<sqlc.arg(earliest);

-- name: RevokeTOTP :execrows
UPDATE authenticators SET state='revoked',revoked_at=sqlc.arg(now),changed_at=sqlc.arg(now),encrypted_secret=NULL WHERE id=sqlc.arg(id) AND kind='totp' AND state IN ('active','disabled','pending') AND revoked_at IS NULL;

-- name: ReadyNoticeIntent :exec
INSERT INTO security_notice_outbox(id,event_id,user_id,address_id,address_version,recipient_snapshot,retain_until,dispatch_state,authority_generation) VALUES(?,?,?,?,?,?,?,'ready',?);
