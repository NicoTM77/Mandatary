-- P1.08 browser-session persistence. These statements store only a SHA-256
-- secret digest and server-derived evidence. They never accept client assurance,
-- method, authentication-time or generation values; the auth service derives all
-- of them from verified proofs and the live installation control row.

-- name: InsertSession :exec
INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,phishing_resistant,authenticated_at,created_at,expires_at,last_activity_at,idle_timeout_seconds,credential_generation,session_generation,state)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active');

-- name: InsertSessionAuthenticator :exec
INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES(?,?,?);

-- name: RevokeSession :execrows
UPDATE sessions SET state='revoked',revoked_at=max(created_at,CAST(sqlc.arg(now) AS INTEGER)) WHERE id=sqlc.arg(id) AND state!='revoked';

-- name: TouchSession :execrows
UPDATE sessions SET last_activity_at=sqlc.arg(now)
WHERE id=sqlc.arg(id) AND state='active' AND revoked_at IS NULL AND last_activity_at<=sqlc.arg(now) AND sqlc.arg(now)<expires_at;

-- name: ListLiveUserSessions :many
SELECT id,purpose,created_at FROM sessions
WHERE user_id=sqlc.arg(user_id) AND state='active' AND revoked_at IS NULL AND expires_at>sqlc.arg(now)
ORDER BY CASE purpose WHEN 'preauth' THEN 0 ELSE 1 END, created_at, id;
