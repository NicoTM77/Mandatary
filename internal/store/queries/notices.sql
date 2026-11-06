-- name: CreateProtectiveIntent :exec
INSERT INTO protective_notice_intents(id,user_id,event_type,occurred_at,authority_generation,recipients,state) VALUES(?,?,?,?,?,?,'pending');

-- name: ListProtectiveIntents :many
SELECT * FROM protective_notice_intents WHERE state='pending' AND authority_generation=? ORDER BY occurred_at,id LIMIT 32;

-- name: MarkProtectiveIntentExpanded :execrows
UPDATE protective_notice_intents SET state='expanded' WHERE id=? AND state='pending';

-- name: GetNotice :one
SELECT * FROM security_notice_outbox WHERE id=?;

-- name: RetryNotice :execrows
UPDATE security_notice_outbox SET delivery_state='pending',attempts=0,repair_count=repair_count+1,retry_started_at=sqlc.arg(now),next_attempt_at=sqlc.arg(now),failure_code=NULL
WHERE id=sqlc.arg(id) AND delivery_state='failed' AND repair_count<3 AND lease_until=0 AND worker_token IS NULL AND retain_until>sqlc.arg(now);

-- name: GetNoticeHealth :one
SELECT
 (SELECT count(*) FROM security_notice_outbox WHERE delivery_state='pending') AS pending,
 (SELECT count(*) FROM security_notice_outbox WHERE delivery_state='failed') AS failed,
 (SELECT count(*) FROM security_notice_outbox WHERE delivery_state='bounced') AS bounced,
 (SELECT count(*) FROM security_notice_outbox WHERE dispatch_state='quarantined') AS quarantined,
 CAST(((SELECT count(*) FROM protective_notice_intents WHERE state='pending') +
  (SELECT count(*) FROM security_events e WHERE e.event_type IN ('authenticator_removed','authenticator_suspended')
   AND NOT EXISTS (SELECT 1 FROM security_notice_outbox o WHERE o.event_id=e.id)
   AND NOT EXISTS (SELECT 1 FROM protective_notice_intents i WHERE i.id=e.id))) AS INTEGER) AS protective;

-- name: NoticeQueueSize :one
SELECT count(*) AS size FROM security_notice_outbox WHERE delivery_state='pending' AND dispatch_state='ready';

-- name: NextNotice :one
SELECT o.*,e.event_type,e.occurred_at FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id
WHERE o.delivery_state='pending' AND o.dispatch_state='ready' AND o.authority_generation=sqlc.arg(generation) AND o.lease_until<=sqlc.arg(now) AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=sqlc.arg(now))
AND (SELECT count(*) FROM security_notice_outbox WHERE lease_until>sqlc.arg(now))<4
ORDER BY e.occurred_at,o.id LIMIT 1;

-- name: ClaimNotice :execrows
UPDATE security_notice_outbox SET attempts=attempts+1,total_attempts=total_attempts+1,last_attempt_at=sqlc.arg(now),lease_until=sqlc.arg(lease_until),worker_token=sqlc.arg(token)
WHERE id=sqlc.arg(id) AND delivery_state='pending' AND dispatch_state='ready' AND lease_until<=sqlc.arg(now);

-- name: FinishNotice :execrows
UPDATE security_notice_outbox SET delivery_state=sqlc.arg(state),failure_code=sqlc.arg(failure),next_attempt_at=sqlc.arg(next_attempt),lease_until=0,worker_token=NULL
WHERE id=sqlc.arg(id) AND worker_token=sqlc.arg(token) AND delivery_state='pending';

-- name: FailExhaustedNotice :execrows
UPDATE security_notice_outbox SET delivery_state='failed',failure_code='permanent',lease_until=0,worker_token=NULL
WHERE id=sqlc.arg(id) AND delivery_state='pending';
