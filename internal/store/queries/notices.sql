-- name: NoticeQueueSize :one
SELECT count(*) AS size FROM security_notice_outbox WHERE delivery_state='pending' AND dispatch_state='ready';

-- name: NextNotice :one
SELECT o.*,e.event_type,e.occurred_at FROM security_notice_outbox o JOIN security_events e ON e.id=o.event_id
WHERE o.delivery_state='pending' AND o.dispatch_state='ready' AND o.authority_generation=sqlc.arg(generation) AND o.lease_until<=sqlc.arg(now) AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=sqlc.arg(now))
AND (SELECT count(*) FROM security_notice_outbox WHERE lease_until>sqlc.arg(now))<4
ORDER BY e.occurred_at,o.id LIMIT 1;

-- name: ClaimNotice :execrows
UPDATE security_notice_outbox SET attempts=attempts+1,last_attempt_at=sqlc.arg(now),lease_until=sqlc.arg(lease_until),worker_token=sqlc.arg(token)
WHERE id=sqlc.arg(id) AND delivery_state='pending' AND dispatch_state='ready' AND lease_until<=sqlc.arg(now);

-- name: FinishNotice :execrows
UPDATE security_notice_outbox SET delivery_state=sqlc.arg(state),failure_code=sqlc.arg(failure),next_attempt_at=sqlc.arg(next_attempt),lease_until=0,worker_token=NULL
WHERE id=sqlc.arg(id) AND worker_token=sqlc.arg(token) AND delivery_state='pending';

-- name: FailExhaustedNotice :execrows
UPDATE security_notice_outbox SET delivery_state='failed',failure_code='permanent',lease_until=0,worker_token=NULL
WHERE id=sqlc.arg(id) AND delivery_state='pending';
