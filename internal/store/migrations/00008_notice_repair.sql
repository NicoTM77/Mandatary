-- +goose Up
ALTER TABLE security_notice_outbox ADD COLUMN total_attempts INTEGER NOT NULL DEFAULT 0 CHECK (total_attempts>=0);
UPDATE security_notice_outbox SET total_attempts=attempts;
ALTER TABLE security_notice_outbox ADD COLUMN repair_count INTEGER NOT NULL DEFAULT 0 CHECK (repair_count BETWEEN 0 AND 3);
ALTER TABLE security_notice_outbox ADD COLUMN retry_started_at INTEGER CHECK (retry_started_at>=0);
-- +goose Down
ALTER TABLE security_notice_outbox DROP COLUMN retry_started_at;
ALTER TABLE security_notice_outbox DROP COLUMN repair_count;
ALTER TABLE security_notice_outbox DROP COLUMN total_attempts;
