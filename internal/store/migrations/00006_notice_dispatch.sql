-- +goose Up
ALTER TABLE security_notice_outbox ADD COLUMN lease_until INTEGER NOT NULL DEFAULT 0 CHECK (lease_until>=0);
ALTER TABLE security_notice_outbox ADD COLUMN worker_token TEXT;
-- +goose Down
ALTER TABLE security_notice_outbox DROP COLUMN worker_token;
ALTER TABLE security_notice_outbox DROP COLUMN lease_until;
