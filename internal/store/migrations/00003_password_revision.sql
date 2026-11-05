-- +goose Up
-- Monotonic optimistic-concurrency marker, NOT an authority generation. Repeated
-- reports must invalidate work that observed an already-set compromise flag.
ALTER TABLE users ADD COLUMN password_revision INTEGER NOT NULL DEFAULT 0
 CHECK(typeof(password_revision)='integer' AND password_revision>=0);

-- +goose Down
ALTER TABLE users DROP COLUMN password_revision;
