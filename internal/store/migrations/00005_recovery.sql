-- +goose Up
CREATE TABLE recovery_batches (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id),
 credential_generation INTEGER NOT NULL CHECK (credential_generation>0),
 state TEXT NOT NULL CHECK (state IN ('active','disabled','revoked')),
 failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 100),
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL,
 CHECK (state!='active' OR failures<100)
) STRICT;
CREATE UNIQUE INDEX one_active_recovery_batch ON recovery_batches(user_id) WHERE state='active';
ALTER TABLE authenticators ADD COLUMN recovery_batch_id TEXT REFERENCES recovery_batches(id);
CREATE TABLE recovery_capabilities (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id),
 secret_hash BLOB NOT NULL UNIQUE CHECK (length(secret_hash)=32),
 credential_generation INTEGER NOT NULL CHECK (credential_generation>0),
 session_generation INTEGER NOT NULL CHECK (session_generation>0),
 password_revision INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK (expires_at>created_at AND expires_at-created_at<=600),
 state TEXT NOT NULL CHECK (state IN ('restricted','bound','revoked')),
 replacement_authenticator_id TEXT REFERENCES authenticators(id)
) STRICT;
-- +goose Down
DROP TABLE recovery_capabilities;
ALTER TABLE authenticators DROP COLUMN recovery_batch_id;
DROP TABLE recovery_batches;
