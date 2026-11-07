-- +goose Up
ALTER TABLE authenticators ADD COLUMN totp_algorithm TEXT CHECK (totp_algorithm IS NULL OR (kind='totp' AND totp_algorithm IN ('SHA1','SHA256')));
CREATE TABLE totp_pending (
 authenticator_id TEXT PRIMARY KEY REFERENCES authenticators(id) ON DELETE RESTRICT,
 session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
 expires_at INTEGER NOT NULL CHECK (expires_at>0)
) STRICT;
CREATE TABLE totp_acceptances (
 authenticator_id TEXT NOT NULL REFERENCES authenticators(id) ON DELETE RESTRICT,
 step INTEGER NOT NULL CHECK (step>=0),
 verifier_period INTEGER NOT NULL CHECK (verifier_period>=0),
 output_hash BLOB NOT NULL CHECK (length(output_hash)=32),
 PRIMARY KEY(authenticator_id,step),
 UNIQUE(authenticator_id,verifier_period)
) STRICT;
-- +goose Down
DROP TABLE totp_acceptances;
DROP TABLE totp_pending;
ALTER TABLE authenticators DROP COLUMN totp_algorithm;
