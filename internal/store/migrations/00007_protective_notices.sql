-- +goose Up
-- Non-importable current local protective notice intent. A broken ordinary
-- event/outbox writer cannot roll back a durable protective revocation.
CREATE TABLE protective_notice_intents (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id),
 event_type TEXT NOT NULL CHECK (event_type IN ('authenticator_removed','authenticator_suspended')),
 occurred_at INTEGER NOT NULL CHECK (occurred_at>=0),
 authority_generation INTEGER NOT NULL CHECK (authority_generation>0),
 recipients TEXT NOT NULL CHECK (length(recipients)<=65536),
 state TEXT NOT NULL CHECK (state IN ('pending','expanded','quarantined'))
) STRICT;
-- +goose Down
DROP TABLE protective_notice_intents;
