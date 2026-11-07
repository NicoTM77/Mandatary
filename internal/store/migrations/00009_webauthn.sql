-- +goose Up
-- Public handles are random and installation-local. Records are authenticated
-- envelopes binding owner, RP/config and immutable credential/account association.
CREATE TABLE webauthn_users (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
 handle BLOB NOT NULL UNIQUE CHECK(length(handle)=32)
) STRICT;
CREATE TABLE webauthn_challenges (
 challenge_id TEXT PRIMARY KEY REFERENCES auth_challenges(id) ON DELETE RESTRICT,
 envelope BLOB NOT NULL
) STRICT;
CREATE TABLE webauthn_credentials (
 authenticator_id TEXT PRIMARY KEY REFERENCES authenticators(id) ON DELETE RESTRICT,
 label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 80),
 envelope BLOB NOT NULL
) STRICT;

-- +goose Down
DROP TABLE webauthn_credentials;
DROP TABLE webauthn_challenges;
DROP TABLE webauthn_users;
