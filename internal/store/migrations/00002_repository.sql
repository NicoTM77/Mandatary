-- +goose Up
-- Local key/installation binding is NOT an archive import field. Missing records
-- on an already initialized store are fatal, never an invitation to rebind keys.
CREATE TABLE repository_metadata (
 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
 installation_id BLOB NOT NULL CHECK (length(installation_id) = 32),
 key_check BLOB NOT NULL CHECK (length(key_check) BETWEEN 61 AND 65597)
) STRICT;

-- N1 storage only; SMTP delivery/configuration/authority are later owning rows.
CREATE TABLE smtp_secrets (
 id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 256),
 ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 61 AND 65597)
) STRICT;

-- +goose Down
DROP TABLE smtp_secrets;
DROP TABLE repository_metadata;
