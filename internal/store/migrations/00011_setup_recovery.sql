-- +goose Up
-- P1.09 first-administrator bootstrap and host emergency recovery control plane
-- (security-contracts.md S3 / S3.1a). Everything here is local, NON-IMPORTABLE
-- control state (S2): a logical backup/restore must never map these tables.
--
-- Only a SHA-256 digest of the token is stored. The plaintext exists solely in the
-- short-lived 0600 reveal file. Expiry is an absolute, immutable timestamp: no
-- statement may extend it and a restart never resets it.
CREATE TABLE setup_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    -- Set once the very first initial-setup generation was issued. A later restart
    -- never mints another token automatically (S3.1): only explicit host rotation.
    initial_issued INTEGER NOT NULL DEFAULT 0 CHECK (initial_issued IN (0,1)),
    -- Set atomically with the first-administrator commit. Setup is then disabled.
    completed_at INTEGER CHECK (completed_at IS NULL OR completed_at > 0),
    -- Highest trusted UTC observed by any setup transition. A clock that moves back
    -- below it is uncertainty: issuance, reveal and exchange deny (S3.1).
    clock_high_water INTEGER NOT NULL DEFAULT 0 CHECK (clock_high_water >= 0)
) STRICT;
INSERT INTO setup_state(singleton) VALUES (1);
-- +goose StatementBegin
CREATE TRIGGER setup_state_monotonic BEFORE UPDATE ON setup_state
WHEN NEW.initial_issued < OLD.initial_issued
 OR (OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT OLD.completed_at)
 OR NEW.clock_high_water < OLD.clock_high_water
BEGIN SELECT RAISE(ABORT, 'setup control state cannot regress'); END;
-- +goose StatementEnd

-- One row per issued generation. The row id IS the generation number and is never
-- reused (AUTOINCREMENT). 'pending' is a crash-recoverable half-issued state that
-- is never revealable; 'claimed' means a reveal was started and is never
-- revealable again (uncertain human receipt).
CREATE TABLE setup_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    purpose TEXT NOT NULL CHECK (purpose IN ('initial_setup','mfa_reset','restore_recovery')),
    target_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    installation_id BLOB NOT NULL CHECK (length(installation_id) = 32),
    build_identity TEXT NOT NULL CHECK (length(build_identity) BETWEEN 1 AND 128),
    digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending','available','claimed','retrieved','consumed','revoked')),
    issued_at INTEGER NOT NULL CHECK (issued_at > 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at AND expires_at - issued_at <= 1800),
    replace_password INTEGER NOT NULL DEFAULT 0 CHECK (replace_password IN (0,1)),
    risk_acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (risk_acknowledged IN (0,1)),
    claimed_at INTEGER,
    retrieved_at INTEGER,
    consumed_at INTEGER,
    revoked_at INTEGER,
    revoke_reason TEXT CHECK (revoke_reason IS NULL OR revoke_reason IN ('rotated','crashed_issue','uncertain_delivery','attempt_ceiling','setup_completed','not_eligible','expired_cleanup','superseded')),
    CHECK ((purpose = 'mfa_reset') = (target_user_id IS NOT NULL)),
    CHECK (purpose != 'initial_setup' OR replace_password = 0),
    CHECK (purpose != 'mfa_reset' OR risk_acknowledged = 1),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)),
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK (state NOT IN ('retrieved','consumed') OR (claimed_at IS NOT NULL AND retrieved_at IS NOT NULL)),
    CHECK (state != 'claimed' OR claimed_at IS NOT NULL)
) STRICT;
-- At most one live generation per purpose and target. Rotation revokes first.
CREATE UNIQUE INDEX one_live_setup_token ON setup_tokens(purpose, coalesce(target_user_id,'')) WHERE state IN ('pending','available','claimed','retrieved');
-- +goose StatementBegin
CREATE TRIGGER setup_token_immutable BEFORE UPDATE ON setup_tokens
WHEN NEW.id IS NOT OLD.id OR NEW.purpose IS NOT OLD.purpose OR NEW.target_user_id IS NOT OLD.target_user_id
 OR NEW.installation_id IS NOT OLD.installation_id OR NEW.build_identity IS NOT OLD.build_identity
 OR NEW.digest IS NOT OLD.digest OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
 OR NEW.replace_password IS NOT OLD.replace_password OR NEW.risk_acknowledged IS NOT OLD.risk_acknowledged
BEGIN SELECT RAISE(ABORT, 'setup token identity and absolute expiry are immutable'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER setup_token_transition BEFORE UPDATE OF state ON setup_tokens
WHEN NEW.state IS NOT OLD.state AND NOT (
    (OLD.state = 'pending' AND NEW.state IN ('available','revoked')) OR
    (OLD.state = 'available' AND NEW.state IN ('claimed','revoked')) OR
    (OLD.state = 'claimed' AND NEW.state IN ('retrieved','revoked')) OR
    (OLD.state = 'retrieved' AND NEW.state IN ('consumed','revoked')))
BEGIN SELECT RAISE(ABORT, 'illegal setup token transition'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER setup_token_keep_evidence BEFORE DELETE ON setup_tokens
BEGIN SELECT RAISE(ABORT, 'setup token history is retained'); END;
-- +goose StatementEnd

-- Durable shared failed-guess counters, per purpose. Rate-limited and malformed
-- requests are not evaluated guesses and never touch these. 100 evaluated
-- failures revoke the live generations of that purpose (explicit host rotation
-- required); five failures start the escalating non-sliding wait.
CREATE TABLE setup_attempts (
    purpose TEXT PRIMARY KEY CHECK (purpose IN ('initial_setup','mfa_reset','restore_recovery')),
    failed INTEGER NOT NULL DEFAULT 0 CHECK (failed BETWEEN 0 AND 100),
    next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0)
) STRICT;
INSERT INTO setup_attempts(purpose) VALUES ('initial_setup'),('mfa_reset'),('restore_recovery');

-- A setup/recovery-only session is NOT a row of `sessions`: that table is read by
-- the normal session verifier and the authorizer, so a setup capability can never
-- be mistaken for (or upgraded into) an AAL label. token_id UNIQUE makes "exactly
-- one session per consumed token" a database invariant, not only a lock protocol.
CREATE TABLE setup_sessions (
    id TEXT PRIMARY KEY CHECK (length(id) = 64),
    token_id INTEGER NOT NULL UNIQUE REFERENCES setup_tokens(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (purpose IN ('initial_setup','mfa_reset','restore_recovery')),
    target_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    secret_hash BLOB NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at - created_at <= 1800),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','completed','revoked')),
    ended_at INTEGER,
    staged_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    staged_verifier BLOB,
    staged_password_format TEXT,
    staged_password_codepoints INTEGER CHECK (staged_password_codepoints IS NULL OR staged_password_codepoints BETWEEN 8 AND 128),
    totp_authenticator_id TEXT REFERENCES authenticators(id) ON DELETE RESTRICT,
    totp_proven_at INTEGER,
    proof_failures INTEGER NOT NULL DEFAULT 0 CHECK (proof_failures BETWEEN 0 AND 100),
    proof_next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (proof_next_attempt_at >= 0),
    last_proof_sent_at INTEGER NOT NULL DEFAULT 0 CHECK (last_proof_sent_at >= 0),
    CHECK ((state = 'active') = (ended_at IS NULL)),
    CHECK (purpose = 'mfa_reset' OR target_user_id IS NULL),
    CHECK (purpose != 'mfa_reset' OR target_user_id IS NOT NULL),
    CHECK ((staged_verifier IS NULL) = (staged_password_format IS NULL) AND (staged_verifier IS NULL) = (staged_password_codepoints IS NULL))
) STRICT;
-- +goose StatementBegin
CREATE TRIGGER setup_session_bound BEFORE INSERT ON setup_sessions
WHEN NOT EXISTS (SELECT 1 FROM setup_tokens t WHERE t.id = NEW.token_id AND t.state = 'consumed'
 AND t.purpose = NEW.purpose AND t.target_user_id IS NEW.target_user_id
 AND NEW.created_at >= t.issued_at AND NEW.created_at < t.expires_at AND NEW.expires_at = t.expires_at)
BEGIN SELECT RAISE(ABORT, 'setup session must be bound to its consumed token and absolute expiry'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER setup_session_immutable BEFORE UPDATE ON setup_sessions
WHEN NEW.id IS NOT OLD.id OR NEW.token_id IS NOT OLD.token_id OR NEW.purpose IS NOT OLD.purpose
 OR NEW.target_user_id IS NOT OLD.target_user_id OR NEW.secret_hash IS NOT OLD.secret_hash
 OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
 OR (OLD.state != 'active' AND NEW.state IS NOT OLD.state)
BEGIN SELECT RAISE(ABORT, 'setup session binding and expiry are immutable'); END;
-- +goose StatementEnd

-- +goose Down
DROP TABLE setup_sessions;
DROP TABLE setup_attempts;
DROP TABLE setup_tokens;
DROP TABLE setup_state;
