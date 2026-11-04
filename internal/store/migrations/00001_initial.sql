-- +goose Up
-- All authority is initially inactive. Runtime self-verification is deliberately
-- absent: neither this store nor a restored archive can establish it.
CREATE TABLE installation_control (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    session_generation INTEGER NOT NULL DEFAULT 0 CHECK (session_generation >= 0),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    restore_generation INTEGER NOT NULL DEFAULT 0 CHECK (restore_generation >= 0),
    restore_quarantined INTEGER NOT NULL DEFAULT 1 CHECK (restore_quarantined IN (0,1))
) STRICT;
INSERT INTO installation_control(singleton) VALUES (1);
-- These are current local controls, NEVER fields an archive importer may map.
-- +goose StatementBegin
CREATE TRIGGER control_generation_monotonic BEFORE UPDATE ON installation_control
WHEN NEW.credential_generation < OLD.credential_generation OR
 NEW.session_generation < OLD.session_generation OR
 NEW.authority_generation < OLD.authority_generation OR
 NEW.restore_generation < OLD.restore_generation
BEGIN SELECT RAISE(ABORT, 'current control generation cannot regress'); END;
-- +goose StatementEnd

CREATE TABLE endpoints (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND substr(id,9,1) = '-' AND substr(id,14,1) = '-'
        AND substr(id,19,1) = '-' AND substr(id,24,1) = '-'
        AND length(replace(id,'-','')) = 32
        AND replace(id,'-','') NOT GLOB '*[^0-9a-f]*'
        AND id != '00000000-0000-0000-0000-000000000000'),
    slug TEXT NOT NULL UNIQUE CHECK (length(slug) BETWEEN 1 AND 63 AND slug NOT GLOB '*[^a-z0-9-]*'),
    name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
    transport TEXT NOT NULL CHECK (transport IN ('unix','mtls','ssh')),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    CHECK (state != 'active' OR (slug = 'local' AND transport = 'unix' AND authority_generation > 0))
) STRICT;
INSERT INTO endpoints(id,slug,name,transport)
VALUES (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
 substr(lower(hex(randomblob(2))),2) || '-8' || substr(lower(hex(randomblob(2))),2) ||
 '-' || lower(hex(randomblob(6))), 'local', 'Local', 'unix');

CREATE TABLE users (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    username TEXT NOT NULL UNIQUE CHECK (length(trim(username)) > 0),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    mfa_requirement TEXT NOT NULL DEFAULT 'required' CHECK (mfa_requirement IN ('optional','required','webauthn')),
    compromised INTEGER NOT NULL DEFAULT 0 CHECK (compromised IN (0,1)),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    CHECK (state != 'active' OR (credential_generation > 0 AND authority_generation > 0))
) STRICT;
CREATE TABLE groups (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    CHECK (state != 'active' OR authority_generation > 0)
) STRICT;
CREATE TABLE agents (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
    owner_user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    owner_group_id TEXT REFERENCES groups(id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    CHECK ((owner_user_id IS NOT NULL) + (owner_group_id IS NOT NULL) = 1),
    CHECK (state != 'active' OR (credential_generation > 0 AND authority_generation > 0))
) STRICT;
CREATE TABLE user_group_memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    PRIMARY KEY (user_id,group_id),
    CHECK (state != 'active' OR authority_generation > 0)
) STRICT;
CREATE TABLE agent_group_memberships (
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    PRIMARY KEY (agent_id,group_id),
    CHECK (state != 'active' OR authority_generation > 0)
) STRICT;
CREATE TABLE administrative_roles (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('super_admin','endpoint_admin')),
    endpoint_id TEXT REFERENCES endpoints(id) ON DELETE RESTRICT,
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    CHECK ((role = 'super_admin' AND endpoint_id IS NULL) OR (role = 'endpoint_admin' AND endpoint_id IS NOT NULL)),
    CHECK (state != 'active' OR (role = 'super_admin' AND authority_generation > 0))
) STRICT;
CREATE UNIQUE INDEX one_active_administrator ON administrative_roles(role) WHERE state = 'active';
CREATE UNIQUE INDEX unique_global_role ON administrative_roles(user_id,role) WHERE endpoint_id IS NULL;
CREATE UNIQUE INDEX unique_endpoint_role ON administrative_roles(user_id,role,endpoint_id) WHERE endpoint_id IS NOT NULL;

CREATE TABLE container_selectors (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE RESTRICT,
    container_name TEXT NOT NULL CHECK (length(container_name) > 0),
    name_is_glob INTEGER NOT NULL DEFAULT 0 CHECK (name_is_glob IN (0,1)),
    compose_project TEXT,
    compose_service TEXT,
    image_pattern TEXT,
    pinned_container_id TEXT,
    pinned_image_digest TEXT,
    UNIQUE (id,endpoint_id)
) STRICT;
CREATE TABLE policies (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    group_id TEXT REFERENCES groups(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    effect TEXT NOT NULL CHECK (effect IN ('ALLOW','DENY')),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','disabled')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    log_tail_max INTEGER CHECK (log_tail_max BETWEEN 1 AND 10000),
    stop_timeout_max INTEGER CHECK (stop_timeout_max BETWEEN 1 AND 300),
    CHECK ((user_id IS NOT NULL) + (group_id IS NOT NULL) + (agent_id IS NOT NULL) = 1),
    CHECK (state != 'active' OR authority_generation > 0),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX policies_target ON policies(endpoint_id,selector_id,operation);

-- Lifecycle records contain only verifiers/ciphertexts/public keys, never raw
-- passwords, TOTP seeds, recovery codes or bearer/session secrets. Services must
-- validate cryptographic formats and protect encryption before activation.
CREATE TABLE authenticators (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('password','totp','webauthn','recovery_code')),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('pending','quarantined','active','disabled','revoked')),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    created_at INTEGER NOT NULL DEFAULT 0 CHECK (created_at >= 0),
    bound_at INTEGER CHECK (bound_at >= created_at),
    changed_at INTEGER CHECK (changed_at >= created_at),
    revoked_at INTEGER CHECK (revoked_at >= created_at),
    expires_at INTEGER CHECK (expires_at > created_at),
    verifier_hash BLOB,
    encrypted_secret BLOB,
    public_key BLOB,
    external_credential_id BLOB UNIQUE,
    password_codepoints INTEGER CHECK (password_codepoints IS NULL OR (kind = 'password' AND password_codepoints BETWEEN 8 AND 128)),
    password_format TEXT,
    max_assurance INTEGER NOT NULL DEFAULT 0 CHECK (max_assurance IN (0,1,2)),
    phishing_resistant INTEGER CHECK (phishing_resistant IN (0,1)),
    retry_ceiling INTEGER NOT NULL DEFAULT 100 CHECK (retry_ceiling BETWEEN 1 AND 100),
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND retry_ceiling),
    next_attempt_at INTEGER CHECK (next_attempt_at >= 0),
    last_accepted_totp_step INTEGER CHECK (last_accepted_totp_step IS NULL OR (kind = 'totp' AND last_accepted_totp_step >= 0)),
    sign_count INTEGER CHECK (sign_count IS NULL OR (kind = 'webauthn' AND sign_count >= 0)),
    backup_eligible INTEGER CHECK (backup_eligible IS NULL OR (kind = 'webauthn' AND backup_eligible IN (0,1))),
    backup_state INTEGER CHECK (backup_state IS NULL OR (kind = 'webauthn' AND backup_state IN (0,1))),
    user_verified INTEGER CHECK (user_verified IS NULL OR (kind = 'webauthn' AND user_verified IN (0,1))),
    CHECK (backup_state IS NOT 1 OR backup_eligible IS 1),
    CHECK (state != 'active' OR (credential_generation > 0 AND bound_at IS NOT NULL AND revoked_at IS NULL AND failed_attempts < retry_ceiling)),
    CHECK (state != 'active' OR
        (kind = 'password' AND verifier_hash IS NOT NULL AND password_format IS NOT NULL AND password_codepoints IS NOT NULL) OR
        (kind = 'totp' AND encrypted_secret IS NOT NULL) OR
        (kind = 'webauthn' AND public_key IS NOT NULL AND external_credential_id IS NOT NULL) OR
        (kind = 'recovery_code' AND verifier_hash IS NOT NULL AND length(verifier_hash) = 32)),
    UNIQUE (id,user_id)
) STRICT;
CREATE UNIQUE INDEX one_active_password ON authenticators(user_id) WHERE kind = 'password' AND state = 'active';
-- +goose StatementBegin
CREATE TRIGGER short_password_insert BEFORE INSERT ON authenticators
WHEN NEW.kind = 'password' AND NEW.password_codepoints < 15
 AND EXISTS (SELECT 1 FROM users WHERE id=NEW.user_id AND mfa_requirement='optional')
BEGIN SELECT RAISE(ABORT, 'short password requires compulsory MFA'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER short_password_update BEFORE UPDATE ON authenticators
WHEN NEW.kind = 'password' AND NEW.password_codepoints < 15
 AND EXISTS (SELECT 1 FROM users WHERE id=NEW.user_id AND mfa_requirement='optional')
BEGIN SELECT RAISE(ABORT, 'short password requires compulsory MFA'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER compulsory_mfa_update BEFORE UPDATE OF mfa_requirement ON users
WHEN NEW.mfa_requirement='optional'
 AND EXISTS (SELECT 1 FROM authenticators WHERE user_id=NEW.id AND kind='password' AND password_codepoints < 15 AND state NOT IN ('revoked','disabled'))
BEGIN SELECT RAISE(ABORT, 'replace short password before enabling password-only use'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER totp_replay_monotonic BEFORE UPDATE OF last_accepted_totp_step ON authenticators
WHEN OLD.last_accepted_totp_step IS NOT NULL AND
 (NEW.last_accepted_totp_step IS NULL OR NEW.last_accepted_totp_step < OLD.last_accepted_totp_step)
BEGIN SELECT RAISE(ABORT, 'TOTP replay state cannot regress'); END;
-- +goose StatementEnd

CREATE TABLE agent_credentials (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    display_prefix TEXT NOT NULL CHECK (length(display_prefix) BETWEEN 1 AND 16),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER CHECK (expires_at > issued_at),
    nonexpiring_approved INTEGER NOT NULL DEFAULT 0 CHECK (nonexpiring_approved IN (0,1)),
    rotation_overlap_until INTEGER CHECK (rotation_overlap_until > issued_at),
    revoked_at INTEGER CHECK (revoked_at >= issued_at),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','revoked')),
    CHECK (expires_at IS NOT NULL OR nonexpiring_approved = 1),
    CHECK (state != 'active' OR (credential_generation > 0 AND revoked_at IS NULL))
) STRICT;
CREATE TABLE sessions (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    secret_hash BLOB NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
    purpose TEXT NOT NULL CHECK (purpose IN ('normal','preauth','setup','recovery')),
    achieved_assurance INTEGER NOT NULL DEFAULT 0 CHECK (achieved_assurance IN (0,1,2)),
    methods INTEGER NOT NULL DEFAULT 0 CHECK (methods IN (0,1,2,3,4,5,8,16)),
    phishing_resistant INTEGER NOT NULL DEFAULT 0 CHECK (phishing_resistant IN (0,1)),
    authenticated_at INTEGER,
    reauthenticated_at INTEGER,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    last_activity_at INTEGER NOT NULL CHECK (last_activity_at >= created_at AND last_activity_at < expires_at),
    idle_timeout_seconds INTEGER NOT NULL DEFAULT 1800 CHECK (idle_timeout_seconds BETWEEN 1 AND 1800),
    revoked_at INTEGER CHECK (revoked_at >= created_at),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    session_generation INTEGER NOT NULL DEFAULT 0 CHECK (session_generation >= 0),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','revoked')),
    CHECK (expires_at - created_at <= 43200),
    CHECK (achieved_assurance = 0 OR (purpose = 'normal' AND authenticated_at IS NOT NULL AND authenticated_at >= created_at AND authenticated_at < expires_at)),
    CHECK (achieved_assurance != 1 OR methods = 1),
    CHECK (achieved_assurance != 2 OR methods IN (3,5,8)),
    CHECK (phishing_resistant = 0 OR (achieved_assurance = 2 AND methods = 8)),
    CHECK (reauthenticated_at IS NULL OR (authenticated_at IS NOT NULL AND reauthenticated_at >= authenticated_at AND reauthenticated_at < expires_at)),
    CHECK (state != 'active' OR (credential_generation > 0 AND session_generation > 0 AND revoked_at IS NULL)),
    UNIQUE (id,user_id)
) STRICT;
CREATE TABLE session_authenticators (
    session_id TEXT NOT NULL,
    authenticator_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (session_id,authenticator_id),
    FOREIGN KEY (session_id,user_id) REFERENCES sessions(id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (authenticator_id,user_id) REFERENCES authenticators(id,user_id) ON DELETE RESTRICT
) STRICT;
CREATE TABLE auth_challenges (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id TEXT REFERENCES sessions(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (purpose IN ('webauthn_binding','webauthn_assertion','totp_binding')),
    challenge_hash BLOB NOT NULL UNIQUE CHECK (length(challenge_hash) = 32),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    consumed_at INTEGER CHECK (consumed_at >= issued_at AND consumed_at < expires_at),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    FOREIGN KEY (session_id,user_id) REFERENCES sessions(id,user_id) ON DELETE RESTRICT
) STRICT;
-- +goose StatementBegin
CREATE TRIGGER challenge_consumed BEFORE UPDATE OF consumed_at ON auth_challenges
WHEN OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NOT OLD.consumed_at
BEGIN SELECT RAISE(ABORT, 'consumed challenge cannot be reset'); END;
-- +goose StatementEnd

CREATE TABLE notification_addresses (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    address TEXT NOT NULL CHECK (length(address) BETWEEN 3 AND 254 AND instr(address,char(10)) = 0 AND instr(address,char(13)) = 0),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    verified_at INTEGER CHECK (verified_at >= created_at),
    revoked_at INTEGER CHECK (revoked_at >= created_at),
    state TEXT NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined','active','revoked')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    CHECK (state != 'active' OR (verified_at IS NOT NULL AND revoked_at IS NULL AND authority_generation > 0)),
    UNIQUE (user_id,address,version),
    UNIQUE (id,user_id,version)
) STRICT;
CREATE TABLE notification_address_proofs (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL,
    address_id TEXT NOT NULL,
    address_version INTEGER NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose = 'notification_address_confirmation'),
    proof_hash BLOB NOT NULL UNIQUE CHECK (length(proof_hash) = 32),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    consumed_at INTEGER CHECK (consumed_at >= issued_at AND consumed_at < expires_at),
    credential_generation INTEGER NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    FOREIGN KEY (address_id,user_id,address_version) REFERENCES notification_addresses(id,user_id,version) ON DELETE RESTRICT
) STRICT;
-- +goose StatementBegin
CREATE TRIGGER address_proof_consumed BEFORE UPDATE OF consumed_at ON notification_address_proofs
WHEN OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NOT OLD.consumed_at
BEGIN SELECT RAISE(ABORT, 'consumed confirmation cannot be reset'); END;
-- +goose StatementEnd
CREATE TABLE security_events (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN ('authenticator_bound','authenticator_replaced','authenticator_removed','authenticator_suspended','recovery_completed','recovery_codes_issued','recovery_codes_replaced','address_change_proposed','address_changed','security_settings_changed')),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    retain_until INTEGER NOT NULL CHECK (retain_until > occurred_at),
    deduplication_key TEXT NOT NULL UNIQUE CHECK (length(deduplication_key) > 0),
    UNIQUE (id,user_id)
) STRICT;
CREATE TABLE security_notice_outbox (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    address_id TEXT NOT NULL,
    address_version INTEGER NOT NULL,
    recipient_snapshot TEXT NOT NULL CHECK (length(recipient_snapshot) BETWEEN 3 AND 254 AND instr(recipient_snapshot,char(10)) = 0 AND instr(recipient_snapshot,char(13)) = 0),
    delivery_state TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','relay-accepted','failed','bounced')),
    dispatch_state TEXT NOT NULL DEFAULT 'quarantined' CHECK (dispatch_state IN ('quarantined','ready','paused')),
    authority_generation INTEGER NOT NULL DEFAULT 0 CHECK (authority_generation >= 0),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER CHECK (next_attempt_at >= 0),
    last_attempt_at INTEGER CHECK (last_attempt_at >= 0),
    failure_code TEXT CHECK (failure_code IN ('tls','auth','recipient','temporary','permanent','storage','ambiguous')),
    retain_until INTEGER NOT NULL CHECK (retain_until > 0),
    CHECK (dispatch_state != 'ready' OR authority_generation > 0),
    CHECK (delivery_state != 'relay-accepted' OR (attempts > 0 AND last_attempt_at IS NOT NULL)),
    FOREIGN KEY (event_id,user_id) REFERENCES security_events(id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (address_id,user_id,address_version) REFERENCES notification_addresses(id,user_id,version) ON DELETE RESTRICT,
    UNIQUE (event_id,address_id,address_version)
) STRICT;
CREATE INDEX security_notice_queue ON security_notice_outbox(dispatch_state,delivery_state,next_attempt_at);
-- Recipient snapshots are immutable so retry cannot retarget a historical notice.
-- +goose StatementBegin
CREATE TRIGGER notice_recipient_immutable BEFORE UPDATE OF event_id,user_id,address_id,address_version,recipient_snapshot ON security_notice_outbox
WHEN NEW.event_id IS NOT OLD.event_id OR NEW.user_id IS NOT OLD.user_id OR NEW.address_id IS NOT OLD.address_id OR NEW.address_version IS NOT OLD.address_version OR NEW.recipient_snapshot IS NOT OLD.recipient_snapshot
BEGIN SELECT RAISE(ABORT, 'notice recipient snapshot is immutable'); END;
-- +goose StatementEnd

CREATE TABLE usage_stats_hourly (
    id INTEGER PRIMARY KEY,
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0 AND bucket_start % 3600 = 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    allowed_count INTEGER NOT NULL DEFAULT 0 CHECK (allowed_count >= 0),
    denied_count INTEGER NOT NULL DEFAULT 0 CHECK (denied_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
-- Nullable attribution uses an expression index: SQL NULL must not allow
-- duplicate human-only or group-owned-agent rollups.
CREATE UNIQUE INDEX usage_hourly_tuple ON usage_stats_hourly(bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,selector_id,operation);
CREATE TABLE usage_stats_daily (
    id INTEGER PRIMARY KEY,
    bucket_start INTEGER NOT NULL CHECK (bucket_start >= 0 AND bucket_start % 86400 = 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    allowed_count INTEGER NOT NULL DEFAULT 0 CHECK (allowed_count >= 0),
    denied_count INTEGER NOT NULL DEFAULT 0 CHECK (denied_count >= 0),
    error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
CREATE UNIQUE INDEX usage_daily_tuple ON usage_stats_daily(bucket_start,coalesce(user_id,''),coalesce(agent_id,''),endpoint_id,selector_id,operation);
CREATE TABLE usage_recent_events (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    user_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES agents(id) ON DELETE RESTRICT,
    endpoint_id TEXT NOT NULL,
    selector_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('container:logs','container:inspect_status','container:inspect_config','container:start','container:stop','container:restart')),
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','error')),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    retain_until INTEGER NOT NULL CHECK (retain_until > occurred_at),
    CHECK (user_id IS NOT NULL OR agent_id IS NOT NULL),
    FOREIGN KEY (selector_id,endpoint_id) REFERENCES container_selectors(id,endpoint_id) ON DELETE RESTRICT
) STRICT;
CREATE INDEX usage_events_retention ON usage_recent_events(retain_until);

-- +goose Down
DROP TABLE usage_recent_events;
DROP TABLE usage_stats_daily;
DROP TABLE usage_stats_hourly;
DROP TABLE security_notice_outbox;
DROP TABLE security_events;
DROP TABLE notification_address_proofs;
DROP TABLE notification_addresses;
DROP TABLE auth_challenges;
DROP TABLE session_authenticators;
DROP TABLE sessions;
DROP TABLE agent_credentials;
DROP TABLE authenticators;
DROP TABLE policies;
DROP TABLE container_selectors;
DROP TABLE administrative_roles;
DROP TABLE agent_group_memberships;
DROP TABLE user_group_memberships;
DROP TABLE agents;
DROP TABLE groups;
DROP TABLE users;
DROP TABLE endpoints;
DROP TABLE installation_control;
