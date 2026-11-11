-- +goose Up
-- P1.10 agent-credential integrity. Additive triggers only: no column, row or
-- existing constraint changes. They make the credential lifecycle one-way in
-- SQLite itself, whatever writer (service, restore import, repair tool) acts:
--   * a revoked credential is final: it can never be reactivated or edited;
--   * the stored verifier, owner agent, issue time, expiry and display
--     identifier of a credential are immutable;
--   * a rotation overlap window may only be shortened, never extended or
--     cleared, so a rotated-out token cannot be revived;
-- Agent-state coupling (active credential vs. non-active agent) is deliberately
-- NOT a trigger: the shared verifier refuses such credentials itself and its
-- defence-in-depth tests model that state; the service revokes before disabling.
-- Quarantine/restore stay stricter than this: imported credentials are never
-- inserted active, and these rules cannot activate anything.

-- +goose StatementBegin
CREATE TRIGGER agent_credential_revoked_is_final BEFORE UPDATE ON agent_credentials
WHEN OLD.state = 'revoked'
BEGIN SELECT RAISE(ABORT, 'a revoked credential is final'); END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER agent_credential_identity_immutable BEFORE UPDATE ON agent_credentials
WHEN NEW.token_hash IS NOT OLD.token_hash OR NEW.agent_id IS NOT OLD.agent_id
 OR ((OLD.state != 'quarantined' OR NEW.state != 'quarantined') AND (
   NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
   OR NEW.nonexpiring_approved IS NOT OLD.nonexpiring_approved OR NEW.display_prefix IS NOT OLD.display_prefix))
BEGIN SELECT RAISE(ABORT, 'credential verifier, owner, issue time, expiry and identifier are immutable'); END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER agent_credential_overlap_shrinks_only BEFORE UPDATE OF rotation_overlap_until ON agent_credentials
WHEN OLD.rotation_overlap_until IS NOT NULL AND (NEW.rotation_overlap_until IS NULL OR NEW.rotation_overlap_until > OLD.rotation_overlap_until)
BEGIN SELECT RAISE(ABORT, 'a rotation overlap window can only be shortened'); END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER agent_credential_overlap_shrinks_only;
DROP TRIGGER agent_credential_identity_immutable;
DROP TRIGGER agent_credential_revoked_is_final;
