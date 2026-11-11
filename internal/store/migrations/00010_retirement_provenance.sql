-- +goose Up
-- Durable per-authenticator retirement provenance (P1.08 rework, NIST E03/E09/E12/I08).
-- A revoked second factor lowers an account's required-assurance floor ONLY when
-- this column proves the removal was authorised. NULL is deliberately NOT
-- "authorised": every revocation recorded before this migration is ambiguous
-- (a protective compromise report and a deliberate fresh-AAL2 removal persisted
-- identical rows), so it is kept as NULL and treated conservatively. Nothing is
-- backfilled or guessed.
--   protective          password-only or retry-ceiling compromise invalidation
--   authorized_removal  removal authorised by fresh maximum-account-assurance evidence
--   recovery_replacement settled by an approved restricted recovery that bound a
--                        replacement factor (also resolves earlier ambiguous rows)
ALTER TABLE authenticators ADD COLUMN retirement_reason TEXT CHECK (retirement_reason IS NULL OR retirement_reason IN ('protective','authorized_removal','recovery_replacement'));

-- +goose StatementBegin
CREATE TRIGGER authenticator_retirement_insert BEFORE INSERT ON authenticators
WHEN NEW.retirement_reason IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'retirement provenance requires a revoked second factor'); END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER authenticator_retirement_update BEFORE UPDATE ON authenticators
WHEN NEW.retirement_reason IS NOT NULL AND (NEW.state != 'revoked' OR NEW.revoked_at IS NULL OR NEW.kind NOT IN ('totp','webauthn'))
BEGIN SELECT RAISE(ABORT, 'retirement provenance requires a revoked second factor'); END;
-- +goose StatementEnd

-- Provenance is write-once. The single permitted transition settles an
-- unresolved protective record when an approved recovery binds a replacement.
-- +goose StatementBegin
CREATE TRIGGER authenticator_retirement_immutable BEFORE UPDATE ON authenticators
WHEN OLD.retirement_reason IS NOT NULL AND NEW.retirement_reason IS NOT OLD.retirement_reason
 AND NOT (OLD.retirement_reason = 'protective' AND COALESCE(NEW.retirement_reason,'') = 'recovery_replacement')
BEGIN SELECT RAISE(ABORT, 'retirement provenance is immutable'); END;
-- +goose StatementEnd

-- An ambiguous (NULL) record can never be promoted to a protective or authorised
-- one: authorisation is never guessed after the fact (only recovery may settle it).
-- +goose StatementBegin
CREATE TRIGGER authenticator_retirement_no_backfill BEFORE UPDATE ON authenticators
WHEN OLD.state = 'revoked' AND OLD.retirement_reason IS NULL AND NEW.retirement_reason IN ('protective','authorized_removal')
BEGIN SELECT RAISE(ABORT, 'ambiguous retirement cannot be backfilled'); END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER authenticator_retirement_no_backfill;
DROP TRIGGER authenticator_retirement_immutable;
DROP TRIGGER authenticator_retirement_update;
DROP TRIGGER authenticator_retirement_insert;
ALTER TABLE authenticators DROP COLUMN retirement_reason;
