-- +goose Up
-- P1.18 logical restore control plane (security-contracts.md S2). Both tables are LOCAL,
-- NON-IMPORTABLE control state: a logical backup must never map them (asserted by
-- TestRestoreControlStateIsNotPartOfAnyExportSurface). They hold only non-secret facts:
-- identifiers, display labels, record states and the imported-versus-effective settings
-- that an administrator must review. No credential, verifier, token hash or ciphertext is
-- ever stored here.
--
-- One report per committed restore. restore_generation is the installation_control
-- restore_generation that the restore transition produced, so it is unique and never reused.
CREATE TABLE restore_reports (
    restore_generation INTEGER PRIMARY KEY CHECK (restore_generation > 0),
    backup_id TEXT NOT NULL CHECK (length(backup_id) BETWEEN 1 AND 64),
    mode TEXT NOT NULL CHECK (mode IN ('full','clean')),
    provenance TEXT NOT NULL CHECK (provenance IN ('authenticated','unauthenticated')),
    initiator TEXT NOT NULL CHECK (initiator IN ('admin','host')),
    restored_at INTEGER NOT NULL CHECK (restored_at > 0),
    summary TEXT NOT NULL CHECK (length(summary) <= 65536)
) STRICT;

-- The redacted authority manifest of that restore: every record the restore imported or
-- retained, with what the archive claimed and what is effective now. decision never grants
-- anything by itself: it records that an administrator approved the record in this generation.
CREATE TABLE restore_manifest (
    restore_generation INTEGER NOT NULL REFERENCES restore_reports(restore_generation) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('endpoint','user','group','agent','user_membership','agent_membership','role','policy','address','credential')),
    item_id TEXT NOT NULL CHECK (length(item_id) BETWEEN 1 AND 300),
    label TEXT NOT NULL CHECK (length(label) <= 300),
    origin TEXT NOT NULL CHECK (origin IN ('imported','local_retained')),
    source_state TEXT CHECK (source_state IS NULL OR length(source_state) <= 32),
    imported TEXT NOT NULL DEFAULT '{}' CHECK (length(imported) <= 4096),
    effective TEXT NOT NULL DEFAULT '{}' CHECK (length(effective) <= 4096),
    decision TEXT NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','approved')),
    decided_at INTEGER CHECK (decided_at IS NULL OR decided_at > 0),
    PRIMARY KEY (restore_generation, kind, item_id),
    CHECK ((decision = 'approved') = (decided_at IS NOT NULL))
) STRICT;
-- +goose StatementBegin
CREATE TRIGGER restore_manifest_decision_is_final BEFORE UPDATE ON restore_manifest
WHEN OLD.decision = 'approved' OR NEW.restore_generation IS NOT OLD.restore_generation OR NEW.kind IS NOT OLD.kind
 OR NEW.item_id IS NOT OLD.item_id OR NEW.origin IS NOT OLD.origin OR NEW.source_state IS NOT OLD.source_state
 OR NEW.imported IS NOT OLD.imported OR NEW.label IS NOT OLD.label
BEGIN SELECT RAISE(ABORT, 'a restore manifest entry is immutable except for its first approval'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER restore_report_immutable BEFORE UPDATE ON restore_reports
BEGIN SELECT RAISE(ABORT, 'a restore report is immutable'); END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER restore_report_immutable;
DROP TRIGGER restore_manifest_decision_is_final;
DROP TABLE restore_manifest;
DROP TABLE restore_reports;
