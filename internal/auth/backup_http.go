package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NicoTM77/Mandatary/internal/backup"
)

// P1.18 routes of the administrative adapter. They exist only when a backup service was attached with
// Admin.SetBackup. Every route sits on an auth.Browser, so cookie, exact Origin, per-session CSRF token,
// JSON-only body, the class's step-up gate (AAL2 within 15 minutes) and the body bound run BEFORE any
// handler, and the service re-checks the fresh administrator inside its own durable transaction.
// Request bodies are single JSON objects with unknown fields refused: there is no field that names a
// state, a generation, a role, a quarantine value or a credential.
//
//	POST /api/v1/admin/backup/export   class backup-export   {"mode":"full"|"clean"}            -> the archive (attachment)
//	POST /api/v1/admin/restore         class backup-restore  {"archive":{...},"confirm":"RESTORE",
//	                                                          "acknowledge_unauthenticated_provenance":bool} -> RestoreReport
//	GET  /api/v1/admin/restore/manifest                      (session, no step-up)                -> ManifestView
//	POST /api/v1/admin/restore/approvals class security-policy-change {"items":[{"kind","id"}...]} -> {"approved":[...]}

const (
	backupBase = adminAPIBase + "/backup"
	restoreURL = adminAPIBase + "/restore"

	// RestoreConfirmation is the exact phrase a restore request must carry. The server enforces it so a
	// scripted or replayed request cannot skip the explicit confirmation the interface asks for.
	RestoreConfirmation = "RESTORE"

	// restoreBodyBytes bounds the restore request: the largest archive plus the envelope around it.
	restoreBodyBytes = backup.MaxArchiveBytes + 64<<10
)

func (h *AdminHTTP) backupRoutes(read RoutePolicy) []policyRoute {
	if h.a.backup == nil {
		return nil
	}
	export := RoutePolicy{Require: RequireSession, Sensitive: OpBackupExport}
	restore := RoutePolicy{Require: RequireSession, Sensitive: OpBackupRestore, MaxBody: restoreBodyBytes}
	approve := RoutePolicy{Require: RequireSession, Sensitive: OpSecurityPolicy}
	return []policyRoute{
		{"POST " + backupBase + "/export", export, h.exportBackup},
		{"POST " + restoreURL, restore, h.restoreBackup},
		{"GET " + restoreURL + "/manifest", read, h.restoreManifest},
		{"POST " + restoreURL + "/approvals", approve, h.reapprove},
	}
}

func (h *AdminHTTP) exportBackup(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Mode string `json:"mode"`
	}
	if !ok || !decodeStrict(r, &body, false) || (body.Mode != string(backup.ModeFull) && body.Mode != string(backup.ModeClean)) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	raw, info, err := h.a.ExportBackup(r.Context(), secret, backup.Mode(body.Mode))
	if err != nil {
		backupFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="mandatary-backup-`+info.BackupID+`-`+string(info.Mode)+`.json"`)
	w.Header().Set("X-Backup-Id", info.BackupID)
	w.Header().Set("X-Backup-Mode", string(info.Mode))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *AdminHTTP) restoreBackup(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Archive                              json.RawMessage `json:"archive"`
		Confirm                              string          `json:"confirm"`
		AcknowledgeUnauthenticatedProvenance bool            `json:"acknowledge_unauthenticated_provenance"`
	}
	if !ok || !decodeStrict(r, &body, false) || body.Confirm != RestoreConfirmation || len(body.Archive) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	res, err := h.a.RestoreBackup(r.Context(), secret, body.Archive, body.AcknowledgeUnauthenticatedProvenance)
	if err != nil {
		backupFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"report": res.Report, "authorizer_notified": res.Notified, "session_ended": true})
}

func (h *AdminHTTP) restoreManifest(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	view, err := h.a.RestoreManifest(r.Context(), secret)
	if err != nil {
		if errors.Is(err, ErrAdminNotFound) {
			writeJSONError(w, http.StatusNotFound, "no_restore")
			return
		}
		backupFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, view)
}

func (h *AdminHTTP) reapprove(w http.ResponseWriter, r *http.Request) {
	secret, ok := adminSecret(r)
	var body struct {
		Items []backup.ItemRef `json:"items"`
	}
	if !ok || !decodeStrict(r, &body, false) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	results, err := h.a.ReapproveRestored(r.Context(), secret, body.Items)
	if err != nil {
		backupFailure(w, err)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"approved": results})
}

// restoreQuarantine is the state a failed restore leaves when its transition already committed.
const restoreQuarantine = "restore_quarantine"

// backupFailure maps service errors to fixed, input-free responses. Archive content, record values,
// keys and the failing check are never reflected; a refusal after the transition adds the
// installation state so the interface can say plainly that the installation is now in quarantine.
func backupFailure(w http.ResponseWriter, err error) {
	body := map[string]any{}
	status, code := http.StatusServiceUnavailable, "unavailable"
	switch {
	case errors.Is(err, backup.ErrMalformed):
		status, code = http.StatusUnprocessableEntity, "archive_malformed"
	case errors.Is(err, backup.ErrUnsupportedVersion):
		status, code = http.StatusUnprocessableEntity, "archive_unsupported_version"
	case errors.Is(err, backup.ErrIntegrity):
		status, code = http.StatusUnprocessableEntity, "archive_integrity_failed"
	case errors.Is(err, backup.ErrConsistency):
		status, code = http.StatusUnprocessableEntity, "archive_inconsistent"
	case errors.Is(err, backup.ErrUnauthenticated):
		status, code = http.StatusConflict, "provenance_unverified"
	case errors.Is(err, backup.ErrSuperseded):
		status, code = http.StatusConflict, "restore_superseded"
	case errors.Is(err, backup.ErrNoRestore):
		status, code = http.StatusNotFound, "no_restore"
	case errors.Is(err, backup.ErrQuarantined):
		status, code = http.StatusConflict, "restore_quarantine"
	case errors.Is(err, backup.ErrConflict):
		status, code = http.StatusConflict, "conflict"
		var c *backup.ConflictError
		if errors.As(err, &c) {
			body["items"] = c.Failures
		}
	case errors.Is(err, backup.ErrInvalid), errors.Is(err, ErrAdminInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, backup.ErrDenied), errors.Is(err, ErrDenied):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrAdminNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, ErrAdminConflict):
		status, code = http.StatusConflict, "conflict"
	}
	body["error"] = code
	if backup.Quarantined(err) {
		body["installation_state"] = restoreQuarantine
	}
	writeAdminJSON(w, status, body)
}
