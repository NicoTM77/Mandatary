package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/backup"
)

// P1.18 administrative export/restore over the real Browser boundary and the real fresh-administrator
// transaction. The archive format, validation and import are tested in internal/backup; here the
// authority contract of the routes is pinned: who may call them, what step-up they need, what they
// leave behind, and that no response carries credential material.

const (
	exportPath   = adminBase + "/backup/export"
	restorePath  = adminBase + "/restore"
	manifestPath = adminBase + "/restore/manifest"
	approvePath  = adminBase + "/restore/approvals"
)

func newBackupHTTP(t *testing.T) *adminHTTP {
	t.Helper()
	e := newAdminEnv(t)
	svc, err := backup.New(e.l.repo, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.SetBackup(svc); err != nil {
		t.Fatal(err)
	}
	b := NewBrowser(e.s)
	adapter, err := NewAdminHTTP(e.a)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Register(b); err != nil {
		t.Fatal(err)
	}
	return &adminHTTP{adminEnv: e, b: b, cookie: encodeSessionCookie(e.secret), csrf: csrfToken(e.secret, e.sessID)}
}

func (h *adminHTTP) exportArchive(mode string) []byte {
	h.t.Helper()
	w := h.post(exportPath, `{"mode":"`+mode+`"}`)
	if w.Code != http.StatusOK {
		h.t.Fatalf("export %s: %d %s", mode, w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

func restoreBody(archive []byte, confirm string, ack bool) string {
	ackText := "false"
	if ack {
		ackText = "true"
	}
	return `{"archive":` + string(archive) + `,"confirm":"` + confirm + `","acknowledge_unauthenticated_provenance":` + ackText + `}`
}

func TestBackupRoutesAreAbsentUntilABackupServiceIsAttached(t *testing.T) {
	t.Parallel()
	h := newAdminHTTP(t) // no SetBackup
	for _, c := range []struct{ method, path string }{{http.MethodPost, exportPath}, {http.MethodPost, restorePath}, {http.MethodGet, manifestPath}, {http.MethodPost, approvePath}} {
		if w := h.do(adminReq{method: c.method, path: c.path, body: `{}`}); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s without a backup service: %d", c.method, c.path, w.Code)
		}
	}
	if err := h.a.SetBackup(nil); err == nil {
		t.Fatal("a nil service must be refused")
	}
	for _, err := range []error{func() error { _, _, e := h.a.ExportBackup(t.Context(), h.secret, backup.ModeFull); return e }(),
		func() error { _, e := h.a.RestoreBackup(t.Context(), h.secret, []byte(`{}`), false); return e }()} {
		if err != ErrAdminUnavailable {
			t.Fatalf("service call without a backup service: %v", err)
		}
	}
}

func TestBackupRouteInventoryDeclaresTheExactStepUpClasses(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	want := map[string]RoutePolicy{
		"POST " + exportPath:  {Require: RequireSession, Sensitive: OpBackupExport},
		"POST " + restorePath: {Require: RequireSession, Sensitive: OpBackupRestore, MaxBody: restoreBodyBytes},
		"GET " + manifestPath: {Require: RequireSession},
		"POST " + approvePath: {Require: RequireSession, Sensitive: OpSecurityPolicy},
	}
	got := map[string]RoutePolicy{}
	for _, r := range h.b.Routes() {
		if strings.Contains(r.Pattern, "backup") || strings.Contains(r.Pattern, "/restore") {
			got[r.Pattern] = r.Policy
		}
	}
	if len(got) != len(want) {
		t.Fatalf("routes %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %+v, want %+v", k, got[k], w)
		}
	}
	// Every state-changing class needs fresh AAL2; only the manifest read does not.
	for _, op := range []SensitiveOperation{OpBackupExport, OpBackupRestore, OpSecurityPolicy} {
		if !sensitivePolicies[op].aal2 {
			t.Errorf("%s must require AAL2", op)
		}
	}
}

func TestExportNeedsFreshAAL2AndIsRefusedForEveryoneElse(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	before := h.snapshot()
	empty, wrong := "", wrongCSRF(h.csrf)
	for name, q := range map[string]adminReq{
		"no cookie":  {method: http.MethodPost, path: exportPath, body: `{"mode":"full"}`, cookie: &empty},
		"no csrf":    {method: http.MethodPost, path: exportPath, body: `{"mode":"full"}`, csrf: &empty},
		"bad csrf":   {method: http.MethodPost, path: exportPath, body: `{"mode":"full"}`, csrf: &wrong},
		"bad origin": {method: http.MethodPost, path: exportPath, body: `{"mode":"full"}`, origin: "https://evil.invalid"},
	} {
		if w := h.do(q); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	for name, body := range map[string]string{"no mode": `{}`, "bad mode": `{"mode":"partial"}`, "state field": `{"mode":"full","state":"active"}`, "not json": `x`} {
		if w := h.post(exportPath, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	h.exec(`UPDATE administrative_roles SET state='disabled' WHERE id='adm'`) // an ordinary signed-in user
	if w := h.post(exportPath, `{"mode":"full"}`); w.Code != http.StatusForbidden {
		t.Errorf("ordinary user export: %d", w.Code)
	}
	h.exec(`UPDATE administrative_roles SET state='active' WHERE id='adm'`)
	h.clock.Advance(DefaultStepUpWindow + time.Second)
	if w := h.post(exportPath, `{"mode":"full"}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "step_up_required") {
		t.Errorf("stale evidence: %d %s", w.Code, w.Body.String())
	}
	h.mustNoChange("denied exports", before)
	h.refresh()
	if w := h.post(exportPath, `{"mode":"clean"}`); w.Code != http.StatusOK {
		t.Fatalf("fresh export: %d %s", w.Code, w.Body.String())
	}
}

func TestAnExportIsAnAttachmentAndNeverCarriesCredentialMaterialInTheClear(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.agentOwnedBy("bot", "u")
	activeBefore := h.scalar(`SELECT count(*) FROM sessions WHERE state='active'`)
	for _, mode := range []string{"full", "clean"} {
		w := h.post(exportPath, `{"mode":"`+mode+`"}`)
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Backup-Mode") != mode {
			t.Fatalf("%s export: %d %v", mode, w.Code, w.Header())
		}
		var a map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil || a["format"] != backup.Format {
			t.Fatalf("archive: %v", err)
		}
		raw := h.rawStore()
		_ = raw
		for _, forbidden := range []string{"secret_hash", "token_hash", "verifier", "password_hash"} {
			if bytes.Contains(w.Body.Bytes(), []byte(forbidden)) {
				t.Fatalf("%s archive names %q", mode, forbidden)
			}
		}
	}
	if h.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != activeBefore || activeBefore == 0 {
		t.Fatal("an export must not touch sessions")
	}
}

// RESTORE-06/08: restore is a protected operation; validation failures and denials change nothing and never quarantine.
func TestRestoreRefusalsChangeNothingAndNeverEnterQuarantine(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	archive := h.exportArchive("full")
	before := h.snapshot()
	control := h.scalar(`SELECT restore_quarantined*1000+restore_generation*100+authority_generation FROM installation_control`)

	tampered := bytes.Replace(archive, []byte(`"mode":"full"`), []byte(`"mode":"clean"`), 1)
	cases := map[string]struct {
		body string
		code int
		err  string
	}{
		"no confirmation":    {restoreBody(archive, "", false), http.StatusBadRequest, "invalid_request"},
		"wrong confirmation": {restoreBody(archive, "restore", false), http.StatusBadRequest, "invalid_request"},
		"no archive":         {`{"confirm":"RESTORE"}`, http.StatusBadRequest, "invalid_request"},
		"unknown field":      {`{"archive":` + string(archive) + `,"confirm":"RESTORE","state":"active"}`, http.StatusBadRequest, "invalid_request"},
		"tampered archive":   {restoreBody(tampered, "RESTORE", false), http.StatusUnprocessableEntity, "archive_malformed"},
		"garbage archive":    {restoreBody([]byte(`{"format":"x"}`), "RESTORE", false), http.StatusUnprocessableEntity, ""},
		"array archive":      {restoreBody([]byte(`[1]`), "RESTORE", false), http.StatusUnprocessableEntity, "archive_malformed"},
	}
	for name, c := range cases {
		w := h.post(restorePath, c.body)
		if w.Code != c.code || (c.err != "" && !strings.Contains(w.Body.String(), c.err)) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "installation_state") {
			t.Errorf("%s: a refusal before the transition must not report quarantine", name)
		}
	}
	// Stale evidence and a non-administrator are refused before the archive is even parsed.
	h.exec(`UPDATE administrative_roles SET state='disabled' WHERE id='adm'`)
	if w := h.post(restorePath, restoreBody(archive, "RESTORE", false)); w.Code != http.StatusForbidden {
		t.Errorf("ordinary user: %d", w.Code)
	}
	h.exec(`UPDATE administrative_roles SET state='active' WHERE id='adm'`)
	h.clock.Advance(DefaultStepUpWindow + time.Second)
	if w := h.post(restorePath, restoreBody(archive, "RESTORE", false)); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "step_up_required") {
		t.Errorf("stale evidence: %d %s", w.Code, w.Body.String())
	}
	h.mustNoChange("refused restores", before)
	if got := h.scalar(`SELECT restore_quarantined*1000+restore_generation*100+authority_generation FROM installation_control`); got != control {
		t.Fatalf("control state changed by a refused restore: %d -> %d", control, got)
	}
}

func TestRestoreBodyBoundIsRaisedOnlyForTheRestoreRoute(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	big := `{"mode":"full","pad":"` + strings.Repeat("a", 70<<10) + `"}`
	if w := h.post(exportPath, big); w.Code < 400 {
		t.Fatalf("export accepted an oversize body: %d", w.Code)
	}
	over := `{"archive":{"pad":"` + strings.Repeat("a", restoreBodyBytes) + `"},"confirm":"RESTORE"}`
	w := h.post(restorePath, over)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("restore accepted a body beyond the archive bound: %d", w.Code)
	}
	if h.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 {
		t.Fatal("an oversize body entered quarantine")
	}
	b := NewBrowser(h.s)
	for name, p := range map[string]RoutePolicy{
		"raise on a read":       {Require: RequireSession, MaxBody: 1 << 20},
		"raise below the floor": {Require: RequireSession, MaxBody: 10},
		"raise above the cap":   {Require: RequireSession, MaxBody: maxRouteBodyBytes + 1},
		"raise without session": {Require: RequireNone, MaxBody: 1 << 20},
	} {
		method := "POST /x/" + strings.ReplaceAll(name, " ", "-")
		if strings.HasPrefix(name, "raise on a read") {
			method = "GET /x/read"
		}
		if err := b.Handle(method, p, http.NotFoundHandler()); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// RESTORE-02/05/09: a restore signs out everyone including the initiator, rotates every generation and
// leaves nothing effective; the old cookie never works again.
func TestAdministratorRestoreEndsEverySessionAndLeavesOnlyInactiveRecords(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.agentOwnedBy("bot", "u")
	archive := h.exportArchive("full")
	notified := h.notifications()
	genBefore := h.scalar(`SELECT authority_generation FROM installation_control`)

	w := h.post(restorePath, restoreBody(archive, "RESTORE", false))
	if w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Report struct {
			State, NextStep   string
			RestoreGeneration int64 `json:"restore_generation"`
		} `json:"report"`
		Notified     bool `json:"authorizer_notified"`
		SessionEnded bool `json:"session_ended"`
	}
	decodeJSON(t, w, &out)
	if !out.SessionEnded || !out.Notified || h.notifications() != notified+1 {
		t.Fatalf("response %+v notifications %d->%d", out, notified, h.notifications())
	}
	if h.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 || h.scalar(`SELECT authority_generation FROM installation_control`) != genBefore+1 {
		t.Fatal("quarantine or generation")
	}
	if h.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 {
		t.Fatal("a session survived the restore")
	}
	for _, q := range []string{`SELECT count(*) FROM users WHERE state='active'`, `SELECT count(*) FROM agents WHERE state='active'`, `SELECT count(*) FROM administrative_roles WHERE state='active'`,
		`SELECT count(*) FROM agent_credentials WHERE state='active'`, `SELECT count(*) FROM authenticators WHERE state='active'`} {
		if h.scalar(q) != 0 {
			t.Fatalf("effective record after restore: %s", q)
		}
	}
	// The initiator's own cookie is dead for every route class, including a re-submission of the restore.
	for _, q := range []adminReq{{method: http.MethodGet, path: manifestPath}, {method: http.MethodGet, path: adminBase + "/users"},
		{method: http.MethodPost, path: restorePath, body: restoreBody(archive, "RESTORE", false)}, {method: http.MethodPost, path: exportPath, body: `{"mode":"full"}`}} {
		if r := h.do(q); r.Code != http.StatusUnauthorized && r.Code != http.StatusForbidden {
			t.Errorf("%s %s after restore: %d", q.method, q.path, r.Code)
		}
	}
	if h.scalar(`SELECT restore_generation FROM installation_control`) != out.Report.RestoreGeneration {
		t.Fatal("a replayed restore advanced the generation")
	}
}

// A failure after the transition still reports quarantine so the interface cannot say "nothing happened".
func TestAFailedImportAfterTheTransitionReportsQuarantineAndEndsSessions(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.group("ops")
	archive := h.exportArchive("full")
	for _, ev := range []string{"INSERT", "UPDATE"} { // whichever way the import reaches a group row, SQLite itself fails it
		h.exec(`CREATE TRIGGER fail_group_` + strings.ToLower(ev) + ` BEFORE ` + ev + ` ON groups BEGIN SELECT RAISE(ABORT,'synthetic constraint failure'); END`)
	}
	w := h.post(restorePath, restoreBody(archive, "RESTORE", false))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"installation_state":"restore_quarantine"`) {
		t.Fatalf("failed import: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "synthetic") {
		t.Fatal("the failure text was reflected")
	}
	if h.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 || h.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 || h.scalar(`SELECT count(*) FROM restore_reports`) != 0 {
		t.Fatal("a failed import must leave quarantine, no session and no report")
	}
}

// afterRecoveryCeremony models the HOST-authorized recovery that ends quarantine (a later card owns the
// ceremony itself; no web route can do this): the administrator account, its role and its factors are
// made effective again at the current generations and a fresh AAL2 session exists.
func (h *adminHTTP) afterRecoveryCeremony() {
	h.t.Helper()
	g := h.scalar(`SELECT authority_generation FROM installation_control`)
	c := h.scalar(`SELECT credential_generation FROM installation_control`)
	s := h.scalar(`SELECT session_generation FROM installation_control`)
	h.exec(`UPDATE installation_control SET restore_quarantined=0`)
	h.exec(`UPDATE users SET state='active',credential_generation=?,authority_generation=? WHERE id='u'`, c, g)
	h.exec(`UPDATE administrative_roles SET state='active',authority_generation=? WHERE id='adm'`, g)
	h.exec(`UPDATE authenticators SET state='active',credential_generation=? WHERE user_id='u'`, c)
	h.exec(`UPDATE sessions SET state='active',revoked_at=NULL,credential_generation=?,session_generation=? WHERE id=?`, c, s, h.sessID)
	h.refresh()
}

func TestRestoredRecordsStayInactiveUntilNamedAndApprovedAfterTheRecoveryCeremony(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	alice := h.person("alice")
	group := h.group("ops")
	archive := h.exportArchive("full")
	if w := h.do(adminReq{method: http.MethodGet, path: manifestPath}); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "no_restore") {
		t.Fatalf("manifest before a restore: %d %s", w.Code, w.Body.String())
	}
	if w := h.post(restorePath, restoreBody(archive, "RESTORE", false)); w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	// Quarantined: even the genuine administrator cookie cannot read the manifest or approve anything.
	before := h.snapshot()
	for _, q := range []adminReq{{method: http.MethodGet, path: manifestPath}, {method: http.MethodPost, path: approvePath, body: `{"items":[{"kind":"user","id":"` + alice + `"}]}`}} {
		if w := h.do(q); w.Code < 400 {
			t.Fatalf("%s %s while quarantined: %d", q.method, q.path, w.Code)
		}
	}
	h.mustNoChange("quarantined approval", before)

	h.afterRecoveryCeremony()
	w := h.do(adminReq{method: http.MethodGet, path: manifestPath})
	if w.Code != http.StatusOK {
		t.Fatalf("manifest: %d %s", w.Code, w.Body.String())
	}
	var m backup.ManifestView
	decodeJSON(t, w, &m)
	if m.Pending == 0 || m.Approved != 0 {
		t.Fatalf("manifest %+v", m)
	}
	for _, forbidden := range []string{"verifier", "token_hash", "secret", "ciphertext", "example.invalid"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("manifest response mentions %q", forbidden)
		}
	}
	// Nothing was approved by the ceremony: alice and the group are still inactive.
	if h.scalar(`SELECT count(*) FROM users WHERE id=? AND state='active'`, alice) != 0 || h.scalar(`SELECT count(*) FROM groups WHERE id=? AND state='active'`, group) != 0 {
		t.Fatal("restored records are effective before approval")
	}
	// Approval needs fresh AAL2 like any other security-policy change.
	h.clock.Advance(DefaultStepUpWindow + time.Second)
	before = h.snapshot()
	if r := h.post(approvePath, `{"items":[{"kind":"user","id":"`+alice+`"}]}`); r.Code != http.StatusForbidden || !strings.Contains(r.Body.String(), "step_up_required") {
		t.Fatalf("stale approval: %d %s", r.Code, r.Body.String())
	}
	h.mustNoChange("stale approval", before)
	h.refresh()
	notified := h.notifications()
	// Naming a record whose prerequisites are not approved, or one this phase cannot approve, changes nothing.
	r := h.post(approvePath, `{"items":[{"kind":"user","id":"`+alice+`"},{"kind":"role","id":"adm"}]}`)
	if r.Code != http.StatusConflict || !strings.Contains(r.Body.String(), "single_administrator") {
		t.Fatalf("partial approval: %d %s", r.Code, r.Body.String())
	}
	if h.scalar(`SELECT count(*) FROM users WHERE id=? AND state='active'`, alice) != 0 || h.notifications() != notified {
		t.Fatal("a refused approval changed state or notified")
	}
	for name, body := range map[string]string{"empty": `{"items":[]}`, "state field": `{"items":[{"kind":"user","id":"` + alice + `","state":"active"}]}`, "unknown kind": `{"items":[{"kind":"credential","id":"x"}]}`, "all": `{"all":true}`} {
		if r := h.post(approvePath, body); r.Code != http.StatusBadRequest && r.Code != http.StatusConflict {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	// The named, approvable records become effective, and the shared authorizer is told once.
	r = h.post(approvePath, `{"items":[{"kind":"user","id":"`+alice+`"},{"kind":"group","id":"`+group+`"}]}`)
	if r.Code != http.StatusOK || h.notifications() != notified+1 {
		t.Fatalf("approval: %d %s (notifications %d)", r.Code, r.Body.String(), h.notifications()-notified)
	}
	if h.scalar(`SELECT count(*) FROM users WHERE id=? AND state='active'`, alice) != 1 || h.scalar(`SELECT count(*) FROM groups WHERE id=? AND state='active'`, group) != 1 {
		t.Fatal("approved records are not effective")
	}
	// Approval is not credential reissuance: no token or factor became usable.
	if h.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`) != 0 {
		t.Fatal("an approval revived a credential")
	}
}
