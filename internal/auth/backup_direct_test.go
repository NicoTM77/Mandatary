package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// P1.18.3 direct-request evidence for the four P1.18 routes: the cases a browser form never sends, driven straight at the real
// Browser boundary and the real services over a real SQLite installation. Whatever the interface does or does not offer, a
// crafted request is refused by the server and changes nothing.

// jsonPatch re-encodes an archive after the caller's edit, so a tamper case changes exactly one decoded field.
func jsonPatch(t *testing.T, archive []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(archive, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func controlFingerprint(h *adminHTTP) int64 {
	return h.scalar(`SELECT restore_quarantined*100000+restore_generation*1000+authority_generation*100+credential_generation*10+session_generation FROM installation_control`)
}

// RESTORE-06 (unauthorized initiators cannot trigger quarantine): every violation of the browser boundary on the restore, approval and
// manifest routes is refused before any handler or service runs.
func TestRestoreApprovalAndManifestRoutesRefuseEveryBoundaryViolation(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	archive := h.exportArchive("full")
	before := h.snapshot()
	control := controlFingerprint(h)
	empty, wrong := "", wrongCSRF(h.csrf)
	restore := restoreBody(archive, "RESTORE", false)
	approve := `{"items":[{"kind":"user","id":"u"}]}`
	for route, body := range map[string]string{restorePath: restore, approvePath: approve} {
		for name, q := range map[string]adminReq{
			"no cookie":           {method: http.MethodPost, path: route, body: body, cookie: &empty},
			"forged cookie":       {method: http.MethodPost, path: route, body: body, cookie: &wrong},
			"no csrf":             {method: http.MethodPost, path: route, body: body, csrf: &empty},
			"wrong csrf":          {method: http.MethodPost, path: route, body: body, csrf: &wrong},
			"foreign origin":      {method: http.MethodPost, path: route, body: body, origin: "https://evil.invalid"},
			"null origin":         {method: http.MethodPost, path: route, body: body, origin: "null"},
			"form content type":   {method: http.MethodPost, path: route, body: body, contentType: "application/x-www-form-urlencoded"},
			"text content type":   {method: http.MethodPost, path: route, body: body, contentType: "text/plain"},
			"no content type":     {method: http.MethodPost, path: route, body: body, contentType: "none"},
			"authorization alone": {method: http.MethodPost, path: route, body: body, cookie: &empty, headers: map[string][]string{"Authorization": {"Bearer not-a-session"}}},
		} {
			if w := h.do(q); w.Code < 400 || w.Code >= 500 {
				t.Errorf("%s %s: %d %s", route, name, w.Code, w.Body.String())
			}
		}
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			if w := h.do(adminReq{method: method, path: route}); w.Code < 400 || w.Code >= 500 {
				t.Errorf("%s %s: %d", method, route, w.Code)
			}
		}
	}
	// The manifest is a session read: it needs the cookie and never accepts a state-changing verb.
	if w := h.do(adminReq{method: http.MethodGet, path: manifestPath, cookie: &empty}); w.Code != http.StatusUnauthorized {
		t.Errorf("manifest without a session: %d", w.Code)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if w := h.do(adminReq{method: method, path: manifestPath, body: `{}`}); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s manifest: %d", method, w.Code)
		}
	}
	h.mustNoChange("boundary violations", before)
	if controlFingerprint(h) != control {
		t.Fatal("a refused request touched the control state")
	}
	if h.scalar(`SELECT count(*) FROM restore_reports`) != 0 {
		t.Fatal("a refused request produced a restore report")
	}
}

// RESTORE-06: version, integrity tag and sealed-envelope tamper over the real route. Every one is a fixed 422 class,
// reflects nothing, leaves the administrator signed in and never enters quarantine.
func TestTamperedAndMisversionedArchivesAreRefusedOverHTTPWithoutQuarantine(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.agentOwnedBy("bot", "u")
	full := h.exportArchive("full")
	before := h.snapshot()
	control := controlFingerprint(h)
	flipFirst := func(s string) string {
		b := []byte(s)
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		return string(b)
	}
	cases := map[string]struct {
		archive []byte
		want    string
	}{
		"integrity tag flipped":  {jsonPatch(t, full, func(m map[string]any) { m["integrity_hmac"] = flipFirst(m["integrity_hmac"].(string)) }), "archive_integrity_failed"},
		"content digest flipped": {jsonPatch(t, full, func(m map[string]any) { m["content_digest"] = flipFirst(m["content_digest"].(string)) }), "archive_integrity_failed"},
		"sealed envelope flipped": {jsonPatch(t, full, func(m map[string]any) {
			s := m["secrets"].(map[string]any)
			s["ciphertext"] = flipFirst(s["ciphertext"].(string))
		}), "archive_integrity_failed"},
		"a user renamed": {jsonPatch(t, full, func(m map[string]any) {
			m["scope"].(map[string]any)["users"].([]any)[0].(map[string]any)["username"] = "mallory"
		}), "archive_integrity_failed"},
		"mode relabelled":                {jsonPatch(t, full, func(m map[string]any) { m["mode"] = "clean" }), ""},
		"schema version from the future": {jsonPatch(t, full, func(m map[string]any) { m["schema_version"] = 2 }), "archive_unsupported_version"},
		"a different format":             {jsonPatch(t, full, func(m map[string]any) { m["format"] = "other" }), ""},
		"a state field smuggled in":      {jsonPatch(t, full, func(m map[string]any) { m["restore_quarantined"] = 0 }), "archive_malformed"},
		"not an object":                  {[]byte(`"RESTORE"`), "archive_malformed"},
		"an empty object":                {[]byte(`{}`), ""},
		"trailing data":                  {append(append([]byte(nil), full...), []byte(` {"x":1}`)...), "invalid_request"},
	}
	for name, c := range cases {
		w := h.post(restorePath, restoreBody(c.archive, "RESTORE", false))
		if w.Code != http.StatusUnprocessableEntity && w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
			continue
		}
		if c.want != "" && !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: want %s, got %d %s", name, c.want, w.Code, w.Body.String())
		}
		for _, leak := range []string{"installation_state", "mallory", "hmac", "digest", "ciphertext"} {
			if strings.Contains(w.Body.String(), leak) {
				t.Errorf("%s: the refusal mentions %q", name, leak)
			}
		}
	}
	h.mustNoChange("tampered archives", before)
	if controlFingerprint(h) != control {
		t.Fatal("a rejected archive changed the control state")
	}
	// The administrator is still signed in and can still use the installation: a rejected archive ends nothing.
	if w := h.do(adminReq{method: http.MethodGet, path: adminBase + "/users"}); w.Code != http.StatusOK {
		t.Fatalf("the administrator was signed out by a rejected archive: %d", w.Code)
	}
	if w := h.post(exportPath, `{"mode":"clean"}`); w.Code != http.StatusOK {
		t.Fatalf("export after a rejected archive: %d", w.Code)
	}
}

// RESTORE-06/09: a clean backup whose tag this installation cannot verify is restorable only after the explicit
// acknowledgement, and the report says its origin was not verified. Nothing is applied by the first, unacknowledged request.
func TestAnUnverifiableCleanArchiveNeedsTheAcknowledgementOverHTTPAndIsReportedAsUnverified(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.person("alice")
	clean := h.exportArchive("clean")
	// A clean archive carries no credential, so a tag this key cannot verify leaves only its content digest: unauthenticated provenance.
	foreign := jsonPatch(t, clean, func(m map[string]any) { m["integrity_hmac"] = strings.Repeat("A", len(m["integrity_hmac"].(string))) })
	before := h.snapshot()
	control := controlFingerprint(h)
	w := h.post(restorePath, restoreBody(foreign, "RESTORE", false))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "provenance_unverified") || strings.Contains(w.Body.String(), "installation_state") {
		t.Fatalf("unacknowledged: %d %s", w.Code, w.Body.String())
	}
	h.mustNoChange("unacknowledged restore", before)
	if controlFingerprint(h) != control || h.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) == 0 {
		t.Fatal("an unacknowledged restore changed the control state or ended the session")
	}
	// A corrupted content digest is still caught on an unauthenticated archive, acknowledged or not.
	corrupt := jsonPatch(t, foreign, func(m map[string]any) {
		m["scope"].(map[string]any)["users"].([]any)[0].(map[string]any)["username"] = "x"
	})
	if w := h.post(restorePath, restoreBody(corrupt, "RESTORE", true)); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "archive_integrity_failed") {
		t.Fatalf("corrupt unauthenticated archive: %d %s", w.Code, w.Body.String())
	}
	if h.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 {
		t.Fatal("a rejected archive entered quarantine")
	}
	w = h.post(restorePath, restoreBody(foreign, "RESTORE", true))
	if w.Code != http.StatusOK {
		t.Fatalf("acknowledged restore: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Report struct {
			Mode                string   `json:"mode"`
			Provenance          string   `json:"provenance"`
			CredentialsStripped bool     `json:"credentials_stripped"`
			Excluded            []string `json:"excluded"`
		} `json:"report"`
	}
	decodeJSON(t, w, &out)
	if out.Report.Provenance != "unauthenticated" || out.Report.Mode != "clean" || !out.Report.CredentialsStripped {
		t.Fatalf("report %+v", out.Report)
	}
	// RESTORE-10: the report names what a restore neither reads nor writes, usage statistics and sessions among them.
	joined := strings.Join(out.Report.Excluded, ",")
	for _, want := range []string{"usage_statistics", "sessions", "control_generations_and_quarantine"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not list %q as out of scope: %s", want, joined)
		}
	}
}

// RESTORE-05: parallel restore requests with the same valid administrator session. Exactly one reaches the import; the others are
// refused by the in-transaction authorization, and the installation ends in one consistent inactive state.
func TestParallelRestoreRequestsOverHTTPLeaveOneConsistentInactiveState(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.person("alice")
	h.group("ops")
	archive := h.exportArchive("full")
	body := restoreBody(archive, "RESTORE", false)
	const callers = 6
	results := make([]*httptest.ResponseRecorder, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = h.do(adminReq{method: http.MethodPost, path: restorePath, body: body})
		}()
	}
	close(start)
	wg.Wait()
	ok := 0
	for i, w := range results {
		switch {
		case w.Code == http.StatusOK:
			ok++
		case w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden || w.Code == http.StatusConflict || w.Code == http.StatusServiceUnavailable:
			// Overtaken: refused by the in-transaction check, superseded, or failed after the transition. Never a success.
		default:
			t.Errorf("request %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if ok != 1 {
		t.Fatalf("%d of %d parallel restores succeeded, want exactly one", ok, callers)
	}
	if h.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("not quarantined")
	}
	if h.scalar(`SELECT count(*) FROM restore_reports`) != 1 {
		t.Fatalf("restore reports: %d", h.scalar(`SELECT count(*) FROM restore_reports`))
	}
	for _, q := range []string{`SELECT count(*) FROM users WHERE state='active'`, `SELECT count(*) FROM groups WHERE state='active'`, `SELECT count(*) FROM agents WHERE state='active'`, `SELECT count(*) FROM policies WHERE state='active'`,
		`SELECT count(*) FROM administrative_roles WHERE state='active'`, `SELECT count(*) FROM sessions WHERE state='active'`} {
		if h.scalar(q) != 0 {
			t.Fatalf("effective authority after parallel restores: %s", q)
		}
	}
	if h.scalar(`SELECT count(*) FROM pragma_foreign_key_check`) != 0 {
		t.Fatal("foreign key violations after parallel restores")
	}
}

// RESTORE-10/11 over HTTP: no export, in either mode, carries a session, a CSRF token, setup or recovery state, notices or the control tables.
func TestNoExportCarriesSessionsOrSetupAndRecoveryState(t *testing.T) {
	t.Parallel()
	h := newBackupHTTP(t)
	h.agentOwnedBy("bot", "u")
	for _, mode := range []string{"full", "clean"} {
		archive := string(h.exportArchive(mode))
		for _, forbidden := range []string{"sessions", "session_authenticators", "csrf", "usage", "setup_generation", "recovery_capability", "security_notice", "rate_limit", "restore_manifest", "installation_control"} {
			if strings.Contains(archive, forbidden) {
				t.Errorf("%s export mentions %q", mode, forbidden)
			}
		}
	}
}
