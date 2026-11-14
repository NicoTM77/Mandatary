package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The canaries are synthetic values placed in credential columns. None may ever be readable in an archive.
var canaries = []string{"synthetic-verifier-do-not-leak-0001", string(seedBytes)}

func canaryEncodings() []string {
	var out []string
	for _, c := range canaries {
		out = append(out, c, base64.StdEncoding.EncodeToString([]byte(c)), base64.RawURLEncoding.EncodeToString([]byte(c)))
	}
	hash := bytes.Repeat([]byte{0xAB}, 32)
	return append(out, base64.StdEncoding.EncodeToString(hash), base64.RawURLEncoding.EncodeToString(hash))
}

func TestExportCarriesTheDocumentedScopeAndNoSecretOrSession(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull)
	for _, c := range canaryEncodings() {
		if contains(raw, c) {
			t.Fatalf("archive contains credential material in the clear (%d bytes of canary)", len(c))
		}
	}
	var a Archive
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if a.Format != Format || a.SchemaVersion != 1 || a.Mode != ModeFull || a.Secrets == nil || a.IntegrityHMAC == "" || a.ContentDigest == "" || a.BackupID == "" {
		t.Fatalf("header %+v", a)
	}
	sc := a.Scope
	if len(sc.Users) != 2 || len(sc.Groups) != 1 || len(sc.Agents) != 1 || len(sc.Policies) != 2 || len(sc.Roles) != 1 || len(sc.Selectors) != 2 ||
		len(sc.Endpoints) != 1 || len(sc.Addresses) != 1 || len(sc.Authenticators) != 2 || len(sc.AgentCredentials) != 1 {
		t.Fatalf("scope %+v", sc)
	}
	// Excluded by scope: no session, usage, setup or control value is readable in the archive.
	for _, forbidden := range []string{"sess-1", "usage", "installation_control", "restore_quarantined", "credential_generation", "authority_generation", "session_generation", "setup_", "rate_limit"} {
		if contains(raw, forbidden) {
			t.Fatalf("archive mentions %q", forbidden)
		}
	}
	// The cleartext scope carries the original expiry of a token and nothing that could mint one.
	if c := sc.AgentCredentials[0]; c.IssuedAt != 1999999000 || c.ExpiresAt == nil || *c.ExpiresAt != 2000999999 {
		t.Fatalf("credential timing not preserved: %+v", c)
	}
}

func TestCleanExportStripsCredentialsAtTheSource(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeClean)
	var a Archive
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if a.Mode != ModeClean || a.Secrets != nil || len(a.Scope.Authenticators) != 0 || len(a.Scope.AgentCredentials) != 0 || len(a.Scope.Users) != 2 {
		t.Fatalf("clean archive %+v", a)
	}
	for _, c := range canaryEncodings() {
		if contains(raw, c) {
			t.Fatal("clean archive carries credential material")
		}
	}
}

func TestExportIsRefusedWithoutAnInSnapshotAuthorization(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	if _, _, err := e.svc.Export(t.Context(), ModeFull, refuse); !errors.Is(err, ErrDenied) {
		t.Fatalf("refusing authorizer: %v", err)
	}
	if _, _, err := e.svc.Export(t.Context(), ModeFull, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("nil authorizer must deny, got %v", err)
	}
	if _, _, err := e.svc.Export(t.Context(), Mode("bogus"), allow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad mode: %v", err)
	}
}

func TestAnUntouchedArchiveVerifiesAndClaimsOnlyProvenance(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	v := e.verify(e.export(ModeFull))
	if v.Provenance() != ProvenanceAuthenticated || v.Mode() != ModeFull || v.BackupID() == "" {
		t.Fatalf("verified %v %v", v.Provenance(), v.Mode())
	}
	// Verification is pure: it has changed nothing and quarantined nothing.
	if c := e.controls(); c.RestoreQuarantined != 0 || c.RestoreGeneration != 1 {
		t.Fatalf("verify changed controls: %+v", c)
	}
}

// RESTORE-06: version, HMAC, envelope and structural tamper. Each rejected archive commits nothing
// and never enters quarantine (the transition happens only after a successful verification).
func TestTamperedArchivesAreRejectedBeforeAnyStateChange(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	full := e.export(ModeFull)
	clean := e.export(ModeClean)
	before := e.snapshot()
	beforeControl := e.controls()

	flipByte := func(raw []byte, marker string) []byte {
		i := bytes.Index(raw, []byte(marker))
		if i < 0 {
			t.Fatalf("marker %q missing", marker)
		}
		out := append([]byte(nil), raw...)
		out[i+len(marker)/2] ^= 0x01
		return out
	}
	sealedCT := func(raw []byte) string {
		var a Archive
		_ = json.Unmarshal(raw, &a)
		return a.Secrets.Ciphertext[:24]
	}
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"a username changed", mutate(t, full, func(m map[string]any) { recordsOf(m, "users")[1].(map[string]any)["username"] = "mallory" }), ErrIntegrity},
		{"a policy effect flipped from DENY to ALLOW", mutate(t, full, func(m map[string]any) {
			for _, p := range recordsOf(m, "policies") {
				if p.(map[string]any)["effect"] == "DENY" {
					p.(map[string]any)["effect"] = "ALLOW"
				}
			}
		}), ErrIntegrity},
		{"a record removed", mutate(t, full, func(m map[string]any) { m["scope"].(map[string]any)["policies"] = recordsOf(m, "policies")[:1] }), ErrIntegrity},
		{"a record added", mutate(t, full, func(m map[string]any) {
			m["scope"].(map[string]any)["groups"] = append(recordsOf(m, "groups"), map[string]any{"id": "evil", "name": "evil", "source_state": "active"})
		}), ErrIntegrity},
		{"backup id changed", mutate(t, full, func(m map[string]any) { m["backup_id"] = "another-backup" }), ErrIntegrity},
		{"created_at changed", mutate(t, full, func(m map[string]any) { m["created_at"] = "2001-01-01T00:00:00Z" }), ErrIntegrity},
		{"mode changed full to clean", mutate(t, full, func(m map[string]any) { m["mode"] = "clean" }), ErrMalformed},
		{"clean archive given a secrets block", mutate(t, clean, func(m map[string]any) {
			m["secrets"] = map[string]any{"salt": "AA==", "nonce": "AA==", "ciphertext": "AA=="}
		}), ErrMalformed},
		{"envelope ciphertext byte flipped", flipByte(full, sealedCT(full)), ErrIntegrity},
		{"envelope removed from a full archive", mutate(t, full, func(m map[string]any) { m["secrets"] = nil }), ErrMalformed},
		{"integrity tag replaced", mutate(t, full, func(m map[string]any) {
			m["integrity_hmac"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		}), ErrIntegrity},
		{"content digest replaced", mutate(t, full, func(m map[string]any) {
			m["content_digest"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
		}), ErrIntegrity},
		{"tag and digest removed", mutate(t, full, func(m map[string]any) { m["integrity_hmac"], m["content_digest"] = "", "" }), ErrIntegrity},
		{"hmac salt changed", mutate(t, full, func(m map[string]any) {
			m["hmac_salt"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		}), ErrIntegrity},
		{"hmac salt of the wrong size", mutate(t, full, func(m map[string]any) { m["hmac_salt"] = "AAAA" }), ErrMalformed},
		{"unknown schema version", mutate(t, full, func(m map[string]any) { m["schema_version"] = 2 }), ErrUnsupportedVersion},
		{"unknown database schema", mutate(t, full, func(m map[string]any) { m["database_schema_version"] = 12 }), ErrUnsupportedVersion},
		{"wrong format name", mutate(t, full, func(m map[string]any) { m["format"] = "something-else" }), ErrUnsupportedVersion},
		{"unknown header field", mutate(t, full, func(m map[string]any) { m["restore_quarantined"] = 0 }), ErrMalformed},
		{"truncated document", full[:len(full)/2], ErrMalformed},
		{"trailing data", append(append([]byte(nil), full...), []byte(`{"x":1}`)...), ErrMalformed},
		{"not an object", []byte(`[1,2,3]`), ErrMalformed},
		{"empty", nil, ErrMalformed},
		{"oversize", bytes.Repeat([]byte(" "), MaxArchiveBytes+1), ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.svc.Verify(c.raw)
			if !errors.Is(err, c.want) {
				t.Fatalf("Verify = %v, want %v", err, c.want)
			}
			if _, err = e.svc.Restore(t.Context(), nil, RestoreOptions{Initiator: InitiatorHost, Authorize: allow}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("restore without a verified archive: %v", err)
			}
		})
	}
	e.sameExceptControl(before)
	if e.controls() != beforeControl {
		t.Fatal("a rejected archive changed the control state")
	}
}

// RESTORE-06: the wrong key and a modified archive are the same fixed answer for a full archive.
func TestAFullArchiveCannotBeVerifiedUnderAnotherKey(t *testing.T) {
	a := newEnv(t, keyHexA)
	a.seed()
	raw := a.export(ModeFull)
	b := newEnv(t, keyHexB)
	if _, err := b.svc.Verify(raw); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong key: %v", err)
	}
	same := newEnv(t, keyHexA) // a DIFFERENT installation holding the SAME key verifies it
	if v := same.verify(raw); v.Provenance() != ProvenanceAuthenticated {
		t.Fatal("same key, fresh installation must verify")
	}
}

// A clean archive moves between keys; the tag cannot be checked, so the provenance is reported as
// unauthenticated and restoring it needs an explicit acknowledgement. It is never silently trusted.
func TestACleanArchiveFromAnotherKeyIsUnauthenticatedAndNeedsAcknowledgement(t *testing.T) {
	a := newEnv(t, keyHexA)
	a.seed()
	raw := a.export(ModeClean)
	b := newEnv(t, keyHexB)
	v := b.verify(raw)
	if v.Provenance() != ProvenanceUnauthenticated {
		t.Fatalf("provenance %v", v.Provenance())
	}
	before := b.snapshot()
	beforeControl := b.controls()
	if _, err := b.svc.Restore(t.Context(), v, RestoreOptions{Initiator: InitiatorHost, Authorize: allow}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("restore without acknowledgement: %v", err)
	}
	b.sameExceptControl(before)
	if b.controls() != beforeControl {
		t.Fatal("an unacknowledged restore changed the control state")
	}
	// The digest still catches corruption of an unauthenticated archive.
	corrupt := mutate(t, raw, func(m map[string]any) { recordsOf(m, "users")[0].(map[string]any)["username"] = "x" })
	if _, err := b.svc.Verify(corrupt); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corrupt clean archive: %v", err)
	}
}

// An attacker who holds the master key can produce an AUTHENTIC archive. Authenticity is not
// consistency and not authority: structurally impossible content is still refused.
func TestAnAuthenticSignedArchiveStillHasToBeConsistent(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull)
	for name, f := range map[string]func(a *Archive){
		"a policy naming an unknown agent": func(a *Archive) {
			id := "ghost"
			a.Scope.Policies[0].AgentID, a.Scope.Policies[0].UserID, a.Scope.Policies[0].GroupID = &id, nil, nil
		},
		"a policy with two subjects":         func(a *Archive) { u := "alice"; a.Scope.Policies[0].UserID = &u },
		"a membership of an unknown group":   func(a *Archive) { a.Scope.UserMemberships[0].GroupID = "ghost" },
		"an agent without an owner":          func(a *Archive) { a.Scope.Agents[0].OwnerUserID = nil },
		"duplicate user ids":                 func(a *Archive) { a.Scope.Users[1].ID = a.Scope.Users[0].ID },
		"duplicate usernames":                func(a *Archive) { a.Scope.Users[1].Username = a.Scope.Users[0].Username },
		"an operation outside the catalogue": func(a *Archive) { a.Scope.Policies[0].Operation = "container:exec" },
		"an unknown effect":                  func(a *Archive) { a.Scope.Policies[0].Effect = "PERMIT" },
		"a selector on another endpoint":     func(a *Archive) { a.Scope.Selectors[0].EndpointID = "00000000-0000-4000-8000-0000000000ff" },
		"no endpoint":                        func(a *Archive) { a.Scope.Endpoints = nil },
		"a remote endpoint":                  func(a *Archive) { a.Scope.Endpoints[0].Slug, a.Scope.Endpoints[0].Transport = "remote", "mtls" },
		"a token that expires before issue":  func(a *Archive) { v := int64(1); a.Scope.AgentCredentials[0].ExpiresAt = &v },
		"an address with a line break":       func(a *Archive) { a.Scope.Addresses[0].Address = "a@example.invalid\r\nBcc: x" },
		"an unknown MFA requirement":         func(a *Archive) { a.Scope.Users[0].MFARequirement = "none" },
		"a credential with no sealed record": func(a *Archive) { a.Scope.AgentCredentials[0].ID = "cred-unsealed" },
		"a credential of an unknown agent":   func(a *Archive) { a.Scope.AgentCredentials[0].AgentID = "ghost" },
		"a second super administrator role":  func(a *Archive) { a.Scope.Roles[0].Role = "root" },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.svc.Verify(e.sign(raw, f))
			if !errors.Is(err, ErrConsistency) {
				t.Fatalf("Verify = %v, want a consistency refusal", err)
			}
		})
	}
	// Control: re-signing without changes verifies (the helper itself is not the cause).
	if _, err := e.svc.Verify(e.sign(raw, func(*Archive) {})); err != nil {
		t.Fatalf("control re-sign: %v", err)
	}
}

// RESTORE-11: an archive has no field for a state, a generation, a quarantine flag or any recovery
// control. A signed archive that tries to carry one is malformed, never partially honoured.
func TestNoLocalControlOrStateFieldCanBeSmuggledIn(t *testing.T) {
	e := newEnv(t, keyHexA)
	e.seed()
	raw := e.export(ModeFull)
	for name, f := range map[string]func(m map[string]any){
		"control block": func(m map[string]any) {
			m["installation_control"] = map[string]any{"restore_quarantined": 0, "credential_generation": 99}
		},
		"quarantine flag":         func(m map[string]any) { m["restore_quarantined"] = false },
		"record state":            func(m map[string]any) { recordsOf(m, "users")[0].(map[string]any)["state"] = "active" },
		"record generation":       func(m map[string]any) { recordsOf(m, "policies")[0].(map[string]any)["authority_generation"] = 99 },
		"credential generation":   func(m map[string]any) { recordsOf(m, "agents")[0].(map[string]any)["credential_generation"] = 99 },
		"recovery control":        func(m map[string]any) { m["scope"].(map[string]any)["setup_tokens"] = []any{} },
		"session list":            func(m map[string]any) { m["scope"].(map[string]any)["sessions"] = []any{} },
		"usage block":             func(m map[string]any) { m["scope"].(map[string]any)["usage"] = []any{} },
		"a record nested control": func(m map[string]any) { recordsOf(m, "groups")[0].(map[string]any)["restore_generation"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			// Re-sign over the DECODED form is impossible (the unknown field does not decode), so the
			// attacker's best case is a correct tag over the changed text; the strict decoder still refuses.
			modified := mutate(t, raw, f)
			if _, err := e.svc.Verify(modified); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Verify = %v, want malformed", err)
			}
		})
	}
}

// The archive types are the whole importable surface. This walks them and fails if a field named for
// a state, a generation, a quarantine or a control value ever appears (source_state is the one
// informational exception: it is displayed to a reviewer and never read to decide a state).
func TestArchiveTypesCannotNameLocalControlState(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type, path string)
	var found []string
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			for _, bad := range []string{"generation", "quarantine", "control", "installation", "session", "recovery", "setup", "master_key", "key_check"} {
				if strings.Contains(tag, bad) {
					found = append(found, path+"."+tag)
				}
			}
			if tag == "state" || tag == "decision" {
				found = append(found, path+"."+tag)
			}
			walk(f.Type, path+"."+tag)
		}
	}
	walk(reflect.TypeOf(Archive{}), "archive")
	walk(reflect.TypeOf(secretPayload{}), "secrets")
	if len(found) > 0 {
		t.Fatalf("archive surface names control/state fields: %v", found)
	}
}
