package auth

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// retireRaw records a retirement exactly as the lifecycle statements do (one
// UPDATE of state, revoked_at and provenance) so a state matrix can name every
// provenance value, including the legacy NULL form old code persisted.
func (e *sessionEnv) retireRaw(id string, reason sql.NullString) {
	e.t.Helper()
	e.exec(`UPDATE authenticators SET state='revoked',revoked_at=?,changed_at=?,retirement_reason=? WHERE id=?`, e.clock.Now().Unix(), e.clock.Now().Unix(), reason, id)
}

// restart closes and reopens the repository and rebuilds every service on it, as
// a process restart would. Nothing is carried in memory.
func (e *sessionEnv) restart() {
	e.t.Helper()
	l := reopenLifecycle(e.t, e.l, e.db)
	w, err := NewWebAuthn(l, WebAuthnSettings{RPID: "example.invalid", Origins: []string{sessionTestOrigin}})
	if err != nil {
		e.t.Fatal(err)
	}
	s, err := NewSessions(l, w, DefaultSessionSettings())
	if err != nil {
		e.t.Fatal(err)
	}
	e.l, e.w, e.s = l, w, s
}

func reason(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// accountOutcome is what each gate does for ONE account state. The assertions
// below are the "session issuance, the sensitive gate and freshSession agree"
// requirement: PasswordLogin, Authenticate, RequireSensitive and the lifecycle
// write all derive from the single shared floor.
type accountOutcome struct {
	login     string // denied | preauth | aal1
	authOK    bool   // a planted password-only normal session authenticates
	gateOK    bool   // RequireSensitive(authenticator-change) admits it
	lifecycle bool   // BeginTOTP (freshSession) admits it
}

func TestSessionFloorGateAndLifecycleAgreeAcrossAccountStates(t *testing.T) { // E03, E09, E12, I08, D-04
	totp := func(e *sessionEnv) string { id, _ := e.mfaAccount(); return id }
	key := func(e *sessionEnv) string {
		_, id := e.enrollKey()
		e.retireSeed()
		e.clock.Advance(time.Minute)
		return id
	}
	both := func(e *sessionEnv) (string, string) {
		id, _, _, keyID := e.bothFactors()
		e.retireSeed()
		e.clock.Advance(time.Minute)
		return id, keyID
	}
	denied := accountOutcome{"denied", false, false, false}
	aal1 := accountOutcome{"aal1", true, true, true}
	stepUp := accountOutcome{"preauth", true, false, false}
	disable := `UPDATE authenticators SET state='disabled',failed_attempts=retry_ceiling WHERE id=?`
	expire := `UPDATE authenticators SET expires_at=created_at+1 WHERE id=?`
	cases := []struct {
		name  string
		setup func(e *sessionEnv)
		want  accountOutcome
	}{
		{"AAL1-only never bound a factor", func(e *sessionEnv) {}, aal1},
		{"live TOTP keeps approved lower-assurance login but no sensitive authority", func(e *sessionEnv) { totp(e) }, stepUp},
		{"live key", func(e *sessionEnv) { key(e) }, stepUp},
		{"TOTP exhausted", func(e *sessionEnv) { e.exec(disable, totp(e)) }, denied},
		{"TOTP expired", func(e *sessionEnv) { e.exec(expire, totp(e)) }, denied},
		{"key disabled", func(e *sessionEnv) { e.exec(disable, key(e)) }, denied},
		{"key expired", func(e *sessionEnv) { e.exec(expire, key(e)) }, denied},
		{"TOTP retired, legacy NULL provenance", func(e *sessionEnv) { e.retireRaw(totp(e), reason("")) }, denied},
		{"TOTP retired protective", func(e *sessionEnv) { e.retireRaw(totp(e), reason(retireProtective)) }, denied},
		{"TOTP retired authorized removal", func(e *sessionEnv) { e.retireRaw(totp(e), reason(retireAuthorized)) }, aal1},
		{"TOTP retired recovery replacement", func(e *sessionEnv) { e.retireRaw(totp(e), reason(retireRecovered)) }, aal1},
		{"key retired legacy NULL provenance", func(e *sessionEnv) { e.retireRaw(key(e), reason("")) }, denied},
		{"key retired protective", func(e *sessionEnv) { e.retireRaw(key(e), reason(retireProtective)) }, denied},
		{"key retired authorized removal", func(e *sessionEnv) { e.retireRaw(key(e), reason(retireAuthorized)) }, aal1},
		{"key retired recovery replacement", func(e *sessionEnv) { e.retireRaw(key(e), reason(retireRecovered)) }, aal1},
		{"live key with disabled TOTP sibling", func(e *sessionEnv) { id, _ := both(e); e.exec(disable, id) }, stepUp},
		{"authorized-removed TOTP does not excuse a disabled key sibling", func(e *sessionEnv) {
			id, keyID := both(e)
			e.retireRaw(id, reason(retireAuthorized))
			e.exec(disable, keyID)
		}, denied},
		{"authorized removal of the only live factor leaves a protectively retired sibling counted", func(e *sessionEnv) {
			id, keyID := both(e)
			e.retireRaw(id, reason(retireAuthorized))
			e.retireRaw(keyID, reason(retireProtective))
		}, denied},
		{"required policy without any factor", func(e *sessionEnv) { e.exec(`UPDATE users SET mfa_requirement='required'`) }, denied},
		{"administrator without any factor", func(e *sessionEnv) {
			e.exec(`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm','u','super_admin','active',1)`)
		}, denied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSessionEnv(t)
			c.setup(e)
			e.clock.Advance(time.Second)
			var got accountOutcome
			switch r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.50"); {
			case err != nil:
				got.login = "denied"
			case r.Session.Info.Assurance == AssurancePreauth:
				got.login = "preauth"
			default:
				got.login = "aal1"
			}
			planted := e.plantPasswordOnly()
			info, err := e.s.Authenticate(t.Context(), planted, true)
			got.authOK = err == nil
			if got.authOK {
				got.gateOK = e.s.RequireSensitive(info.SessionInfo, OpAuthenticatorChange) == nil
				// the password-change class shares the floor: it must agree too
				if (e.s.RequireSensitive(info.SessionInfo, OpPasswordChange) == nil) != got.gateOK {
					t.Fatal("authenticator-change and password-change gates disagree")
				}
			}
			_, lifeErr := e.l.BeginTOTP(t.Context(), planted, "SHA256")
			got.lifecycle = lifeErr == nil
			if got != c.want {
				t.Fatalf("login=%s authenticates=%v gate=%v lifecycle=%v, want %+v", got.login, got.authOK, got.gateOK, got.lifecycle, c.want)
			}
			// the invariant itself: the middleware gate never admits what the
			// lifecycle write denies, nor the reverse.
			if got.gateOK != got.lifecycle {
				t.Fatalf("session gate (%v) and lifecycle freshness (%v) disagree", got.gateOK, got.lifecycle)
			}
		})
	}
}

// The usable-factor inventory is separate from the floor: with a live factor the
// approved lower-assurance login still exists, but it carries no sensitive
// authority and step-up proves the live factor.
func TestSessionFloorUsableCapabilityIsNotPermissionToDowngrade(t *testing.T) { // E03, SB-4
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	skipped := e.passwordOnly()
	if skipped.Info.RequiredAssurance != 2 || skipped.Info.UsableAssurance != 2 || skipped.Info.Assurance != AssurancePasswordOnly {
		t.Fatalf("skip-MFA session mislabelled: %+v", skipped.Info)
	}
	info, err := e.s.Authenticate(t.Context(), skipped.Secret(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range SensitiveOperations() {
		if err := e.s.RequireSensitive(info.SessionInfo, op); err != ErrStepUpRequired {
			t.Fatalf("%s admitted or mis-signalled for a password-only session: %v", op, err)
		}
	}
	if _, err = e.s.StepUpPassword(t.Context(), skipped.Secret(), []byte(sessionTestPassword), sessionTestIP); err != ErrDenied {
		t.Fatal("password alone stepped up an AAL2-capable account", err)
	}
	up, err := e.stepUpTOTP(skipped.Secret(), id, en)
	if err != nil || up.Info.Assurance != AssuranceAAL2 || up.Info.RequiredAssurance != 2 {
		t.Fatal("real TOTP step-up failed", err)
	}
	// Capability without a usable factor is not offered: a floor-2 session with no
	// usable factor can only report "unavailable", never "step up with a password".
	pure := SessionInfo{Assurance: AssurancePasswordOnly, RequiredAssurance: 2, UsableAssurance: 1, AuthenticatedAt: e.clock.Now()}
	for _, op := range SensitiveOperations() {
		if err := e.s.RequireSensitive(pure, op); err != ErrAssuranceUnavailable {
			t.Fatalf("%s: unusable floor-2 account must be assurance-unavailable, got %v", op, err)
		}
	}
	// An unset floor is never defaulted to AAL1.
	unset := SessionInfo{Assurance: AssuranceAAL2, UsableAssurance: 2, AuthenticatedAt: e.clock.Now()}
	for _, op := range SensitiveOperations() {
		if err := e.s.RequireSensitive(unset, op); err != ErrDenied {
			t.Fatalf("%s: unset required assurance must default-deny, got %v", op, err)
		}
	}
}

// A retry-ceiling suspension is not a retirement: it never writes provenance and
// the exhausted factor keeps the floor at 2 through real failed proofs.
func TestSessionFloorRetryCeilingSuspensionKeepsFloorWithoutProvenance(t *testing.T) { // E09, D-04, protective invalidation
	e := newSessionEnv(t)
	id, _ := e.mfaAccount()
	e.exec(`UPDATE authenticators SET failed_attempts=retry_ceiling-1 WHERE id=?`, id)
	if _, err := e.l.VerifyTOTP(t.Context(), "u", id, "000000", "192.0.2.60"); err != ErrDenied {
		t.Fatal("wrong code accepted", err)
	}
	var state string
	var revoked sql.NullInt64
	if err := e.db.QueryRow(`SELECT state,revoked_at FROM authenticators WHERE id=?`, id).Scan(&state, &revoked); err != nil || state != "disabled" || revoked.Valid {
		t.Fatalf("real ceiling crossing did not disable the factor: %s %v %v", state, revoked, err)
	}
	if e.retirement(id).Valid {
		t.Fatal("retry-ceiling suspension recorded retirement provenance")
	}
	e.clock.Advance(time.Second)
	if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.61"); err != ErrDenied {
		t.Fatal("exhausted factor lowered the floor", err)
	}
	e.restart()
	if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.62"); err != ErrDenied {
		t.Fatal("restart lowered the floor of a suspended factor", err)
	}
}

// Provenance is written by the SAME statement as the revocation for every real
// retirement path, and persists across restart.
func TestSessionFloorRetirementProvenanceRecordedPerPath(t *testing.T) { // E09, E12 COMPROMISE-REPORT, I08
	cases := []struct {
		name, want string
		run        func(e *sessionEnv) string
	}{
		{"TOTP password-only report", retireProtective, func(e *sessionEnv) string {
			id, _ := e.mfaAccount()
			if err := e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.70"); err != nil {
				t.Fatal(err)
			}
			return id
		}},
		{"WebAuthn password-only report", retireProtective, func(e *sessionEnv) string {
			_, id := e.enrollKey()
			e.retireSeed()
			e.clock.Advance(time.Minute)
			if err := e.w.ReportCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.71"); err != nil {
				t.Fatal(err)
			}
			return id
		}},
		{"TOTP fresh maximum-assurance removal", retireAuthorized, func(e *sessionEnv) string {
			id, en := e.mfaAccount()
			if err := e.l.RevokeTOTP(t.Context(), e.aal2TOTP(id, en).Secret(), id); err != nil {
				t.Fatal(err)
			}
			return id
		}},
		{"WebAuthn fresh maximum-assurance removal", retireAuthorized, func(e *sessionEnv) string {
			v, id := e.enrollKey()
			e.retireSeed()
			e.clock.Advance(time.Minute)
			if err := e.w.Revoke(t.Context(), e.aal2Key(v).Secret(), id); err != nil {
				t.Fatal(err)
			}
			return id
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSessionEnv(t)
			id := c.run(e)
			if got := e.retirement(id); !got.Valid || got.String != c.want {
				t.Fatalf("retirement provenance %v, want %q", got, c.want)
			}
			e.restart()
			if got := e.retirement(id); !got.Valid || got.String != c.want {
				t.Fatalf("provenance lost across restart: %v", got)
			}
			e.clock.Advance(time.Second)
			_, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.72")
			if (c.want == retireProtective) != (err == ErrDenied) {
				t.Fatalf("after restart a %s retirement gave login err=%v", c.want, err)
			}
		})
	}
}

// Storage-layer guarantees: provenance exists only on revoked second factors, is
// write-once, and an ambiguous (NULL) record can never be backfilled into
// authorization. The only transition is settlement by approved recovery.
func TestSessionFloorProvenanceStorageRules(t *testing.T) { // E09: no silent backfill
	e := newSessionEnv(t)
	id, _ := e.mfaAccount()
	rejects := func(label, wantMessage, q string, args ...any) {
		t.Helper()
		_, err := e.db.Exec(q, args...)
		if err == nil {
			t.Fatalf("storage accepted: %s", label)
		}
		if !strings.Contains(err.Error(), wantMessage) {
			t.Fatalf("%s: rejected for the wrong reason: %v", label, err)
		}
	}
	accepts := func(label, q string, args ...any) {
		t.Helper()
		if _, err := e.db.Exec(q, args...); err != nil {
			t.Fatalf("storage rejected %s: %v", label, err)
		}
	}
	const needsRevoked, immutable, backfill = "requires a revoked second factor", "immutable", "cannot be backfilled"
	rejects("provenance on a live factor", needsRevoked, `UPDATE authenticators SET retirement_reason='authorized_removal' WHERE id=?`, id)
	rejects("provenance on a password", needsRevoked, `UPDATE authenticators SET state='revoked',revoked_at=created_at,retirement_reason='authorized_removal' WHERE id='pwd'`)
	rejects("unknown value", "CHECK", `UPDATE authenticators SET state='revoked',revoked_at=created_at,retirement_reason='bogus' WHERE id=?`, id)
	rejects("provenance on insert", needsRevoked, `INSERT INTO authenticators(id,user_id,kind,retirement_reason) VALUES('ins','u','totp','authorized_removal')`)
	accepts("protective revocation", `UPDATE authenticators SET state='revoked',revoked_at=created_at,retirement_reason='protective' WHERE id=?`, id)
	rejects("protective -> authorized", immutable, `UPDATE authenticators SET retirement_reason='authorized_removal' WHERE id=?`, id)
	rejects("protective -> NULL", immutable, `UPDATE authenticators SET retirement_reason=NULL WHERE id=?`, id)
	rejects("un-revoking a retired factor", needsRevoked, `UPDATE authenticators SET state='active',revoked_at=NULL WHERE id=?`, id)
	accepts("recovery settles protective", `UPDATE authenticators SET retirement_reason='recovery_replacement' WHERE id=?`, id)
	rejects("recovery -> protective", immutable, `UPDATE authenticators SET retirement_reason='protective' WHERE id=?`, id)
	rejects("recovery -> authorized", immutable, `UPDATE authenticators SET retirement_reason='authorized_removal' WHERE id=?`, id)

	// An ambiguous legacy record (revoked before the migration, so NULL) is never
	// promoted to authorized or protective; only recovery may settle it.
	e.exec(`INSERT INTO authenticators(id,user_id,kind,state,credential_generation,created_at,bound_at,public_key,external_credential_id) VALUES('legacy-key','u','webauthn','active',1,5,5,x'01',x'02')`)
	e.exec(`UPDATE authenticators SET state='revoked',revoked_at=created_at+1 WHERE id='legacy-key'`)
	if e.retirement("legacy-key").Valid {
		t.Fatal("a provenance-less revocation acquired a reason by itself")
	}
	rejects("legacy NULL -> authorized (guessed authorization)", backfill, `UPDATE authenticators SET retirement_reason='authorized_removal' WHERE id='legacy-key'`)
	rejects("legacy NULL -> protective", backfill, `UPDATE authenticators SET retirement_reason='protective' WHERE id='legacy-key'`)
	accepts("recovery settles a legacy NULL record", `UPDATE authenticators SET retirement_reason='recovery_replacement' WHERE id='legacy-key'`)
}

// Two retirements racing for one factor: exactly one wins, its provenance is the
// recorded one, and it is the loser's call that fails.
func TestSessionFloorConcurrentRetirementFirstProvenanceWins(t *testing.T) { // concurrency, E12
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	fresh := e.aal2TOTP(id, en)
	var wg sync.WaitGroup
	var removeErr, reportErr error
	wg.Add(2)
	go func() { defer wg.Done(); removeErr = e.l.RevokeTOTP(t.Context(), fresh.Secret(), id) }()
	go func() {
		defer wg.Done()
		reportErr = e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.73")
	}()
	wg.Wait()
	if (removeErr == nil) == (reportErr == nil) {
		t.Fatalf("expected exactly one retirement to win: remove=%v report=%v", removeErr, reportErr)
	}
	want := retireAuthorized
	if reportErr == nil {
		want = retireProtective
	}
	if got := e.retirement(id); !got.Valid || got.String != want {
		t.Fatalf("recorded provenance %v does not belong to the winning path (%s)", got, want)
	}
}

// Login racing a protective report: whichever order the serialized control writer
// picks, no live session of any kind survives and no later login succeeds.
func TestSessionFloorConcurrentReportAndLoginLeaveNoPasswordOnlySession(t *testing.T) { // E12, G01
	e := newSessionEnv(t)
	id, _ := e.mfaAccount()
	var wg sync.WaitGroup
	errs := make(chan error, 9)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), fmt.Sprintf("192.0.2.%d", 100+i))
			_ = err
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The single shared password-work slot may be busy with a racing login,
		// which denies the report without any state change; retry until admitted.
		var err error
		for i := 0; i < 200; i++ {
			if err = e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, "192.0.2.99"); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		errs <- err
	}()
	wg.Wait()
	if err := <-errs; err != nil {
		t.Fatal("report never admitted", err)
	}
	if n := e.scalar(`SELECT count(*) FROM sessions WHERE user_id='u' AND state='active' AND revoked_at IS NULL`); n != 0 {
		t.Fatalf("%d live sessions or login capabilities survive the compromise report", n)
	}
	e.clock.Advance(time.Second)
	if _, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.98"); err != ErrDenied {
		t.Fatal("login after the report succeeded", err)
	}
}
