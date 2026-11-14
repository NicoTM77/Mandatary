package auth

import (
	"strings"
	"testing"
	"time"
)

// loginAAL2 performs the ordinary password + TOTP login and returns the session.
func (e *setupEnv) loginAAL2(a firstAdmin, ip string) {
	e.t.Helper()
	sessions := e.sessions()
	login, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), ip)
	if err != nil {
		e.t.Fatal(err)
	}
	e.advance(31 * time.Second) // a fresh verifier period; codes are single-use
	if _, err = sessions.LoginTOTP(e.ctx(), login.Session.Secret(), a.totp.ID, enrollmentCode(e.t, a.totp, e.clock.Now()), ip); err != nil {
		e.t.Fatal(err)
	}
}

// S3.1b: host-local MFA reset is gated, scoped to one existing administrator,
// and only the ordinary login path produces a session afterwards.
func TestHostRecoveryIssuanceScope(t *testing.T) {
	t.Run("not before first setup", func(t *testing.T) {
		e := newSetupEnv(t)
		e.ensure()
		if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err == nil {
			t.Fatal("MFA reset issued on an installation with no administrator")
		}
	})
	t.Run("restore recovery is refused outside a restore quarantine", func(t *testing.T) {
		e := newSetupEnv(t)
		e.firstAdmin()
		if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeRestoreRecovery, RiskAcknowledged: true}); err == nil {
			t.Fatal("restore recovery issued on an installation that was never restored (see restore_recovery_test.go)")
		}
	})
	t.Run("risk acknowledgement is mandatory", func(t *testing.T) {
		e := newSetupEnv(t)
		e.firstAdmin()
		if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser}); err == nil {
			t.Fatal("MFA reset issued without the recorded risk acknowledgement")
		}
		if e.scalar(`SELECT count(*) FROM setup_tokens WHERE purpose='mfa_reset'`) != 0 {
			t.Fatal("a refused issue left a generation behind")
		}
	})
	t.Run("unknown and malformed targets", func(t *testing.T) {
		e := newSetupEnv(t)
		e.firstAdmin()
		for _, name := range []string{"", "nobody", strings.Repeat("a", 200), "first-admin ", "FIRST-ADMIN\x00"} {
			if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: name, RiskAcknowledged: true}); err == nil {
				t.Fatalf("issued for %q", name)
			}
		}
	})
	t.Run("initial setup cannot be reissued after completion", func(t *testing.T) {
		e := newSetupEnv(t)
		e.firstAdmin()
		if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err == nil {
			t.Fatal("initial setup re-issued on a set-up installation")
		}
	})
	t.Run("not for a non-active or non-administrator account", func(t *testing.T) {
		e := newSetupEnv(t)
		e.firstAdmin()
		e.exec(`UPDATE administrative_roles SET state='disabled'`)
		if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err == nil {
			t.Fatal("MFA reset issued for an account with no active administrator role")
		}
	})
}

// End-to-end: reset replaces the TOTP, retires the old one (and its sessions) at
// issuance and settles it to the replacement at completion, notifies the
// existing verified address, never issues a login session, and a second reset
// needs a new explicit host action.
func TestHostMFAResetEndToEnd(t *testing.T) {
	e := newSetupEnv(t)
	admin := e.firstAdmin()
	e.advance(time.Minute)
	e.loginAAL2(admin, "192.0.2.80")
	if e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 1 {
		t.Fatal("expected one live administrator session")
	}

	issued, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Purpose != PurposeMFAReset || issued.ExpiresAt.Sub(issued.IssuedAt) != SetupTokenLifetime {
		t.Fatalf("issued generation: %+v", issued)
	}
	// Issuance ends the account's sessions BEFORE the ceremony (S3.2) ...
	if e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 {
		t.Fatal("administrator sessions survived recovery issuance")
	}
	// ... and (S3.2) the old second factors are durably retired in the same
	// issuance transaction, so nothing issued before the ceremony can
	// authenticate during it.
	if e.scalar(`SELECT count(*) FROM authenticators WHERE kind IN ('totp','webauthn') AND state='active'`) != 0 {
		t.Fatal("an old second factor stayed usable after recovery issuance")
	}
	e.advance(31 * time.Second)
	e.assertOldFactorsDenied(admin, "192.0.2.81")

	// Wrong target at the host reveals nothing.
	other := &fakeTerminal{}
	if _, err = e.s.Reveal(e.ctx(), PurposeMFAReset, "nobody", other); err == nil || other.token() != "" {
		t.Fatal("reveal for an unrelated username")
	}
	if _, err = e.s.Reveal(e.ctx(), PurposeInitialSetup, "", other); err == nil || other.token() != "" {
		t.Fatal("initial-setup reveal exposed an MFA-reset generation")
	}
	token := e.reveal(PurposeMFAReset, setupTestUser)
	sessionsBefore := e.scalar(`SELECT count(*) FROM sessions`)
	session, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if session.Purpose != PurposeMFAReset || session.TargetUser != setupTestUser || session.ReplacePassword {
		t.Fatalf("session scope: %+v", session.SetupSessionInfo)
	}
	// Nothing about the recovery capability is a login session.
	if e.scalar(`SELECT count(*) FROM sessions`) != sessionsBefore {
		t.Fatal("recovery exchange created a normal session")
	}
	// Scope: no new account, no password through a reset that did not ask for one,
	// and no completion before MFA proof.
	if _, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: "intruder", Password: []byte(setupTestPassword), Addresses: []string{"x@example.invalid"}}); err == nil {
		t.Fatal("recovery session created an account")
	}
	if _, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Password: []byte("another synthetic passphrase 8")}); err == nil {
		t.Fatal("recovery session replaced a password it was not authorized to replace")
	}
	if _, err = e.s.Complete(e.ctx(), session.Secret()); err == nil {
		t.Fatal("recovery completed without proving a new factor")
	}
	en, err := e.s.BeginTOTP(e.ctx(), session.Secret(), "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	if err = e.s.ConfirmTOTP(e.ctx(), session.Secret(), enrollmentCode(t, en, e.clock.Now()), setupTestIP); err != nil {
		t.Fatal(err)
	}
	result, err := e.s.Complete(e.ctx(), session.Secret())
	if err != nil {
		t.Fatal(err)
	}
	if result.Purpose != PurposeMFAReset || result.Username != setupTestUser {
		t.Fatalf("result %+v", result)
	}
	// The old factor was retired at issuance (and settled here); exactly one new
	// factor is active; still no session was minted.
	if e.scalar(`SELECT count(*) FROM authenticators WHERE kind='totp' AND state='active'`) != 1 || e.text(`SELECT state FROM authenticators WHERE id=?`, admin.totp.ID) == "active" {
		t.Fatal("old TOTP was not retired / new TOTP not active")
	}
	if e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 {
		t.Fatal("recovery completion left or created a session")
	}
	for _, event := range []string{"authenticator_replaced", "recovery_completed"} {
		if e.scalar(`SELECT count(*) FROM security_events WHERE event_type=?`, event) != 1 {
			t.Fatalf("missing durable %s event", event)
		}
	}
	if e.scalar(`SELECT count(*) FROM security_notice_outbox WHERE recipient_snapshot='first@example.invalid'`) < 3 {
		t.Fatal("notices for the reset were not queued to the existing verified address")
	}
	// The token and session are spent; the surface is closed again.
	if _, err = e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("spent MFA-reset token exchanged again")
	}
	if _, err = e.s.Authenticate(e.ctx(), session.Secret()); err == nil {
		t.Fatal("completed recovery session still authenticates")
	}
	if open, _ := e.s.surfaceOpen(e.ctx()); open {
		t.Fatal("setup surface open after recovery completed")
	}
	// The old factor cannot log in; the NEW one can, with the unchanged password,
	// reaching AAL2 only through the ordinary path.
	sessions := e.sessions()
	e.advance(31 * time.Second)
	login, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.82")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.LoginTOTP(e.ctx(), login.Session.Secret(), admin.totp.ID, enrollmentCode(t, admin.totp, e.clock.Now()), "192.0.2.82"); err == nil {
		t.Fatal("retired factor still logs in")
	}
	e.advance(31 * time.Second)
	login, err = sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.83")
	if err != nil {
		t.Fatal(err)
	}
	issuedSession, err := sessions.LoginTOTP(e.ctx(), login.Session.Secret(), en.ID, enrollmentCode(t, en, e.clock.Now()), "192.0.2.83")
	if err != nil || issuedSession.Info.Assurance != AssuranceAAL2 {
		t.Fatalf("new factor login: %v", err)
	}
}

// A reset with password replacement stages a verifier that must not be the old
// password, and only commits together with the proven new factor.
func TestHostMFAResetWithPasswordReplacement(t *testing.T) {
	e := newSetupEnv(t)
	admin := e.firstAdmin()
	if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, ReplacePassword: true, RiskAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	session, err := e.s.Exchange(e.ctx(), e.reveal(PurposeMFAReset, setupTestUser), setupTestIP)
	if err != nil || !session.ReplacePassword {
		t.Fatalf("session: %v %+v", err, session.SetupSessionInfo)
	}
	if _, err = e.s.BeginTOTP(e.ctx(), session.Secret(), "SHA256"); err == nil {
		t.Fatal("TOTP began before the required password replacement")
	}
	if _, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Password: []byte(setupTestPassword)}); err == nil {
		t.Fatal("the current password was accepted as its own replacement")
	}
	const replacement = "a different uncommon passphrase 77"
	const verifierQuery = `SELECT hex(verifier_hash) FROM authenticators WHERE kind='password' AND state='active'`
	verifierBefore := e.text(verifierQuery)
	if _, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Password: []byte(replacement)}); err != nil {
		t.Fatal(err)
	}
	// Staged, not applied: the stored password verifier is unchanged until
	// completion. (An ordinary login is already impossible: issuance retired
	// every second factor, so no administrator login can reach AAL2.)
	if verifierBefore == "" || e.text(verifierQuery) != verifierBefore {
		t.Fatal("the staged password replaced the stored verifier before completion")
	}
	sessions := e.sessions()
	en, err := e.s.BeginTOTP(e.ctx(), session.Secret(), "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	if err = e.s.ConfirmTOTP(e.ctx(), session.Secret(), enrollmentCode(t, en, e.clock.Now()), setupTestIP); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Complete(e.ctx(), session.Secret()); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.91"); err == nil {
		t.Fatal("the replaced password still verifies")
	}
	if _, err = sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(replacement), "192.0.2.92"); err != nil {
		t.Fatal(err)
	}
	_ = admin
}

// Re-issuing rotates: the earlier generation, its session and its staged data die.
func TestRotationInvalidatesEarlierGenerationAndSession(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	token := e.reveal(PurposeInitialSetup, "")
	session, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"first@example.invalid"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Authenticate(e.ctx(), session.Secret()); err == nil {
		t.Fatal("a session survived rotation of its generation")
	}
	if e.scalar(`SELECT count(*) FROM users`) != 0 || e.scalar(`SELECT count(*) FROM notification_addresses`) != 0 {
		t.Fatal("staged records survived rotation")
	}
	if _, err = e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("rotated-away token exchanged")
	}
}

// S3.1: a clock that moves backwards is uncertainty: every operation denies.
func TestClockRollbackDeniesSetupOperations(t *testing.T) {
	e := newSetupEnv(t)
	e.ensure()
	e.advance(10 * time.Minute)
	if _, err := e.s.Reconcile(e.ctx()); err != nil { // records the high-water mark
		t.Fatal(err)
	}
	token := e.reveal(PurposeInitialSetup, "")
	e.advance(-9 * time.Minute)
	if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
		t.Fatal("exchange accepted after the clock moved backwards")
	}
	if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err == nil {
		t.Fatal("issuance accepted after the clock moved backwards")
	}
}

// assertOldFactorsDenied proves the pre-issuance password+TOTP cannot mint any
// session: it must never reach AAL2 (nor any other session) after issuance.
func (e *setupEnv) assertOldFactorsDenied(a firstAdmin, ip string) {
	e.t.Helper()
	sessions := e.sessions()
	before := e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`)
	login, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), ip)
	if err == nil {
		e.advance(31 * time.Second)
		if _, err = sessions.LoginTOTP(e.ctx(), login.Session.Secret(), a.totp.ID, enrollmentCode(e.t, a.totp, e.clock.Now()), ip); err == nil {
			e.t.Fatal("old password+TOTP minted a session during the recovery window")
		}
	}
	if e.scalar(`SELECT count(*) FROM sessions WHERE state='active' AND achieved_assurance>=2`) != 0 || e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) > before {
		e.t.Fatal("a usable session exists after old-factor login during the recovery window")
	}
}

// S3.2: issuance invalidates old second factors, saved codes and recovery
// capabilities BEFORE the token exists; an abandoned or expired ceremony is
// recovered by explicit host re-issuance, never by reviving old credentials.
func TestHostMFAResetIssuanceInvalidatesOldCredentials(t *testing.T) {
	e := newSetupEnv(t)
	admin := e.firstAdmin()
	e.advance(time.Minute)
	sessions := e.sessions()
	login, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	fresh, err := sessions.LoginTOTP(e.ctx(), login.Session.Secret(), admin.totp.ID, enrollmentCode(t, admin.totp, e.clock.Now()), "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	codes, err := e.l.IssueRecoveryCodes(e.ctx(), fresh.Secret())
	if err != nil {
		t.Fatal(err)
	}
	saved := codes.ExportOnce()
	if len(saved) < 3 {
		t.Fatal("no saved codes issued")
	}
	// A recovery capability already obtained with a saved code must also die.
	e.advance(31 * time.Second)
	capability, err := e.l.Recover(e.ctx(), setupTestUser, []byte(setupTestPassword), saved[0], "192.0.2.91")
	if err != nil {
		t.Fatalf("precondition: saved-code recovery: %v", err)
	}
	if cap, _ := capability.ExportOnce(); len(cap) == 0 || e.scalar(`SELECT count(*) FROM recovery_capabilities WHERE state!='revoked'`) == 0 {
		t.Fatal("precondition: no live recovery capability")
	}

	if _, err = e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"second factors": `SELECT count(*) FROM authenticators WHERE kind IN ('totp','webauthn') AND state!='revoked'`,
		"saved codes":    `SELECT count(*) FROM authenticators WHERE kind='recovery_code' AND state!='revoked'`,
		"code batches":   `SELECT count(*) FROM recovery_batches WHERE state!='revoked'`,
		"capabilities":   `SELECT count(*) FROM recovery_capabilities WHERE state!='revoked'`,
		"sessions":       `SELECT count(*) FROM sessions WHERE state='active'`,
	} {
		if n := e.scalar(q); n != 0 {
			t.Fatalf("%d live %s survived MFA-reset issuance", n, name)
		}
	}
	// Old second factors are retired as protective (never lowering the floor).
	if e.text(`SELECT retirement_reason FROM authenticators WHERE id=?`, admin.totp.ID) != retireProtective {
		t.Fatal("old factor not retired with protective provenance")
	}
	e.advance(31 * time.Second)
	e.assertOldFactorsDenied(admin, "192.0.2.92")
	e.advance(31 * time.Second)
	if _, err = e.l.Recover(e.ctx(), setupTestUser, []byte(setupTestPassword), saved[1], "192.0.2.93"); err == nil {
		t.Fatal("a saved code started a recovery after MFA-reset issuance")
	}

	// Abandoned ceremony: the generation expires unused. Old credentials do not
	// revive; explicit host re-issuance recovers, and completion succeeds.
	e.advance(SetupTokenLifetime + time.Minute)
	e.assertOldFactorsDenied(admin, "192.0.2.95")
	if _, err = e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err != nil {
		t.Fatalf("host re-issue after an abandoned ceremony: %v", err)
	}
	session, err := e.s.Exchange(e.ctx(), e.reveal(PurposeMFAReset, setupTestUser), setupTestIP)
	if err != nil {
		t.Fatal(err)
	}
	en, err := e.s.BeginTOTP(e.ctx(), session.Secret(), "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	if err = e.s.ConfirmTOTP(e.ctx(), session.Secret(), enrollmentCode(t, en, e.clock.Now()), setupTestIP); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Complete(e.ctx(), session.Secret()); err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	login, err = sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.96")
	if err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	issued, err := sessions.LoginTOTP(e.ctx(), login.Session.Secret(), en.ID, enrollmentCode(t, en, e.clock.Now()), "192.0.2.96")
	if err != nil || issued.Info.Assurance != AssuranceAAL2 {
		t.Fatalf("new factor login after re-issued recovery: %v", err)
	}
}
