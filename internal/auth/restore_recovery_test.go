package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/backup"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.18 RESTORE-08 and security-contracts.md S2.2.1/3/5: the host-authorized restore-administrator recovery. It is the
// P1.09 helper mechanism (protected reveal, shared control-state lock, 30-minute single use) with its own purpose. It
// enrolls exactly ONE new administrator with a fresh password and fresh MFA, ends restore quarantine in the same
// transaction, and approves, revives or reactivates nothing that the backup carried. Every test here runs the real
// services over a real SQLite installation and a real loopback TLS mail receiver.

const (
	recoveryTestUser     = "recovery-admin"
	recoveryTestPassword = "synthetic recovery passphrase 52"
	recoveryTestAddress  = "recovery@example.invalid"
)

func allowAll(context.Context, *store.Queries, store.InstallationControl, int64) error { return nil }

// restoredInstallation sets up a real first administrator, takes a real full backup and restores it as the host
// operator would on a fresh or live instance. It returns the BACKUP administrator's credentials: material that must
// never leave quarantine on its own.
func (e *setupEnv) restoredInstallation() firstAdmin {
	e.t.Helper()
	backupAdmin := e.firstAdmin()
	svc, err := backup.New(e.repo, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	raw, _, err := svc.Export(e.ctx(), backup.ModeFull, allowAll)
	if err != nil {
		e.t.Fatal(err)
	}
	verified, err := svc.Verify(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err = svc.Restore(e.ctx(), verified, backup.RestoreOptions{Initiator: backup.InitiatorHost, Authorize: allowAll}); err != nil {
		e.t.Fatal(err)
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		e.t.Fatal("the restore did not leave quarantine in force")
	}
	return backupAdmin
}

func (e *setupEnv) issueRestoreRecovery() (TokenStatus, error) {
	return e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeRestoreRecovery, RiskAcknowledged: true})
}

// recoverySession issues, reveals on a fake terminal and exchanges a restore-recovery token.
func (e *setupEnv) recoverySession() SetupSession {
	e.t.Helper()
	if _, err := e.issueRestoreRecovery(); err != nil {
		e.t.Fatal(err)
	}
	session, err := e.s.Exchange(e.ctx(), e.reveal(PurposeRestoreRecovery, ""), setupTestIP)
	if err != nil {
		e.t.Fatal(err)
	}
	return session
}

// stageRecovery stages the recovery administrator's account (one address) in a fresh live session.
func (e *setupEnv) stageRecovery() firstAdmin {
	e.t.Helper()
	session := e.recoverySession()
	addresses, err := e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: recoveryTestUser, Password: []byte(recoveryTestPassword), Addresses: []string{recoveryTestAddress}})
	if err != nil {
		e.t.Fatal(err)
	}
	return firstAdmin{session: session, addresses: addresses}
}

// recoveryAdmin runs the entire host ceremony to the final commit.
func (e *setupEnv) recoveryAdmin() firstAdmin {
	e.t.Helper()
	a := e.stageRecovery()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *setupEnv) activeAuthority() map[string]int64 {
	e.t.Helper()
	out := map[string]int64{}
	for table, query := range map[string]string{
		"users":                  `SELECT count(*) FROM users WHERE state='active'`,
		"groups":                 `SELECT count(*) FROM groups WHERE state='active'`,
		"agents":                 `SELECT count(*) FROM agents WHERE state='active'`,
		"roles":                  `SELECT count(*) FROM administrative_roles WHERE state='active'`,
		"policies":               `SELECT count(*) FROM policies WHERE state='active'`,
		"endpoints":              `SELECT count(*) FROM endpoints WHERE state='active'`,
		"agent_credentials":      `SELECT count(*) FROM agent_credentials WHERE state='active'`,
		"user_group_memberships": `SELECT count(*) FROM user_group_memberships WHERE state='active'`,
		"sessions":               `SELECT count(*) FROM sessions WHERE state='active'`,
	} {
		out[table] = e.scalar(query)
	}
	return out
}

// RESTORE-08 (scope of issuance): the ceremony exists only inside a restore quarantine, only with the recorded
// acknowledgement, and only for the one purpose; it is never a second way to get an initial administrator.
func TestRestoreRecoveryIsIssuedOnlyInsideARestoreQuarantine(t *testing.T) {
	t.Run("not on a fresh installation awaiting its first setup", func(t *testing.T) {
		e := newSetupEnv(t)
		if _, err := e.issueRestoreRecovery(); err == nil {
			t.Fatal("restore recovery issued on an installation that was never restored")
		}
	})
	t.Run("not on a set-up installation that is not quarantined", func(t *testing.T) {
		e := newSetupEnv(t)
		e.firstAdmin()
		if _, err := e.issueRestoreRecovery(); err == nil {
			t.Fatal("restore recovery issued outside restore quarantine")
		}
		if e.scalar(`SELECT count(*) FROM setup_tokens WHERE purpose='restore_recovery'`) != 0 {
			t.Fatal("a refused issue left a generation behind")
		}
	})
	t.Run("the host acknowledgement and an empty target are mandatory", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		for name, req := range map[string]IssueRequest{
			"no acknowledgement": {Purpose: PurposeRestoreRecovery},
			"a named account":    {Purpose: PurposeRestoreRecovery, Username: setupTestUser, RiskAcknowledged: true},
			"replace password":   {Purpose: PurposeRestoreRecovery, ReplacePassword: true, RiskAcknowledged: true},
			"an unknown purpose": {Purpose: SetupPurpose("restore"), RiskAcknowledged: true},
		} {
			if _, err := e.s.Issue(e.ctx(), req); err == nil {
				t.Fatalf("%s: issued", name)
			}
		}
		if e.scalar(`SELECT count(*) FROM setup_tokens`) != 1 { // only the first setup's own generation exists
			t.Fatal("a refused issue left a generation behind")
		}
	})
	t.Run("the restored administrator cannot be the target of an MFA reset instead", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err == nil {
			t.Fatal("an MFA reset was issued for a quarantined (restored) administrator")
		}
	})
	t.Run("status tells the host operator", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		status, err := e.s.Status(e.ctx())
		if err != nil || !status.RestoreRecoveryEligible || status.Eligible {
			t.Fatalf("status %+v %v", status, err)
		}
	})
}

// RESTORE-08 and S2.2.3/4/5: one recovery administrator with a fresh password and a fresh second factor; nothing from the
// backup is made effective, revived or approved; quarantine ends in the one transaction that completes the enrollment.
func TestRestoreRecoveryEnrollsExactlyOneFreshAdministratorAndApprovesNothing(t *testing.T) {
	e := newSetupEnv(t)
	backupAdmin := e.restoredInstallation()
	before := e.activeAuthority()
	if before["users"] != 0 || before["roles"] != 0 || before["sessions"] != 0 || before["endpoints"] != 0 {
		t.Fatalf("the restore left effective authority: %v", before)
	}
	generations := e.text(`SELECT credential_generation||','||session_generation||','||authority_generation||','||restore_generation FROM installation_control`)

	issued, err := e.issueRestoreRecovery()
	if err != nil || issued.Purpose != PurposeRestoreRecovery || issued.ExpiresAt.Sub(issued.IssuedAt) != SetupTokenLifetime {
		t.Fatalf("issue: %+v %v", issued, err)
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("issuing a token ended quarantine")
	}
	token := e.reveal(PurposeRestoreRecovery, "")
	session, err := e.s.Exchange(e.ctx(), token, setupTestIP)
	if err != nil || session.Purpose != PurposeRestoreRecovery {
		t.Fatalf("exchange: %+v %v", session.SetupSessionInfo, err)
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("exchanging a token ended quarantine")
	}
	// A username that the backup already holds is refused: restored accounts can neither be re-elected nor shadowed.
	if _, err = e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: setupTestUser, Password: []byte(recoveryTestPassword), Addresses: []string{recoveryTestAddress}}); err == nil {
		t.Fatal("the recovery administrator was staged under a restored account's name")
	}
	addresses, err := e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: recoveryTestUser, Password: []byte(recoveryTestPassword), Addresses: []string{recoveryTestAddress}})
	if err != nil {
		t.Fatal(err)
	}
	a := firstAdmin{session: session, addresses: addresses}
	e.confirmAddress(a, 0)
	// Without a proven factor nothing commits and quarantine stays.
	if _, err = e.s.Complete(e.ctx(), session.Secret()); err == nil {
		t.Fatal("the ceremony completed without a proven second factor")
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("a refused completion ended quarantine")
	}
	e.enrollTOTP(&a)
	result, err := e.s.Complete(e.ctx(), session.Secret())
	if err != nil || result.Purpose != PurposeRestoreRecovery || result.Username != recoveryTestUser {
		t.Fatalf("complete: %+v %v", result, err)
	}

	// Quarantine ended; the generations the restore set were NOT lowered or reset to a backup value.
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 {
		t.Fatal("quarantine was not ended by the ceremony")
	}
	if got := e.text(`SELECT credential_generation||','||session_generation||','||authority_generation||','||restore_generation FROM installation_control`); got != generations {
		t.Fatalf("generations changed: %s -> %s", generations, got)
	}
	// Exactly the new administrator is effective: one user, one role, one password, one factor, the one proven address.
	after := e.activeAuthority()
	for table, want := range map[string]int64{"users": 1, "roles": 1, "groups": 0, "agents": 0, "policies": 0, "endpoints": 0, "agent_credentials": 0, "user_group_memberships": 0, "sessions": 0} {
		if after[table] != want {
			t.Fatalf("effective %s after the ceremony: got %d want %d (%v)", table, after[table], want, after)
		}
	}
	if e.scalar(`SELECT count(*) FROM users u JOIN administrative_roles r ON r.user_id=u.id AND r.state='active' AND r.role='super_admin' WHERE u.username=? AND u.state='active' AND u.mfa_requirement='required'`, recoveryTestUser) != 1 {
		t.Fatal("the recovery administrator is not the one active super administrator")
	}
	if e.scalar(`SELECT count(*) FROM authenticators WHERE state='active'`) != 2 || e.scalar(`SELECT count(*) FROM authenticators a JOIN users u ON u.id=a.user_id WHERE a.state='active' AND u.username=?`, recoveryTestUser) != 2 {
		t.Fatal("exactly one fresh password and one fresh second factor, both the recovery administrator's, may be active")
	}
	if e.scalar(`SELECT count(*) FROM notification_addresses WHERE state='active'`) != 1 {
		t.Fatal("only the freshly proven address may be active")
	}
	// The backup's administrator account, role, factors and address stay switched off; nothing was approved.
	if e.text(`SELECT state FROM users WHERE username=?`, setupTestUser) != "quarantined" || e.scalar(`SELECT count(*) FROM administrative_roles r JOIN users u ON u.id=r.user_id WHERE u.username=? AND r.state='active'`, setupTestUser) != 0 {
		t.Fatal("the restored administrator became effective")
	}
	if e.scalar(`SELECT count(*) FROM authenticators a JOIN users u ON u.id=a.user_id WHERE u.username=? AND a.state='active'`, setupTestUser) != 0 {
		t.Fatal("a restored authenticator was reactivated")
	}
	if e.scalar(`SELECT count(*) FROM restore_manifest WHERE decision='approved'`) != 0 {
		t.Fatal("the ceremony approved a manifest entry")
	}
	// No session of any kind came out of the ceremony, and the setup capability and its plaintext are gone.
	if e.scalar(`SELECT count(*) FROM sessions WHERE state='active'`) != 0 || e.scalar(`SELECT count(*) FROM setup_sessions WHERE state='active'`) != 0 || e.scalar(`SELECT count(*) FROM setup_tokens WHERE state IN ('pending','available','claimed','retrieved')`) != 0 {
		t.Fatal("a session or a live setup capability survived the ceremony")
	}
	if names, err := e.repo.RevealFileNames(); err != nil || len(names) != 0 {
		t.Fatalf("plaintext reveal file survived: %v %v", names, err)
	}
	if _, err = e.s.Authenticate(e.ctx(), session.Secret()); err == nil {
		t.Fatal("the completed recovery session still authenticates")
	}
	// A binding notice is durable for exactly the proven address.
	if e.scalar(`SELECT count(*) FROM security_notice_outbox WHERE recipient_snapshot=? AND dispatch_state='ready'`, recoveryTestAddress) < 1 {
		t.Fatal("no durable notice for the recovery administrator's proven address")
	}

	// The ordinary AAL2 login of the NEW administrator now works; the backup administrator's does not (RESTORE-08).
	sessions := e.sessions()
	e.advance(31 * time.Second)
	login, err := sessions.PasswordLogin(e.ctx(), recoveryTestUser, []byte(recoveryTestPassword), "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.LoginTOTP(e.ctx(), login.Session.Secret(), a.totp.ID, enrollmentCode(t, a.totp, e.clock.Now()), "192.0.2.90"); err != nil {
		t.Fatalf("the recovery administrator cannot sign in: %v", err)
	}
	if _, err = sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.91"); err == nil {
		t.Fatal("the backup administrator's password still signs in")
	}
	e.advance(31 * time.Second)
	if login, err = sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.92"); err == nil {
		if _, err = sessions.LoginTOTP(e.ctx(), login.Session.Secret(), backupAdmin.totp.ID, enrollmentCode(t, backupAdmin.totp, e.clock.Now()), "192.0.2.92"); err == nil {
			t.Fatal("the backup administrator's password and TOTP reached a session")
		}
	}
	if e.scalar(`SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username=?`, setupTestUser) != 0 {
		t.Fatal("a session exists for the restored administrator")
	}
}

// RESTORE-08: backup password/MFA alone cannot leave quarantine, and no web or setup path can end it without the ceremony.
func TestBackupCredentialsAndOrdinaryPathsCannotLeaveRestoreQuarantine(t *testing.T) {
	e := newSetupEnv(t)
	backupAdmin := e.restoredInstallation()
	sessions := e.sessions()

	// The backup's own password and TOTP, exactly as they were enrolled.
	e.advance(31 * time.Second)
	if login, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.93"); err == nil {
		if _, err = sessions.LoginTOTP(e.ctx(), login.Session.Secret(), backupAdmin.totp.ID, enrollmentCode(t, backupAdmin.totp, e.clock.Now()), "192.0.2.93"); err == nil {
			t.Fatal("backup credentials produced a session inside quarantine")
		}
	}
	if e.scalar(`SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("a session row exists inside quarantine")
	}
	// The initial-setup and MFA-reset surfaces cannot be turned into a way out either.
	if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err == nil {
		t.Fatal("initial setup was issued inside a restore quarantine")
	}
	if _, err := e.s.EnsureInitial(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.scalar(`SELECT count(*) FROM setup_tokens WHERE purpose='initial_setup' AND state IN ('pending','available','claimed','retrieved')`) != 0 {
		t.Fatal("a first-administrator generation is live inside a restore quarantine")
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("quarantine ended without the ceremony")
	}
	// An unfinished ceremony (token issued, exchanged, staged, never completed) leaves quarantine in force and nothing active.
	a := e.stageRecovery()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 || e.activeAuthority()["users"] != 0 {
		t.Fatal("an unfinished ceremony changed the installation")
	}
	e.advance(SetupTokenLifetime + time.Second)
	if _, err := e.s.Reconcile(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("an expired ceremony completed")
	}
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 || e.activeAuthority()["users"] != 0 {
		t.Fatal("an expired ceremony changed the installation")
	}
	if e.scalar(`SELECT count(*) FROM users WHERE username=?`, recoveryTestUser) != 0 {
		t.Fatal("an expired ceremony left its staged account behind")
	}
}

// RESTORE-08: "can enroll the initial recovery administrator only; cannot call container or policy APIs". The setup
// session is its own capability: it is not a session, carries no assurance label and is not read by the session
// verifier, so it reaches nothing that a session or an agent credential reaches.
func TestRestoreRecoverySessionIsNotASessionAndCannotDoAnythingElse(t *testing.T) {
	e := newSetupEnv(t)
	e.restoredInstallation()
	a := e.stageRecovery()
	secret := a.session.Secret()
	sessions := e.sessions()

	if _, err := sessions.Authenticate(e.ctx(), secret, false); err == nil {
		t.Fatal("a restore-recovery capability authenticated as a session")
	}
	if _, err := sessions.AuthenticatePreauth(e.ctx(), secret); err == nil {
		t.Fatal("a restore-recovery capability authenticated as a preauth session")
	}
	// It enrolls only what the ceremony needs: a second account, a second TOTP, a replacement password and an address
	// belonging to somebody else are all refused.
	if _, err := e.s.StageAccount(e.ctx(), secret, AccountRequest{Username: "second-admin", Password: []byte(recoveryTestPassword), Addresses: []string{"second@example.invalid"}}); err == nil {
		t.Fatal("a second account was staged in the same ceremony")
	}
	if _, err := e.s.BeginTOTP(e.ctx(), secret, "SHA256"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.BeginTOTP(e.ctx(), secret, "SHA256"); err == nil {
		t.Fatal("a second second-factor enrollment was started")
	}
	// Setup tokens are domain-separated by purpose: the same text can never verify for another purpose.
	token, err := e.s.newToken()
	if err != nil {
		t.Fatal(err)
	}
	if digestEqual(setupDigest(PurposeInitialSetup, token), setupDigest(PurposeRestoreRecovery, token)) || digestEqual(setupDigest(PurposeMFAReset, token), setupDigest(PurposeRestoreRecovery, token)) {
		t.Fatal("token digests are not separated by purpose")
	}
	if e.scalar(`SELECT count(*) FROM sessions`) != 0 || e.scalar(`SELECT count(*) FROM agent_credentials WHERE state='active'`) != 0 {
		t.Fatal("the ceremony produced a session or an agent credential")
	}
}

// A token wins once and every guard of the shared mechanism still applies to this purpose.
func TestRestoreRecoveryTokenWinsOnceAndIsBounded(t *testing.T) {
	t.Run("replay of an exchanged token is denied", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		if _, err := e.issueRestoreRecovery(); err != nil {
			t.Fatal(err)
		}
		token := e.reveal(PurposeRestoreRecovery, "")
		if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err != nil {
			t.Fatal(err)
		}
		if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
			t.Fatal("a consumed restore-recovery token exchanged twice")
		}
		if _, err := e.s.Reveal(e.ctx(), PurposeRestoreRecovery, "", &fakeTerminal{}); err == nil {
			t.Fatal("a consumed generation revealed again")
		}
	})
	t.Run("the absolute 30 minute expiry holds", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		if _, err := e.issueRestoreRecovery(); err != nil {
			t.Fatal(err)
		}
		token := e.reveal(PurposeRestoreRecovery, "")
		e.advance(SetupTokenLifetime)
		if _, err := e.s.Exchange(e.ctx(), token, setupTestIP); err == nil {
			t.Fatal("an expired restore-recovery token exchanged")
		}
	})
	t.Run("a revealed token is shown exactly once", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		if _, err := e.issueRestoreRecovery(); err != nil {
			t.Fatal(err)
		}
		e.reveal(PurposeRestoreRecovery, "")
		again := &fakeTerminal{}
		if _, err := e.s.Reveal(e.ctx(), PurposeRestoreRecovery, "", again); err == nil || again.token() != "" {
			t.Fatal("a second reveal showed the token")
		}
	})
	t.Run("another purpose's reveal never shows it", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		if _, err := e.issueRestoreRecovery(); err != nil {
			t.Fatal(err)
		}
		other := &fakeTerminal{}
		if _, err := e.s.Reveal(e.ctx(), PurposeInitialSetup, "", other); err == nil || other.token() != "" {
			t.Fatal("an initial-setup reveal exposed a restore-recovery generation")
		}
	})
	t.Run("a wrong token is a counted guess and never a way in", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		if _, err := e.issueRestoreRecovery(); err != nil {
			t.Fatal(err)
		}
		e.reveal(PurposeRestoreRecovery, "")
		wrong, err := e.s.newToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.s.Exchange(e.ctx(), string(wrong), setupTestIP); err == nil {
			t.Fatal("a guessed token exchanged")
		}
		if e.scalar(`SELECT failed FROM setup_attempts WHERE purpose='restore_recovery'`) != 1 {
			t.Fatal("the guess was not counted for this purpose")
		}
	})
	t.Run("two completions race and exactly one commits", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		a := e.stageRecovery()
		e.confirmAddress(a, 0)
		e.enrollTOTP(&a)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.s.Complete(e.ctx(), a.session.Secret())
			}()
		}
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			}
		}
		if wins != 1 || e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 1 || e.scalar(`SELECT count(*) FROM users WHERE username=? AND state='active'`, recoveryTestUser) != 1 {
			t.Fatalf("completion wins: %d (%v)", wins, errs)
		}
	})
	t.Run("a second ceremony is possible only after a new restore", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		e.recoveryAdmin()
		if _, err := e.issueRestoreRecovery(); err == nil {
			t.Fatal("restore recovery issued after the ceremony ended quarantine")
		}
	})
}

// Quarantine can end in exactly one place. If anything else ended it while a ceremony was open, the ceremony refuses
// instead of enrolling an administrator into an installation nobody restored.
func TestRestoreRecoveryRefusesWhenTheQuarantineIsNoLongerThere(t *testing.T) {
	e := newSetupEnv(t)
	e.restoredInstallation()
	a := e.stageRecovery()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	e.exec(`UPDATE installation_control SET restore_quarantined=0`) // an out-of-band edit the product never performs
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("the ceremony completed outside a restore quarantine")
	}
	if e.scalar(`SELECT count(*) FROM users WHERE username=? AND state='active'`, recoveryTestUser) != 0 || e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 0 {
		t.Fatal("an administrator was established outside a restore quarantine")
	}
}

// S2.2.1 / RESTORE-05: a restore whose import failed leaves quarantine in force, and the host can still recover. The
// manifest does not exist then, and nothing the ceremony does depends on one.
func TestRestoreRecoveryWorksAfterAFailedImport(t *testing.T) {
	e := newSetupEnv(t)
	e.firstAdmin()
	svc, err := backup.New(e.repo, "test")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := svc.Export(e.ctx(), backup.ModeFull, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := svc.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(`CREATE TRIGGER fail_import BEFORE INSERT ON restore_reports BEGIN SELECT RAISE(ABORT,'synthetic constraint failure'); END`)
	if _, err = svc.Restore(e.ctx(), verified, backup.RestoreOptions{Initiator: backup.InitiatorHost, Authorize: allowAll}); err == nil || !backup.Quarantined(err) {
		t.Fatalf("restore: %v", err)
	}
	e.exec(`DROP TRIGGER fail_import`)
	if e.scalar(`SELECT count(*) FROM restore_reports`) != 0 || e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("expected a quarantined installation with no report")
	}
	e.recoveryAdmin()
	if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 || e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 1 {
		t.Fatal("the ceremony did not recover an installation whose import failed")
	}
}

// S2.2.5: a crash after the commit leaves the committed enrollment in place and no usable plaintext, and a crash before it
// leaves quarantine in force with nothing active.
func TestRestoreRecoveryCrashPoints(t *testing.T) {
	t.Run("after commit", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		a := e.stageRecovery()
		e.confirmAddress(a, 0)
		e.enrollTOTP(&a)
		e.s.hook = failAt("complete:after-commit")
		_, _ = e.s.Complete(e.ctx(), a.session.Secret())
		e.restart()
		if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 || e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 1 {
			t.Fatal("the committed ceremony was lost")
		}
		if _, err := e.issueRestoreRecovery(); err == nil {
			t.Fatal("a second ceremony became possible after the commit")
		}
	})
	t.Run("an enrollment transaction that fails changes nothing", func(t *testing.T) {
		e := newSetupEnv(t)
		e.restoredInstallation()
		a := e.stageRecovery()
		e.confirmAddress(a, 0)
		e.enrollTOTP(&a)
		e.exec(`CREATE TRIGGER fail_role BEFORE INSERT ON administrative_roles BEGIN SELECT RAISE(ABORT,'synthetic constraint failure'); END`)
		if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
			t.Fatal("completion succeeded through a failing role insert")
		}
		if e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 || e.activeAuthority()["users"] != 0 {
			t.Fatal("a failed completion left a partial administrator or ended quarantine")
		}
		e.exec(`DROP TRIGGER fail_role`)
		if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err != nil {
			t.Fatalf("the same session could not retry after the fault cleared: %v", err)
		}
	})
}
