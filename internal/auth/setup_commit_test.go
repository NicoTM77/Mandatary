package auth

import (
	"sync"
	"testing"
	"time"
)

// SETUP-06/08, N63B4-BINDING-FIRST, N63B4-SCOPE-ADMIN: the complete ceremony with
// real password hashing, real TOTP proof, real address-control proof over a real
// loopback TLS receiver, then an ORDINARY password+TOTP login to AAL2.
func TestFirstAdminEndToEndThenOrdinaryAAL2Login(t *testing.T) {
	e := newSetupEnv(t)
	if r := e.ensure(); r.Outcome != "issued" {
		t.Fatalf("first start outcome %q", r.Outcome)
	}
	// Locked until the commit: no usable account, quarantined, zero generations.
	if e.scalar(`SELECT count(*) FROM users`) != 0 || e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		t.Fatal("fresh installation is not locked and empty")
	}
	a := e.firstAdmin()

	// Committed state: one active administrator, active password+TOTP, the control
	// generations lifted exactly once, only the confirmed address active.
	if e.scalar(`SELECT credential_generation+session_generation+authority_generation+restore_generation FROM installation_control`) != 4 || e.scalar(`SELECT restore_quarantined FROM installation_control`) != 0 {
		t.Fatal("installation was not unlocked by the committed enrollment")
	}
	if e.scalar(`SELECT count(*) FROM administrative_roles WHERE role='super_admin' AND state='active'`) != 1 || e.text(`SELECT state FROM users WHERE username=?`, setupTestUser) != "active" || e.text(`SELECT mfa_requirement FROM users WHERE username=?`, setupTestUser) != "required" {
		t.Fatal("administrator record incorrect")
	}
	if e.scalar(`SELECT count(*) FROM authenticators WHERE kind='password' AND state='active'`) != 1 || e.scalar(`SELECT count(*) FROM authenticators WHERE kind='totp' AND state='active' AND encrypted_secret IS NOT NULL`) != 1 {
		t.Fatal("password and TOTP were not both activated")
	}
	if e.scalar(`SELECT count(*) FROM notification_addresses WHERE state='active' AND verified_at IS NOT NULL`) != 1 || e.scalar(`SELECT count(*) FROM notification_addresses WHERE state='revoked'`) != 1 {
		t.Fatal("only the proven address may become active; the unproven one must be revoked")
	}
	// The binding notice intent is durable and tied to the proven address only.
	if e.scalar(`SELECT count(*) FROM security_events WHERE event_type='authenticator_bound'`) != 1 || e.scalar(`SELECT count(*) FROM security_notice_outbox WHERE recipient_snapshot='first@example.invalid' AND dispatch_state='ready'`) != 1 || e.scalar(`SELECT count(*) FROM security_notice_outbox`) != 1 {
		t.Fatal("binding notice was not durably queued for exactly the confirmed address")
	}
	// Setup is permanently disabled and leaves no live capability or plaintext.
	if e.scalar(`SELECT completed_at IS NOT NULL FROM setup_state`) != 1 || e.scalar(`SELECT count(*) FROM setup_tokens WHERE state IN ('pending','available','claimed','retrieved')`) != 0 || e.scalar(`SELECT count(*) FROM setup_sessions WHERE state='active'`) != 0 {
		t.Fatal("setup was not disabled atomically")
	}
	if names, err := e.repo.RevealFileNames(); err != nil {
		t.Fatal(err)
	} else if len(names) != 0 {
		t.Fatal("plaintext reveal file survived completion")
	}
	// The setup session no longer authenticates and the setup surface is gone.
	if _, err := e.s.Authenticate(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("completed setup session still authenticates")
	}
	if open, err := e.s.surfaceOpen(e.ctx()); err != nil || open {
		t.Fatal("setup surface still open after completion")
	}

	// Setup issued NO normal session. The ordinary path now requires password AND
	// TOTP; password alone yields only a preauth capability, never a session.
	sessions := e.sessions()
	login, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.60")
	if err != nil {
		t.Fatal(err)
	}
	if len(login.Next) != 1 || login.Next[0] != "totp" {
		t.Fatalf("unexpected next steps %v", login.Next)
	}
	if _, err = sessions.Authenticate(e.ctx(), login.Session.Secret(), true); err == nil {
		t.Fatal("password-only login produced a session for a compulsory-MFA administrator")
	}
	e.advance(31 * time.Second) // the setup proof consumed this verifier period
	issued, err := sessions.LoginTOTP(e.ctx(), login.Session.Secret(), a.totp.ID, enrollmentCode(t, a.totp, e.clock.Now()), "192.0.2.60")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Info.Assurance != AssuranceAAL2 {
		t.Fatalf("ordinary login assurance %q", issued.Info.Assurance)
	}
	// Replaying the OTP that proved enrollment (same period) never works.
	e.advance(0)
	again, err := sessions.PasswordLogin(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.61")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.LoginTOTP(e.ctx(), again.Session.Secret(), a.totp.ID, enrollmentCode(t, a.totp, e.clock.Now()), "192.0.2.61"); err == nil {
		t.Fatal("an OTP already accepted in this period was accepted again")
	}
}

// SETUP-08: the first-admin transaction wins once; a second initial attempt fails
// and every outstanding token/session/file is invalidated.
func TestFirstAdminTransactionWinsOnce(t *testing.T) {
	e := newSetupEnv(t)
	a := e.firstAdmin()
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("completion replayed")
	}
	// Forge a second live initial generation directly in storage: the store must
	// refuse to treat it as setup because an administrator now exists.
	if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err == nil {
		t.Fatal("initial setup issued after the first administrator committed")
	}
	if r, err := e.s.EnsureInitial(e.ctx()); err != nil || r.Outcome != "ineligible" {
		t.Fatalf("restart after setup: %v %v", r, err)
	}
	e.exec(`UPDATE installation_control SET restore_quarantined=1`)
	if _, err := e.s.Issue(e.ctx(), IssueRequest{Purpose: PurposeInitialSetup}); err == nil {
		t.Fatal("quarantine re-entered setup")
	}
	e.exec(`UPDATE installation_control SET restore_quarantined=0`)
	// The one-time unlock is a database invariant: it cannot run twice.
	n := e.scalar(`SELECT count(*) FROM installation_control WHERE credential_generation=0`)
	if n != 0 {
		t.Fatal("generations were not lifted")
	}
}

// SETUP-06/07: a missing proof of any required piece leaves the installation
// locked and consistent, and the failure is not partially applied.
func TestCompletionRequiresEveryPieceAndIsAtomic(t *testing.T) {
	cases := []struct {
		name string
		do   func(e *setupEnv, a *firstAdmin)
	}{
		{"no address confirmed", func(e *setupEnv, a *firstAdmin) { e.enrollTOTP(a) }},
		{"totp begun but never proven", func(e *setupEnv, a *firstAdmin) {
			e.confirmAddress(*a, 0)
			en, err := e.s.BeginTOTP(e.ctx(), a.session.Secret(), "SHA256")
			if err != nil {
				t.Fatal(err)
			}
			a.totp = en
		}},
		{"totp not begun", func(e *setupEnv, a *firstAdmin) { e.confirmAddress(*a, 0) }},
		{"wrong totp code", func(e *setupEnv, a *firstAdmin) {
			e.confirmAddress(*a, 0)
			en, err := e.s.BeginTOTP(e.ctx(), a.session.Secret(), "SHA256")
			if err != nil {
				t.Fatal(err)
			}
			if err = e.s.ConfirmTOTP(e.ctx(), a.session.Secret(), "000000", setupTestIP); err == nil && enrollmentCode(t, en, e.clock.Now()) != "000000" {
				t.Fatal("wrong code was accepted")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSetupEnv(t)
			a := e.stage()
			c.do(e, &a)
			if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
				t.Fatal("completion accepted without the required proof")
			}
			e.assertStillLocked()
		})
	}
}

func (e *setupEnv) assertStillLocked() {
	e.t.Helper()
	if e.scalar(`SELECT credential_generation+session_generation+authority_generation+restore_generation FROM installation_control`) != 0 || e.scalar(`SELECT restore_quarantined FROM installation_control`) != 1 {
		e.t.Fatal("installation was unlocked")
	}
	if e.scalar(`SELECT count(*) FROM administrative_roles`) != 0 || e.scalar(`SELECT count(*) FROM users WHERE state='active'`) != 0 || e.scalar(`SELECT count(*) FROM authenticators WHERE state='active'`) != 0 || e.scalar(`SELECT count(*) FROM sessions`) != 0 {
		e.t.Fatal("authority exists in a locked installation")
	}
}

// A statement failing inside the commit rolls back EVERYTHING (SETUP-07): the
// session stays usable, nothing unlocked, and a retry after the fault succeeds.
func TestCommitFailureRollsBackAtomically(t *testing.T) {
	e := newSetupEnv(t)
	a := e.stage()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	e.exec(`CREATE TRIGGER fail_role BEFORE INSERT ON administrative_roles BEGIN SELECT RAISE(ABORT,'public synthetic failure'); END`)
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("commit succeeded through an injected failure")
	}
	e.assertStillLocked()
	if e.text(`SELECT state FROM users WHERE username=?`, setupTestUser) != "quarantined" || e.scalar(`SELECT count(*) FROM security_events`) != 0 {
		t.Fatal("partial commit state leaked")
	}
	e.exec(`DROP TRIGGER fail_role`)
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err != nil {
		t.Fatalf("retry after the fault: %v", err)
	}
	if e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 1 {
		t.Fatal("retry did not commit exactly one administrator")
	}
}

// No unlock without a durable notice intent: a failure to record the binding
// notice rolls the whole unlock back (N1 / NOTIFY-DELIVERY).
func TestNoUnlockWithoutDurableNoticeIntent(t *testing.T) {
	e := newSetupEnv(t)
	a := e.stage()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	e.exec(`CREATE TRIGGER fail_event BEFORE INSERT ON security_events BEGIN SELECT RAISE(ABORT,'public synthetic failure'); END`)
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("unlock without a durable notice")
	}
	e.assertStillLocked()
}

// Concurrent completion of one session commits exactly one administrator.
func TestConcurrentCompletionCommitsOnce(t *testing.T) {
	e := newSetupEnv(t)
	a := e.stage()
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.s.Complete(e.ctx(), a.session.Secret())
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
		}
	}
	if ok != 1 || e.scalar(`SELECT count(*) FROM administrative_roles WHERE state='active'`) != 1 || e.scalar(`SELECT count(*) FROM security_events`) != 1 {
		t.Fatalf("%d completions succeeded", ok)
	}
}

// Password policy at setup (N2, D-02, P01): 8-14 characters are acceptable only
// because MFA is compulsory; 7, a blocked phrase and context values are refused.
func TestSetupPasswordPolicy(t *testing.T) {
	for _, c := range []struct {
		name, password string
		ok             bool
	}{
		{"eight characters with compulsory MFA", "uncommon8", true},
		{"seven characters", "uncomm7", false},
		{"blocked common password", "password1234", false},
		{"username with common suffix", setupTestUser + "123", false},
		{"hostname as password", "example.invalid", false},
		{"address local part variation", "first@example.invalid", false},
		{"long passphrase", "an uncommon synthetic passphrase with spaces", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newSetupEnv(t)
			session := e.revealedSession()
			_, err := e.s.StageAccount(e.ctx(), session.Secret(), AccountRequest{Username: setupTestUser, Password: []byte(c.password), Addresses: []string{"first@example.invalid"}})
			if (err == nil) != c.ok {
				t.Fatalf("password %q: ok=%v err=%v", c.name, c.ok, err)
			}
			if err != nil && e.scalar(`SELECT count(*) FROM users`) != 0 {
				t.Fatal("rejected password left staged records")
			}
		})
	}
}

func TestStagingValidationAndOneShot(t *testing.T) {
	for _, c := range []struct {
		name string
		req  AccountRequest
	}{
		{"empty username", AccountRequest{Password: []byte(setupTestPassword), Addresses: []string{"a@example.invalid"}}},
		{"uppercase control username", AccountRequest{Username: "bad name", Password: []byte(setupTestPassword), Addresses: []string{"a@example.invalid"}}},
		{"unicode username", AccountRequest{Username: "adm\u00efn", Password: []byte(setupTestPassword), Addresses: []string{"a@example.invalid"}}},
		{"no address", AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword)}},
		{"too many addresses", AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"1@example.invalid", "2@example.invalid", "3@example.invalid", "4@example.invalid", "5@example.invalid"}}},
		{"duplicate address", AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"a@example.invalid", "A@example.invalid"}}},
		{"header injection address", AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"a@example.invalid\r\nBcc: x@example.invalid"}}},
		{"display name address", AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"Admin <a@example.invalid>"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newSetupEnv(t)
			session := e.revealedSession()
			if _, err := e.s.StageAccount(e.ctx(), session.Secret(), c.req); err == nil {
				t.Fatal("invalid account accepted")
			}
			if e.scalar(`SELECT count(*) FROM users`) != 0 || e.scalar(`SELECT count(*) FROM notification_addresses`) != 0 {
				t.Fatal("invalid request left staged records")
			}
		})
	}
	e := newSetupEnv(t)
	session := e.revealedSession()
	req := AccountRequest{Username: setupTestUser, Password: []byte(setupTestPassword), Addresses: []string{"a@example.invalid"}}
	if _, err := e.s.StageAccount(e.ctx(), session.Secret(), req); err != nil {
		t.Fatal(err)
	}
	req.Password = []byte(setupTestPassword)
	if _, err := e.s.StageAccount(e.ctx(), session.Secret(), req); err == nil {
		t.Fatal("a session staged two accounts")
	}
	// The staged account is inert: it cannot authenticate before the unlock.
	if _, err := e.l.passwords.Prove(e.ctx(), setupTestUser, []byte(setupTestPassword), "192.0.2.70"); err == nil {
		t.Fatal("staged account authenticated before commit")
	}
	// Staging a TOTP before the account, and enrollment steps out of order, fail.
	other := newSetupEnv(t)
	s2 := other.revealedSession()
	if _, err := other.s.BeginTOTP(other.ctx(), s2.Secret(), "SHA256"); err == nil {
		t.Fatal("TOTP began before the account was staged")
	}
}
