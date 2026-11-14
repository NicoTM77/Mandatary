package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"time"
)

// The REAL host-authorized restore-administrator recovery (security-contracts.md S2.2.5, RESTORE-08), driven through the
// production Setup service over the fixture's own repository: issue on the host helper's protocol, reveal on a terminal,
// exchange, stage a NEW account with a fresh password, prove a fresh address and a fresh TOTP, complete. It replaces the
// earlier model that re-activated the backup administrator's authenticators and its revoked session, which the contract
// forbids (S2.2.3/5): after this ceremony the backup administrator and everything it held stay inactive and the only
// effective person is the NEW recovery administrator.
//
// Only two things are synthetic: the mail transport (the address proof is captured instead of mailed; the real SMTP path
// is exercised by the setup tests) and the administrator's AAL2 session row, which is the same row Sessions.LoginTOTP issues
// (see adminEnv.aal2Session) but without the process-wide serialized password work, so parallel fixtures stay parallel.
// TestRestoreRecoveryEnrollsExactlyOneFreshAdministratorAndApprovesNothing signs in through the real login.

const (
	fixtureRecoveryUser     = "recovery-admin"
	fixtureRecoveryPassword = "synthetic recovery passphrase 52"
	fixtureRecoveryAddress  = "recovery@example.invalid"
)

// RecoveredAdmin is what the ceremony produced.
type RecoveredAdmin struct {
	Username string
	Password string
	// Seed is the base32 TOTP seed the person saw exactly once during enrollment (a browser fixture computes codes from it).
	Seed   string
	UserID string
	totp   Enrollment
}

// hostRecoveryCeremony runs the real ceremony and returns the recovery administrator. It does NOT sign anybody in.
func (e *adminEnv) hostRecoveryCeremony() RecoveredAdmin {
	e.t.Helper()
	ctx := e.t.Context()
	s, err := NewSetup(e.l.repo, e.l, SetupSettings{Build: "fixture-build"})
	if err != nil {
		e.t.Fatal(err)
	}
	s.now = e.clock.Now
	var proof string
	s.sendProof = func(_ context.Context, _, p string) string { proof = p; return "" }

	if _, err = s.Issue(ctx, IssueRequest{Purpose: PurposeRestoreRecovery, RiskAcknowledged: true}); err != nil {
		e.t.Fatalf("host issue: %v", err)
	}
	term := &fakeTerminal{}
	if _, err = s.Reveal(ctx, PurposeRestoreRecovery, "", term); err != nil || term.token() == "" {
		e.t.Fatalf("host reveal: %v", err)
	}
	session, err := s.Exchange(ctx, term.token(), setupTestIP)
	if err != nil {
		e.t.Fatalf("exchange: %v", err)
	}
	secret := session.Secret()
	addresses, err := s.StageAccount(ctx, secret, AccountRequest{Username: fixtureRecoveryUser, Password: []byte(fixtureRecoveryPassword), Addresses: []string{fixtureRecoveryAddress}})
	if err != nil {
		e.t.Fatalf("stage: %v", err)
	}
	if err = s.SendAddressProof(ctx, secret, addresses[0].ID); err != nil || proof == "" {
		e.t.Fatalf("address proof: %v", err)
	}
	if err = s.ConfirmAddress(ctx, secret, addresses[0].ID, proof, setupTestIP); err != nil {
		e.t.Fatalf("confirm address: %v", err)
	}
	en, err := s.BeginTOTP(ctx, secret, "SHA256")
	if err != nil {
		e.t.Fatalf("begin totp: %v", err)
	}
	if err = s.ConfirmTOTP(ctx, secret, enrollmentCode(e.t, en, e.clock.Now()), setupTestIP); err != nil {
		e.t.Fatalf("confirm totp: %v", err)
	}
	if _, err = s.Complete(ctx, secret); err != nil {
		e.t.Fatalf("complete: %v", err)
	}
	var userID string
	if err = e.db.QueryRow(`SELECT id FROM users WHERE username=? AND state='active'`, fixtureRecoveryUser).Scan(&userID); err != nil {
		e.t.Fatalf("the recovery administrator is not active: %v", err)
	}
	return RecoveredAdmin{Username: fixtureRecoveryUser, Password: fixtureRecoveryPassword, Seed: en.secret, UserID: userID, totp: en}
}

// signInRecoveryAdmin stores the AAL2 password+TOTP session the recovery administrator's ordinary login would produce, at
// the CURRENT control generations, makes it the fixture's administrator session and returns its cookie value and CSRF token.
func (e *adminEnv) signInRecoveryAdmin(r RecoveredAdmin) (cookie, csrf string) {
	e.t.Helper()
	var pwd, totp string
	if err := e.db.QueryRow(`SELECT id FROM authenticators WHERE user_id=? AND kind='password' AND state='active'`, r.UserID).Scan(&pwd); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.QueryRow(`SELECT id FROM authenticators WHERE user_id=? AND kind='totp' AND state='active'`, r.UserID).Scan(&totp); err != nil {
		e.t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		e.t.Fatal(err)
	}
	const id = "recovery-admin-aal2"
	now := e.clock.Now().Unix()
	sum := sha256.Sum256(secret)
	cfg := DefaultSessionSettings()
	credential := e.scalar(`SELECT credential_generation FROM installation_control`)
	sessionGen := e.scalar(`SELECT session_generation FROM installation_control`)
	e.exec(`INSERT INTO sessions(id,user_id,secret_hash,purpose,achieved_assurance,methods,phishing_resistant,authenticated_at,created_at,expires_at,last_activity_at,idle_timeout_seconds,credential_generation,session_generation,state) VALUES(?,?,?,'normal',2,?,0,?,?,?,?,?,?,?,'active')`,
		id, r.UserID, sum[:], evidencePassword|evidenceTOTP, now, now, now+int64(cfg.Absolute/time.Second), now, int64(cfg.Idle/time.Second), credential, sessionGen)
	for _, a := range []string{pwd, totp} {
		e.exec(`INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES(?,?,?)`, id, a, r.UserID)
	}
	e.secret, e.sessID = secret, id
	return encodeSessionCookie(secret), csrfToken(secret, id)
}
