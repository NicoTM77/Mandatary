package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// Sessions issued here must be judged identically by the shared authorizer's
// credential verifier (C2 boundary). Any disagreement would let one layer trust a
// session the other rejects, so both are driven through the same mutations.

func (e *sessionEnv) verify(secret []byte) (authz.VerifiedPrincipal, error) {
	var vp authz.VerifiedPrincipal
	err := e.l.repo.Read(context.Background(), func(q *store.Queries) error {
		c, err := q.GetInstallationControl(context.Background())
		if err != nil {
			return err
		}
		vp, err = authz.NewStoreCredentialVerifier().VerifyPrincipal(context.Background(), q, c, authz.PrincipalCredentials{SessionSecret: secret}, e.clock.Now())
		return err
	})
	return vp, err
}

func TestIssuedSessionsAreAcceptedAndRejectedIdenticallyByTheAuthorizerVerifier(t *testing.T) { // C2, N63B4-SCOPE-ADMIN, SCOPE-PASSWORD
	mutations := map[string]string{
		"none":                  ``,
		"administrator role":    `INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('adm','u','super_admin','active',1)`,
		"MFA required":          `UPDATE users SET mfa_requirement='required'`,
		"WebAuthn only":         `UPDATE users SET mfa_requirement='webauthn'`,
		"compromised":           `UPDATE users SET compromised=1`,
		"user disabled":         `UPDATE users SET state='disabled'`,
		"session generation":    `UPDATE installation_control SET session_generation=session_generation+1`,
		"credential generation": `UPDATE installation_control SET credential_generation=credential_generation+1`,
		"restore quarantine":    `UPDATE installation_control SET restore_quarantined=1`,
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			e := newSessionEnv(t)
			id, en := e.mfaAccount()
			po := e.passwordOnly()
			aal2 := e.aal2TOTP(id, en)
			pre, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "" {
				e.exec(mutation)
			}
			for label, secret := range map[string][]byte{"password-only": po.Secret(), "AAL2": aal2.Secret()} {
				_, ours := e.s.Authenticate(t.Context(), secret, false)
				vp, theirs := e.verify(secret)
				if (ours == nil) != (theirs == nil) {
					t.Fatalf("%s: session service err=%v, authorizer verifier err=%v", label, ours, theirs)
				}
				if ours == nil && label == "password-only" && vp.AchievedAssurance != 1 {
					t.Fatal("password-only session verified above AAL1")
				}
				if ours == nil && label == "AAL2" && (vp.AchievedAssurance != 2 || vp.PhishingResistant) {
					t.Fatal("TOTP session verified with wrong assurance")
				}
			}
			// A preauth capability is accepted by neither.
			if _, err := e.verify(pre.Session.Secret()); err == nil {
				t.Fatal("authorizer verifier accepted a preauth capability")
			}
			if _, err := e.s.Authenticate(t.Context(), pre.Session.Secret(), false); err == nil {
				t.Fatal("session service accepted a preauth capability")
			}
		})
	}
}

func TestConcurrentCompletionOfOnePreauthYieldsOneSession(t *testing.T) { // SESSION-CREATION / fixation under race
	e := newSessionEnv(t)
	e.enrollTOTP()
	e.retireSeed()
	e.clock.Advance(time.Minute)
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	baseline := e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal' AND state='active'`)
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.s.LoginWithoutMFA(t.Context(), r.Session.Secret()); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || e.scalar(`SELECT count(*) FROM sessions WHERE purpose='normal' AND state='active'`) != baseline+1 {
		t.Fatalf("%d sessions minted from one preauth capability", wins.Load())
	}
}

func TestLiveSessionsPerUserAreBounded(t *testing.T) { // resource bound; oldest preauth/session is revoked first
	e := newSessionEnv(t)
	e.retireSeed()
	e.s.maxLive = 3
	var all []IssuedSession
	for i := 0; i < 5; i++ {
		e.clock.Advance(time.Second)
		all = append(all, e.passwordOnly())
	}
	if n := e.scalar(`SELECT count(*) FROM sessions WHERE user_id='u' AND state='active' AND expires_at>?`, e.clock.Now().Unix()); n != 3 {
		t.Fatalf("%d live sessions, want exactly the bound of 3", n)
	}
	for i, s := range all {
		_, err := e.s.Authenticate(t.Context(), s.Secret(), false)
		if (i < 2) != (err == ErrDenied) {
			t.Fatalf("session %d: err=%v; only the two oldest may be revoked", i, err)
		}
	}
}

func TestSessionLifetimeFollowsConfiguredStricterSettings(t *testing.T) { // A05: configuration can only tighten
	e := newSessionEnv(t)
	s, err := NewSessions(e.l, e.w, SessionSettings{Absolute: time.Hour, Idle: 2 * time.Minute, StepUp: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	var created, expires, idle int64
	if err = e.db.QueryRow(`SELECT created_at,expires_at,idle_timeout_seconds FROM sessions WHERE id=?`, r.Session.Info.ID).Scan(&created, &expires, &idle); err != nil {
		t.Fatal(err)
	}
	if expires-created != 3600 || idle != 120 {
		t.Fatalf("persisted limits %d/%d do not follow the configuration", expires-created, idle)
	}
	e.clock.Advance(2 * time.Minute)
	if _, err = s.Authenticate(t.Context(), r.Session.Secret(), false); err != ErrDenied {
		t.Fatal("configured idle timeout not enforced")
	}
	// Step-up window follows configuration as well (5m here).
	r2, _ := s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	e.clock.Advance(5*time.Minute + time.Second)
	got, _ := s.Authenticate(t.Context(), r2.Session.Secret(), true)
	_ = got
	info := r2.Session.Info
	info.AuthenticatedAt = e.clock.Now().Add(-5*time.Minute - time.Second)
	if err = s.RequireSensitive(info, OpPasswordChange); err != ErrStepUpRequired {
		t.Fatal("configured step-up window not enforced", err)
	}
}

func TestProtectiveReportInvalidatesCopiedSessions(t *testing.T) { // COMPROMISE-REPORT, G01 immediate invalidation
	e := newSessionEnv(t)
	id, en := e.mfaAccount()
	issued := e.aal2TOTP(id, en)
	if _, err := e.s.Authenticate(t.Context(), issued.Secret(), false); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(31 * time.Second)
	if err := e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), id, sessionTestIP); err != nil {
		t.Fatal("protective report denied", err)
	}
	if _, err := e.s.Authenticate(t.Context(), issued.Secret(), false); err != ErrDenied {
		t.Fatal("session survived the compromise report of its own factor")
	}
	// The report grants no new session: a fresh password login cannot reach AAL2.
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err == nil && r.Session.Info.Assurance == AssuranceAAL2 {
		t.Fatal("compromise report produced an AAL2 session")
	}
}
