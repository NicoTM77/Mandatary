package auth

import (
	"context"
	"strings"
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

// C2 parity after a factor becomes unusable (rework 430, review F3). A legitimate
// skip-MFA AAL1 session is issued while the second factor is live (approved
// optional-MFA behaviour); the factor is then made unusable in every way the
// product can. The session service and the shared authorizer verifier must keep
// judging that SAME session identically (both accept it as AAL1: blocked issuance
// plus revocation is the control, not a Sessions-only rejection), and the
// session carries no sensitive authority while the retained floor stays 2.
func TestSkipMFASessionParityAfterFactorBecomesUnusable(t *testing.T) { // C2, E03, E09, E12, D-04
	disable := `UPDATE authenticators SET state='disabled',failed_attempts=retry_ceiling WHERE id=?`
	expire := `UPDATE authenticators SET expires_at=created_at+1 WHERE id=?`
	retire := func(r string) string {
		if r == "" {
			return `UPDATE authenticators SET state='revoked',revoked_at=?,changed_at=? WHERE id=?`
		}
		return `UPDATE authenticators SET state='revoked',revoked_at=?,changed_at=?,retirement_reason='` + r + `' WHERE id=?`
	}
	type factor struct {
		name  string
		setup func(e *sessionEnv) string
	}
	factors := []factor{
		{"TOTP", func(e *sessionEnv) string { id, _ := e.mfaAccount(); return id }},
		{"key", func(e *sessionEnv) string {
			_, id := e.enrollKey()
			e.retireSeed()
			e.clock.Advance(time.Minute)
			return id
		}},
	}
	mutations := []struct {
		name string
		sql  func() string
		gate bool // true: the floor drops to 1 and sensitive writes are admitted
	}{
		{"exhausted or disabled", func() string { return disable }, false},
		{"expired", func() string { return expire }, false},
		{"retired protective", func() string { return retire(retireProtective) }, false},
		{"retired legacy NULL provenance", func() string { return retire("") }, false},
		{"retired authorized removal", func() string { return retire(retireAuthorized) }, true},
		{"retired recovery replacement", func() string { return retire(retireRecovered) }, true},
	}
	for _, f := range factors {
		for _, m := range mutations {
			t.Run(f.name+" "+m.name, func(t *testing.T) {
				e := newSessionEnv(t)
				id := f.setup(e)
				po := e.passwordOnly()
				if po.Info.Assurance != AssurancePasswordOnly {
					t.Fatalf("control: skip-MFA session is %v", po.Info.Assurance)
				}
				if _, err := e.s.Authenticate(t.Context(), po.Secret(), false); err != nil {
					t.Fatal("control: session service rejected the issued session", err)
				}
				if _, err := e.verify(po.Secret()); err != nil {
					t.Fatal("control: authorizer verifier rejected the issued session", err)
				}
				e.clock.Advance(time.Second)
				now := e.clock.Now().Unix()
				switch q := m.sql(); {
				case strings.Contains(q, "revoked_at=?"):
					e.exec(q, now, now, id)
				default:
					e.exec(q, id)
				}
				e.clock.Advance(time.Second)
				info, ours := e.s.Authenticate(t.Context(), po.Secret(), false)
				vp, theirs := e.verify(po.Secret())
				if (ours == nil) != (theirs == nil) {
					t.Fatalf("C2 disagreement: session service err=%v, authorizer verifier err=%v", ours, theirs)
				}
				if ours != nil {
					t.Fatalf("an already-issued AAL1 session must stay accepted by both layers, got %v", ours)
				}
				if vp.AchievedAssurance != 1 || info.Assurance != AssurancePasswordOnly {
					t.Fatalf("assurance upgraded: verifier=%d session=%v", vp.AchievedAssurance, info.Assurance)
				}
				for _, op := range SensitiveOperations() {
					err := e.s.RequireSensitive(info.SessionInfo, op)
					// AAL2-only classes are never admitted to an AAL1 session; the
					// floor-based classes follow the retained floor.
					want := m.gate && !sensitivePolicies[op].aal2
					if want != (err == nil) {
						t.Fatalf("%s: sensitive gate err=%v, want admitted=%v (floor %d)", op, err, want, info.RequiredAssurance)
					}
					if err != nil && err != ErrAssuranceUnavailable {
						t.Fatalf("%s: an AAL1 session without a usable factor must be assurance-unavailable, got %v", op, err)
					}
				}
				if _, lifeErr := e.l.BeginTOTP(t.Context(), po.Secret(), "SHA256"); m.gate != (lifeErr == nil) {
					t.Fatalf("lifecycle binding err=%v, want admitted=%v", lifeErr, m.gate)
				}
			})
		}
	}
}

// A password holder can push a live TOTP over its retry ceiling through the real
// LoginTOTP path. That crossing revokes no sessions, so both layers must keep
// agreeing on the skip-MFA session issued before it, and the session still has no
// sensitive authority.
func TestSkipMFASessionParityAfterRealRetryCeilingCrossing(t *testing.T) { // C2, E09, D-04
	e := newSessionEnv(t)
	id, _ := e.mfaAccount()
	po := e.passwordOnly()
	e.exec(`UPDATE authenticators SET failed_attempts=retry_ceiling-1 WHERE id=?`, id)
	r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.40")
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(31 * time.Second)
	if _, err = e.s.LoginTOTP(t.Context(), r.Session.Secret(), id, "000000", "192.0.2.40"); err == nil {
		t.Fatal("wrong code accepted")
	}
	if e.scalar(`SELECT failed_attempts>=retry_ceiling AND state='disabled' FROM authenticators WHERE id=?`, id) != 1 {
		t.Fatal("setup: the ceiling was not really crossed")
	}
	info, ours := e.s.Authenticate(t.Context(), po.Secret(), false)
	_, theirs := e.verify(po.Secret())
	if (ours == nil) != (theirs == nil) {
		t.Fatalf("C2 disagreement after real ceiling crossing: session service err=%v, authorizer verifier err=%v", ours, theirs)
	}
	if ours != nil {
		t.Fatalf("ceiling crossing must not revoke or reject the earlier AAL1 session in either layer: %v", ours)
	}
	for _, op := range SensitiveOperations() {
		if err := e.s.RequireSensitive(info.SessionInfo, op); err != ErrAssuranceUnavailable {
			t.Fatalf("%s admitted or mis-signalled after the factor was exhausted: %v", op, err)
		}
	}
	// New password-only issuance stays blocked: the blocked-issuance control.
	if r, err := e.s.PasswordLogin(t.Context(), "synthetic-user", []byte(sessionTestPassword), "192.0.2.41"); err == nil {
		t.Fatalf("password login issued a session on a stranded floor-2 account: %+v", r.Session.Info)
	}
}
