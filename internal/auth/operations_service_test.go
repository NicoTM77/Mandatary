package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/ops"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.13 integration with the REAL P1.05-P1.10 issuers (C2 checkpoint fixture IDs
// C2R-H/E/Q/R/B/T). Credentials minted by the real password, session, TOTP,
// recovery, bootstrap and agent-administration services are presented to the shared
// ops.Service over the same SQLite repository; the backend is the container-free
// mock behind an attempt-counting spy (C1 O2). Every denial must leave the spy with
// ZERO operational invocations, and every follow stream must end on every session,
// token and policy revocation or expiry (C2 observation O1: session revocation
// paths do not notify the authorizer, so the stream's own bounded revalidation is
// exercised as well as the immediate notification).

var opsOperational = map[string]bool{"InspectStatus": true, "InspectConfig": true, "Logs": true, "Start": true, "Stop": true, "Restart": true}

type opsSpy struct {
	*docker.MockBackend
	mu    sync.Mutex
	calls map[string]int
}

func (s *opsSpy) rec(n string) { s.mu.Lock(); s.calls[n]++; s.mu.Unlock() }
func (s *opsSpy) attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.calls {
		if opsOperational[k] {
			n += v
		}
	}
	return n
}
func (s *opsSpy) ResolveTarget(ctx context.Context, ref string) (docker.ContainerSummary, error) {
	s.rec("ResolveTarget")
	return s.MockBackend.ResolveTarget(ctx, ref)
}
func (s *opsSpy) InspectStatus(ctx context.Context, t docker.TargetIdentity) (docker.InspectStatus, error) {
	s.rec("InspectStatus")
	return s.MockBackend.InspectStatus(ctx, t)
}
func (s *opsSpy) InspectConfig(ctx context.Context, t docker.TargetIdentity) (docker.InspectConfig, error) {
	s.rec("InspectConfig")
	return s.MockBackend.InspectConfig(ctx, t)
}
func (s *opsSpy) Logs(ctx context.Context, t docker.TargetIdentity, o docker.LogOptions) (docker.LogStream, error) {
	s.rec("Logs")
	return s.MockBackend.Logs(ctx, t, o)
}
func (s *opsSpy) Start(ctx context.Context, t docker.TargetIdentity) error {
	s.rec("Start")
	return s.MockBackend.Start(ctx, t)
}
func (s *opsSpy) Stop(ctx context.Context, t docker.TargetIdentity, o docker.StopOptions) error {
	s.rec("Stop")
	return s.MockBackend.Stop(ctx, t, o)
}
func (s *opsSpy) Restart(ctx context.Context, t docker.TargetIdentity, o docker.RestartOptions) error {
	s.rec("Restart")
	return s.MockBackend.Restart(ctx, t, o)
}

var _ docker.DockerBackend = (*opsSpy)(nil)

// opsTicker delivers a revalidation tick only when the test sends it.
type opsTicker struct {
	ch      chan time.Time
	stopped chan struct{}
	once    sync.Once
}

func (f *opsTicker) C() <-chan time.Time { return f.ch }
func (f *opsTicker) Stop()               { f.once.Do(func() { close(f.stopped) }) }
func (f *opsTicker) tick() {
	select {
	case f.ch <- time.Time{}:
	case <-f.stopped:
	}
}

type opsHarness struct {
	t   *testing.T
	az  *authz.Authorizer
	svc *ops.Service
	spy *opsSpy
	run func(string, ...any)

	mu      sync.Mutex
	tickers []*opsTicker
}

func newOpsHarness(t *testing.T, repo *store.Repository, now func() time.Time, run func(string, ...any)) *opsHarness {
	t.Helper()
	identity, containers := docker.DefaultMockFixtures(authzEndpoint)
	m, err := docker.NewMockBackend(docker.MockOptions{EndpointID: authzEndpoint, Identity: identity, Containers: containers})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.VerifySelf(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := &opsHarness{t: t, run: run, spy: &opsSpy{MockBackend: m, calls: map[string]int{}}}
	h.az, err = authz.NewAuthorizer(authz.Config{Repository: repo, Clock: now, Backends: map[domain.EndpointID]docker.DockerBackend{authzEndpoint: h.spy}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.az.Close() })
	h.svc, err = ops.New(ops.Config{Authorizer: h.az, NewTicker: func(time.Duration) ops.Ticker {
		f := &opsTicker{ch: make(chan time.Time), stopped: make(chan struct{})}
		h.mu.Lock()
		h.tickers = append(h.tickers, f)
		h.mu.Unlock()
		return f
	}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// seed activates the local endpoint and the edge-proxy selector (a setup blocker on
// a fresh installation, so bootstrap tests seed only after completion).
func (h *opsHarness) seed() {
	h.t.Helper()
	h.run(`UPDATE endpoints SET id=?,state='active',authority_generation=1 WHERE slug='local'`, string(authzEndpoint))
	h.run(`INSERT INTO container_selectors(id,endpoint_id,container_name,name_is_glob) VALUES ('sel-ops',?,'edge-proxy',0)`, string(authzEndpoint))
}

// grant inserts an explicit ALLOW for all six operations on edge-proxy.
func (h *opsHarness) grant(col, id string) {
	h.t.Helper()
	for _, op := range ops.Operations() {
		h.run(`INSERT INTO policies(id,`+col+`,endpoint_id,selector_id,operation,effect,state,authority_generation) VALUES (?,?,?,'sel-ops',?,'ALLOW','active',1)`,
			"ops-"+col+"-"+id+"-"+string(op), id, string(authzEndpoint), string(op))
	}
	if err := h.svc.NotifyAuthorityChange(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *opsHarness) ungrant() {
	h.t.Helper()
	h.run(`DELETE FROM policies WHERE id LIKE 'ops-%'`)
	if err := h.svc.NotifyAuthorityChange(h.t.Context()); err != nil {
		h.t.Fatal(err)
	}
}

func opsRequest(creds authz.PrincipalCredentials, op docker.Operation) ops.Request {
	five := 5
	r := ops.Request{Credentials: creds, EndpointID: authzEndpoint, Target: "edge-proxy", Operation: op}
	switch op {
	case docker.OpLogs:
		r.Logs = &docker.LogOptions{Tail: 5, Stdout: true, Stderr: true}
	case docker.OpStop:
		r.Stop = &docker.StopOptions{TimeoutSeconds: &five}
	case docker.OpRestart:
		r.Restart = &docker.RestartOptions{TimeoutSeconds: &five}
	}
	return r
}

func opsSession(secret []byte) authz.PrincipalCredentials {
	return authz.PrincipalCredentials{SessionSecret: secret}
}

// allowAll: every operation is executed through the service for this identity.
func (h *opsHarness) allowAll(id string, creds authz.PrincipalCredentials) {
	h.t.Helper()
	for _, op := range ops.Operations() {
		before := h.spy.attempts()
		res, err := h.svc.Execute(h.t.Context(), opsRequest(creds, op))
		if err != nil {
			reason, _ := authz.ReasonOf(err)
			h.t.Fatalf("%s %s: expected allow, got %v (%s)", id, op, err, reason)
		}
		if res.Logs != nil {
			_ = res.Logs.Close()
		}
		if res.Target.ContainerID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			h.t.Fatalf("%s %s: dispatched on %s", id, op, res.Target.ContainerID)
		}
		if got := h.spy.attempts() - before; got != 1 {
			h.t.Fatalf("%s %s: %d operational attempts, want exactly 1", id, op, got)
		}
	}
	h.t.Logf("%s: 6/6 permission keys executed", id)
}

// denyAll: every operation is refused with the wanted status and (when set) reason,
// no stream is returned, and the backend sees ZERO operational attempts.
func (h *opsHarness) denyAll(id string, creds authz.PrincipalCredentials, want int, reason authz.DenialReason) {
	h.t.Helper()
	before := h.spy.attempts()
	leases := h.az.ActiveLeaseCount()
	for _, op := range ops.Operations() {
		res, err := h.svc.Execute(h.t.Context(), opsRequest(creds, op))
		if err == nil || res.Logs != nil || res.Status != nil || res.Config != nil {
			if res.Logs != nil {
				_ = res.Logs.Close()
			}
			h.t.Fatalf("%s %s: expected a denial, got an outcome", id, op)
		}
		if want != 0 && authz.StatusCode(err) != want {
			h.t.Fatalf("%s %s: status %d (%v), want %d", id, op, authz.StatusCode(err), err, want)
		}
		if got, _ := authz.ReasonOf(err); reason != "" && got != reason {
			h.t.Fatalf("%s %s: reason %q, want %q", id, op, got, reason)
		}
	}
	if d := h.spy.attempts() - before; d != 0 {
		h.t.Fatalf("%s: %d operational backend ATTEMPTS on denial", id, d)
	}
	// Only growth is a defect: a just-ended stream's watcher may still be releasing.
	if h.az.ActiveLeaseCount() > leases {
		h.t.Fatalf("%s: a denied request registered a lease", id)
	}
	h.t.Logf("%s: 6/6 denied status=%d reason=%q operational attempts=0", id, want, reason)
}

// opsFollow is a live follow stream with its own revalidation clock.
type opsFollow struct {
	*ops.LogStream
	tk *opsTicker
}

// settle delivers two ticks: the second is accepted only once the watcher finished
// the pass for the first, so a still-live stream is known to have been revalidated.
func (f opsFollow) settle() { f.tk.tick(); f.tk.tick() }

func (h *opsHarness) follow(creds authz.PrincipalCredentials) opsFollow {
	h.t.Helper()
	h.mu.Lock()
	n := len(h.tickers)
	h.mu.Unlock()
	r := opsRequest(creds, docker.OpLogs)
	r.Logs.Follow = true
	res, err := h.svc.Execute(h.t.Context(), r)
	if err != nil {
		h.t.Fatalf("open follow stream: %v", err)
	}
	h.t.Cleanup(func() { _ = res.Logs.Close() })
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tickers) != n+1 {
		h.t.Fatalf("follow stream started %d watchers, want 1", len(h.tickers)-n)
	}
	return opsFollow{LogStream: res.Logs, tk: h.tickers[n]}
}

func opsWaitDone(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(120 * time.Second):
		t.Fatalf("%s: not observed", what)
	}
}

func opsAlive(t *testing.T, st opsFollow, what string) {
	t.Helper()
	select {
	case <-st.Done():
		t.Fatalf("%s: stream already ended", what)
	default:
	}
}

// --- H/E/Q/R: human sessions from the real issuers ---

func TestOpsServiceHumanIdentitiesFromRealIssuers(t *testing.T) { // C2R-H01-H09, C2R-E01, C2R-Q06, C2R-R01
	e := newSessionEnv(t)
	h := newOpsHarness(t, e.l.repo, e.clock.Now, e.exec)
	h.seed()
	h.grant("user_id", "u")
	ctx := t.Context()

	// H01: password-only AAL1 (optional-MFA account) is accepted as AAL1 only.
	po := e.passwordOnly()
	h.allowAll("C2R-H01-password-only-AAL1", opsSession(po.Secret()))

	totpID, en := e.bothFactorsTOTPOnly()
	// H02: a preauth capability (password proven, MFA pending) is not an identity.
	pre, err := e.s.PasswordLogin(ctx, "synthetic-user", []byte(sessionTestPassword), sessionTestIP)
	if err != nil || pre.Session.Info.Assurance != AssurancePreauth {
		t.Fatalf("setup preauth: %v %v", err, pre.Session.Info.Assurance)
	}
	h.denyAll("C2R-H02-preauth-capability", opsSession(pre.Session.Secret()), 401, authz.ReasonUnauthenticated)

	// H03: AAL2 TOTP.
	aal2 := e.aal2TOTP(totpID, en)

	// H05: the approved optional-MFA skip path still yields AAL1 after enrollment.
	po1 := e.passwordOnly()
	if po1.Info.Assurance != AssurancePasswordOnly {
		t.Fatalf("setup: skip-MFA session assurance %v", po1.Info.Assurance)
	}
	h.allowAll("C2R-H05-skip-MFA-AAL1", opsSession(po1.Secret()))
	h.allowAll("C2R-H03-AAL2-TOTP", opsSession(aal2.Secret()))

	// H06: caller assertions never lift an AAL1 identity under a stronger requirement.
	e.exec(`UPDATE users SET mfa_requirement='required' WHERE id='u'`)
	lift := opsSession(po1.Secret())
	lift.UntrustedCallerAssurance, lift.UntrustedCallerAdmin = 2, true
	h.denyAll("C2R-H06-password-only-vs-required-MFA", opsSession(po1.Secret()), 401, authz.ReasonUnauthenticated)
	h.denyAll("C2R-H06b-caller-asserted-AAL2", lift, 401, authz.ReasonUnauthenticated)
	h.allowAll("C2R-H06c-TOTP-satisfies-required", opsSession(aal2.Secret()))

	// H07: a phishing-resistant requirement is not met by TOTP.
	e.exec(`UPDATE users SET mfa_requirement='webauthn' WHERE id='u'`)
	h.denyAll("C2R-H07-TOTP-vs-webauthn-requirement", opsSession(aal2.Secret()), 401, authz.ReasonUnauthenticated)
	e.exec(`UPDATE users SET mfa_requirement='optional' WHERE id='u'`)

	// H08: an administrator role raises the floor and grants nothing.
	e.exec(`INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES('ops-adm','u','super_admin','active',1)`)
	h.denyAll("C2R-H08-admin-AAL1", opsSession(po1.Secret()), 401, authz.ReasonUnauthenticated)
	h.allowAll("C2R-H08b-admin-AAL2-with-explicit-grant", opsSession(aal2.Secret()))
	h.ungrant()
	h.denyAll("C2R-H08c-admin-AAL2-without-grant", opsSession(aal2.Secret()), 403, authz.ReasonDefaultDeny)
	e.exec(`DELETE FROM administrative_roles WHERE id='ops-adm'`)
	h.grant("user_id", "u")

	// Q06: a real protective TOTP compromise report ends the factor-bound session.
	e.clock.Advance(31 * time.Second)
	if err = e.l.ReportTOTPCompromise(ctx, "synthetic-user", []byte(sessionTestPassword), totpID, sessionTestIP); err != nil {
		t.Fatal(err)
	}
	h.denyAll("C2R-Q06-after-real-TOTP-compromise-report", opsSession(aal2.Secret()), 401, authz.ReasonUnauthenticated)

	// E01: idle expiry through the same service.
	e.clock.Advance(DefaultSessionIdle)
	h.denyAll("C2R-E01-idle-expired", opsSession(po1.Secret()), 401, authz.ReasonUnauthenticated)
	if h.spy.attempts() == 0 {
		t.Fatal("control: nothing was ever dispatched")
	}
}

// bothFactorsTOTPOnly enrolls one TOTP factor on the optional-MFA account without
// forcing the MFA requirement, so password-only and AAL2 sessions coexist.
func (e *sessionEnv) bothFactorsTOTPOnly() (string, Enrollment) {
	e.t.Helper()
	id, en := e.enrollTOTP()
	e.retireSeed()
	e.clock.Advance(time.Minute)
	return id, en
}

func TestOpsServiceRecoveryCapabilityIsNotAnIdentity(t *testing.T) { // C2R-R01, R02, R03
	e := newSessionEnv(t)
	h := newOpsHarness(t, e.l.repo, e.clock.Now, e.exec)
	h.seed()
	h.grant("user_id", "u")
	ctx := t.Context()
	totpID, en := e.mfaAccount()
	aal2 := e.aal2TOTP(totpID, en)
	codes, err := e.l.IssueRecoveryCodes(ctx, aal2.Secret())
	if err != nil {
		t.Fatal(err)
	}
	list := codes.ExportOnce()
	if len(list) == 0 {
		t.Fatal("no saved codes")
	}
	h.allowAll("C2R-R00-control-ordinary-AAL2-before-recovery", opsSession(aal2.Secret()))
	st := h.follow(opsSession(aal2.Secret()))

	e.clock.Advance(time.Minute)
	res, err := e.l.Recover(ctx, "synthetic-user", []byte(sessionTestPassword), list[0], sessionTestIP)
	if err != nil {
		t.Fatal("recover:", err)
	}
	capSecret, replacement := res.ExportOnce()
	if len(capSecret) == 0 || len(replacement) == 0 {
		t.Fatal("recovery result empty")
	}
	h.denyAll("C2R-R01-recovery-capability-as-session", opsSession(capSecret), 401, authz.ReasonUnauthenticated)
	h.denyAll("C2R-R01b-recovery-capability-as-agent-token", authz.PrincipalCredentials{AgentToken: string(capSecret)}, 401, "")
	// Entering saved-code recovery revoked the ordinary session in the same transaction:
	// refused at once, and the live stream ends on its next bounded revalidation.
	h.denyAll("C2R-R03-pre-recovery-AAL2-revoked-by-recovery", opsSession(aal2.Secret()), 401, authz.ReasonUnauthenticated)
	st.tk.tick()
	opsWaitDone(t, st.Done(), "stream end after recovery entry")
}

// --- O1: every real session-revocation path ends an active follow stream ---

func TestOpsFollowStreamEndsOnEveryRealSessionRevocationPath(t *testing.T) { // C2R-O1 (required by the P1.13 card)
	type path struct {
		id     string
		revoke func(t *testing.T, e *sessionEnv, aal2 IssuedSession, totpID string)
	}
	paths := []path{
		{"logout", func(t *testing.T, e *sessionEnv, aal2 IssuedSession, _ string) {
			if err := e.s.Logout(t.Context(), aal2.Secret()); err != nil {
				t.Fatal(err)
			}
		}},
		{"saved-code-recovery-entry", func(t *testing.T, e *sessionEnv, aal2 IssuedSession, _ string) {
			codes, err := e.l.IssueRecoveryCodes(t.Context(), aal2.Secret())
			if err != nil {
				t.Fatal(err)
			}
			e.clock.Advance(time.Minute)
			if _, err = e.l.Recover(t.Context(), "synthetic-user", []byte(sessionTestPassword), codes.ExportOnce()[0], sessionTestIP); err != nil {
				t.Fatal(err)
			}
		}},
		{"protective-TOTP-compromise-report", func(t *testing.T, e *sessionEnv, _ IssuedSession, totpID string) {
			e.clock.Advance(31 * time.Second)
			if err := e.l.ReportTOTPCompromise(t.Context(), "synthetic-user", []byte(sessionTestPassword), totpID, sessionTestIP); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, p := range paths {
		for _, trigger := range []string{"notify", "bounded-revalidation"} {
			t.Run(p.id+"/"+trigger, func(t *testing.T) {
				e := newSessionEnv(t)
				h := newOpsHarness(t, e.l.repo, e.clock.Now, e.exec)
				h.seed()
				h.grant("user_id", "u")
				totpID, en := e.mfaAccount()
				aal2 := e.aal2TOTP(totpID, en)
				st := h.follow(opsSession(aal2.Secret()))
				opsAlive(t, st, "before revocation")
				p.revoke(t, e, aal2, totpID)
				before := h.spy.attempts()
				switch trigger {
				case "notify":
					if err := h.svc.NotifyAuthorityChange(t.Context()); err != nil {
						t.Fatal(err)
					}
				default:
					st.tk.tick()
				}
				opsWaitDone(t, st.Done(), "stream end")
				if _, err := st.Next(t.Context()); err == nil {
					t.Fatal("a frame was delivered after the session was revoked")
				}
				opsWaitDone(t, st.tk.stopped, "watcher exit")
				if n := h.az.ActiveLeaseCount(); n != 0 {
					t.Fatalf("%d leases remain", n)
				}
				h.denyAll("fresh-requests-after-"+p.id, opsSession(aal2.Secret()), 401, authz.ReasonUnauthenticated)
				if h.spy.attempts() != before {
					t.Fatal("operational attempt after session revocation")
				}
			})
		}
	}
}

// --- B: bootstrap and host MFA reset are bootstrap/recovery-only identities ---

func TestOpsServiceBootstrapAndHostRecoveryAreNeverOperationalIdentities(t *testing.T) { // C2R-B01..B08, O1 (MFA-reset issuance)
	e := newSetupEnv(t)
	ctx := e.ctx()
	a := e.stage() // live initial-setup session on a still-locked installation
	h := newOpsHarness(t, e.repo, e.clock.Now, e.exec)
	h.denyAll("C2R-B01-live-initial-setup-session-locked-install", opsSession(a.session.Secret()), 0, "")
	h.denyAll("C2R-B01b-setup-session-as-agent-token", authz.PrincipalCredentials{AgentToken: string(a.session.Secret())}, 0, "")
	e.confirmAddress(a, 0)
	e.enrollTOTP(&a)
	if _, err := e.s.Complete(ctx, a.session.Secret()); err != nil {
		t.Fatal(err)
	}
	var adminID string
	if err := e.db.QueryRow(`SELECT id FROM users WHERE username=?`, setupTestUser).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	h.seed()
	h.grant("user_id", adminID)
	h.denyAll("C2R-B02-spent-setup-session-unlocked-install", opsSession(a.session.Secret()), 401, authz.ReasonUnauthenticated)

	sessions := e.sessions()
	login := func(ip string, en Enrollment) IssuedSession {
		t.Helper()
		e.advance(31 * time.Second)
		pre, err := sessions.PasswordLogin(ctx, setupTestUser, []byte(setupTestPassword), ip)
		if err != nil {
			t.Fatal(err)
		}
		h.denyAll("C2R-B03-admin-preauth-"+ip, opsSession(pre.Session.Secret()), 401, authz.ReasonUnauthenticated)
		s, err := sessions.LoginTOTP(ctx, pre.Session.Secret(), en.ID, enrollmentCode(t, en, e.clock.Now()), ip)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	adm := login("192.0.2.90", a.totp)
	h.allowAll("C2R-B04-bootstrapped-admin-ordinary-AAL2", opsSession(adm.Secret()))
	st := h.follow(opsSession(adm.Secret()))

	// Host MFA-reset issuance revokes the administrator's sessions at once; the stream
	// ends via the bounded revalidation (the issuing path does not notify).
	if _, err := e.s.Issue(ctx, IssueRequest{Purpose: PurposeMFAReset, Username: setupTestUser, RiskAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	h.denyAll("C2R-B05-admin-session-after-reset-issuance", opsSession(adm.Secret()), 401, authz.ReasonUnauthenticated)
	st.tk.tick()
	opsWaitDone(t, st.Done(), "stream end after MFA-reset issuance")

	token := e.reveal(PurposeMFAReset, setupTestUser)
	rs, err := e.s.Exchange(ctx, token, setupTestIP)
	if err != nil {
		t.Fatal(err)
	}
	h.denyAll("C2R-B06-live-mfa-reset-session", opsSession(rs.Secret()), 401, authz.ReasonUnauthenticated)
	h.denyAll("C2R-B06b-mfa-reset-session-as-agent-token", authz.PrincipalCredentials{AgentToken: string(rs.Secret())}, 401, "")
	h.denyAll("C2R-B06c-raw-reset-token-as-session", opsSession([]byte(token)), 401, authz.ReasonUnauthenticated)
	en, err := e.s.BeginTOTP(ctx, rs.Secret(), "SHA256")
	if err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Second)
	if err = e.s.ConfirmTOTP(ctx, rs.Secret(), enrollmentCode(t, en, e.clock.Now()), setupTestIP); err != nil {
		t.Fatal(err)
	}
	if _, err = e.s.Complete(ctx, rs.Secret()); err != nil {
		t.Fatal(err)
	}
	h.denyAll("C2R-B07-spent-reset-session", opsSession(rs.Secret()), 401, authz.ReasonUnauthenticated)
	h.denyAll("C2R-B07c-pre-reset-admin-session", opsSession(adm.Secret()), 401, authz.ReasonUnauthenticated)
	adm2 := login("192.0.2.91", en)
	h.allowAll("C2R-B08-post-reset-ordinary-AAL2", opsSession(adm2.Secret()))
	h.ungrant()
	h.denyAll("C2R-B08b-bootstrapped-super-admin-no-grant", opsSession(adm2.Secret()), 403, authz.ReasonDefaultDeny)
}

// --- T: agent tokens from the real P1.10 administration service ---

func TestOpsServiceAgentTokenLifecycleEndsStreams(t *testing.T) { // C2R-T01..T06
	e := newAdminEnv(t)
	h := newOpsHarness(t, e.l.repo, e.clock.Now, e.exec)
	h.seed()
	// The administrator's real notification hook is the service's push entry point.
	e.hook = h.svc.NotifyAuthorityChange
	ctx := t.Context()
	h.denyAll("C2R-T01-super-admin-AAL2-no-grant", opsSession(e.secret), 403, authz.ReasonDefaultDeny)
	agent := e.agentOwnedBy("ops-bot", "u") // owned by the administrator
	cred, token := e.issue(agent, CredentialRequest{TTL: time.Hour})
	tc := authz.PrincipalCredentials{AgentToken: string(token)}
	h.denyAll("C2R-T02-admin-owned-agent-no-grant", tc, 403, authz.ReasonDefaultDeny)
	h.grant("agent_id", agent)
	h.allowAll("C2R-T03-agent-explicit-grant", tc)
	h.denyAll("C2R-T03b-admin-still-no-grant", opsSession(e.secret), 403, authz.ReasonDefaultDeny)

	// T05: revocation is applied before RevokeCredential returns: no tick, no extra
	// notification by the test, no waiting.
	st := h.follow(tc)
	opsAlive(t, st, "before revocation")
	if err := e.a.RevokeCredential(ctx, e.secret, agent, cred.Credential.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-st.Done():
	default:
		t.Fatal("C2R-T05: RevokeCredential returned with the follow stream still live")
	}
	// The authorizer has already canceled the lease; the stream's watcher releases it
	// and then stops its ticker, so the ticker's stop is the synchronization point.
	opsWaitDone(t, st.tk.stopped, "C2R-T05 watcher exit")
	if h.az.ActiveLeaseCount() != 0 {
		t.Fatal("C2R-T05: lease remains")
	}
	h.denyAll("C2R-T05b-revoked-token", tc, 401, authz.ReasonUnauthenticated)

	// T06: a new token works; the revoked one never does again.
	cred2, token2 := e.issue(agent, CredentialRequest{TTL: time.Hour})
	tc2 := authz.PrincipalCredentials{AgentToken: string(token2)}
	h.allowAll("C2R-T06-new-token", tc2)
	h.denyAll("C2R-T06b-old-token-still-revoked", tc, 401, authz.ReasonUnauthenticated)

	// Rotation without overlap ends the old token's stream at once.
	st2 := h.follow(tc2)
	res, err := e.a.RotateCredential(ctx, e.secret, agent, RotateRequest{Immediate: true, CredentialRequest: CredentialRequest{TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	token3 := res.New.ExportOnce()
	select {
	case <-st2.Done():
	default:
		t.Fatal("C2R-T07: rotation without overlap left the old token's stream live")
	}
	tc3 := authz.PrincipalCredentials{AgentToken: string(token3)}
	h.allowAll("C2R-T07b-rotated-in-token", tc3)

	// Rotation WITH overlap: the old token's stream survives the overlap and ends at
	// its expiry through the bounded revalidation; the new token is unaffected.
	st3 := h.follow(tc3)
	res, err = e.a.RotateCredential(ctx, e.secret, agent, RotateRequest{Overlap: 10 * time.Minute, CredentialRequest: CredentialRequest{TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	token4 := res.New.ExportOnce()
	tc4 := authz.PrincipalCredentials{AgentToken: string(token4)}
	st3.settle() // revalidated inside the overlap and still live
	opsAlive(t, st3, "during overlap after a revalidation pass")
	h.allowAll("C2R-T08-old-token-valid-in-overlap", tc3)
	h.allowAll("C2R-T08b-new-token", tc4)
	e.advance(10 * time.Minute)
	st3.tk.tick()
	opsWaitDone(t, st3.Done(), "C2R-T09 overlap-expired stream end")
	h.denyAll("C2R-T09-overlap-expired-token", tc3, 401, authz.ReasonUnauthenticated)
	h.allowAll("C2R-T09b-new-token-unaffected", tc4)

	// Token lifetime expiry (pull path) and disabling the agent (push path).
	st4 := h.follow(tc4)
	e.advance(2 * time.Hour)
	st4.tk.tick()
	opsWaitDone(t, st4.Done(), "C2R-E03 token-expired stream end")
	h.denyAll("C2R-E03-expired-token", tc4, 401, authz.ReasonUnauthenticated)

	_, token5 := e.issue(agent, CredentialRequest{TTL: time.Hour})
	tc5 := authz.PrincipalCredentials{AgentToken: string(token5)}
	h.allowAll("C2R-T10-fresh-token", tc5)
	st5 := h.follow(tc5)
	if err = e.a.DisableAgent(ctx, e.secret, agent); err != nil {
		t.Fatal(err)
	}
	select {
	case <-st5.Done():
	default:
		t.Fatal("C2R-T10: DisableAgent returned with the stream live")
	}
	h.denyAll("C2R-T10b-disabled-agent", tc5, 401, authz.ReasonUnauthenticated)
	_ = cred2
}
