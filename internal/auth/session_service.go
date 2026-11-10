package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"io"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// write runs fn in one durable control transaction and keeps a logical denial
// (ErrDenied, safe to show as 401/403) distinct from storage uncertainty
// (store.ErrStorage, 503). Nothing is acknowledged unless commit and sync succeed.
func (s *Sessions) write(ctx context.Context, fn func(*store.Queries) error) error {
	// Once admitted, the transition must finish even if an untrusted caller hangs up.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	denied := false
	err := s.l.repo.Control(ctx, func(q *store.Queries) error {
		e := fn(q)
		if errors.Is(e, ErrDenied) {
			denied = true
		}
		return e
	}, nil)
	switch {
	case err == nil:
		return nil
	case denied && !s.l.repo.FailedClosed():
		return ErrDenied
	}
	return store.ErrStorage
}

func (s *Sessions) read(ctx context.Context, fn func(*store.Queries) error) error {
	denied := false
	err := s.l.repo.Read(ctx, func(q *store.Queries) error {
		e := fn(q)
		if errors.Is(e, ErrDenied) {
			denied = true
		}
		return e
	})
	switch {
	case err == nil:
		return nil
	case denied && !s.l.repo.FailedClosed():
		return ErrDenied
	}
	return store.ErrStorage
}

func (s *Sessions) newSecret() ([]byte, error) {
	b := make([]byte, sessionSecretBytes)
	if _, err := io.ReadFull(s.random, b); err != nil {
		return nil, ErrDenied // never a predictable fallback
	}
	return b, nil
}

// accountView is the live, server-side policy and factor inventory of one user.
type accountView struct {
	user        store.User
	admin       bool
	hasPassword bool
	// floor is the REQUIRED assurance (assuranceFloor): what a maximum-available
	// sensitive write needs. It is independent of which factors are usable now.
	floor    int64
	password store.Authenticator
	totp     map[string]store.Authenticator
	keys     map[string]store.Authenticator
}

func loadAccount(ctx context.Context, q *store.Queries, c store.InstallationControl, userID string, now int64) (accountView, error) {
	var v accountView
	u, e := q.GetUser(ctx, userID)
	if e != nil {
		return v, authorityReadError(e)
	}
	if !activeControl(c) || u.State != "active" || u.Compromised != 0 || u.CredentialGeneration != c.CredentialGeneration || u.AuthorityGeneration != c.AuthorityGeneration {
		return v, ErrDenied
	}
	switch u.MfaRequirement {
	case "optional", "required", "webauthn":
	default:
		return v, ErrDenied
	}
	v.user = u
	if v.admin, e = isAdministrator(ctx, q, u.ID); e != nil {
		return v, e
	}
	all, e := q.ListUserAuthenticators(ctx, u.ID)
	if e != nil {
		return v, e
	}
	v.floor = assuranceFloor(c, u, v.admin, all)
	v.totp, v.keys = map[string]store.Authenticator{}, map[string]store.Authenticator{}
	for _, a := range all {
		switch a.Kind {
		case "password":
			if activeBinding(c, u, a, now) {
				v.password, v.hasPassword = a, true
			}
		case "totp":
			if liveFactor(c, a, now) {
				v.totp[a.ID] = a
			}
		case "webauthn":
			// Only keys that can produce UV-backed evidence count as a factor.
			if liveFactor(c, a, now) && a.UserVerified.Valid && a.UserVerified.Int64 == 1 {
				v.keys[a.ID] = a
			}
		}
	}
	return v, nil
}

// mfaRequired: administrators and any non-optional policy can never complete a
// password-only login, regardless of enrollment state.
func (a accountView) mfaRequired() bool { return a.user.MfaRequirement != "optional" || a.admin }
func (a accountView) allowsTOTP() bool  { return a.user.MfaRequirement != "webauthn" }
func (a accountView) usableTOTP(id string) bool {
	_, ok := a.totp[id]
	return ok && a.allowsTOTP()
}
func (a accountView) usableKey(id string) bool { _, ok := a.keys[id]; return ok }
func (a accountView) hasSecondFactor() bool {
	return (a.allowsTOTP() && len(a.totp) > 0) || len(a.keys) > 0
}

// usableAssurance is the highest assurance this account can PROVE right now with
// currently usable factors. It is informational capability only (the step-up
// hint). It must never decide a gate or permit a downgrade: that is the floor.
func (a accountView) usableAssurance() int64 {
	if a.hasSecondFactor() {
		return 2
	}
	return 1
}

// passwordOnlyAllowed is the policy question "may this account hold a lower-
// assurance (password-only) session at all": optional MFA, long password.
func (a accountView) passwordOnlyAllowed() bool {
	return a.hasPassword && !a.mfaRequired() && a.password.PasswordCodepoints.Valid && a.password.PasswordCodepoints.Int64 >= 15
}

// lowerAssuranceUsable additionally requires that the lower-assurance session
// is not a stranded one: with a required floor of 2 and no usable second factor
// the account could never step up, so password evidence alone gets NO session
// (a protective report or exhausted factor must not turn into password-only
// access, NIST E12/I08/D-04). Recovery is the approved way back.
func (a accountView) lowerAssuranceUsable() bool {
	return a.passwordOnlyAllowed() && (a.floor < 2 || a.hasSecondFactor())
}

// next lists only what policy permits after a correct password.
func (a accountView) next() []string {
	var n []string
	if a.allowsTOTP() && len(a.totp) > 0 {
		n = append(n, "totp")
	}
	if len(a.keys) > 0 {
		n = append(n, "webauthn")
	}
	if len(n) > 0 && a.passwordOnlyAllowed() {
		n = append(n, "no-mfa")
	}
	return n
}

type evidence struct {
	purpose        string
	assurance      int64
	methods        int64
	phishing       bool
	authenticators []string
	idle, lifetime time.Duration
	// usable (capability, informational) and required (the floor, which gates
	// sensitive writes) are copied into the session view; neither is stored or
	// read from the client.
	usable, required int64
}

func methodLabels(methods int64) []string {
	switch methods {
	case evidencePassword:
		return []string{"password"}
	case evidencePassword | evidenceTOTP:
		return []string{"password", "totp"}
	case evidencePassword | evidenceWebAuthn:
		return []string{"password", "webauthn"}
	case evidenceWebAuthnUV:
		return []string{"webauthn-uv"}
	}
	return []string{}
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// issue creates the successor session row, links the factors actually used,
// revokes predecessors and enforces the per-user live-session bound, all inside
// the caller's durable control transaction. The secret exists only in memory
// until that transaction commits.
func (s *Sessions) issue(ctx context.Context, q *store.Queries, c store.InstallationControl, userID string, ev evidence, now int64, predecessors ...string) (IssuedSession, error) {
	if s.l.repo.FailedClosed() {
		return IssuedSession{}, store.ErrStorage
	}
	secret, err := s.newSecret()
	if err != nil {
		return IssuedSession{}, err
	}
	id, err := randomID()
	if err != nil {
		return IssuedSession{}, ErrDenied
	}
	digest := sha256.Sum256(secret)
	expires := now + int64(ev.lifetime/time.Second)
	authenticatedAt := sql.NullInt64{}
	if ev.purpose == "normal" {
		authenticatedAt = nullable(now)
	}
	for _, old := range predecessors {
		if _, err = q.RevokeSession(ctx, store.RevokeSessionParams{Now: now, ID: old}); err != nil {
			return IssuedSession{}, err
		}
	}
	if err = q.InsertSession(ctx, store.InsertSessionParams{
		ID: id, UserID: userID, SecretHash: digest[:], Purpose: ev.purpose,
		AchievedAssurance: ev.assurance, Methods: ev.methods, PhishingResistant: b2i(ev.phishing),
		AuthenticatedAt: authenticatedAt, CreatedAt: now, ExpiresAt: expires, LastActivityAt: now,
		IdleTimeoutSeconds: int64(ev.idle / time.Second), CredentialGeneration: c.CredentialGeneration, SessionGeneration: c.SessionGeneration,
	}); err != nil {
		return IssuedSession{}, err
	}
	for _, a := range ev.authenticators {
		if err = q.InsertSessionAuthenticator(ctx, store.InsertSessionAuthenticatorParams{SessionID: id, AuthenticatorID: a, UserID: userID}); err != nil {
			return IssuedSession{}, err
		}
	}
	live, err := q.ListLiveUserSessions(ctx, store.ListLiveUserSessionsParams{UserID: userID, Now: now})
	if err != nil {
		return IssuedSession{}, err
	}
	// Revoke the oldest rows (preauth first) until the bound holds, never the one
	// just created.
	remaining := len(live)
	for _, old := range live {
		if remaining <= s.maxLive {
			break
		}
		if old.ID == id {
			continue
		}
		if _, err = q.RevokeSession(ctx, store.RevokeSessionParams{Now: now, ID: old.ID}); err != nil {
			return IssuedSession{}, err
		}
		remaining--
	}
	info := SessionInfo{ID: id, UserID: userID, Methods: methodLabels(ev.methods), PhishingResistant: ev.phishing, UsableAssurance: ev.usable, RequiredAssurance: ev.required, CreatedAt: time.Unix(now, 0), ExpiresAt: time.Unix(expires, 0), LastActivityAt: time.Unix(now, 0)}
	switch {
	case ev.purpose == "preauth":
		info.Assurance, info.Methods = AssurancePreauth, []string{}
	case ev.assurance == 2:
		info.Assurance, info.AuthenticatedAt = AssuranceAAL2, time.Unix(now, 0)
	default:
		info.Assurance, info.AuthenticatedAt = AssurancePasswordOnly, time.Unix(now, 0)
	}
	return IssuedSession{secret: secret, Info: info}, nil
}

// storedSession loads a session by secret in the caller's transaction and applies
// purpose, state, generation and clock checks. It does not decide assurance.
func (s *Sessions) storedSession(ctx context.Context, q *store.Queries, secret []byte, purpose string, now int64) (store.InstallationControl, store.Session, error) {
	var c store.InstallationControl
	var row store.Session
	if len(secret) != sessionSecretBytes || now < 0 || now > 253402300799 {
		return c, row, ErrDenied
	}
	c, e := q.GetInstallationControl(ctx)
	if e != nil {
		return c, row, e
	}
	if !activeControl(c) {
		return c, row, ErrDenied
	}
	digest := sha256.Sum256(secret)
	row, e = q.GetSessionByHash(ctx, digest[:])
	if e != nil {
		return c, row, authorityReadError(e)
	}
	if subtle.ConstantTimeCompare(row.SecretHash, digest[:]) != 1 || row.Purpose != purpose || row.State != "active" || row.RevokedAt.Valid ||
		row.CredentialGeneration != c.CredentialGeneration || row.SessionGeneration != c.SessionGeneration ||
		now < row.CreatedAt || now >= row.ExpiresAt || row.LastActivityAt > now || row.IdleTimeoutSeconds <= 0 || now-row.LastActivityAt >= row.IdleTimeoutSeconds {
		return c, row, ErrDenied
	}
	return c, row, nil
}

func authTime(row store.Session) sql.NullInt64 {
	if row.ReauthenticatedAt.Valid {
		return row.ReauthenticatedAt
	}
	return row.AuthenticatedAt
}

// verifySession is the one place a persisted normal session is trusted. The row's
// labels must be backed by live factor bindings and satisfy the account's CURRENT
// policy, so role/policy changes, factor revocation and compromise apply at once.
func (s *Sessions) verifySession(ctx context.Context, q *store.Queries, secret []byte, now int64) (store.InstallationControl, store.Session, accountView, error) {
	c, row, e := s.storedSession(ctx, q, secret, "normal", now)
	var acct accountView
	if e != nil {
		return c, row, acct, e
	}
	at := authTime(row)
	if !at.Valid || at.Int64 > now || row.CreatedAt > now {
		return c, row, acct, ErrDenied
	}
	acct, e = loadAccount(ctx, q, c, row.UserID, now)
	if e != nil {
		return c, row, acct, e
	}
	used, e := q.ListSessionAuthenticators(ctx, row.ID)
	if e != nil {
		return c, row, acct, e
	}
	if !evidenceBacked(c, acct.user, row, at.Int64, used, now) {
		return c, row, acct, ErrDenied
	}
	// phishing_resistant is only ever the WebAuthn-UV evidence class.
	if (row.PhishingResistant == 1) != (row.Methods == evidenceWebAuthnUV) {
		return c, row, acct, ErrDenied
	}
	if acct.mfaRequired() && row.AchievedAssurance < 2 {
		return c, row, acct, ErrDenied
	}
	// A lower-assurance session on an account that requires 2 is only meaningful
	// while a usable second factor exists to step up with.
	if row.AchievedAssurance < 2 && !acct.lowerAssuranceUsable() {
		return c, row, acct, ErrDenied
	}
	if acct.user.MfaRequirement == "webauthn" && (row.AchievedAssurance != 2 || row.Methods != evidenceWebAuthnUV || row.PhishingResistant != 1) {
		return c, row, acct, ErrDenied
	}
	return c, row, acct, nil
}

func (s *Sessions) viewOf(row store.Session, acct accountView, secret []byte) Session {
	at := authTime(row)
	info := SessionInfo{
		ID: row.ID, UserID: row.UserID, Methods: methodLabels(row.Methods), PhishingResistant: row.PhishingResistant == 1,
		UsableAssurance: acct.usableAssurance(), RequiredAssurance: acct.floor, CreatedAt: time.Unix(row.CreatedAt, 0), ExpiresAt: time.Unix(row.ExpiresAt, 0), LastActivityAt: time.Unix(row.LastActivityAt, 0),
	}
	if at.Valid {
		info.AuthenticatedAt = time.Unix(at.Int64, 0)
	}
	if row.AchievedAssurance == 2 {
		info.Assurance = AssuranceAAL2
	} else {
		info.Assurance = AssurancePasswordOnly
	}
	return Session{SessionInfo: info, secret: append([]byte(nil), secret...)}
}

// Authenticate resolves a presented cookie secret into a trusted Session. The
// secret is the only client input; assurance, methods, time and generations all
// come from the database. activity=true counts the request as meaningful user
// activity (idle reset only, never the overall deadline); background polling and
// streams pass false so they cannot keep an abandoned session alive.
func (s *Sessions) Authenticate(ctx context.Context, secret []byte, activity bool) (Session, error) {
	var out Session
	var last int64
	err := s.read(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		_, row, acct, e := s.verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		out, last = s.viewOf(row, acct, secret), row.LastActivityAt
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	now := s.l.now().Unix()
	if activity && now-last >= int64(activityGranularity/time.Second) {
		err = s.write(ctx, func(q *store.Queries) error {
			n, e := q.TouchSession(ctx, store.TouchSessionParams{Now: now, ID: out.ID})
			if e != nil {
				return e
			}
			if n != 1 {
				return ErrDenied // revoked or expired between the read and this write
			}
			return nil
		})
		if err != nil {
			return Session{}, err
		}
		out.LastActivityAt = time.Unix(now, 0)
	}
	return out, nil
}

// AuthenticatePreauth recognises a login-ceremony capability. It is not a session
// and carries no assurance; it only lets the second-factor step proceed.
func (s *Sessions) AuthenticatePreauth(ctx context.Context, secret []byte) (Session, error) {
	var out Session
	err := s.read(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		_, row, _, e := s.preauth(ctx, q, secret, now)
		if e != nil {
			return e
		}
		out = Session{SessionInfo: SessionInfo{ID: row.ID, UserID: row.UserID, Assurance: AssurancePreauth, Methods: []string{}, CreatedAt: time.Unix(row.CreatedAt, 0), ExpiresAt: time.Unix(row.ExpiresAt, 0), LastActivityAt: time.Unix(row.LastActivityAt, 0)}, secret: append([]byte(nil), secret...)}
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}

// preauth validates a login capability and that it still carries the live
// password evidence from the ceremony that created it.
func (s *Sessions) preauth(ctx context.Context, q *store.Queries, secret []byte, now int64) (store.InstallationControl, store.Session, accountView, error) {
	c, row, e := s.storedSession(ctx, q, secret, "preauth", now)
	var acct accountView
	if e != nil {
		return c, row, acct, e
	}
	if row.AchievedAssurance != 0 || row.Methods != 0 || row.AuthenticatedAt.Valid || row.PhishingResistant != 0 {
		return c, row, acct, ErrDenied
	}
	acct, e = loadAccount(ctx, q, c, row.UserID, now)
	if e != nil {
		return c, row, acct, e
	}
	used, e := q.ListSessionAuthenticators(ctx, row.ID)
	if e != nil {
		return c, row, acct, e
	}
	if len(used) != 1 || !acct.hasPassword || used[0].ID != acct.password.ID {
		return c, row, acct, ErrDenied
	}
	return c, row, acct, nil
}

// PasswordLogin is the first step of every browser login. A correct password
// alone yields either a clearly labelled password-only session (only where policy
// allows it) or a short preauth capability; it can never yield AAL2.
func (s *Sessions) PasswordLogin(ctx context.Context, name string, password []byte, ip string) (LoginResult, error) {
	proof, err := s.l.passwords.Prove(ctx, name, password, ip)
	if err != nil {
		return LoginResult{}, ErrDenied
	}
	var result LoginResult
	err = s.write(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		c, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		acct, e := loadAccount(ctx, q, c, proof.UserID, now)
		if e != nil {
			return e
		}
		if !acct.hasPassword || acct.password.ID != proof.AuthenticatorID {
			return ErrDenied
		}
		next := acct.next()
		switch {
		case !acct.hasSecondFactor() && acct.lowerAssuranceUsable() && !proof.RequiresMFA:
			issued, e := s.issue(ctx, q, c, acct.user.ID, evidence{purpose: "normal", assurance: 1, methods: evidencePassword, authenticators: []string{acct.password.ID}, idle: s.settings.Idle, lifetime: s.settings.Absolute, usable: 1, required: acct.floor}, now)
			if e != nil {
				return e
			}
			result = LoginResult{Session: issued}
		case len(next) > 0:
			issued, e := s.issue(ctx, q, c, acct.user.ID, evidence{purpose: "preauth", authenticators: []string{acct.password.ID}, idle: preauthLifetime, lifetime: preauthLifetime}, now)
			if e != nil {
				return e
			}
			result = LoginResult{Session: issued, Next: next}
		default:
			// MFA is required but no usable second factor exists: deny, do not weaken.
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, nil
}

// LoginWithoutMFA completes an explicitly password-only login for an account whose
// policy allows it. The result is labelled lower assurance and never AAL2.
func (s *Sessions) LoginWithoutMFA(ctx context.Context, preauth []byte) (IssuedSession, error) {
	var out IssuedSession
	err := s.write(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		c, row, acct, e := s.preauth(ctx, q, preauth, now)
		if e != nil {
			return e
		}
		if !acct.lowerAssuranceUsable() {
			return ErrDenied
		}
		out, e = s.issue(ctx, q, c, acct.user.ID, evidence{purpose: "normal", assurance: 1, methods: evidencePassword, authenticators: []string{acct.password.ID}, idle: s.settings.Idle, lifetime: s.settings.Absolute, usable: acct.usableAssurance(), required: acct.floor}, now, row.ID)
		return e
	})
	if err != nil {
		return IssuedSession{}, err
	}
	return out, nil
}

// preauthOwner is a cheap pre-check so invalid capabilities never spend factor
// attempts: the ceremony must be live and its account must allow the factor.
func (s *Sessions) preauthOwner(ctx context.Context, secret []byte) (store.Session, accountView, error) {
	var row store.Session
	var acct accountView
	err := s.read(ctx, func(q *store.Queries) error {
		var e error
		_, row, acct, e = s.preauth(ctx, q, secret, s.l.now().Unix())
		return e
	})
	return row, acct, err
}

// LoginTOTP finishes a login with a verified TOTP. The password-bound preauth is
// consumed and replaced by a NEW secret (no session fixation).
func (s *Sessions) LoginTOTP(ctx context.Context, preauth []byte, authenticatorID, code, ip string) (IssuedSession, error) {
	row, acct, err := s.preauthOwner(ctx, preauth)
	if err != nil {
		return IssuedSession{}, err
	}
	if !acct.usableTOTP(authenticatorID) {
		return IssuedSession{}, ErrDenied
	}
	proof, err := s.l.VerifyTOTP(ctx, row.UserID, authenticatorID, code, ip)
	if err != nil {
		return IssuedSession{}, ErrDenied
	}
	var out IssuedSession
	err = s.write(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		c, current, acct, e := s.preauth(ctx, q, preauth, now)
		if e != nil {
			return e
		}
		if current.ID != row.ID || proof.UserID != acct.user.ID || !acct.usableTOTP(proof.AuthenticatorID) {
			return ErrDenied
		}
		out, e = s.issue(ctx, q, c, acct.user.ID, evidence{purpose: "normal", assurance: 2, methods: evidencePassword | evidenceTOTP, authenticators: []string{acct.password.ID, proof.AuthenticatorID}, idle: s.settings.Idle, lifetime: s.settings.Absolute, usable: 2, required: acct.floor}, now, current.ID)
		return e
	})
	if err != nil {
		return IssuedSession{}, err
	}
	return out, nil
}

func (s *Sessions) webauthnReady() bool { return s.w != nil }

// BeginLoginWebAuthn starts the UV assertion ceremony for a live preauth.
func (s *Sessions) BeginLoginWebAuthn(ctx context.Context, preauth []byte) (AssertionOptions, error) {
	_, acct, err := s.preauthOwner(ctx, preauth)
	if err != nil || !s.webauthnReady() || len(acct.keys) == 0 {
		return AssertionOptions{}, ErrDenied
	}
	return s.w.BeginAssertion(ctx, preauth)
}

// LoginWebAuthn finishes a login with a verified UP+UV assertion. UV=false,
// replayed, foreign-origin and wrong-session assertions are rejected by the
// WebAuthn service before this point; only UV evidence is recorded here.
func (s *Sessions) LoginWebAuthn(ctx context.Context, preauth []byte, challengeID string, response []byte, ip string) (IssuedSession, error) {
	row, acct, err := s.preauthOwner(ctx, preauth)
	if err != nil || !s.webauthnReady() || len(acct.keys) == 0 {
		return IssuedSession{}, ErrDenied
	}
	proof, err := s.w.FinishAssertion(ctx, preauth, challengeID, response, ip)
	if err != nil {
		return IssuedSession{}, ErrDenied
	}
	var out IssuedSession
	err = s.write(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		c, current, acct, e := s.preauth(ctx, q, preauth, now)
		if e != nil {
			return e
		}
		if current.ID != row.ID || proof.UserID != acct.user.ID || !acct.usableKey(proof.AuthenticatorID) {
			return ErrDenied
		}
		out, e = s.issue(ctx, q, c, acct.user.ID, evidence{purpose: "normal", assurance: 2, methods: evidenceWebAuthnUV, phishing: true, authenticators: []string{acct.password.ID, proof.AuthenticatorID}, idle: s.settings.Idle, lifetime: s.settings.Absolute, usable: 2, required: acct.floor}, now, current.ID)
		return e
	})
	if err != nil {
		return IssuedSession{}, err
	}
	return out, nil
}

// stepUpCandidate loads the current normal session for a step-up and the username
// needed to verify fresh password evidence for THAT account only.
func (s *Sessions) stepUpCandidate(ctx context.Context, secret []byte) (store.Session, accountView, error) {
	var row store.Session
	var acct accountView
	err := s.read(ctx, func(q *store.Queries) error {
		var e error
		_, row, acct, e = s.verifySession(ctx, q, secret, s.l.now().Unix())
		return e
	})
	return row, acct, err
}

// stepUp replaces the session with a successor that carries ONLY the new
// evidence. It never lowers assurance or phishing resistance and always revokes
// the predecessor, so a captured pre-step-up cookie dies at the moment of
// re-authentication. A failed proof never reaches this point.
func (s *Sessions) stepUp(ctx context.Context, secret []byte, prior store.Session, ev evidence, check func(accountView) bool) (IssuedSession, error) {
	var out IssuedSession
	err := s.write(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		c, current, acct, e := s.verifySession(ctx, q, secret, now)
		if e != nil {
			return e
		}
		if current.ID != prior.ID || !check(acct) {
			return ErrDenied
		}
		// Assurance and phishing resistance can only rise.
		if ev.assurance < current.AchievedAssurance || (current.PhishingResistant == 1 && !ev.phishing) {
			return ErrDenied
		}
		ev.idle, ev.lifetime, ev.usable, ev.required = s.settings.Idle, s.settings.Absolute, acct.usableAssurance(), acct.floor
		ev.purpose = "normal"
		out, e = s.issue(ctx, q, c, acct.user.ID, ev, now, current.ID)
		return e
	})
	if err != nil {
		return IssuedSession{}, err
	}
	return out, nil
}

// StepUpPassword re-verifies the password for an account that has no second
// factor to offer. For an AAL2-capable account it is refused: a password alone can
// never refresh (or substitute for) MFA evidence.
func (s *Sessions) StepUpPassword(ctx context.Context, secret, password []byte, ip string) (IssuedSession, error) {
	prior, acct, err := s.stepUpCandidate(ctx, secret)
	if err != nil {
		return IssuedSession{}, err
	}
	if acct.floor >= 2 || acct.hasSecondFactor() || !acct.passwordOnlyAllowed() {
		return IssuedSession{}, ErrDenied
	}
	proof, err := s.l.passwords.Prove(ctx, acct.user.Username, password, ip)
	if err != nil || proof.UserID != acct.user.ID || proof.RequiresMFA {
		return IssuedSession{}, ErrDenied
	}
	return s.stepUp(ctx, secret, prior, evidence{assurance: 1, methods: evidencePassword, authenticators: []string{proof.AuthenticatorID}}, func(a accountView) bool {
		return a.floor < 2 && !a.hasSecondFactor() && a.passwordOnlyAllowed() && a.password.ID == proof.AuthenticatorID
	})
}

// StepUpTOTP re-verifies password + TOTP and yields a fresh AAL2 session.
func (s *Sessions) StepUpTOTP(ctx context.Context, secret, password []byte, authenticatorID, code, ip string) (IssuedSession, error) {
	prior, acct, err := s.stepUpCandidate(ctx, secret)
	if err != nil {
		return IssuedSession{}, err
	}
	if !acct.usableTOTP(authenticatorID) || !acct.hasPassword || prior.PhishingResistant == 1 {
		return IssuedSession{}, ErrDenied // includes WebAuthn-only policy and downgrades
	}
	pw, err := s.l.passwords.Prove(ctx, acct.user.Username, password, ip)
	if err != nil || pw.UserID != acct.user.ID || pw.AuthenticatorID != acct.password.ID {
		return IssuedSession{}, ErrDenied
	}
	proof, err := s.l.VerifyTOTP(ctx, acct.user.ID, authenticatorID, code, ip)
	if err != nil {
		return IssuedSession{}, ErrDenied
	}
	return s.stepUp(ctx, secret, prior, evidence{assurance: 2, methods: evidencePassword | evidenceTOTP, authenticators: []string{pw.AuthenticatorID, proof.AuthenticatorID}}, func(a accountView) bool {
		return a.usableTOTP(proof.AuthenticatorID) && a.hasPassword && a.password.ID == pw.AuthenticatorID
	})
}

// BeginStepUpWebAuthn starts a UV assertion bound to the current session.
func (s *Sessions) BeginStepUpWebAuthn(ctx context.Context, secret []byte) (AssertionOptions, error) {
	_, acct, err := s.stepUpCandidate(ctx, secret)
	if err != nil || !s.webauthnReady() || len(acct.keys) == 0 {
		return AssertionOptions{}, ErrDenied
	}
	return s.w.BeginAssertion(ctx, secret)
}

// StepUpWebAuthn re-verifies with a signed UP+UV assertion (phishing resistant).
func (s *Sessions) StepUpWebAuthn(ctx context.Context, secret []byte, challengeID string, response []byte, ip string) (IssuedSession, error) {
	prior, acct, err := s.stepUpCandidate(ctx, secret)
	if err != nil || !s.webauthnReady() || len(acct.keys) == 0 {
		return IssuedSession{}, ErrDenied
	}
	proof, err := s.w.FinishAssertion(ctx, secret, challengeID, response, ip)
	if err != nil {
		return IssuedSession{}, ErrDenied
	}
	return s.stepUp(ctx, secret, prior, evidence{assurance: 2, methods: evidenceWebAuthnUV, phishing: true, authenticators: []string{proof.AuthenticatorID}}, func(a accountView) bool {
		return proof.UserID == a.user.ID && a.usableKey(proof.AuthenticatorID)
	})
}

// Logout durably revokes the presented session (normal or preauth). The caller
// clears the cookie only after this returns nil.
func (s *Sessions) Logout(ctx context.Context, secret []byte) error {
	return s.write(ctx, func(q *store.Queries) error {
		now := s.l.now().Unix()
		if len(secret) != sessionSecretBytes {
			return ErrDenied
		}
		digest := sha256.Sum256(secret)
		row, e := q.GetSessionByHash(ctx, digest[:])
		if e != nil {
			return authorityReadError(e)
		}
		if row.State != "active" || row.RevokedAt.Valid {
			return ErrDenied
		}
		n, e := q.RevokeSession(ctx, store.RevokeSessionParams{Now: now, ID: row.ID})
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDenied
		}
		return nil
	})
}
