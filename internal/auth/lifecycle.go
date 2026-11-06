package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// NoticeSettings is trusted deployment configuration, never request input.
// No connection or mail is sent by constructing a lifecycle service.
type NoticeSettings struct {
	Origin, Contact, Sender, Relay, Mode, Username, CredentialID string
	RootCAs                                                      *x509.CertPool
}

func (n NoticeSettings) valid() bool {
	u, e := url.Parse(n.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	if n.Mode != "implicit" && n.Mode != "starttls" {
		return false
	}
	host, port, e := net.SplitHostPort(n.Relay)
	if e != nil || host == "" || port == "" || strings.ContainsAny(n.Relay, "\r\n") {
		return false
	}
	return validMailbox(n.Contact) && validMailbox(n.Sender)
}
func validMailbox(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, "\r\n") {
		return false
	}
	a, e := mail.ParseAddress(s)
	return e == nil && a.Address == s && strings.Contains(s, "@")
}

type Lifecycle struct {
	repo      *store.Repository
	notices   NoticeSettings
	now       func() time.Time
	gate      *trafficGate
	passwords *Service
}

func NewLifecycle(r *store.Repository, n NoticeSettings) (*Lifecycle, error) {
	if r == nil || !n.valid() {
		return nil, ErrDenied
	}
	g, e := newTrafficGate()
	if e != nil {
		return nil, ErrDenied
	}
	origin, e := url.Parse(n.Origin)
	if e != nil {
		return nil, ErrDenied
	}
	passwords, e := NewService(r, DefaultPolicy(), origin.Hostname())
	if e != nil {
		return nil, ErrDenied
	}
	l := &Lifecycle{repo: r, notices: n, now: time.Now, gate: g, passwords: passwords}
	passwords.now = func() time.Time { return l.now() }
	return l, nil
}

// Enrollment is a reveal-once provisioning result, never factor/session evidence.
// Formatting is redacted; only the protected ceremony may explicitly export it.
type Enrollment struct {
	ID     string
	secret string
}

func (Enrollment) String() string        { return "[REDACTED]" }
func (Enrollment) GoString() string      { return "[REDACTED]" }
func (e *Enrollment) ExportOnce() []byte { b := []byte(e.secret); e.secret = ""; return b }
func randomID() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", ErrDenied
	}
	return hex.EncodeToString(b), nil
}
func nullable(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: true} }

// freshSession consumes only server-persisted achieved evidence. It issues no
// cookies/session and cannot turn enrollment or a caller's assurance field into
// authentication. P1.08 owns creation and transport of normal sessions.
func freshSession(ctx context.Context, q *store.Queries, secret []byte, now int64) (store.InstallationControl, store.User, store.Session, error) {
	var c store.InstallationControl
	var u store.User
	var s store.Session
	deny := func() (store.InstallationControl, store.User, store.Session, error) { return c, u, s, ErrDenied }
	if len(secret) < 32 || len(secret) > 256 || now < 0 || now > 253402300799 {
		return deny()
	}
	var e error
	c, e = q.GetInstallationControl(ctx)
	if e != nil || !activeControl(c) {
		return deny()
	}
	hash := sha256.Sum256(secret)
	s, e = q.GetSessionByHash(ctx, hash[:])
	if e != nil {
		return deny()
	}
	u, e = q.GetUser(ctx, s.UserID)
	if e != nil || u.State != "active" || u.Compromised != 0 || u.CredentialGeneration != c.CredentialGeneration || u.AuthorityGeneration != c.AuthorityGeneration {
		return deny()
	}
	at := s.AuthenticatedAt
	if s.ReauthenticatedAt.Valid {
		at = s.ReauthenticatedAt
	}
	if s.Purpose != "normal" || s.State != "active" || s.RevokedAt.Valid || s.CredentialGeneration != c.CredentialGeneration || s.SessionGeneration != c.SessionGeneration || !at.Valid || at.Int64 > now || now-at.Int64 > 900 || now < s.CreatedAt || now >= s.ExpiresAt || s.LastActivityAt > now || now-s.LastActivityAt >= s.IdleTimeoutSeconds {
		return deny()
	}
	all, e := q.ListUserAuthenticators(ctx, u.ID)
	if e != nil {
		return deny()
	}
	required := int64(1)
	for _, a := range all {
		if (a.Kind == "totp" || a.Kind == "webauthn") && a.BoundAt.Valid && !a.RevokedAt.Valid && a.CredentialGeneration == c.CredentialGeneration {
			required = 2
		}
	}
	if s.AchievedAssurance < required || (u.MfaRequirement == "webauthn" && (s.Methods != 8 || s.PhishingResistant != 1)) {
		return deny()
	}
	used, e := q.ListSessionAuthenticators(ctx, s.ID)
	if e != nil {
		return deny()
	}
	password, totp, key, uv := false, false, false, false
	for _, a := range used {
		if a.UserID != u.ID || !liveFactor(c, a, now) || a.BoundAt.Int64 > at.Int64 {
			return deny()
		}
		switch a.Kind {
		case "password":
			password = activeBinding(c, u, a, now)
		case "totp":
			totp = true
		case "webauthn":
			key = true
			uv = a.UserVerified.Valid && a.UserVerified.Int64 == 1
		default:
			return deny()
		}
	}
	valid := (s.AchievedAssurance == 1 && s.Methods == 1 && password) || (s.AchievedAssurance == 2 && ((s.Methods == 3 && password && totp) || (s.Methods == 5 && password && key) || (s.Methods == 8 && key && uv)))
	if !valid {
		return deny()
	}
	return c, u, s, nil
}
func liveFactor(c store.InstallationControl, a store.Authenticator, now int64) bool {
	return a.State == "active" && a.CredentialGeneration == c.CredentialGeneration && a.BoundAt.Valid && !a.RevokedAt.Valid && (!a.ExpiresAt.Valid || now < a.ExpiresAt.Int64) && a.FailedAttempts < a.RetryCeiling
}

func (l *Lifecycle) BeginTOTP(ctx context.Context, session []byte, algorithm string) (Enrollment, error) {
	if algorithm != "SHA1" && algorithm != "SHA256" {
		return Enrollment{}, ErrDenied
	}
	id, e := randomID()
	if e != nil {
		return Enrollment{}, ErrDenied
	}
	seed := make([]byte, 32)
	if _, e = rand.Read(seed); e != nil {
		return Enrollment{}, ErrDenied
	}
	defer clear(seed)
	encrypted, e := l.repo.EncryptSecret("totp", id, seed)
	if e != nil {
		return Enrollment{}, ErrDenied
	}
	e = l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, s, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		addresses, e := activeAddresses(ctx, q, u.ID, c.AuthorityGeneration)
		if e != nil || len(addresses) == 0 {
			return ErrDenied
		}
		if e = q.CreatePendingTOTP(ctx, store.CreatePendingTOTPParams{ID: id, UserID: u.ID, CredentialGeneration: c.CredentialGeneration, CreatedAt: now, EncryptedSecret: encrypted, TotpAlgorithm: sql.NullString{String: algorithm, Valid: true}}); e != nil {
			return e
		}
		expiry := now + 600
		if expiry > s.ExpiresAt {
			expiry = s.ExpiresAt
		}
		return q.BindPendingTOTP(ctx, store.BindPendingTOTPParams{AuthenticatorID: id, SessionID: s.ID, ExpiresAt: expiry})
	}, nil)
	if e != nil {
		return Enrollment{}, ErrDenied
	}
	return Enrollment{ID: id, secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)}, nil
}

// loadTOTP never reenters Repository inside a Control callback. The owning
// serialized verification rechecks exact ciphertext/algorithm and current state
// before using this snapshot, avoiding lifecycle-lock recursion against Close.
func (l *Lifecycle) loadTOTP(ctx context.Context, id string) (store.Authenticator, []byte, error) {
	var a store.Authenticator
	e := l.repo.Read(ctx, func(q *store.Queries) error { var e error; a, e = q.GetAuthenticator(ctx, id); return e })
	if e != nil || a.Kind != "totp" {
		return store.Authenticator{}, nil, ErrDenied
	}
	seed, e := l.repo.DecryptSecret("totp", id, a.EncryptedSecret)
	if e != nil {
		return store.Authenticator{}, nil, ErrDenied
	}
	return a, seed, nil
}

func activeAddresses(ctx context.Context, q *store.Queries, user string, generation int64) ([]store.NotificationAddress, error) {
	addresses, e := q.ListNotificationAddresses(ctx, user)
	if e != nil {
		return nil, e
	}
	out := []store.NotificationAddress{}
	for _, a := range addresses {
		if a.State == "active" && a.VerifiedAt.Valid && !a.RevokedAt.Valid && a.AuthorityGeneration == generation {
			if !validMailbox(a.Address) {
				return nil, ErrDenied
			}
			out = append(out, a)
		}
	}
	return out, nil
}
func (l *Lifecycle) enqueue(ctx context.Context, q *store.Queries, c store.InstallationControl, user, event string, now int64) error {
	addresses, e := activeAddresses(ctx, q, user, c.AuthorityGeneration)
	if e != nil || len(addresses) == 0 {
		return ErrDenied
	}
	id, e := randomID()
	if e != nil {
		return e
	}
	// Bounded component retention; deployment privacy/retention review remains the
	// P1.19/20 release gate. Pending/failed notices must not be silently deleted.
	retain := now + 30*86400
	if e = q.CreateSecurityEvent(ctx, store.CreateSecurityEventParams{ID: id, UserID: user, EventType: event, OccurredAt: now, RetainUntil: retain, DeduplicationKey: id}); e != nil {
		return e
	}
	for _, a := range addresses {
		out, e := randomID()
		if e != nil {
			return e
		}
		if e = q.ReadyNoticeIntent(ctx, store.ReadyNoticeIntentParams{ID: out, EventID: id, UserID: user, AddressID: a.ID, AddressVersion: a.Version, RecipientSnapshot: a.Address, RetainUntil: retain, AuthorityGeneration: c.AuthorityGeneration}); e != nil {
			return e
		}
	}
	return nil
}
func (l *Lifecycle) ConfirmTOTP(ctx context.Context, session []byte, id, code, ip string) error {
	if !l.gate.allow(ip, l.now()) {
		return ErrDenied
	}
	observed, seed, err := l.loadTOTP(ctx, id)
	if err != nil {
		return ErrDenied
	}
	defer clear(seed)
	accepted := false
	caller := ctx
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, s, e := freshSession(ctx, q, session, now)
		if e != nil {
			return nil
		}
		a, e := q.GetAuthenticator(ctx, id)
		if e != nil {
			return nil
		}
		pending, e := q.GetPendingTOTP(ctx, id)
		if e != nil {
			return nil
		}
		if a.UserID != u.ID || a.Kind != "totp" || a.State != "pending" || a.CredentialGeneration != c.CredentialGeneration || pending.SessionID != s.ID || now >= pending.ExpiresAt || now < a.CreatedAt || a.FailedAttempts >= a.RetryCeiling || (a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64) || caller.Err() != nil {
			return nil
		}
		if !bytes.Equal(a.EncryptedSecret, observed.EncryptedSecret) || a.TotpAlgorithm != observed.TotpAlgorithm {
			return ErrDenied
		}
		step, ok := matchTOTP(seed, a.TotpAlgorithm.String, code, now)
		if !ok {
			_, e = q.RecordTOTPFailure(ctx, store.RecordTOTPFailureParams{ID: id, NextAttemptAt: nullable(now + passwordWait(a.FailedAttempts+1))})
			return e
		}
		if l.repo.FailedClosed() {
			return ErrDenied
		}
		n, e := q.ActivateTOTP(ctx, store.ActivateTOTPParams{ID: id, Now: nullable(now), Step: nullable(step)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		hash := sha256.Sum256([]byte(code))
		if e = q.RecordTOTPAcceptance(ctx, store.RecordTOTPAcceptanceParams{AuthenticatorID: id, Step: step, VerifierPeriod: now / 30, OutputHash: hash[:]}); e != nil {
			return e
		}
		if e = l.enqueue(ctx, q, c, u.ID, "authenticator_bound", now); e != nil {
			return e
		}
		accepted = true
		return nil
	}, nil)
	if e != nil || !accepted {
		return ErrDenied
	}
	return nil
}

// RevokeTOTP requires fresh maximum-account-strength proof and never relaxes
// mandatory MFA or short-password rules. The final required factor cannot be
// removed; protective compromise reports are a distinct suspension protocol.
func (l *Lifecycle) RevokeTOTP(ctx context.Context, session []byte, id string) error {
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		now := l.now().Unix()
		c, u, _, e := freshSession(ctx, q, session, now)
		if e != nil {
			return e
		}
		a, e := q.GetAuthenticator(ctx, id)
		if e != nil || a.UserID != u.ID || a.Kind != "totp" || a.RevokedAt.Valid {
			return ErrDenied
		}
		factors, e := q.ListUserAuthenticators(ctx, u.ID)
		if e != nil {
			return e
		}
		remaining := false
		for _, f := range factors {
			if f.ID != id && (f.Kind == "totp" || f.Kind == "webauthn") && liveFactor(c, f, now) {
				remaining = true
			}
		}
		if u.MfaRequirement != "optional" && !remaining {
			return ErrDenied
		}
		n, e := q.RevokeTOTP(ctx, store.RevokeTOTPParams{ID: id, Now: nullable(now)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: u.ID, Now: nullable(now)}); e != nil {
			return e
		}
		return l.enqueue(ctx, q, c, u.ID, "authenticator_removed", now)
	}, nil)
	if e != nil {
		return ErrDenied
	}
	return nil
}

// FactorProof is a single possession observation, NOT an AAL2/session. The
// later authentication ceremony must bind it to fresh password evidence and
// recheck generations, expiry and binding before granting any normal session.
type FactorProof struct{ UserID, AuthenticatorID string }

func (l *Lifecycle) VerifyTOTP(ctx context.Context, user, id, code, ip string) (FactorProof, error) {
	if ctx.Err() != nil || !l.gate.allow(ip, l.now()) {
		return FactorProof{}, ErrDenied
	}
	observed, seed, err := l.loadTOTP(ctx, id)
	if err != nil {
		return FactorProof{}, ErrDenied
	}
	defer clear(seed)
	result := FactorProof{}
	caller := ctx
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e := l.repo.Control(ctx, func(q *store.Queries) error {
		c, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		u, e := q.GetUser(ctx, user)
		if e != nil {
			return nil
		}
		a, e := q.GetAuthenticator(ctx, id)
		if e != nil {
			return nil
		}
		now := l.now().Unix()
		if !activeControl(c) || u.State != "active" || u.Compromised != 0 || u.CredentialGeneration != c.CredentialGeneration || u.AuthorityGeneration != c.AuthorityGeneration || a.UserID != u.ID || a.Kind != "totp" || !liveFactor(c, a, now) || (a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64) || caller.Err() != nil {
			return nil
		}
		if !bytes.Equal(a.EncryptedSecret, observed.EncryptedSecret) || a.TotpAlgorithm != observed.TotpAlgorithm {
			return ErrDenied
		}
		step, ok := matchTOTP(seed, a.TotpAlgorithm.String, code, now)
		hash := sha256.Sum256([]byte(code))
		replay, e := q.HasTOTPReplay(ctx, store.HasTOTPReplayParams{ID: id, Step: step, Period: now / 30, Earliest: now/30 - 1, Hash: hash[:]})
		if e != nil {
			return e
		}
		if !ok || replay || (a.LastAcceptedTotpStep.Valid && step <= a.LastAcceptedTotpStep.Int64) {
			_, e = q.RecordTOTPFailure(ctx, store.RecordTOTPFailureParams{ID: id, NextAttemptAt: nullable(now + passwordWait(a.FailedAttempts+1))})
			return e
		}
		if l.repo.FailedClosed() {
			return nil
		}
		n, e := q.AdvanceTOTPStep(ctx, store.AdvanceTOTPStepParams{ID: id, Step: nullable(step)})
		if e != nil || n != 1 {
			return ErrDenied
		}
		if e = q.RecordTOTPAcceptance(ctx, store.RecordTOTPAcceptanceParams{AuthenticatorID: id, Step: step, VerifierPeriod: now / 30, OutputHash: hash[:]}); e != nil {
			return e
		}
		if e = q.PruneTOTPAcceptances(ctx, store.PruneTOTPAcceptancesParams{ID: id, Earliest: now/30 - 2}); e != nil {
			return e
		}
		result = FactorProof{UserID: user, AuthenticatorID: id}
		return nil
	}, nil)
	if e != nil || result.UserID == "" {
		return FactorProof{}, ErrDenied
	}
	return result, nil
}
