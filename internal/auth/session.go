package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"time"
)

// Assurance is a server-derived label. It is read only from the persisted session
// row and verified factor evidence; no request field, cookie, header, account flag
// or enrollment state can set it. "password-only" is lower assurance and is never
// AAL2. "preauth" is a short capability to finish a login ceremony, not a session.
type Assurance string

const (
	AssurancePreauth      Assurance = "preauth"
	AssurancePasswordOnly Assurance = "password-only"
	AssuranceAAL2         Assurance = "aal2"
)

// Persisted evidence method mask (migration 00001_initial.sql).
const (
	evidencePassword   int64 = 1
	evidenceTOTP       int64 = 2
	evidenceWebAuthn   int64 = 4
	evidenceWebAuthnUV int64 = 8
)

// Documented defaults and hard ceilings (TD §4.3; NIST mapping A05/S06). The
// ceilings equal the SQLite CHECK constraints, so unsafe values cannot even be
// persisted. Lengthening them needs an explicit assurance review, not a flag.
const (
	DefaultSessionAbsolute = 12 * time.Hour
	DefaultSessionIdle     = 30 * time.Minute
	DefaultStepUpWindow    = 15 * time.Minute
	preauthLifetime        = 5 * time.Minute
	// Activity is recorded at most this often. A skipped update can only make an
	// idle expiry earlier, never later, than the last request.
	activityGranularity = 15 * time.Second
	// Bounded live rows per user. Without a password a client cannot create any.
	maxLiveSessionsPerUser = 32
	sessionSecretBytes     = 32
)

// SessionSettings are trusted deployment configuration, never request input.
type SessionSettings struct {
	Absolute, Idle, StepUp time.Duration
}

// DefaultSessionSettings returns the approved 12h / 30m / 15m policy.
func DefaultSessionSettings() SessionSettings {
	return SessionSettings{Absolute: DefaultSessionAbsolute, Idle: DefaultSessionIdle, StepUp: DefaultStepUpWindow}
}

func (c SessionSettings) valid() bool {
	whole := func(d time.Duration) bool { return d > 0 && d%time.Second == 0 }
	return whole(c.Absolute) && whole(c.Idle) && whole(c.StepUp) &&
		c.Absolute <= DefaultSessionAbsolute && c.Idle <= DefaultSessionIdle && c.StepUp <= DefaultStepUpWindow &&
		c.Idle <= c.Absolute
}

// ErrStepUpRequired means the session is valid but its authentication evidence is
// too old (or too weak) for the requested sensitive operation, and a successful
// re-authentication can fix it. ErrAssuranceUnavailable means the ACCOUNT cannot
// reach the required assurance at all (for example an AAL2-only operation for an
// account with no second factor); re-entering a password never helps.
var (
	ErrStepUpRequired       = errors.New("step-up authentication required")
	ErrAssuranceUnavailable = errors.New("assurance unavailable for account")
	sessionCSRFLabel        = []byte("mandatary csrf v1\x00")
)

// SessionInfo is the trusted, secret-free view of a persisted session.
type SessionInfo struct {
	ID                string
	UserID            string
	Assurance         Assurance
	Methods           []string
	PhishingResistant bool
	// RequiredAssurance is the account's required-assurance FLOOR (1 or 2): what
	// a maximum-available sensitive write demands, derived by assuranceFloor
	// from bound factors and their retirement provenance. It is the only value
	// RequireSensitive gates on. An unavailable, exhausted, expired or protectively
	// invalidated factor keeps it at 2. Zero (unset) is denied, never defaulted.
	RequiredAssurance int64
	// UsableAssurance is the highest assurance the account can PROVE right now
	// with usable factors (2 only when a live second factor exists). It is
	// capability for the step-up hint and the SPA, never permission to lower
	// RequiredAssurance or to downgrade a gate.
	UsableAssurance int64
	AuthenticatedAt time.Time
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastActivityAt  time.Time
}

// Session is a verified session plus its secret, which downstream lifecycle
// services need as their opaque input. Formatting and logging are redacted.
type Session struct {
	SessionInfo
	secret []byte
}

func (Session) String() string   { return "Session{[REDACTED]}" }
func (Session) GoString() string { return "Session{[REDACTED]}" }
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(slog.String("session_id", s.ID), slog.String("secret", "[REDACTED]"))
}

// Secret returns a copy of the opaque session secret for lifecycle services.
func (s Session) Secret() []byte { return append([]byte(nil), s.secret...) }

// CSRFToken is derived from the server-held session secret and session ID. It is
// verifiable only by the server, differs per session and changes on rotation.
func (s Session) CSRFToken() string { return csrfToken(s.secret, s.ID) }

func csrfToken(secret []byte, id string) string {
	m := hmac.New(sha256.New, secret)
	m.Write(sessionCSRFLabel)
	m.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// IssuedSession is a newly created cookie secret. It is only ever produced after
// the creating transaction is durable; formatting and logging are redacted.
type IssuedSession struct {
	secret []byte
	Info   SessionInfo
}

func (IssuedSession) String() string   { return "IssuedSession{[REDACTED]}" }
func (IssuedSession) GoString() string { return "IssuedSession{[REDACTED]}" }
func (i IssuedSession) LogValue() slog.Value {
	return slog.GroupValue(slog.String("session_id", i.Info.ID), slog.String("secret", "[REDACTED]"))
}

// Secret returns a copy of the opaque secret (tests and the HTTP cookie writer).
func (i IssuedSession) Secret() []byte { return append([]byte(nil), i.secret...) }

// CSRFToken returns the token the browser must echo for this session.
func (i IssuedSession) CSRFToken() string { return csrfToken(i.secret, i.Info.ID) }

// LoginResult is the outcome of the password step. Next lists only what the
// ACCOUNT policy allows after a correct password: "totp", "webauthn", "no-mfa".
type LoginResult struct {
	Session IssuedSession
	Next    []string
	// totp lists the account's usable authenticator apps (random, non-secret record
	// identifiers) read in the same transaction as the proof, so the login adapter can
	// offer a choice without presenting the new session's secret to a second lookup.
	totp []totpRow
}

// Sessions is the server-authoritative session service. Every assurance, method,
// authentication time and generation is derived from verified proofs and the live
// installation control row inside one durable control transaction.
type Sessions struct {
	l        *Lifecycle
	w        *WebAuthnService
	settings SessionSettings
	origin   *url.URL
	random   io.Reader
	maxLive  int
	// afterRecover is a test-only seam (nil in production) that runs between the committed
	// consumption of a saved code and the derivation of the HTTP response (P1.18.4 P116-L6).
	afterRecover func()
}

// NewSessions binds the session service to the trusted HTTPS origin already
// configured for the lifecycle service. When WebAuthn is configured, that origin
// must also be an allowed WebAuthn origin, so cookie and ceremony names agree.
func NewSessions(l *Lifecycle, w *WebAuthnService, settings SessionSettings) (*Sessions, error) {
	if l == nil || !settings.valid() || (w != nil && w.lifecycle != l) {
		return nil, ErrDenied
	}
	origin, err := url.Parse(l.notices.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return nil, ErrDenied
	}
	if w != nil {
		allowed := false
		for _, o := range w.verifier.Config.RPOrigins {
			allowed = allowed || o == origin.Scheme+"://"+origin.Host
		}
		if !allowed {
			return nil, ErrDenied
		}
	}
	return &Sessions{l: l, w: w, settings: settings, origin: origin, random: rand.Reader, maxLive: maxLiveSessionsPerUser}, nil
}
