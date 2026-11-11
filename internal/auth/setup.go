package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// P1.09: one-time first-administrator bootstrap and host-local emergency recovery
// (security-contracts.md S3, TD §10.3). This file holds the shared vocabulary,
// token primitives and the clock/eligibility guards that every transition uses.
//
// What this is NOT: a login path. A setup/recovery session lives in its own table
// (setup_sessions), is never read by the normal session verifier or the shared
// authorizer, carries no assurance label, and can only perform the narrow
// enrollment steps of its purpose. Unlocking the installation requires committed
// password + proven MFA enrollment AND a subsequent ordinary qualifying login.

// SetupPurpose names the one thing a token may be exchanged for.
type SetupPurpose string

const (
	PurposeInitialSetup    SetupPurpose = "initial_setup"
	PurposeMFAReset        SetupPurpose = "mfa_reset"
	PurposeRestoreRecovery SetupPurpose = "restore_recovery"
)

func (p SetupPurpose) valid() bool {
	return p == PurposeInitialSetup || p == PurposeMFAReset || p == PurposeRestoreRecovery
}

const (
	// SetupTokenLifetime is the ABSOLUTE lifetime of one generation (TD §10.3).
	// No retrieval, restart, retry or rotation of another generation extends it.
	SetupTokenLifetime = 30 * time.Minute
	setupTokenEntropy  = 32 // 256 bits from the OS CSPRNG
	setupTokenChars    = 52 // base32 of 32 bytes without padding
	// A guessing campaign revokes the live generations of the attacked purpose at
	// this many evaluated failures; waits start at five (same schedule as passwords).
	setupFailureCeiling = 100
	setupMaxAddresses   = 4
	setupMaxProofs      = 12
	setupProofLifetime  = 15 * time.Minute
	setupProofResend    = 60 * time.Second
	setupUsernameMax    = 64
	setupRevealHeader   = "MANDATARY-SETUP-REVEAL v1"
)

// Fixed public outcomes. None carries input, token, digest or storage detail.
var (
	ErrSetupDenied      = errors.New("setup request denied")
	ErrSetupBusy        = errors.New("setup request rate limited")
	ErrSetupUnavailable = errors.New("setup unavailable")
	// errSetupLogical marks a refusal inside a control callback so it is reported
	// as a denial rather than storage uncertainty. It rolls the callback back.
	errSetupLogical = errors.New("setup refused")
)

// SetupSettings is trusted deployment configuration, never request input.
type SetupSettings struct {
	// Origin is the configured HTTPS origin (scheme://host[:port], no path). The
	// logged setup URL derives only from it, never from a Host/forwarded header.
	Origin string
	// Build identifies this binary. A host helper whose build differs from the one
	// that issued a token refuses to reveal it (S3.1b step 1).
	Build string
}

// SetupURL is the single secret-free URL that may be logged. It never contains a
// token, query, fragment or userinfo; the secret is entered into the form.
func (c SetupSettings) SetupURL() (string, bool) {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(c.Origin, " \t\r\n") {
		return "", false
	}
	return strings.TrimSuffix(c.Origin, "/") + "/setup", true
}

// valid allows an empty Origin: the host helper has no HTTP surface and needs no
// URL. Every HTTP/URL use requires a valid origin and checks it itself.
func (c SetupSettings) valid() bool {
	if c.Origin != "" {
		if _, ok := c.SetupURL(); !ok {
			return false
		}
	}
	return c.Build != "" && len(c.Build) <= 128 && !strings.ContainsAny(c.Build, "\r\n\x00")
}

// SetupPending reports whether the installation is an eligible empty store with
// no completed setup. It is read-only and needs no origin or mail configuration.
func SetupPending(ctx context.Context, repo *store.Repository, now time.Time) (bool, error) {
	pending := false
	err := repo.Read(ctx, func(q *store.Queries) error {
		pending = clockReadable(ctx, q, now.Unix()) == nil && setupEligible(ctx, q) == nil
		return nil
	})
	if err != nil {
		return false, ErrSetupUnavailable
	}
	return pending, nil
}

// Setup is the setup/recovery service. Enrollment methods need the lifecycle
// service (password policy, notices, SMTP); the host-protocol methods (issue,
// reveal, status, reconcile, exchange) need only the repository, so the host
// helper never constructs mail or HTTP surfaces.
type Setup struct {
	repo     *store.Repository
	l        *Lifecycle
	settings SetupSettings
	now      func() time.Time
	random   io.Reader
	gate     *trafficGate
	// sendProof delivers an address-confirmation proof; nil means no protected
	// delivery is configured and confirmation (hence completion) is impossible.
	sendProof func(ctx context.Context, to, proof string) string
	// hook is a test-only fault-injection seam invoked at each protocol step. It is
	// nil in production and can only add failures, never skip a check.
	hook func(step string) error
}

// NewSetup builds the service. l may be nil (host helper / mail not configured).
func NewSetup(repo *store.Repository, l *Lifecycle, settings SetupSettings) (*Setup, error) {
	if repo == nil || !settings.valid() || (l != nil && l.repo != repo) {
		return nil, ErrSetupDenied
	}
	gate, err := newTrafficGate()
	if err != nil {
		return nil, ErrSetupDenied
	}
	s := &Setup{repo: repo, l: l, settings: settings, now: time.Now, random: rand.Reader, gate: gate}
	if l != nil {
		s.now = func() time.Time { return l.now() }
		s.sendProof = l.sendAddressProof
	}
	return s, nil
}

func (s *Setup) step(name string) error {
	if s.hook != nil {
		return s.hook(name)
	}
	return nil
}

func (s *Setup) randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.random, b); err != nil {
		clear(b)
		return nil, ErrSetupUnavailable
	}
	return b, nil
}

func (s *Setup) randomHex() (string, error) {
	b, err := s.randomBytes(32)
	if err != nil {
		return "", err
	}
	defer clear(b)
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range b {
		out[2*i], out[2*i+1] = digits[v>>4], digits[v&15]
	}
	return string(out), nil
}

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newToken returns the canonical 52-character token. The caller must clear it.
func (s *Setup) newToken() ([]byte, error) {
	raw, err := s.randomBytes(setupTokenEntropy)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	out := make([]byte, tokenEncoding.EncodedLen(len(raw)))
	tokenEncoding.Encode(out, raw)
	return out, nil
}

// canonicalToken accepts the canonical form with optional hyphen grouping and
// surrounding ASCII whitespace (paste convenience). Anything else is rejected
// BEFORE any proof evaluation and therefore never counts as a failed guess.
func canonicalToken(input string) ([]byte, bool) {
	if len(input) > 128 {
		return nil, false
	}
	trimmed := strings.Trim(input, " \t\r\n")
	compact := strings.ReplaceAll(trimmed, "-", "")
	if len(compact) != setupTokenChars {
		return nil, false
	}
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return nil, false
		}
	}
	return []byte(compact), true
}

// groupedToken is the display form only (hyphen every four characters).
func groupedToken(canonical []byte) []byte {
	out := make([]byte, 0, len(canonical)+len(canonical)/4)
	for i, c := range canonical {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, c)
	}
	return out
}

// setupDigest is domain-separated by purpose so a token for one purpose can never
// verify as another. SHA-256 is sufficient because the input has 256 random bits;
// this is not a password verifier.
func setupDigest(purpose SetupPurpose, canonical []byte) []byte {
	h := sha256.New()
	h.Write([]byte("mandatary setup token v1\x00"))
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write(canonical)
	return h.Sum(nil)
}

func digestEqual(a, b []byte) bool {
	return len(a) == 32 && len(b) == 32 && subtle.ConstantTimeCompare(a, b) == 1
}

func revealFileName(purpose string, generation int64) string {
	return purpose + "-" + strconv.FormatInt(generation, 10) + ".token"
}

// setupClock enforces trustworthy-UTC monotonicity (S3.1): any transition that
// observes a clock below the recorded high-water mark, or an out-of-range value,
// is denied; observing a later time advances the mark durably in the same
// transaction. Moving the host clock back therefore never regains a window.
func setupClock(ctx context.Context, q *store.Queries, now int64) error {
	if now <= 0 || now > 253402300799 {
		return errSetupLogical
	}
	n, err := q.AdvanceSetupClock(ctx, now)
	if err != nil {
		return err
	}
	if n != 1 {
		return errSetupLogical
	}
	return nil
}

// clockReadable is the read-only counterpart for non-writing checks.
func clockReadable(ctx context.Context, q *store.Queries, now int64) error {
	st, err := q.GetSetupState(ctx)
	if err != nil {
		return err
	}
	if now <= 0 || now > 253402300799 || now < st.ClockHighWater {
		return errSetupLogical
	}
	return nil
}

// setupEligible is the empty-store test (SETUP-01). A missing/corrupt control
// record, a completed setup, any non-zero local control generation, a lifted
// quarantine or ANY prior authority record makes the installation ineligible.
// It never creates, repairs or migrates anything.
func setupEligible(ctx context.Context, q *store.Queries) error {
	c, err := q.GetInstallationControl(ctx)
	if err != nil {
		return err
	}
	st, err := q.GetSetupState(ctx)
	if err != nil {
		return err
	}
	if st.CompletedAt.Valid || c.CredentialGeneration != 0 || c.SessionGeneration != 0 || c.AuthorityGeneration != 0 || c.RestoreGeneration != 0 || c.RestoreQuarantined != 1 {
		return errSetupLogical
	}
	blockers, err := q.CountSetupBlockers(ctx)
	if err != nil {
		return err
	}
	if blockers != 0 {
		return errSetupLogical
	}
	return nil
}

// run executes one bounded control transaction. fn returns errSetupLogical (or
// wraps it) for a refusal; any other error is storage uncertainty. A client
// disconnect cannot cancel an already admitted protective write.
func (s *Setup) run(ctx context.Context, fn func(ctx context.Context, q *store.Queries, now int64) error, after func() error) error {
	logical := false
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := s.repo.Control(bounded, func(q *store.Queries) error {
		now := s.now().Unix()
		if err := setupClock(bounded, q, now); err != nil {
			logical = errors.Is(err, errSetupLogical)
			return err
		}
		if err := fn(bounded, q, now); err != nil {
			logical = errors.Is(err, errSetupLogical)
			return err
		}
		return nil
	}, after)
	return classify(err, logical)
}

func classify(err error, logical bool) error {
	switch {
	case err == nil:
		return nil
	case logical:
		return ErrSetupDenied
	default:
		return ErrSetupUnavailable
	}
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
