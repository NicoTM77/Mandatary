package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NicoTM77/Mandatary/internal/auth/nfc17"
	"github.com/NicoTM77/Mandatary/internal/store"
)

var ErrDenied = errors.New("authentication failed")

// Proof is only an observed password match, NOT a session/capability or AAL2.
// Later ceremonies MUST recheck current binding/generations and prove MFA.
// A compulsory-MFA proof intentionally resets NO retry state.
type Proof struct {
	UserID, AuthenticatorID string
	RequiresMFA             bool
}
type Service struct {
	repo   *store.Repository
	policy Policy
	now    func() time.Time
	gate   *trafficGate
	verify func([]byte, []byte, string) bool
}

// Admission is bounded across Service handles in this process, before any KDF.
// Repository.Control serializes helpers/other processes as well; no speculative
// parallel hashes can overrun the remaining durable proof-failure budget.
var passwordWork = make(chan struct{}, 1)
var dummyOnce sync.Once
var dummyVerifier []byte
var dummyError error

func NewService(r *store.Repository, p Policy) (*Service, error) {
	if r == nil || p.MinimumPasswordOnly < 15 || p.MinimumPasswordOnly > 128 || p.MinimumMFA < 8 || p.MinimumMFA > 128 {
		return nil, ErrDenied
	}
	dummyOnce.Do(func() {
		dummyVerifier, dummyError = hashPassword([]byte("public dummy proof work, not a credential"), bytes.NewReader([]byte("0123456789abcdef")))
	})
	if dummyError != nil {
		return nil, ErrDenied
	}
	gate, e := newTrafficGate()
	if e != nil {
		return nil, ErrDenied
	}
	return &Service{repo: r, policy: p, now: time.Now, gate: gate, verify: VerifyPassword}, nil
}

// Prove is called only inside a trusted protected-transport adapter. ip is the
// validated peer address, never an unchecked forwarded header. All denied cases
// share one safe error (future adapter: 401 / {"error":"authentication failed"}).
// Entire proof evaluation is under the shared control lock. This deliberate
// bounded serialization trades throughput for exact durable ceiling semantics;
// it does not issue or revive any authority. No external network runs here.
func (s *Service) Prove(ctx context.Context, name string, raw []byte, ip string) (Proof, error) {
	if ctx.Err() != nil {
		return Proof{}, ErrDenied
	}
	caller := ctx
	if len(name) == 0 || len(name) > 256 || !s.gate.allow(ip, s.now()) {
		return Proof{}, ErrDenied
	}
	select {
	case passwordWork <- struct{}{}:
		defer func() { <-passwordWork }()
	default:
		return Proof{}, ErrDenied
	}
	canonical, e := nfc17.Canonical(raw)
	if e != nil {
		return Proof{}, ErrDenied
	}
	var result Proof
	// Once admitted, a bounded control transaction must finish recording actual
	// proof work even if an untrusted HTTP caller disconnects. Cancellation must
	// neither erase failures nor be mistaken for storage uncertainty/poisoning.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e = s.repo.Control(ctx, func(q *store.Queries) (failure error) {
		evaluated := false
		defer func() {
			if failure != nil && evaluated {
				s.repo.FailClosed()
			}
		}()
		control, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		if !activeControl(control) {
			return nil
		}
		u, e := q.GetUserByUsername(ctx, name)
		if errors.Is(e, sql.ErrNoRows) {
			_ = s.verify(canonical, dummyVerifier, PasswordProfile)
			return nil
		}
		if e != nil {
			return e
		}
		a, e := q.GetLocalBinding(ctx, u.ID)
		if errors.Is(e, sql.ErrNoRows) {
			_ = s.verify(canonical, dummyVerifier, PasswordProfile)
			return nil
		}
		if e != nil {
			return e
		}
		now := s.now().Unix()
		if !activeBinding(control, u, a, now) {
			_ = s.verify(canonical, dummyVerifier, PasswordProfile)
			return nil
		}
		if a.NextAttemptAt.Valid && now < a.NextAttemptAt.Int64 {
			return nil
		}
		if _, _, valid := parseVerifier(a.VerifierHash, a.PasswordFormat.String); !valid {
			_ = s.verify(canonical, dummyVerifier, PasswordProfile)
			return nil
		}
		if caller.Err() != nil {
			return nil
		}
		matched := s.verify(canonical, a.VerifierHash, a.PasswordFormat.String)
		evaluated = true
		// Recheck after expensive work in this SAME serialized transaction; no
		// unobserved change/reset/restore can be acknowledged as a successful proof.
		current, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		user, e := q.GetUser(ctx, u.ID)
		if e != nil {
			return e
		}
		binding, e := q.GetAuthenticator(ctx, a.ID)
		if e != nil {
			return e
		}
		if current != control || user != u || !samePassword(a, binding) || !activeBinding(current, user, binding, s.now().Unix()) {
			return nil
		}
		if !matched {
			n, e := q.RecordProofFailure(ctx, store.RecordProofFailureParams{ID: a.ID, ObservedFailures: a.FailedAttempts, NextAttemptAt: sql.NullInt64{Int64: now + passwordWait(a.FailedAttempts+1), Valid: true}})
			if e != nil {
				return e
			}
			if n != 1 {
				return ErrDenied
			}
			return nil
		}
		stronger, e := q.HasStrongerAuthenticator(ctx, store.HasStrongerAuthenticatorParams{UserID: u.ID, CredentialGeneration: control.CredentialGeneration, Now: sql.NullInt64{Int64: s.now().Unix(), Valid: true}})
		if e != nil {
			return e
		}
		required := u.MfaRequirement != "optional"
		if !required && !stronger {
			n, e := q.ResetProofFailures(ctx, a.ID)
			if e != nil {
				return e
			}
			if n != 1 {
				return ErrDenied
			}
		}
		result = Proof{UserID: u.ID, AuthenticatorID: a.ID, RequiresMFA: required}
		return nil
	}, nil)
	if e != nil || result.UserID == "" {
		return Proof{}, ErrDenied
	}
	return result, nil
}

// ReplacePassword is an internal persistence primitive for a separately
// authorized fresh appropriate-strength ceremony (P1.08/09), NOT a reset API.
// The observed verifier is a concurrency precondition, never authorization.
// It cannot enroll/activate a missing, disabled, revoked or imported binding.
func (s *Service) ReplacePassword(ctx context.Context, id string, observed, raw []byte) error {
	select {
	case passwordWork <- struct{}{}:
		defer func() { <-passwordWork }()
	default:
		return ErrDenied
	}
	var c store.InstallationControl
	var u store.User
	var a store.Authenticator
	e := s.repo.Read(ctx, func(q *store.Queries) error {
		var e error
		c, e = q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		u, e = q.GetUser(ctx, id)
		if e != nil {
			return e
		}
		a, e = q.GetLocalBinding(ctx, id)
		return e
	})
	if e != nil {
		return ErrDenied
	}
	// Compromise is allowed only for replacement eligibility, never proof success.
	eligible := u
	eligible.Compromised = 0
	if !activeBinding(c, eligible, a, s.now().Unix()) || !bytes.Equal(a.VerifierHash, observed) {
		return ErrDenied
	}
	if _, _, valid := parseVerifier(a.VerifierHash, a.PasswordFormat.String); !valid {
		return ErrDenied
	}
	canonical, e := s.policy.Validate(ctx, raw, u.MfaRequirement != "optional", []string{u.Username})
	if e != nil {
		return e
	}
	if VerifyPassword(canonical, a.VerifierHash, a.PasswordFormat.String) {
		return ErrPassword
	}
	replacement, e := HashPassword(canonical)
	if e != nil {
		return e
	}
	e = s.repo.Control(ctx, func(q *store.Queries) error {
		current, e := q.GetInstallationControl(ctx)
		if e != nil {
			return e
		}
		user, e := q.GetUser(ctx, id)
		if e != nil {
			return e
		}
		binding, e := q.GetAuthenticator(ctx, a.ID)
		if e != nil {
			return e
		}
		if current != c || user != u || !samePassword(a, binding) {
			return ErrDenied
		}
		now := s.now().Unix()
		eligible = user
		eligible.Compromised = 0
		if !activeBinding(current, eligible, binding, now) {
			return ErrDenied
		}
		n, e := q.UpdateVerifier(ctx, store.UpdateVerifierParams{ID: a.ID, ObservedVerifier: observed, VerifierHash: replacement, PasswordFormat: sql.NullString{String: PasswordProfile, Valid: true}, PasswordCodepoints: sql.NullInt64{Int64: int64(utf8.RuneCount(canonical)), Valid: true}, CredentialGeneration: a.CredentialGeneration, Now: sql.NullInt64{Int64: now, Valid: true}})
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrDenied
		}
		if _, e = q.ClearCompromiseFlag(ctx, id); e != nil {
			return e
		}
		return q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: id, Now: sql.NullInt64{Int64: now, Valid: true}})
	}, nil)
	if e != nil {
		return ErrDenied
	}
	return nil
}

// MarkCompromised is a narrow protective primitive, not an administrator
// authorization check. Its later caller must authorize the report; it grants
// no replacement/session authority. Repository uncertainty poisons acceptance.
func (s *Service) MarkCompromised(ctx context.Context, userID string) error {
	// The caller has already authorized this protective intent. A client cannot
	// cancel it into an unrecorded report or a process-wide availability failure.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e := s.repo.Control(ctx, func(q *store.Queries) error {
		n, e := q.CompromiseUser(ctx, userID)
		if e != nil {
			s.repo.FailClosed()
			return e
		}
		if n != 1 {
			return ErrDenied
		}
		e = q.RevokeUserSessions(ctx, store.RevokeUserSessionsParams{UserID: userID, Now: sql.NullInt64{Int64: s.now().Unix(), Valid: true}})
		if e != nil {
			s.repo.FailClosed()
		}
		return e
	}, nil)
	if e != nil {
		return ErrDenied
	}
	return nil
}

func activeControl(c store.InstallationControl) bool {
	return c.RestoreQuarantined == 0 && c.CredentialGeneration > 0 && c.SessionGeneration > 0 && c.AuthorityGeneration > 0 && c.RestoreGeneration > 0
}
func activeBinding(c store.InstallationControl, u store.User, a store.Authenticator, now int64) bool {
	return activeControl(c) && u.State == "active" && u.Compromised == 0 && u.CredentialGeneration == c.CredentialGeneration && u.AuthorityGeneration == c.AuthorityGeneration && a.UserID == u.ID && a.Kind == "password" && a.State == "active" && a.CredentialGeneration == c.CredentialGeneration && a.BoundAt.Valid && !a.RevokedAt.Valid && (!a.ExpiresAt.Valid || now < a.ExpiresAt.Int64) && a.FailedAttempts < a.RetryCeiling && a.PasswordCodepoints.Valid && a.PasswordCodepoints.Int64 >= 8 && a.PasswordCodepoints.Int64 <= 128 && (u.MfaRequirement != "optional" || a.PasswordCodepoints.Int64 >= 15)
}
func samePassword(a, b store.Authenticator) bool {
	return a.ID == b.ID && a.UserID == b.UserID && a.Kind == b.Kind && a.State == b.State && a.CredentialGeneration == b.CredentialGeneration && a.CreatedAt == b.CreatedAt && a.BoundAt == b.BoundAt && a.ChangedAt == b.ChangedAt && a.RevokedAt == b.RevokedAt && a.ExpiresAt == b.ExpiresAt && a.RetryCeiling == b.RetryCeiling && a.FailedAttempts == b.FailedAttempts && a.NextAttemptAt == b.NextAttemptAt && a.PasswordCodepoints == b.PasswordCodepoints && a.PasswordFormat == b.PasswordFormat && bytes.Equal(a.VerifierHash, b.VerifierHash)
}
func passwordWait(failures int64) int64 {
	if failures < 5 {
		return 0
	}
	shift := (failures - 5) / 5
	if shift > 6 {
		shift = 6
	}
	return 1 << uint(shift)
}

// Fixed windows never slide on denied traffic. Keys are process-ephemeral HMACs,
// not stored/logged IPs. Bounded map, idle expiry; capacity exhaustion denies.
// Account/factor waits are durable and cannot be bypassed by map churn/restart.
type trafficWindow struct {
	start time.Time
	count int
}
type trafficGate struct {
	mu  sync.Mutex
	key [32]byte
	ips map[[32]byte]trafficWindow
}

func newTrafficGate() (*trafficGate, error) {
	g := &trafficGate{ips: make(map[[32]byte]trafficWindow)}
	_, e := rand.Read(g.key[:])
	return g, e
}
func (g *trafficGate) allow(ip string, now time.Time) bool {
	addr, e := netip.ParseAddr(ip)
	if e != nil || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if addr.Is6() {
		addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	mac := hmac.New(sha256.New, g.key[:])
	_, _ = mac.Write(addr.AsSlice())
	var key [32]byte
	copy(key[:], mac.Sum(nil))
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.ips[key]
	if !ok {
		if len(g.ips) >= 4096 {
			for k, v := range g.ips {
				if now.Sub(v.start) >= time.Minute {
					delete(g.ips, k)
				}
			}
		}
		if len(g.ips) >= 4096 {
			return false
		}
	}
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute {
		w = trafficWindow{start: now}
	}
	if now.Before(w.start) || w.count >= 30 {
		return false
	}
	w.count++
	g.ips[key] = w
	return true
}
