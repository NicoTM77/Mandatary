package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"

	"github.com/NicoTM77/Mandatary/internal/store"
)

// Agent bearer-token format (TD §3.2): the recognizable prefix "mdt_" followed
// by the base62 rendering of 256 uniformly random bits, left-padded to a fixed
// 43 digits (62^43 > 2^256, so every 256-bit value fits and no bit is discarded).
// Only the SHA-256 of the whole token is ever stored; the short display
// identifier comes from the credential's separate random UUID, never from token
// characters, so it carries no information about the secret.
const (
	AgentTokenPrefix = "mdt_"
	agentTokenDigits = 43
	agentTokenLength = len(AgentTokenPrefix) + agentTokenDigits
	agentTokenBits   = 256
	base62Alphabet   = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var errAgentTokenRandom = errors.New("agent token randomness unavailable")

// ValidAgentTokenFormat reports whether s is a canonical agent token: exact
// prefix, exact length and base62 digits only. Adapters MAY use it to reject a
// malformed Authorization value before any storage lookup; it proves nothing
// about validity, and a well-formed value is still only a candidate.
func ValidAgentTokenFormat(s string) bool {
	if len(s) != agentTokenLength || !strings.HasPrefix(s, AgentTokenPrefix) {
		return false
	}
	for i := len(AgentTokenPrefix); i < len(s); i++ {
		if strings.IndexByte(base62Alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

// agentTokenHash is the only persisted representation of a token. It matches the
// verifier in internal/authz, which hashes the presented bearer value the same way.
func agentTokenHash(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

// newAgentToken reads exactly 32 bytes from source. All-zero output means a
// broken source, never a real draw (probability 2^-256) and is refused rather
// than issued. There is no fallback generator.
func newAgentToken(source io.Reader) ([]byte, error) {
	var raw [agentTokenBits / 8]byte
	defer clear(raw[:])
	if _, err := io.ReadFull(source, raw[:]); err != nil {
		return nil, errAgentTokenRandom
	}
	zero := true
	for _, b := range raw {
		zero = zero && b == 0
	}
	if zero {
		return nil, errAgentTokenRandom
	}
	n := new(big.Int).SetBytes(raw[:])
	defer n.SetInt64(0)
	digits := make([]byte, agentTokenDigits)
	base, remainder := big.NewInt(62), new(big.Int)
	for i := agentTokenDigits - 1; i >= 0; i-- {
		n.DivMod(n, base, remainder)
		digits[i] = base62Alphabet[remainder.Int64()]
	}
	if n.Sign() != 0 { // unreachable: 62^43 > 2^256; fail closed rather than truncate
		return nil, errAgentTokenRandom
	}
	return append([]byte(AgentTokenPrefix), digits...), nil
}

// CredentialStatus is the single server-derived label for a stored credential,
// mirroring the conditions the shared authorizer's verifier applies.
type CredentialStatus string

const (
	// CredentialActive is accepted now with no rotation pending.
	CredentialActive CredentialStatus = "active"
	// CredentialOverlapping was rotated out and is still accepted until its overlap ends.
	CredentialOverlapping CredentialStatus = "overlapping"
	// CredentialRotatedOut passed its overlap end: rejected.
	CredentialRotatedOut CredentialStatus = "rotated_out"
	CredentialExpired    CredentialStatus = "expired"
	CredentialRevoked    CredentialStatus = "revoked"
	// CredentialQuarantined is stored but never accepted (restore import, staged).
	CredentialQuarantined CredentialStatus = "quarantined"
	// CredentialStale belongs to an older credential generation or an inconsistent record.
	CredentialStale CredentialStatus = "stale"
)

// Live reports whether the status is one the verifier may still accept.
func (s CredentialStatus) Live() bool { return s == CredentialActive || s == CredentialOverlapping }

// credentialStatus applies the verifier's checks to one stored row. It never
// authenticates anything; it labels rows for the administrative views and the
// at-most-two-live-credentials rule, and a parity test pins it to the verifier.
func credentialStatus(c store.InstallationControl, cred store.AgentCredential, now int64) CredentialStatus {
	switch {
	case cred.State == "revoked" || cred.RevokedAt.Valid:
		return CredentialRevoked
	case cred.State != "active":
		return CredentialQuarantined
	case cred.CredentialGeneration <= 0 || cred.CredentialGeneration != c.CredentialGeneration || cred.IssuedAt > now:
		return CredentialStale
	}
	switch cred.NonexpiringApproved {
	case 1:
		if cred.ExpiresAt.Valid {
			return CredentialStale
		}
	case 0:
		if !cred.ExpiresAt.Valid || cred.ExpiresAt.Int64 <= cred.IssuedAt {
			return CredentialStale
		}
		if now >= cred.ExpiresAt.Int64 {
			return CredentialExpired
		}
	default:
		return CredentialStale
	}
	if cred.RotationOverlapUntil.Valid {
		if now >= cred.RotationOverlapUntil.Int64 {
			return CredentialRotatedOut
		}
		return CredentialOverlapping
	}
	return CredentialActive
}

// CredentialView is the secret-free metadata of one credential: never a token or
// a hash. Times are Unix seconds.
type CredentialView struct {
	ID            string           `json:"id"`
	DisplayID     string           `json:"display_id"`
	Status        CredentialStatus `json:"status"`
	IssuedAt      int64            `json:"issued_at"`
	ExpiresAt     *int64           `json:"expires_at"`
	NonExpiring   bool             `json:"non_expiring"`
	OverlapUntil  *int64           `json:"overlap_until"`
	RevokedAt     *int64           `json:"revoked_at"`
	CredentialGen int64            `json:"credential_generation"`
	AcceptedNow   bool             `json:"accepted_now"`
}

func credentialView(c store.InstallationControl, cred store.AgentCredential, now int64) CredentialView {
	view := CredentialView{ID: cred.ID, DisplayID: cred.DisplayPrefix, Status: credentialStatus(c, cred, now), IssuedAt: cred.IssuedAt, NonExpiring: cred.NonexpiringApproved == 1, CredentialGen: cred.CredentialGeneration}
	view.AcceptedNow = view.Status.Live()
	if cred.ExpiresAt.Valid {
		v := cred.ExpiresAt.Int64
		view.ExpiresAt = &v
	}
	if cred.RotationOverlapUntil.Valid {
		v := cred.RotationOverlapUntil.Int64
		view.OverlapUntil = &v
	}
	if cred.RevokedAt.Valid {
		v := cred.RevokedAt.Int64
		view.RevokedAt = &v
	}
	return view
}

// IssuedCredential carries the one-time plaintext of a newly issued token. It is
// produced only AFTER the creating transaction is durable, redacts every
// formatting/logging/JSON path, and surrenders the secret once via ExportOnce.
type IssuedCredential struct {
	Credential CredentialView
	secret     []byte
}

func (IssuedCredential) String() string                { return "IssuedCredential{[REDACTED]}" }
func (IssuedCredential) GoString() string              { return "IssuedCredential{[REDACTED]}" }
func (IssuedCredential) LogValue() slog.Value          { return slog.StringValue("[REDACTED]") }
func (IssuedCredential) MarshalJSON() ([]byte, error)  { return json.Marshal("[REDACTED]") }
func (IssuedCredential) MarshalText() ([]byte, error)  { return []byte("[REDACTED]"), nil }
func (i *IssuedCredential) ExportOnce() (token []byte) { token, i.secret = i.secret, nil; return token }
