package authz

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"strings"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// PrincipalKind distinguishes human users from non-human machine agents.
type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalAgent PrincipalKind = "agent"
)

// Session method bitmask values from schema migration 00001_initial.sql.
const (
	methodPassword   int64 = 1
	methodTOTP       int64 = 2
	methodWebAuthn   int64 = 4
	methodWebAuthnUV int64 = 8
	methodRecovery   int64 = 16
)

// SessionID is a strongly-typed human session UUID.
type SessionID string

// AgentCredentialID is a strongly-typed agent credential UUID.
type AgentCredentialID string

// PolicyID is a strongly-typed policy rule UUID.
type PolicyID string

// PrincipalCredentials carries credential lookup references for authorization.
// Secret fields are redacted in all string and log formatting.
// Caller-supplied fields never establish assurance or administrative authority;
// all assurance, purpose, role, and generation attributes are loaded from trusted storage.
type PrincipalCredentials struct {
	UserID            domain.UserID
	SessionID         SessionID
	SessionSecret     []byte
	AgentID           domain.AgentID
	AgentCredentialID AgentCredentialID
	AgentToken        string
	AgentTokenHash    []byte

	// UntrustedCallerAssurance and UntrustedCallerAdmin are ignored by the authorizer
	// and exist to allow negative tests to prove caller assertions cannot escalate authority.
	UntrustedCallerAssurance int64
	UntrustedCallerAdmin     bool
}

func (PrincipalCredentials) String() string   { return "PrincipalCredentials{[REDACTED]}" }
func (PrincipalCredentials) GoString() string { return "PrincipalCredentials{[REDACTED]}" }
func (c PrincipalCredentials) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("user_id", string(c.UserID)),
		slog.String("session_id", string(c.SessionID)),
		slog.String("agent_id", string(c.AgentID)),
		slog.String("agent_credential_id", string(c.AgentCredentialID)),
		slog.String("secret", "[REDACTED]"),
	)
}

// VerifiedPrincipal contains the trusted server-verified principal identity,
// achieved assurance, active group memberships, and control generations.
type VerifiedPrincipal struct {
	Kind                PrincipalKind
	UserID              domain.UserID
	SessionID           SessionID
	AgentID             domain.AgentID
	AgentCredentialID   AgentCredentialID
	AchievedAssurance   int64
	PhishingResistant   bool
	ActiveGroups        []domain.GroupID
	DenyCandidateGroups []domain.GroupID
	Generations         store.Generations
}

// CredentialVerifier validates principal and credential status against trusted state.
type CredentialVerifier interface {
	VerifyPrincipal(
		ctx context.Context,
		q *store.Queries,
		control store.InstallationControl,
		creds PrincipalCredentials,
		now time.Time,
	) (VerifiedPrincipal, error)
}

type storeCredentialVerifier struct{}

// NewStoreCredentialVerifier returns the default SQLite-backed CredentialVerifier.
func NewStoreCredentialVerifier() CredentialVerifier {
	return storeCredentialVerifier{}
}

func activeInstallationControl(c store.InstallationControl) bool {
	return c.Singleton == 1 &&
		c.RestoreQuarantined == 0 &&
		c.CredentialGeneration > 0 &&
		c.SessionGeneration > 0 &&
		c.AuthorityGeneration > 0 &&
		c.RestoreGeneration > 0
}

func (storeCredentialVerifier) VerifyPrincipal(
	ctx context.Context,
	q *store.Queries,
	control store.InstallationControl,
	creds PrincipalCredentials,
	now time.Time,
) (VerifiedPrincipal, error) {
	if !activeInstallationControl(control) {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	hasUser := creds.SessionID != "" || len(creds.SessionSecret) > 0 || creds.UserID != ""
	hasAgent := creds.AgentCredentialID != "" || creds.AgentToken != "" || len(creds.AgentTokenHash) > 0 || creds.AgentID != ""
	if (hasUser && hasAgent) || (!hasUser && !hasAgent) {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	nowUnix := now.Unix()
	gens := store.Generations{
		Credential: control.CredentialGeneration,
		Session:    control.SessionGeneration,
		Authority:  control.AuthorityGeneration,
		Restore:    control.RestoreGeneration,
	}

	if hasUser {
		return verifyUserSession(ctx, q, control, gens, creds, nowUnix)
	}
	return verifyAgentToken(ctx, q, control, gens, creds, nowUnix)
}

func verifyUserSession(
	ctx context.Context,
	q *store.Queries,
	control store.InstallationControl,
	gens store.Generations,
	creds PrincipalCredentials,
	nowUnix int64,
) (VerifiedPrincipal, error) {
	if len(creds.SessionSecret) == 0 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	secretSum := sha256.Sum256(creds.SessionSecret)

	var sess store.Session
	var err error
	if creds.SessionID != "" {
		if !isValidID(string(creds.SessionID)) {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
		sess, err = q.GetSession(ctx, string(creds.SessionID))
		if err != nil {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
		if subtle.ConstantTimeCompare(sess.SecretHash, secretSum[:]) != 1 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	} else {
		sess, err = q.GetSessionByHash(ctx, secretSum[:])
		if err != nil {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	}

	if creds.UserID != "" && string(creds.UserID) != sess.UserID {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	// Validate session state, purpose, generations, absolute expiry, and idle timeout.
	if sess.State != "active" || sess.RevokedAt.Valid || sess.Purpose != "normal" || !sess.AuthenticatedAt.Valid {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if sess.CredentialGeneration <= 0 || sess.CredentialGeneration != control.CredentialGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if sess.SessionGeneration <= 0 || sess.SessionGeneration != control.SessionGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if sess.ExpiresAt <= sess.CreatedAt || nowUnix >= sess.ExpiresAt {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if sess.IdleTimeoutSeconds <= 0 || nowUnix-sess.LastActivityAt >= sess.IdleTimeoutSeconds {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	// Validate session assurance and method bitmask invariants (TD §4.1).
	if sess.Methods <= 0 || (sess.Methods&methodRecovery) != 0 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if sess.AchievedAssurance < 1 || sess.AchievedAssurance > 2 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if sess.AchievedAssurance == 2 {
		hasWebAuthnUV := (sess.Methods & methodWebAuthnUV) != 0
		hasPasswordAndSecondFactor := (sess.Methods&methodPassword) != 0 && (sess.Methods&(methodTOTP|methodWebAuthn)) != 0
		if !hasWebAuthnUV && !hasPasswordAndSecondFactor {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	}
	if sess.PhishingResistant == 1 && (sess.Methods&(methodWebAuthn|methodWebAuthnUV)) == 0 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	if !isValidID(sess.UserID) {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	userID := domain.UserID(sess.UserID)
	user, err := q.GetUser(ctx, sess.UserID)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if user.State != "active" || user.Compromised != 0 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if user.CredentialGeneration <= 0 || user.CredentialGeneration != control.CredentialGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if user.AuthorityGeneration <= 0 || user.AuthorityGeneration != control.AuthorityGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	// Check administrative roles: admin roles NEVER grant implicit container operations,
	// and any user with an administrative role requires AAL2 MFA (TD §4.1).
	roles, err := q.ListUserAdministrativeRoles(ctx, user.ID)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	hasAdminRole := false
	for _, r := range roles {
		if r.State != "disabled" {
			hasAdminRole = true
			break
		}
	}

	switch user.MfaRequirement {
	case "optional":
		if hasAdminRole && sess.AchievedAssurance < 2 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	case "required":
		if sess.AchievedAssurance < 2 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	case "webauthn":
		if sess.AchievedAssurance < 2 || sess.PhishingResistant != 1 || (sess.Methods&(methodWebAuthn|methodWebAuthnUV)) == 0 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	default:
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	// If session_authenticators bindings are recorded, every bound authenticator must remain active.
	boundAuths, err := q.ListSessionAuthenticators(ctx, sess.ID)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	for _, a := range boundAuths {
		if a.UserID != user.ID || a.State != "active" || a.RevokedAt.Valid || a.CredentialGeneration != control.CredentialGeneration {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
		if a.ExpiresAt.Valid && nowUnix >= a.ExpiresAt.Int64 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	}

	memberships, err := q.ListUserGroupMembershipsWithGroups(ctx, user.ID)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	var activeGroups, denyGroups []domain.GroupID
	for _, m := range memberships {
		if !isValidID(m.GroupID) {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
		gid := domain.GroupID(m.GroupID)
		if m.MembershipState == "active" &&
			m.MembershipAuthorityGeneration == control.AuthorityGeneration &&
			m.GroupState == "active" &&
			m.GroupAuthorityGeneration == control.AuthorityGeneration {
			activeGroups = append(activeGroups, gid)
			denyGroups = append(denyGroups, gid)
		} else if m.MembershipState != "disabled" && m.GroupState != "disabled" {
			denyGroups = append(denyGroups, gid)
		}
	}

	return VerifiedPrincipal{
		Kind:                PrincipalUser,
		UserID:              userID,
		SessionID:           SessionID(sess.ID),
		AchievedAssurance:   sess.AchievedAssurance,
		PhishingResistant:   sess.PhishingResistant == 1,
		ActiveGroups:        activeGroups,
		DenyCandidateGroups: denyGroups,
		Generations:         gens,
	}, nil
}

func verifyAgentToken(
	ctx context.Context,
	q *store.Queries,
	control store.InstallationControl,
	gens store.Generations,
	creds PrincipalCredentials,
	nowUnix int64,
) (VerifiedPrincipal, error) {
	var tokenHash []byte
	if creds.AgentToken != "" {
		if !strings.HasPrefix(creds.AgentToken, "mdt_") || len(creds.AgentToken) < 16 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
		sum := sha256.Sum256([]byte(creds.AgentToken))
		tokenHash = sum[:]
	} else if len(creds.AgentTokenHash) == 32 {
		tokenHash = creds.AgentTokenHash
	} else {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	cred, err := q.GetAgentCredentialByHash(ctx, tokenHash)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if subtle.ConstantTimeCompare(cred.TokenHash, tokenHash) != 1 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if creds.AgentCredentialID != "" && string(creds.AgentCredentialID) != cred.ID {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if creds.AgentID != "" && string(creds.AgentID) != cred.AgentID {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	if cred.State != "active" || cred.RevokedAt.Valid {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if cred.CredentialGeneration <= 0 || cred.CredentialGeneration != control.CredentialGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	if cred.NonexpiringApproved == 1 {
		if cred.ExpiresAt.Valid {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	} else if cred.NonexpiringApproved == 0 {
		if !cred.ExpiresAt.Valid || cred.ExpiresAt.Int64 <= cred.IssuedAt || nowUnix >= cred.ExpiresAt.Int64 {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
	} else {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	if cred.RotationOverlapUntil.Valid && nowUnix >= cred.RotationOverlapUntil.Int64 {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	if !isValidID(cred.AgentID) {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	agentID := domain.AgentID(cred.AgentID)
	agent, err := q.GetAgent(ctx, cred.AgentID)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if agent.State != "active" {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if agent.CredentialGeneration <= 0 || agent.CredentialGeneration != control.CredentialGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if agent.AuthorityGeneration <= 0 || agent.AuthorityGeneration != control.AuthorityGeneration {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	if agent.OwnerUserID.Valid == agent.OwnerGroupID.Valid {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}

	// Only explicit agent_group_memberships apply; owner_user_id and owner_group_id
	// never confer implicit permissions (TD §2.1, §3.1, §3.3).
	memberships, err := q.ListAgentGroupMembershipsWithGroups(ctx, agent.ID)
	if err != nil {
		return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
	}
	var activeGroups, denyGroups []domain.GroupID
	for _, m := range memberships {
		if !isValidID(m.GroupID) {
			return VerifiedPrincipal{}, newUnauthenticated(ReasonUnauthenticated)
		}
		gid := domain.GroupID(m.GroupID)
		if m.MembershipState == "active" &&
			m.MembershipAuthorityGeneration == control.AuthorityGeneration &&
			m.GroupState == "active" &&
			m.GroupAuthorityGeneration == control.AuthorityGeneration {
			activeGroups = append(activeGroups, gid)
			denyGroups = append(denyGroups, gid)
		} else if m.MembershipState != "disabled" && m.GroupState != "disabled" {
			denyGroups = append(denyGroups, gid)
		}
	}

	return VerifiedPrincipal{
		Kind:                PrincipalAgent,
		AgentID:             agentID,
		AgentCredentialID:   AgentCredentialID(cred.ID),
		AchievedAssurance:   0,
		PhishingResistant:   false,
		ActiveGroups:        activeGroups,
		DenyCandidateGroups: denyGroups,
		Generations:         gens,
	}, nil
}
