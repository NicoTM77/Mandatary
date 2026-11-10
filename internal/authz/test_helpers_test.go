package authz_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/NicoTM77/Mandatary/tests/security/fixtures"
)

const (
	testLocalEndpointID = domain.EndpointID("00000000-0000-4000-8000-000000000001")
	testOtherEndpointID = domain.EndpointID("00000000-0000-4000-8000-000000000002")

	testUserID1    = domain.UserID("10000000-0000-4000-8000-000000000001")
	testUserID2    = domain.UserID("10000000-0000-4000-8000-000000000002")
	testAdminID    = domain.UserID("10000000-0000-4000-8000-000000000099")
	testSessionID1 = authz.SessionID("20000000-0000-4000-8000-000000000001")
	testSessionID2 = authz.SessionID("20000000-0000-4000-8000-000000000002")
	testAdminSess  = authz.SessionID("20000000-0000-4000-8000-000000000099")

	testGroupID1 = domain.GroupID("30000000-0000-4000-8000-000000000001")
	testGroupID2 = domain.GroupID("30000000-0000-4000-8000-000000000002")

	testAgentID1 = domain.AgentID("40000000-0000-4000-8000-000000000001")
	testAgentID2 = domain.AgentID("40000000-0000-4000-8000-000000000002")
	testCredID1  = authz.AgentCredentialID("50000000-0000-4000-8000-000000000001")
	testCredID2  = authz.AgentCredentialID("50000000-0000-4000-8000-000000000002")

	testSelectorID1 = domain.SelectorID("60000000-0000-4000-8000-000000000001")
	testSelectorID2 = domain.SelectorID("60000000-0000-4000-8000-000000000002")
	testSelectorID3 = domain.SelectorID("60000000-0000-4000-8000-000000000003")

	testPolicyID1 = authz.PolicyID("70000000-0000-4000-8000-000000000001")
	testPolicyID2 = authz.PolicyID("70000000-0000-4000-8000-000000000002")
	testPolicyID3 = authz.PolicyID("70000000-0000-4000-8000-000000000003")
	testPolicyID4 = authz.PolicyID("70000000-0000-4000-8000-000000000004")

	testEdgeProxyID     = docker.ContainerID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	testBillingWorkerID = docker.ContainerID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	testBatchMigratorID = docker.ContainerID("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	testCacheRedisID    = docker.ContainerID("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
)

type testEnv struct {
	t          *testing.T
	dir        string
	dbPath     string
	masterKey  *store.MasterKey
	repo       *store.Repository
	rawDB      *sql.DB
	clock      *fixtures.Clock
	backend    *docker.MockBackend
	authorizer *authz.Authorizer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	dbPath := filepath.Join(dir, "mandatary.db")
	mk, err := store.LoadMasterKey(strings.Repeat("11", 32), "")
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}

	repo, err := store.Open(context.Background(), store.Options{
		DataDir:   dir,
		MasterKey: mk,
		OwnerUID:  os.Geteuid(),
		OwnerGID:  os.Getegid(),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		_ = repo.Close()
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := rawDB.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`); err != nil {
		_ = rawDB.Close()
		_ = repo.Close()
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	t.Cleanup(func() {
		_ = rawDB.Close()
		_ = repo.Close()
	})

	clock := fixtures.NewClock()

	idCfg, mockContainers := docker.DefaultMockFixtures(testLocalEndpointID)
	backend, err := docker.NewMockBackend(docker.MockOptions{
		EndpointID: testLocalEndpointID,
		Identity:   idCfg,
		Containers: mockContainers,
	})
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if err := backend.VerifySelf(context.Background()); err != nil {
		t.Fatalf("VerifySelf: %v", err)
	}

	env := &testEnv{
		t:         t,
		dir:       dir,
		dbPath:    dbPath,
		masterKey: mk,
		repo:      repo,
		rawDB:     rawDB,
		clock:     clock,
		backend:   backend,
	}
	env.activateControlAndEndpoint(1, 1, 1, 1)

	az, err := authz.NewAuthorizer(authz.Config{
		Repository: repo,
		Clock:      clock.Now,
		Backends: map[domain.EndpointID]docker.DockerBackend{
			testLocalEndpointID: backend,
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	env.authorizer = az
	return env
}

func (e *testEnv) execSQL(query string, args ...any) {
	e.t.Helper()
	if _, err := e.rawDB.ExecContext(context.Background(), query, args...); err != nil {
		e.t.Fatalf("execSQL(%q): %v", query, err)
	}
}

func (e *testEnv) activateControlAndEndpoint(credGen, sessGen, authGen, restoreGen int64) {
	e.t.Helper()
	e.execSQL(
		`UPDATE installation_control SET credential_generation = ?, session_generation = ?, authority_generation = ?, restore_generation = ?, restore_quarantined = 0 WHERE singleton = 1`,
		credGen, sessGen, authGen, restoreGen,
	)
	e.execSQL(
		`UPDATE endpoints SET id = ?, state = 'active', authority_generation = ? WHERE slug = 'local'`,
		string(testLocalEndpointID), authGen,
	)
}

type seedUserOpts struct {
	ID                   domain.UserID
	Username             string
	State                string
	MfaRequirement       string
	Compromised          int64
	CredentialGeneration int64
	AuthorityGeneration  int64
}

func (e *testEnv) seedUser(opts seedUserOpts) {
	e.t.Helper()
	if opts.State == "" {
		opts.State = "active"
	}
	if opts.MfaRequirement == "" {
		opts.MfaRequirement = "required"
	}
	if opts.CredentialGeneration == 0 {
		opts.CredentialGeneration = 1
	}
	if opts.AuthorityGeneration == 0 {
		opts.AuthorityGeneration = 1
	}
	e.execSQL(
		`INSERT INTO users (id, username, state, mfa_requirement, compromised, credential_generation, authority_generation, password_revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1)
		 ON CONFLICT(id) DO UPDATE SET
		   username = excluded.username,
		   state = excluded.state,
		   mfa_requirement = excluded.mfa_requirement,
		   compromised = excluded.compromised,
		   credential_generation = excluded.credential_generation,
		   authority_generation = excluded.authority_generation`,
		string(opts.ID), opts.Username, opts.State, opts.MfaRequirement, opts.Compromised, opts.CredentialGeneration, opts.AuthorityGeneration,
	)
}

type seedSessionOpts struct {
	ID                   authz.SessionID
	UserID               domain.UserID
	RawSecret            []byte
	Purpose              string
	AchievedAssurance    int64
	Methods              int64
	PhishingResistant    int64
	CreatedAt            int64
	ExpiresAt            int64
	LastActivityAt       int64
	IdleTimeoutSeconds   int64
	AuthenticatedAt      sql.NullInt64
	RevokedAt            sql.NullInt64
	CredentialGeneration int64
	SessionGeneration    int64
	State                string
}

func (e *testEnv) seedSession(opts seedSessionOpts) []byte {
	e.t.Helper()
	now := e.clock.Now().Unix()
	if len(opts.RawSecret) == 0 {
		opts.RawSecret = []byte("session-secret-0123456789abcdef0123456789abcdef-" + string(opts.ID))
	}
	sum := sha256.Sum256(opts.RawSecret)
	if opts.Purpose == "" {
		opts.Purpose = "normal"
	}
	if opts.AchievedAssurance == 0 && opts.Purpose == "normal" {
		opts.AchievedAssurance = 2
	}
	if opts.Methods == 0 && opts.Purpose == "normal" {
		opts.Methods = 3
	}
	if opts.CreatedAt == 0 {
		opts.CreatedAt = now - 300
	}
	if opts.ExpiresAt == 0 {
		opts.ExpiresAt = now + 3600
	}
	if opts.LastActivityAt == 0 {
		opts.LastActivityAt = now - 60
	}
	if opts.IdleTimeoutSeconds == 0 {
		opts.IdleTimeoutSeconds = 1800
	}
	if !opts.AuthenticatedAt.Valid && opts.Purpose == "normal" {
		opts.AuthenticatedAt = sql.NullInt64{Int64: opts.CreatedAt, Valid: true}
	}
	if opts.CredentialGeneration == 0 {
		opts.CredentialGeneration = 1
	}
	if opts.SessionGeneration == 0 {
		opts.SessionGeneration = 1
	}
	if opts.State == "" {
		opts.State = "active"
	}
	e.execSQL(
		`INSERT INTO sessions (
			id, user_id, secret_hash, purpose, achieved_assurance, methods, phishing_resistant,
			authenticated_at, created_at, expires_at, last_activity_at, idle_timeout_seconds,
			revoked_at, credential_generation, session_generation, state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			user_id = excluded.user_id,
			secret_hash = excluded.secret_hash,
			purpose = excluded.purpose,
			achieved_assurance = excluded.achieved_assurance,
			methods = excluded.methods,
			phishing_resistant = excluded.phishing_resistant,
			authenticated_at = excluded.authenticated_at,
			created_at = excluded.created_at,
			expires_at = excluded.expires_at,
			last_activity_at = excluded.last_activity_at,
			idle_timeout_seconds = excluded.idle_timeout_seconds,
			revoked_at = excluded.revoked_at,
			credential_generation = excluded.credential_generation,
			session_generation = excluded.session_generation,
			state = excluded.state`,
		string(opts.ID), string(opts.UserID), sum[:], opts.Purpose, opts.AchievedAssurance, opts.Methods,
		opts.PhishingResistant, opts.AuthenticatedAt, opts.CreatedAt, opts.ExpiresAt, opts.LastActivityAt,
		opts.IdleTimeoutSeconds, opts.RevokedAt, opts.CredentialGeneration, opts.SessionGeneration, opts.State,
	)
	return opts.RawSecret
}

type seedAgentOpts struct {
	ID                   domain.AgentID
	Name                 string
	OwnerUserID          sql.NullString
	OwnerGroupID         sql.NullString
	State                string
	CredentialGeneration int64
	AuthorityGeneration  int64
}

func (e *testEnv) seedAgent(opts seedAgentOpts) {
	e.t.Helper()
	if opts.State == "" {
		opts.State = "active"
	}
	if opts.CredentialGeneration == 0 {
		opts.CredentialGeneration = 1
	}
	if opts.AuthorityGeneration == 0 {
		opts.AuthorityGeneration = 1
	}
	if !opts.OwnerUserID.Valid && !opts.OwnerGroupID.Valid {
		opts.OwnerUserID = sql.NullString{String: string(testUserID1), Valid: true}
	}
	e.execSQL(
		`INSERT INTO agents (id, name, owner_user_id, owner_group_id, state, credential_generation, authority_generation)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name,
		   owner_user_id = excluded.owner_user_id,
		   owner_group_id = excluded.owner_group_id,
		   state = excluded.state,
		   credential_generation = excluded.credential_generation,
		   authority_generation = excluded.authority_generation`,
		string(opts.ID), opts.Name, opts.OwnerUserID, opts.OwnerGroupID, opts.State, opts.CredentialGeneration, opts.AuthorityGeneration,
	)
}

type seedAgentCredentialOpts struct {
	ID                   authz.AgentCredentialID
	AgentID              domain.AgentID
	RawToken             string
	DisplayPrefix        string
	IssuedAt             int64
	ExpiresAt            sql.NullInt64
	NonexpiringApproved  int64
	RotationOverlapUntil sql.NullInt64
	RevokedAt            sql.NullInt64
	CredentialGeneration int64
	State                string
}

func (e *testEnv) seedAgentCredential(opts seedAgentCredentialOpts) string {
	e.t.Helper()
	now := e.clock.Now().Unix()
	if opts.RawToken == "" {
		opts.RawToken = "mdt_testtoken0123456789abcdef0123456789abcdef" + string(opts.ID)
	}
	sum := sha256.Sum256([]byte(opts.RawToken))
	if opts.DisplayPrefix == "" {
		opts.DisplayPrefix = "mdt_test1234"
	}
	if opts.IssuedAt == 0 {
		opts.IssuedAt = now - 600
	}
	if !opts.ExpiresAt.Valid && opts.NonexpiringApproved == 0 {
		opts.ExpiresAt = sql.NullInt64{Int64: now + 86400, Valid: true}
	}
	if opts.CredentialGeneration == 0 {
		opts.CredentialGeneration = 1
	}
	if opts.State == "" {
		opts.State = "active"
	}
	e.execSQL(
		`INSERT INTO agent_credentials (
			id, agent_id, token_hash, display_prefix, issued_at, expires_at,
			nonexpiring_approved, rotation_overlap_until, revoked_at, credential_generation, state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			agent_id = excluded.agent_id,
			token_hash = excluded.token_hash,
			display_prefix = excluded.display_prefix,
			issued_at = excluded.issued_at,
			expires_at = excluded.expires_at,
			nonexpiring_approved = excluded.nonexpiring_approved,
			rotation_overlap_until = excluded.rotation_overlap_until,
			revoked_at = excluded.revoked_at,
			credential_generation = excluded.credential_generation,
			state = excluded.state`,
		string(opts.ID), string(opts.AgentID), sum[:], opts.DisplayPrefix, opts.IssuedAt, opts.ExpiresAt,
		opts.NonexpiringApproved, opts.RotationOverlapUntil, opts.RevokedAt, opts.CredentialGeneration, opts.State,
	)
	return opts.RawToken
}

func (e *testEnv) seedGroup(id domain.GroupID, name, state string, authGen int64) {
	e.t.Helper()
	if state == "" {
		state = "active"
	}
	if authGen == 0 {
		authGen = 1
	}
	e.execSQL(
		`INSERT INTO groups (id, name, state, authority_generation) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET name = excluded.name, state = excluded.state, authority_generation = excluded.authority_generation`,
		string(id), name, state, authGen,
	)
}

func (e *testEnv) seedUserGroupMembership(userID domain.UserID, groupID domain.GroupID, state string, authGen int64) {
	e.t.Helper()
	if state == "" {
		state = "active"
	}
	if authGen == 0 {
		authGen = 1
	}
	e.execSQL(
		`INSERT INTO user_group_memberships (user_id, group_id, state, authority_generation) VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, group_id) DO UPDATE SET state = excluded.state, authority_generation = excluded.authority_generation`,
		string(userID), string(groupID), state, authGen,
	)
}

func (e *testEnv) seedAgentGroupMembership(agentID domain.AgentID, groupID domain.GroupID, state string, authGen int64) {
	e.t.Helper()
	if state == "" {
		state = "active"
	}
	if authGen == 0 {
		authGen = 1
	}
	e.execSQL(
		`INSERT INTO agent_group_memberships (agent_id, group_id, state, authority_generation) VALUES (?, ?, ?, ?)
		 ON CONFLICT(agent_id, group_id) DO UPDATE SET state = excluded.state, authority_generation = excluded.authority_generation`,
		string(agentID), string(groupID), state, authGen,
	)
}

func (e *testEnv) seedSelector(sel store.ContainerSelector) {
	e.t.Helper()
	if sel.EndpointID == "" {
		sel.EndpointID = testLocalEndpointID
	}
	e.execSQL(
		`INSERT INTO container_selectors (
			id, endpoint_id, container_name, name_is_glob, compose_project, compose_service,
			image_pattern, pinned_container_id, pinned_image_digest
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			endpoint_id = excluded.endpoint_id,
			container_name = excluded.container_name,
			name_is_glob = excluded.name_is_glob,
			compose_project = excluded.compose_project,
			compose_service = excluded.compose_service,
			image_pattern = excluded.image_pattern,
			pinned_container_id = excluded.pinned_container_id,
			pinned_image_digest = excluded.pinned_image_digest`,
		sel.ID, string(sel.EndpointID), sel.ContainerName, sel.NameIsGlob, sel.ComposeProject,
		sel.ComposeService, sel.ImagePattern, sel.PinnedContainerID, sel.PinnedImageDigest,
	)
}

func (e *testEnv) seedPolicy(p store.Policy) {
	e.t.Helper()
	if p.EndpointID == "" {
		p.EndpointID = testLocalEndpointID
	}
	if p.State == "" {
		p.State = "active"
	}
	if p.AuthorityGeneration == 0 {
		p.AuthorityGeneration = 1
	}
	e.execSQL(
		`INSERT INTO policies (
			id, user_id, group_id, agent_id, endpoint_id, selector_id,
			operation, effect, state, authority_generation, log_tail_max, stop_timeout_max
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			user_id = excluded.user_id,
			group_id = excluded.group_id,
			agent_id = excluded.agent_id,
			endpoint_id = excluded.endpoint_id,
			selector_id = excluded.selector_id,
			operation = excluded.operation,
			effect = excluded.effect,
			state = excluded.state,
			authority_generation = excluded.authority_generation,
			log_tail_max = excluded.log_tail_max,
			stop_timeout_max = excluded.stop_timeout_max`,
		p.ID, p.UserID, p.GroupID, p.AgentID, string(p.EndpointID), p.SelectorID,
		p.Operation, p.Effect, p.State, p.AuthorityGeneration, p.LogTailMax, p.StopTimeoutMax,
	)
}

// dispatchDecision executes the operation on backend using ONLY the immutable
// TargetIdentity bound in dec, proving mutable names are never re-resolved at dispatch.
func dispatchDecision(ctx context.Context, backend docker.DockerBackend, dec authz.Decision) error {
	switch dec.Operation {
	case authz.OpContainerInspectStatus:
		_, err := backend.InspectStatus(ctx, dec.Target)
		return err
	case authz.OpContainerInspectConfig:
		_, err := backend.InspectConfig(ctx, dec.Target)
		return err
	case authz.OpContainerLogs:
		opts := docker.LogOptions{Tail: docker.DefaultLogTail, Stdout: true, Stderr: true}
		if dec.LogOptions != nil {
			opts = *dec.LogOptions
		}
		stream, err := backend.Logs(ctx, dec.Target, opts)
		if err != nil {
			return err
		}
		return stream.Close()
	case authz.OpContainerStart:
		return backend.Start(ctx, dec.Target)
	case authz.OpContainerStop:
		return backend.Stop(ctx, dec.Target, docker.StopOptions{TimeoutSeconds: dec.TimeoutSeconds})
	case authz.OpContainerRestart:
		return backend.Restart(ctx, dec.Target, docker.RestartOptions{TimeoutSeconds: dec.TimeoutSeconds})
	default:
		return docker.ErrUnsupportedOperation
	}
}
