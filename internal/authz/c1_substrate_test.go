package authz_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/logging"
	"github.com/NicoTM77/Mandatary/internal/store"
	"github.com/NicoTM77/Mandatary/tests/security/fixtures"
)

const (
	c1CanaryTOTPSeed    = "CANARY_C1_TOTP_SEED_SECRET_VALUE_987654"
	c1CanaryBearerToken = "mdt_CANARY_C1_AGENT_TOKEN_0123456789abcdef0123456789abcdef"
)

// TestC1IntegratedSubstrateCheckpoint verifies the C1 integrated substrate gate:
// fresh/reopened SQLite + MasterKey secret store + shared authz.Authorizer + docker.MockBackend;
// allow/deny, protected/missing/conflicting identity, redaction/tamper cases,
// and zero operational backend calls on all rejected fixtures.
func TestC1IntegratedSubstrateCheckpoint(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "data")
	dbPath := filepath.Join(dir, "mandatary.db")

	mk, err := store.LoadMasterKey(strings.Repeat("22", 32), "")
	if err != nil {
		t.Fatalf("LoadMasterKey: %v", err)
	}

	// 1. Fresh SQLite open + secret encryption + authority/policy persistence.
	opts := store.Options{
		DataDir:   dir,
		MasterKey: mk,
		OwnerUID:  os.Geteuid(),
		OwnerGID:  os.Getegid(),
	}
	repo1, err := store.Open(ctx, opts)
	if err != nil {
		t.Fatalf("store.Open fresh: %v", err)
	}

	canarySecret := []byte(c1CanaryTOTPSeed)
	ciphertext, err := repo1.EncryptSecret("totp", string(testUserID1), canarySecret)
	if err != nil {
		_ = repo1.Close()
		t.Fatalf("EncryptSecret: %v", err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		_ = repo1.Close()
		t.Fatalf("sql.Open: %v", err)
	}

	clock := fixtures.NewClock()
	now := clock.Now().Unix()
	rawToken := c1CanaryBearerToken
	tokenHash := sha256.Sum256([]byte(rawToken))

	stmts := []struct {
		q    string
		args []any
	}{
		{
			`UPDATE installation_control SET credential_generation=1, session_generation=1, authority_generation=1, restore_generation=1, restore_quarantined=0 WHERE singleton=1`,
			nil,
		},
		{
			`UPDATE endpoints SET id=?, state='active', authority_generation=1 WHERE slug='local'`,
			[]any{string(testLocalEndpointID)},
		},
		{
			`INSERT INTO users (id, username, state, mfa_requirement, compromised, credential_generation, authority_generation, password_revision)
			 VALUES (?, 'c1_owner', 'active', 'required', 0, 1, 1, 1)`,
			[]any{string(testUserID1)},
		},
		{
			`INSERT INTO agents (id, name, owner_user_id, owner_group_id, state, credential_generation, authority_generation)
			 VALUES (?, 'c1_agent', ?, NULL, 'active', 1, 1)`,
			[]any{string(testAgentID1), string(testUserID1)},
		},
		{
			`INSERT INTO agent_credentials (id, agent_id, token_hash, display_prefix, issued_at, expires_at, nonexpiring_approved, credential_generation, state)
			 VALUES (?, ?, ?, 'mdt_CANARY12', ?, ?, 0, 1, 'active')`,
			[]any{string(testCredID1), string(testAgentID1), tokenHash[:], now - 60, now + 3600},
		},
		{
			`INSERT INTO container_selectors (id, endpoint_id, container_name, name_is_glob, compose_project, compose_service, image_pattern)
			 VALUES (?, ?, 'edge-proxy', 0, 'platform', 'edge-proxy', 'nginx:1.27*')`,
			[]any{string(testSelectorID1), string(testLocalEndpointID)},
		},
		{
			`INSERT INTO policies (id, agent_id, endpoint_id, selector_id, operation, effect, state, authority_generation)
			 VALUES (?, ?, ?, ?, ?, 'ALLOW', 'active', 1)`,
			[]any{string(testPolicyID1), string(testAgentID1), string(testLocalEndpointID), string(testSelectorID1), string(authz.OpContainerInspectConfig)},
		},
	}
	for _, s := range stmts {
		if _, sErr := rawDB.ExecContext(ctx, s.q, s.args...); sErr != nil {
			_ = rawDB.Close()
			_ = repo1.Close()
			t.Fatalf("seed fresh repository (%q): %v", s.q, sErr)
		}
	}
	_ = rawDB.Close()
	if err := repo1.Close(); err != nil {
		t.Fatalf("repo1.Close: %v", err)
	}

	// 2. Tamper check: opening with wrong MasterKey must fail closed!
	wrongMK, _ := store.LoadMasterKey(strings.Repeat("33", 32), "")
	wrongOpts := opts
	wrongOpts.ExistingOnly = true
	wrongOpts.MasterKey = wrongMK
	if bad, err := store.Open(ctx, wrongOpts); err == nil {
		_ = bad.Close()
		t.Fatalf("expected store.Open with wrong MasterKey to fail closed")
	}

	// 3. Reopen SQLite with valid MasterKey, verify secret decryption and tamper rejection on AAD.
	opts.ExistingOnly = true
	repo2, err := store.Open(ctx, opts)
	if err != nil {
		t.Fatalf("store.Open reopen: %v", err)
	}
	defer func() { _ = repo2.Close() }()

	decrypted, err := repo2.DecryptSecret("totp", string(testUserID1), ciphertext)
	if err != nil || !bytes.Equal(decrypted, canarySecret) {
		t.Fatalf("DecryptSecret after reopen failed: %v", err)
	}
	if _, err := repo2.DecryptSecret("totp", string(testUserID2), ciphertext); err == nil {
		t.Fatalf("expected DecryptSecret with wrong AAD subject ID to fail")
	}

	// 4. Bind reopened repository + MockBackend + shared Authorizer + structured logger redaction check.
	var logBuf bytes.Buffer
	logger, err := logging.New(&logBuf, slog.LevelDebug, "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	idCfg, mockContainers := docker.DefaultMockFixtures(testLocalEndpointID)
	backend, err := docker.NewMockBackend(docker.MockOptions{
		EndpointID: testLocalEndpointID,
		Identity:   idCfg,
		Containers: mockContainers,
	})
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if err := backend.VerifySelf(ctx); err != nil {
		t.Fatalf("backend.VerifySelf: %v", err)
	}

	az, err := authz.NewAuthorizer(authz.Config{
		Repository: repo2,
		Clock:      clock.Now,
		Backends:   map[domain.EndpointID]docker.DockerBackend{testLocalEndpointID: backend},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}

	creds := authz.PrincipalCredentials{
		AgentCredentialID: testCredID1,
		AgentToken:        rawToken,
	}

	// Negative rejected fixtures must make ZERO operational backend calls.
	rejectedCases := []struct {
		name   string
		req    authz.AuthorizeRequest
		status int
	}{
		{
			name: "protected_self_target",
			req: authz.AuthorizeRequest{
				Principal:  creds,
				EndpointID: testLocalEndpointID,
				TargetRef:  "mandatary-self",
				Operation:  authz.OpContainerInspectConfig,
			},
			status: 403,
		},
		{
			name: "protected_peer_target",
			req: authz.AuthorizeRequest{
				Principal:  creds,
				EndpointID: testLocalEndpointID,
				TargetRef:  "mandatary-peer-stopped",
				Operation:  authz.OpContainerInspectConfig,
			},
			status: 403,
		},
		{
			name: "ungranted_target_billing_worker",
			req: authz.AuthorizeRequest{
				Principal:  creds,
				EndpointID: testLocalEndpointID,
				TargetRef:  "billing-worker",
				Operation:  authz.OpContainerInspectConfig,
			},
			status: 403,
		},
		{
			name: "ungranted_operation_stop_on_edge_proxy",
			req: authz.AuthorizeRequest{
				Principal:  creds,
				EndpointID: testLocalEndpointID,
				TargetRef:  "edge-proxy",
				Operation:  authz.OpContainerStop,
			},
			status: 403,
		},
		{
			name: "invalid_bearer_token_canary",
			req: authz.AuthorizeRequest{
				Principal:  authz.PrincipalCredentials{AgentToken: "mdt_wrong_token_value_0123456789abcdef"},
				EndpointID: testLocalEndpointID,
				TargetRef:  "edge-proxy",
				Operation:  authz.OpContainerInspectConfig,
			},
			status: 401,
		},
	}

	for _, rc := range rejectedCases {
		_, err := az.Authorize(ctx, rc.req)
		if err == nil {
			t.Fatalf("rejected case %s: expected error, got nil", rc.name)
		}
		if got := authz.StatusCode(err); got != rc.status {
			t.Fatalf("rejected case %s: status = %d, want %d (%v)", rc.name, got, rc.status, err)
		}
		logger.Info("authorization denied", "principal", rc.req.Principal, "err", err)
	}

	if ops := backend.Counters().TotalOperational(); ops != 0 {
		t.Fatalf("expected 0 operational backend calls across all rejected C1 fixtures, got %d", ops)
	}

	// Positive allowed fixture: edge-proxy container:inspect_config -> dispatches by immutable ID and redacts env secrets.
	dec, err := az.Authorize(ctx, authz.AuthorizeRequest{
		Principal:  creds,
		EndpointID: testLocalEndpointID,
		TargetRef:  "edge-proxy",
		Operation:  authz.OpContainerInspectConfig,
	})
	if err != nil {
		t.Fatalf("positive C1 Authorize failed: %v", err)
	}
	cfgResp, err := backend.InspectConfig(ctx, dec.Target)
	if err != nil {
		t.Fatalf("backend.InspectConfig: %v", err)
	}
	if ops := backend.Counters().TotalOperational(); ops != 1 {
		t.Fatalf("expected exactly 1 operational call after positive dispatch, got %d", ops)
	}

	// Verify container env secret canaries are redacted in InspectConfig and logs contain zero secret canaries!
	for _, envLine := range cfgResp.Env {
		if strings.Contains(envLine, "CANARY_MOCK_PROXY_SECRET") || strings.Contains(envLine, "mdt_mock_token_value") {
			t.Fatalf("unredacted secret in InspectConfig.Env: %q", envLine)
		}
	}
	logOutput := logBuf.String()
	for _, canary := range []string{c1CanaryTOTPSeed, c1CanaryBearerToken, "CANARY_MOCK_PROXY_SECRET", "CANARY_MOCK_SELF_SECRET"} {
		if strings.Contains(logOutput, canary) {
			t.Fatalf("canary %q leaked into structured logs: %s", canary, logOutput)
		}
	}
}
