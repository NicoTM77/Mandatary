package authz_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/NicoTM77/Mandatary/internal/authz"
	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestOperationParameterConstraints(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.seedUser(seedUserOpts{ID: testUserID1, Username: "alice"})
	secret := env.seedSession(seedSessionOpts{ID: testSessionID1, UserID: testUserID1})
	creds := authz.PrincipalCredentials{SessionID: testSessionID1, SessionSecret: secret}

	env.seedSelector(store.ContainerSelector{
		ID:            string(testSelectorID1),
		EndpointID:    testLocalEndpointID,
		ContainerName: "edge-proxy",
		NameIsGlob:    0,
	})

	// Policy 1: container:logs with log_tail_max = 500
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID1),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerLogs),
		Effect:     "ALLOW",
		LogTailMax: sql.NullInt64{Int64: 500, Valid: true},
	})

	// Policy 2: container:stop with stop_timeout_max = 15
	env.seedPolicy(store.Policy{
		ID:             string(testPolicyID2),
		UserID:         sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID:     testLocalEndpointID,
		SelectorID:     string(testSelectorID1),
		Operation:      string(authz.OpContainerStop),
		Effect:         "ALLOW",
		StopTimeoutMax: sql.NullInt64{Int64: 15, Valid: true},
	})

	// Policy 3: container:restart with stop_timeout_max = 5
	env.seedPolicy(store.Policy{
		ID:             string(testPolicyID3),
		UserID:         sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID:     testLocalEndpointID,
		SelectorID:     string(testSelectorID1),
		Operation:      string(authz.OpContainerRestart),
		Effect:         "ALLOW",
		StopTimeoutMax: sql.NullInt64{Int64: 5, Valid: true},
	})

	// Policy 4: container:start (no parameter caps)
	env.seedPolicy(store.Policy{
		ID:         string(testPolicyID4),
		UserID:     sql.NullString{String: string(testUserID1), Valid: true},
		EndpointID: testLocalEndpointID,
		SelectorID: string(testSelectorID1),
		Operation:  string(authz.OpContainerStart),
		Effect:     "ALLOW",
	})

	intPtr := func(v int) *int { return &v }
	now := env.clock.Now()

	cases := []struct {
		name       string
		op         docker.Operation
		logOpts    *docker.LogOptions
		stopOpts   *docker.StopOptions
		rstOpts    *docker.RestartOptions
		wantAllow  bool
		wantReason authz.DenialReason
	}{
		{
			name:      "logs_within_policy_cap_allowed",
			op:        authz.OpContainerLogs,
			logOpts:   &docker.LogOptions{Tail: 250, Stdout: true, Stderr: true},
			wantAllow: true,
		},
		{
			name:      "logs_at_exact_policy_cap_allowed",
			op:        authz.OpContainerLogs,
			logOpts:   &docker.LogOptions{Tail: 500, Stdout: true},
			wantAllow: true,
		},
		{
			name:       "logs_exceeding_policy_cap_denied",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: 501, Stdout: true},
			wantAllow:  false,
			wantReason: authz.ReasonParameterCapExceeded,
		},
		{
			name:       "logs_default_tail_10000_exceeds_policy_cap_500_denied",
			op:         authz.OpContainerLogs,
			logOpts:    nil,
			wantAllow:  false,
			wantReason: authz.ReasonParameterCapExceeded,
		},
		{
			name:       "logs_tail_all_rejected",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: 100, TailAll: true, Stdout: true},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "logs_neither_stdout_nor_stderr_rejected",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: 100, Stdout: false, Stderr: false},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "logs_until_before_since_rejected",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: 100, Stdout: true, Since: now, Until: now.Add(-time.Minute)},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "logs_negative_tail_rejected",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: -1, Stdout: true},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "logs_tail_above_global_max_10000_rejected",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: 10001, Stdout: true},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:      "stop_default_timeout_10s_within_cap_15s_allowed",
			op:        authz.OpContainerStop,
			stopOpts:  nil,
			wantAllow: true,
		},
		{
			name:      "stop_explicit_timeout_15s_at_cap_allowed",
			op:        authz.OpContainerStop,
			stopOpts:  &docker.StopOptions{TimeoutSeconds: intPtr(15)},
			wantAllow: true,
		},
		{
			name:       "stop_timeout_16s_exceeds_cap_15s_denied",
			op:         authz.OpContainerStop,
			stopOpts:   &docker.StopOptions{TimeoutSeconds: intPtr(16)},
			wantAllow:  false,
			wantReason: authz.ReasonParameterCapExceeded,
		},
		{
			name:       "stop_timeout_zero_rejected",
			op:         authz.OpContainerStop,
			stopOpts:   &docker.StopOptions{TimeoutSeconds: intPtr(0)},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "stop_timeout_301_exceeds_global_max_rejected",
			op:         authz.OpContainerStop,
			stopOpts:   &docker.StopOptions{TimeoutSeconds: intPtr(301)},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "restart_default_timeout_10s_exceeds_cap_5s_denied",
			op:         authz.OpContainerRestart,
			rstOpts:    nil,
			wantAllow:  false,
			wantReason: authz.ReasonParameterCapExceeded,
		},
		{
			name:      "restart_explicit_timeout_5s_within_cap_allowed",
			op:        authz.OpContainerRestart,
			rstOpts:   &docker.RestartOptions{TimeoutSeconds: intPtr(5)},
			wantAllow: true,
		},
		{
			name:       "inappropriate_stop_options_on_start_rejected",
			op:         authz.OpContainerStart,
			stopOpts:   &docker.StopOptions{TimeoutSeconds: intPtr(5)},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "inappropriate_log_options_on_stop_rejected",
			op:         authz.OpContainerStop,
			logOpts:    &docker.LogOptions{Tail: 10, Stdout: true},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "inappropriate_restart_options_on_logs_rejected",
			op:         authz.OpContainerLogs,
			logOpts:    &docker.LogOptions{Tail: 10, Stdout: true},
			rstOpts:    &docker.RestartOptions{TimeoutSeconds: intPtr(5)},
			wantAllow:  false,
			wantReason: authz.ReasonInvalidParameters,
		},
		{
			name:       "unsupported_operation_container_exec_rejected",
			op:         docker.Operation("container:exec"),
			wantAllow:  false,
			wantReason: authz.ReasonInvalidOperation,
		},
		{
			name:       "unsupported_operation_endpoint_discover_rejected",
			op:         docker.Operation("endpoint:discover"),
			wantAllow:  false,
			wantReason: authz.ReasonInvalidOperation,
		},
		{
			name:       "unsupported_operation_wildcard_rejected",
			op:         docker.Operation("container:*"),
			wantAllow:  false,
			wantReason: authz.ReasonInvalidOperation,
		},
		{
			name:       "empty_operation_rejected",
			op:         docker.Operation(""),
			wantAllow:  false,
			wantReason: authz.ReasonInvalidOperation,
		},
	}

	beforeOps := env.backend.Counters().TotalOperational()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := env.authorizer.Authorize(ctx, authz.AuthorizeRequest{
				Principal:      creds,
				EndpointID:     testLocalEndpointID,
				TargetRef:      "edge-proxy",
				Operation:      tc.op,
				LogOptions:     tc.logOpts,
				StopOptions:    tc.stopOpts,
				RestartOptions: tc.rstOpts,
			})
			if tc.wantAllow {
				if err != nil {
					t.Fatalf("expected ALLOW, got error %v", err)
				}
				if dec.Target.ContainerID != testEdgeProxyID {
					t.Fatalf("Decision.Target.ContainerID = %s, want %s", dec.Target.ContainerID, testEdgeProxyID)
				}
			} else {
				if !errors.Is(err, authz.ErrForbidden) {
					t.Fatalf("expected 403 ErrForbidden, got %v", err)
				}
				if tc.wantReason != "" && !authz.HasReason(err, tc.wantReason) {
					r, _ := authz.ReasonOf(err)
					t.Fatalf("reason = %q, want %q", r, tc.wantReason)
				}
			}
		})
	}
	if got := env.backend.Counters().TotalOperational() - beforeOps; got != 0 {
		t.Fatalf("expected 0 operational calls during Authorize parameter checks, got %d", got)
	}
}
