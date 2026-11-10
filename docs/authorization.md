# Selector evaluator and unified default-deny authorizer (P1.11)

## Delivered scope and boundaries

`internal/authz` provides the single shared policy evaluation engine and composite
container selector evaluator for Mandatary (`TD §§2.1, 3.3–3.4, 7`;
`security-contracts.md §S1`):

- `Authorizer`: unified default-deny authorization service shared by later REST
  and MCP execution paths (`Authorize`, `ValidateDecision`, `AcquireLease`,
  `NotifyPolicyChange`, `InvalidateAll`, `InspectEndpointPolicyTargets`).
- `MatchSelector` and `MatchGlob`: deterministic linear-time selector evaluation
  with endpoint isolation, optional Compose/image guardrails, and optional
  immutable container ID and image digest pins.
- `ValidateRequestParameters` and `SatisfiesPolicyConstraints`: enforcement of
  the exact six approved Phase 1 permission keys (`container:logs`,
  `container:inspect_status`, `container:inspect_config`, `container:start`,
  `container:stop`, `container:restart`) and per-policy parameter caps
  (`log_tail_max`, `stop_timeout_max`) reusing `docker.ValidateLogOptions` and
  `docker.ValidateStopTimeout`.
- `CredentialVerifier` and `NewStoreCredentialVerifier`: server-side validation
  of human sessions and machine agent tokens against `installation_control`,
  generation counters, restore quarantine, account/session/token state, exact
  expiry/idle/rotation-overlap boundaries, and NIST SP 800-63B-4 assurance
  requirements.
- `internal/store/queries/authz.sql` (`internal/store/authz.sql.go`, generated
  via pinned `sqlc v1.31.1`): read-only SQLite queries consumed inside
  `Repository.Read` snapshots.

The `cmd/mandatary` binary remains the loopback-only static skeleton. P1.11 does
not expose HTTP/MCP routes, implement the P1.08/P1.10 credential issuers, or
build the P1.13 operation execution/rate-limiting service. Later **C2**
integration binds these same authorization suites to live session/token issuer
services from P1.08–P1.10; **P1.13** binds `Authorizer` to shared execution,
rate limiting, and audit/usage recording; **P1.14** exposes REST/MCP handlers;
and **P1.19** provides live-container deployment evidence.

## Precedence order and trust boundary

`Authorizer.Authorize` evaluates every request in strict precedence order:

1. **Self-protection & runtime safety state (`403 ErrForbidden`)**:
   - Any target bearing `io.mandatary.self=true` or any label in the reserved
     `io.mandatary.*` namespace, or matching the verified self/peer container
     set on the endpoint's `DockerBackend`, is rejected with
     `ReasonSelfProtected` before authentication or policy evaluation.
   - Any missing, closed, or `UNVERIFIED` backend (`!backend.Ready()` or
     `VerificationState() != StateVerified`) is rejected with
     `ReasonSafetyUnverified`.
2. **Principal & credential status (`401 ErrUnauthenticated`)**:
   - `VerifyPrincipal` loads `installation_control`, `users`, `sessions`,
     `session_authenticators`, `administrative_roles`, `agents`,
     `agent_credentials`, `user_group_memberships`, and
     `agent_group_memberships` inside a coherent `Repository.Read` snapshot.
   - Caller-supplied assurance or administrator assertions on
     `PrincipalCredentials` are never trusted.
   - Missing, disabled, quarantined, compromised, revoked, expired,
     idle-expired, rotation-overlap-expired, or stale-generation principals,
     sessions, or agent tokens return `401 ErrUnauthenticated`.
   - `preauth`, `setup`, and `recovery` session purposes are rejected for
     operational requests. Accounts with `mfa_requirement='required'`,
     `mfa_requirement='webauthn'`, or any assigned administrative role require
     verified AAL2 MFA (`achieved_assurance >= 2`, and phishing-resistant
     WebAuthn when `mfa_requirement='webauthn'`).
3. **Endpoint state, operation catalog, parameter validation & target existence (`403 ErrForbidden`)**:
   - Endpoint must be `active`, `slug='local'`, `transport='unix'`, and match
     `installation_control.authority_generation` (`ReasonEndpointInactive`).
   - Only the six approved Phase 1 permission keys are accepted
     (`ReasonInvalidOperation`); malformed or cross-operation parameters are
     rejected (`ReasonInvalidParameters`); deleted/non-existent targets fail
     closed (`ReasonTargetMissing`).
4. **Explicit `DENY` across direct and group rules (`403 ReasonExplicitDeny`)**:
   - Direct and group rules are evaluated with **deny-overrides-allow** across
     all applicable groups.
   - Per `RESTORE-03`, both `active` and `quarantined` `DENY` rules (and `DENY`
     rules attached to quarantined group memberships) conservatively block
     access, whereas `quarantined` or `disabled` `ALLOW` rules never grant
     access.
5. **Explicit `ALLOW` with parameter constraint satisfaction (`200 OK`)**:
   - Requires at least one matching `active` `ALLOW` policy at the current
     `authority_generation` whose `log_tail_max` / `stop_timeout_max` caps are
     satisfied by the normalized request parameters (otherwise
     `403 ReasonParameterCapExceeded`).
   - Agent ownership (`owner_user_id` or `owner_group_id`) never implies owner
     permission inheritance; only direct agent policies and explicit active
     `agent_group_memberships` apply.
   - Administrative roles (`super_admin`, `endpoint_admin`) grant zero implicit
     container operations.
   - Binds an immutable `docker.TargetIdentity` (`EndpointID` + 64-hex
     `ContainerID`) in `Decision.Target` so downstream dispatch never
     re-resolves mutable container names.
6. **Default fallback (`403 ReasonDefaultDeny`)**:
   - Any unmatched request or poisoned/unavailable repository handle fails
     closed with fixed secret-free error sentinels (`"authentication required"`
     or `"operation not permitted"`).

## Composite selector semantics and lifecycle behavior (TD §§3.3, 7)

All present fields on `store.ContainerSelector` are conjunctive (`AND`):

- `endpoint_id`: mandatory canonical endpoint UUID; prevents cross-endpoint
  collisions when two endpoints host identically named containers.
- `container_name` + `name_is_glob` (`0` = exact canonical name match after
  stripping a leading `/`; `1` = validated linear-time glob supporting `*`, `?`,
  and `[...]` character classes without backtracking).
- `compose_project` and `compose_service` (optional): enforced only when
  `Valid=true` on the selector. Broad name-only or glob-only grants without
  these fields remain valid for standalone `docker run` containers. Disagreement
  between summary fields and `com.docker.compose.{project,service}` labels fails
  closed.
- `image_pattern` (optional): linear-time glob matched against the container's
  image reference.
- `pinned_container_id` (optional): 64-character lowercase hex container ID pin;
  fails closed after same-name container recreation.
- `pinned_image_digest` (optional): canonical `sha256:<64 lowercase hex>` image
  digest pin.

When a container is deleted, policies referencing its selector remain persisted
in SQLite and are reported by `Authorizer.InspectEndpointPolicyTargets` with
`TargetMissing: true` (`"Inactive / Target Missing"`, `TD §7.2`) while all
operational requests against the missing target deny with `ReasonTargetMissing`.

## Policy invalidation and active leases (TD §3.4)

- `AcquireLease` issues a cancellable `Lease` bound to the `Decision`'s
  immutable `TargetIdentity`, `Generations`, and normalized parameters.
- `ValidateDecision` and `Lease.Revalidate` re-verify the target by its
  **immutable 64-hex `ContainerID`** (detecting removal, recreation, or rename
  away from the selector) and re-evaluate safety state, `installation_control`
  generations, principal/session/token status, group memberships, `DENY`
  overrides, and tightened parameter caps (`log_tail_max`, `stop_timeout_max`).
- `NotifyPolicyChange` increments the policy epoch and revalidates all active
  leases, immediately canceling any lease whose authorization was revoked or
  tightened while preserving unrelated valid leases.
- Policy writers must commit first, then call `NotifyPolicyChange` before
  acknowledging the change. A mutex-protected revision fences evaluations that
  overlap notification, backend replacement, or explicit invalidation: stale
  SQLite snapshots cannot publish a successful decision or validation afterward.
  Lease registration and publication check the same revision. I/O is not
  performed under the revision writer lock. Overlapping evaluations may deny
  conservatively; unchanged existing leases can re-evaluate against fresh policy.
- Decisions are private issuance-bound handles: validation requires the issuing
  authorizer, endpoint backend revision, and explicit invalidation revision.
  Rebinding even the same backend, remove/re-register, and `InvalidateAll` cannot
  resurrect an old decision. A policy epoch change alone permits fresh dynamic
  re-evaluation, rather than permanently revoking unrelated valid handles.
- Local validation cancellation and credential failure cancel only matching
  principal/session/credential leases, not peers using the same group policy.
  Shared backend/target failures still cancel affected peers; policy notification
  revalidates every active lease.
- Future session creation/authentication/activity or token issuance, negative
  idle ages, and validation before a decision's issuance time deny. This is
  bounded detection of observable clock uncertainty, **not** a trustworthy-time
  source or malicious full-host rollback guarantee.
- Successful `Decision` and `*Lease` handles redact all `fmt` verbs and implement
  `slog.LogValuer`; private verification credentials are never log projections.
  Handles are trusted in-process values, not serialized capability tokens.
- `RegisterBackend`, `RemoveBackend`, `InvalidateAll`, and `Close` immediately
  cancel affected active leases.

## Acceptance and requirement-to-test mapping

| Requirement / dimension | P1.11 test coverage (`internal/authz`) | Later phase / owning task |
| --- | --- | --- |
| Precedence order (`Self -> 401 -> DENY -> ALLOW -> Default 403`) | `TestAuthorizerPrecedenceOrder` (`authorizer_test.go`) | P1.13 (service), P1.14 (REST/MCP status codes) |
| Storage fail-closed & canary/error/log redaction | `TestStorageFailClosedAndDenialRedaction` (`authorizer_test.go`) | P1.13, P1.14 |
| Cross-product of direct/group `DENY`-overrides-`ALLOW`, 20 principal/credential states, endpoint selector (`ep_local` vs `ep_foreign`), and all 6 operations (1,560 subtests) | `TestAuthorizationCrossProductMatrix` (`matrix_test.go`) | C2 (live P1.08–P1.10 credential issuers) |
| Agent owner non-inheritance (`owner_user_id`, `owner_group_id`) & `super_admin` zero implicit container grants | `TestAgentOwnerNonInheritanceAndAdminZeroGrant` (`matrix_test.go`) | P1.13, P1.14 |
| Assurance & session purpose boundaries (`preauth`, `setup`, `recovery`, AAL1 vs AAL2, `webauthn`, admin MFA, untrusted caller fields) | `TestAssuranceAndPurposeBoundaries` (`matrix_test.go`) | C2, P1.08, P1.09 |
| Selector evaluation matrix (exact, glob, compose guardrails, image pattern, container ID pin, image digest pin, cross-endpoint, protected labels) | `TestSelectorEvaluationMatrix` (`selector_test.go`) | P1.16 (UI policy editor) |
| Container rename, impostor rename, same-name recreation, label-change recreation, pinned ID recreation denial, missing target & `InspectEndpointPolicyTargets` | `TestContainerLifecycleRenameRecreateMissingMatrix` (`selector_test.go`) | P1.13, P1.16 |
| Immutable `TargetIdentity` (`EndpointID` + 64-hex `ContainerID`) dispatch binding under post-authorize rename race | `TestImmutableTargetIdentityDispatchBinding` (`selector_test.go`) | P1.13 |
| Operation catalog & parameter constraints (`log_tail_max`, `stop_timeout_max`, `TailAll`, bounds, inappropriate options, unsupported ops) | `TestOperationParameterConstraints` (`params_test.go`) | P1.13, P1.14 |
| Deterministic clock expiry boundaries (session absolute/idle expiry, agent token expiry & rotation overlap) | `TestDeterministicClockExpiryBoundaries` (`invalidation_test.go`) | C2 |
| Policy change invalidation of active leases (`log_tail_max` tightening, `DENY` insertion, group disable, restore quarantine) | `TestPolicyChangeInvalidatesActiveAuthorizations` (`invalidation_test.go`) | P1.13, P1.15 (policy CRUD) |
| Concurrent `Authorize` / `AcquireLease` / `NotifyPolicyChange` race safety | `TestConcurrentAuthorizeAndPolicyInvalidationRace` (`invalidation_test.go`) | P1.13 |
| Revocation publication fence with held real SQLite snapshots and zero post-revocation dispatch | `TestPolicyRevocationPublicationFence` (`publication_test.go`) | P1.13 dispatch integration |
| Permanent issuer/backend/invalidation bindings; sequential and concurrent rebind/invalidation | `TestDecisionIssuingBindings`, `TestConcurrentDecisionBindingPublication` (`binding_test.go`) | SELF-13, P1.13 |
| Principal-local failure isolation and shared-failure cancellation | `TestSharedPolicyLeaseFailureIsolation` (`lease_isolation_test.go`) | C2, P1.13 |
| Observable clock rollback and future evidence denial with healthy boundary controls | `TestObservableClockRollbackDenies` (`clock_rollback_test.go`), existing expiry/overlap suite | RESTORE-04 bounded domain enforcement; P1.18 owns actual restore |
| Human/agent success-path decision/lease `fmt`, JSON and text/JSON structured-log canaries | `TestSuccessfulAuthorizationSecretRedaction` (`redaction_test.go`) | TD §9.3; P1.13/P1.14 adapters |
| **C1** integrated substrate gate (fresh/reopened SQLite + `MasterKey` secret store + tamper checks + `Authorizer` + `MockBackend` + log redaction + 0 operational calls on rejected fixtures) | `TestC1IntegratedSubstrateCheckpoint` (`c1_substrate_test.go`) | Independent reviewer gate check; P1.13/P1.14 |

## `SELF-01`–`SELF-13` service-level coverage and remaining boundaries

| Contract ID | P1.11 service-level test (`internal/authz/self_protection_test.go`) | P1.11 verified behavior | Remaining adapter / deployment owner |
| --- | --- | --- | --- |
| `SELF-01` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-01_no_runtime_evidence_and_no_deployment_binding` | Authorizer rejects all operations (`403 ReasonSafetyUnverified`) with 0 operational backend calls when runtime evidence and deployment binding are absent. | P1.14 (`/api/v1/readyz` HTTP 503), P1.19 (live container startup) |
| `SELF-02` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-02_partial_nonexistent_or_conflicting_explicit_id` | Short, non-existent, unlabelled, and cgroup-conflicting `MANDATARY_SELF_CONTAINER_ID` values keep backend unverified; Authorizer denies all operations with 0 operational calls. | P1.14 (`/api/v1/readyz`), P1.19 |
| `SELF-03` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-03_unique_label_without_proof_denies_and_multiple_peers_with_one_proven_id_allows_ordinary` | Label-only candidate without process/UUID proof denies all targets; with two `io.mandatary.self=true` containers and one proven own ID, ordinary targets are allowed while both self and peer are denied (`403 ReasonSelfProtected`, 0 ops on protected targets). | P1.13, P1.14 |
| `SELF-04` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-04_wildcard_and_explicit_allow_and_admin_targeting_self_denied` | Wildcard `*`, explicit name/ID `ALLOW` policies, and `super_admin` user targeting own container by name or 64-hex ID are denied (`403 ReasonSelfProtected`) before policy with 0 operational calls; `ListContainers` omits self/peers. | P1.14 (REST/MCP routes), P1.16 (UI container list) |
| `SELF-05` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-05_recreate_self_invalidates_proof_until_fresh_verify` | Self-container recreation (`StartedAt` continuity change) transitions backend to `UNVERIFIED` and causes Authorizer to deny all targets until fresh `VerifySelf`. | P1.13, P1.14 |
| `SELF-06` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-06_name_reassigned_to_new_self_labelled_replacement_denied` | Reassigning an authorized container name to a newly created `io.mandatary.self=true` container causes `ValidateDecision` on the prior `Decision` and new `Authorize` calls on the name/ID to fail closed with 0 operational calls. | P1.13, P1.14 |
| `SELF-07` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-07_lose_verification_after_allow_before_dispatch_and_cancel_active_stream` | `SimulateEventDiscontinuity` after `AcquireLease` causes `ValidateDecision` and `Lease.Revalidate` to fail closed (`403`), cancels `Lease.Context()`, and blocks new dispatches with 0 operational calls. | P1.13, P1.14 (SSE/MCP stream termination) |
| `SELF-08` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-08_multi_instance_peers_all_protected_regardless_of_names` | Peer containers carrying `io.mandatary.self=true` or any `io.mandatary.*` label (including innocuous names) are denied across all operations with 0 operational calls. | P1.13, P1.14 |
| `SELF-09` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-09_unverified_startup_after_restore_cannot_use_cached_proof` | Fresh/restored backend without `VerifySelf` remains `UNVERIFIED`; Authorizer denies all operations with 0 operational calls regardless of active SQLite policies. | P1.13, P1.18 (backup/restore service) |
| `SELF-10` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-10_shared_authorizer_blocks_all_operations_on_protected_targets` | Shared `Authorizer` blocks all six Phase 1 operations against self and peer targets for both human session and machine agent credentials. | P1.13, P1.14 (REST & MCP parity) |
| `SELF-11` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-11_private_cgroup_namespace_with_instance_uuid_binding_and_overlap_rejection` | Private cgroup namespace (`PrivateCgroupNS=true`) with unique `io.mandatary.self.instance-uuid` allows ordinary targets and blocks self; duplicate UUID overlap during recreation invalidates proof and denies all targets. | P1.19 (live `cgroupns=private` container test) |
| `SELF-12` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-12_all_state_protected_peers_denied_across_all_operations` | Protected peers in `created`, `running`, `paused`, `restarting`, `exited`, `removing`, and `dead` states are denied across all six operations with 0 operational calls. | P1.13, P1.14 |
| `SELF-13` | `TestSelfProtectionContracts_SELF01_to_SELF13/SELF-13_endpoint_rebind_clears_cached_verification_and_native_mock_makes_zero_real_calls` | Rebinding an endpoint via `RegisterBackend` cancels active leases and requires fresh `VerifySelf` on the new backend; `MockBackend` executes in-memory with zero live Docker socket connections. | P1.14, P1.19 |
