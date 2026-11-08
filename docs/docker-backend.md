# Docker backend adapter, mock fixtures and sanitizers (P1.12)

## Delivered scope

`internal/docker` provides the Phase 1 restricted Docker intermediary package:

- `DockerBackend`: interface covering only the six approved Phase 1 container
  operations (`container:logs`, `container:inspect_status`,
  `container:inspect_config`, `container:start`, `container:stop`,
  `container:restart`) plus internal self-verification and target resolution.
- `SDKAdapter`: official `github.com/moby/moby/client` (`v0.6.2`) adapter with
  mandatory injected `http.RoundTripper` transport and Engine API version floor
  enforcement (`>= 1.44`, `SUP-03`).
- `MockBackend`: deterministic, concurrency-safe, container-free in-memory
  implementation with sample containers across all lifecycle states, followable
  log streams, and fault injection.
- `SafetyMonitor`: shared runtime self-protection state machine
  (`UNVERIFIED -> VERIFIED -> UNVERIFIED`) implementing
  `security-contracts.md` §S1 (`SELF-01`–`SELF-13`).
- Explicit allowlisted output schemas (`InspectStatus`, `InspectConfig`,
  `ContainerSummary`) and fail-closed sanitizers for environment variables,
  labels, command arguments, mount sources, and SDK/transport errors.

The `cmd/mandatary` binary remains the loopback-only static skeleton; P1.12 does
not expose HTTP/MCP routes or enable `MANDATARY_DOCKER_SOCKET` /
`MANDATARY_DEV_MOCK_DOCKER` in `internal/config`. Shared execution/rate-limiting
is owned by **P1.13**, REST/MCP transport wiring by **P1.14**, UI views by
**P1.16**, and container/OpenRC packaging and live-container isolation evidence
by **P1.19**.

## Self-protection and deployment identity binding (§S1)

| Artifact | Value / Format | Role |
| --- | --- | --- |
| Container label `io.mandatary.self` | Exact string `"true"` | Required on the Mandatary container for positive own-instance verification; never sufficient alone without process or explicit identity proof (`SELF-03`). |
| Reserved label namespace `io.mandatary.*` | Any label key with prefix `io.mandatary.` | Conservatively marks any container in any state (`created`, `running`, `paused`, `restarting`, `removing`, `exited`, `dead`) as a protected peer (`SELF-08`, `SELF-12`). |
| Env `MANDATARY_SELF_CONTAINER_ID` | 64-character lowercase hex container ID | Explicit operator-supplied container ID; must match runtime cgroup evidence when both are present (`SELF-02`). |
| Env `MANDATARY_SELF_INSTANCE_UUID` + label `io.mandatary.self.instance-uuid` | Canonical lowercase non-nil UUID (`domain.ParseEndpointID`) | Deployment instance-UUID binding used to prove unique own-instance identity when private cgroup namespaces (`cgroupns=private`) hide the container ID in `/proc/self/cgroup` (`SELF-11`). Duplicate or missing UUIDs fail closed. |

Every backend instance starts in `UNVERIFIED` (`SELF-09`). Any missing,
conflicting, ambiguous, stale, or daemon-mismatched proof keeps or returns the
backend to `UNVERIFIED`, cancels active log streams immediately (`SELF-07`), and
denies all operational calls with zero operational SDK dispatches.

## Sanitizer and parameter bounds (TD §§1.1–1.2, 10.2)

- **Inspect schemas**: `InspectStatus` and `InspectConfig` populate only
  explicit allowlisted fields from `container.InspectResponse`. Unknown or
  privilege-sensitive upstream fields (`GraphDriver`, `ResolvConfPath`,
  `ExecIDs`, `HostConfig.Privileged`, `CapAdd`, `SecurityOpt`, `Health.Log`,
  `Config.Healthcheck.Test`, network `DriverOpts`) are omitted by construction.
- **Safe labels (`InspectStatus` / `ContainerSummary`)**: Only
  `com.docker.compose.{project,service,container-number,oneoff}` and
  `org.opencontainers.image.{title,version,revision,source,vendor}` are admitted;
  values matching secret or high-entropy rules are redacted to `"[REDACTED]"`.
  All `io.mandatary.*` and arbitrary labels are omitted.
- **Environment & command redaction (`InspectConfig`)**:
  - Keys matching case-insensitive substrings `*KEY*`, `*SECRET*`, `*TOKEN*`,
    `*PASSWORD*`, `*PASS*`, `*CREDENTIAL*`, `*DSN*`, `*PRIVATE*`, `*AUTH*`,
    `*COOKIE*`, `*SESSION*`, or `*BEARER*` redact their value to `"[REDACTED]"`.
  - Values containing `mdt_`, `-----BEGIN`, `Bearer `, `Basic `, URL userinfo
    (`scheme://user:pass@host`), inline secret assignments, or high-entropy
    tokens (`>= 20` chars with Shannon entropy `>= 3.75` bits/char, or hex
    `>= 32` chars with `>= 3.5` bits/char, excluding pure POSIX path lists) are
    redacted to `"[REDACTED]"`.
- **Operation parameter bounds**:
  - `Stop` / `Restart` timeout: `1–300` seconds (default `10` seconds); `0` and
    negative values are rejected (`ErrInvalidParameter`).
  - `Logs`: `Tail` `1–10,000` (default `10,000`; `TailAll` rejected), at least
    one of `Stdout`/`Stderr` required, `Until >= Since`, 64 KiB max frame size
    (`MaxLogFrameBytes`), and 4 MiB max non-follow response size
    (`MaxLogResponseBytes`).
- **Error redaction**: `SanitizeError` maps all SDK, HTTP, and transport errors
  to fixed secret-free `docker.Error` sentinels without wrapping raw socket paths
  or daemon messages.

## Requirement-to-test map

| Requirement | P1.12 test coverage (`internal/docker`) | Downstream integration owner |
| --- | --- | --- |
| `SELF-01` Missing self-identity | `TestSELF01_MissingIdentityFailsClosedZeroOperationalCalls` | P1.13 (service), P1.14 (`/api/v1/readyz`, REST/MCP), P1.19 (live container) |
| `SELF-02` Invalid/conflicting explicit ID | `TestSELF02_InvalidOrConflictingExplicitIDFailsClosed` | P1.13, P1.14 |
| `SELF-03` Ambiguous/label-only identity & multi-peer positive control | `TestSELF03_AmbiguousOrLabelOnlyIdentityAndMultiPeerPositiveControl` | P1.13, P1.14 |
| `SELF-04` Self-target denied and omitted | `TestSELF04_SelfTargetDeniedAndOmittedZeroOperationalCalls` | P1.13, P1.14, P1.16 (UI) |
| `SELF-05` Recreation / stale ID / daemon change | `TestSELF05_RecreationStaleIDAndDaemonChangeInvalidateProof` | P1.13, P1.14 |
| `SELF-06` Rename race / immutable ID dispatch | `TestSELF06_ImmutableIDDispatchAndDelayedEventPeerCheck` | P1.13, P1.14 |
| `SELF-07` Mid-flight verification loss cancels active streams | `TestSELF07_LossOfProofCancelsActiveStreamsAndBlocksDispatch` | P1.13, P1.14 (SSE/MCP streams) |
| `SELF-08` Multi-instance peer set & delayed event protection | `TestSELF08_MultiInstancePeerSetAndDelayedEventProtection` | P1.13, P1.14 |
| `SELF-09` Starts `UNVERIFIED` (no persisted/restored proof) | `TestSELF09_StartsUnverifiedNoPersistedOrRestoredProof` | P1.11 (restore), P1.13 |
| `SELF-10` Shared safety state under concurrency | `TestSELF10_SharedSafetyStateConcurrentAccess` | P1.13, P1.14 |
| `SELF-11` Private cgroup namespace + instance-UUID binding | `TestSELF11_PrivateCgroupInstanceUUIDBindingAndOverlap`, `TestParseCgroupContainerID` | P1.19 (container packaging) |
| `SELF-12` All-state protected peers (`created`..`dead`) | `TestSELF12_AllStateProtectedPeersDeniedAndHidden` | P1.13, P1.14 |
| `SELF-13` Mock isolation & no native real-socket exemption | `TestSELF13_MockIsolationAndNoImplicitSocketAccess` | P1.14, P1.19 |
| `SUP-03` Engine API `>= 1.44` negotiation | `TestEngineAPINegotiationAndMinimum144` | P1.19 (live Engine matrix) |
| TD §§1.1–1.2 Inspect allowlists, secret/entropy redaction, error redaction | `TestInspectStatusAllowlistAndUnknownFields`, `TestInspectConfigEnvCommandMountAndResourceSanitization`, `TestTransportAndSDKErrorsRedacted` | P1.13, P1.14, P1.16 |
| TD §§1.2, 5, 10.4 Operation catalog, parameter bounds, SDK & mock parity | `TestOperationParameterBounds`, `TestSDKAdapterAllowedOperationsAndBounds`, `TestMockBackendFullLifecycleAndFaultInjection` | P1.13, P1.14 |
