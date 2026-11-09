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
| Container label `io.mandatary.self` | Exact string `"true"` | Required on the Mandatary container for positive own-instance verification; never sufficient without reliable current-process evidence or a trusted unique deployment binding (`SELF-03`). |
| Reserved label namespace `io.mandatary.*` | Any label key with prefix `io.mandatary.` | Conservatively marks any container in any state (`created`, `running`, `paused`, `restarting`, `removing`, `exited`, `dead`) as a protected peer (`SELF-08`, `SELF-12`). |
| Env `MANDATARY_SELF_CONTAINER_ID` | 64-character lowercase hex container ID | Operator assertion, not proof by itself: must match reliable current-process evidence or the unique trusted deployment binding. Bare/stale explicit IDs cannot enable native access (`SELF-01`, `SELF-02`, `SELF-13`). |
| Env `MANDATARY_SELF_INSTANCE_UUID` + label `io.mandatary.self.instance-uuid` | Canonical lowercase non-nil UUID (`domain.ParseEndpointID`) | Deployment instance-UUID binding used to prove unique own-instance identity when private cgroup namespaces (`cgroupns=private`) hide the container ID in `/proc/self/cgroup` (`SELF-11`). Duplicate or missing UUIDs fail closed. |

Every backend instance starts in `UNVERIFIED` (`SELF-09`). Any missing,
conflicting, ambiguous, stale, or daemon-mismatched proof keeps or returns the
backend to `UNVERIFIED`, cancels active log streams immediately (`SELF-07`), and
denies all operational calls with zero operational SDK dispatches.

Verification reserves a new generation **before** inventory I/O. Invalidation,
configuration changes, closure and newer verification attempts supersede older
work; stale work cannot publish proof or carry target metadata across generations.
Closing a backend is terminal. A fresh backend is required after closure.

Every ordinary admission rechecks daemon/self continuity and a complete all-state
inventory, including uniqueness of any instance-UUID binding. Unknown/malformed
inventory and connection/I/O failures invalidate proof and cancel all streams.
Known logical missing-target/invalid-argument denials do not by themselves imply
a disconnected daemon. Removing an overlap or reconnecting does not restore
readiness: explicit fresh `VerifySelf` is required.

Active streams recheck continuity before and after each delivery (including
buffered `Read` bytes); idle streams also have a one-second safety watcher with a
two-second check deadline. Explicit `InvalidateSafety` cancels immediately, without
waiting for the watcher. Integration owners must signal event continuity loss,
reconnect and endpoint changes through that method; this package does not expose
an event subscription or claim real-Docker integration evidence. `Close` and a
per-`Next` canceled context interrupt blocked body reads independently of the
parser lock. Callers must close streams; cancellation discards undelivered bytes.
Both TTY and multiplexed log bodies observe and latch non-EOF errors **below**
buffering/framing. A body read reporting bytes **and** a fault discards those
bytes and synchronously invalidates proof/cancels peers before returning to the
parser. Neither `bufio` prefetch nor an exactly filled `io.ReadFull` request may
defer or discard that fault, even when it accompanies complete frames or a
header exceeding an output limit. Body errors always mean continuity failure,
not a logical missing-target/invalid-argument denial. Explicit fresh proof is
required for new operations; revoked old streams never recover. Raw TTY reads
still avoid an extra buffering layer near the response cap. Ordinary bytes with
healthy EOF and consumer `Close` do not invalidate a healthy daemon proof.
Stream metadata checks classify errors before invalidation: an error matching a
known consumer cancellation/Close is local and terminates only that stream,
including pre/post-delivery checks and the idle watcher. Independent transport
errors, malformed/uncertain metadata, explicit invalidation and the internal
two-second watchdog still revoke global proof and cancel peers. A consumer
cancellation cannot mask an independently returned transport fault.

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
    `>= 32` chars with `>= 3.5` bits/char) are
    redacted to `"[REDACTED]"`.
  - Ordinary POSIX path lists remain readable only when no path segment matches
    the entropy rules; a slash or URL prefix cannot exempt an opaque credential.
    Secret flag/value pairs are redacted in both entrypoint and command arrays,
    including pairs that cross the entrypoint/command boundary.
- **Operation parameter bounds**:
  - `Stop` / `Restart` timeout: `1–300` seconds (default `10` seconds); `0` and
    negative values are rejected (`ErrInvalidParameter`).
  - `Logs`: `Tail` `1–10,000` (default `10,000`; `TailAll` rejected), at least
    one of `Stdout`/`Stderr` required, `Until >= Since`, 64 KiB max frame size
    (`MaxLogFrameBytes`), and 4 MiB max non-follow response size
    (`MaxLogResponseBytes`).
    Raw TTY output is chunked to at most 64 KiB without interpreting newlines or
    changing CRLF/final fragments; the same 4 MiB non-follow cap applies. This is
    reading existing container logs, not Phase 4 interactive TTY/exec support.
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

### Review regressions (F1–F7)

`review_regression_test.go` retains the independent run374 reproducers, including
healthy process-proof, self-denial, PATH and inline-secret controls. Additional
permanent cases cover config/close/newer-failed verification barriers and the
SDK inventory boundary (`safety_epoch_test.go`), target-proof generation changes
(`dispatch_epoch_test.go`), seven disconnect paths with active buffered streams
and explicit recovery (`transport_regression_test.go`), startup malformed inventory
and an entered idle read (`inventory_regression_test.go`), SDK/mock post-startup
UUID overlap and resynchronization (`continuity_regression_test.go`), shared
entrypoint/command/env projection (`sanitizer_regression_test.go`), and exact raw
TTY frame/response bounds (`tty_regression_test.go`). F3-R first-delivery body
faults, parsed-HTTP fixture timing, `Next`/`Read` denial, peer cancellation,
explicit proof recovery and healthy EOF/local-Close controls are covered by
`stream_fault_regression_test.go` and `tty_fault_test.go`. F3-M complete-frame
synthetic/parsed-HTTP faults via both APIs, caller-buffer preservation, peer
cancellation, explicit recovery and revoked-old-stream controls are retained in
`multiplex_fault_regression_test.go` (derived from run378). Exact header/payload
fills, prefetched frames, error-before-limit ordering and healthy co-returned
EOF are covered by `multiplex_fault_test.go`; `log_body_test.go` checks the
sticky, fixed fault classification independently of request-error exceptions.
`stream_close_fault_test.go` holds body `Close` between read interruption and
unregistration to prove per-`Next` cancellation does not masquerade as daemon
loss in either framing mode; independent healthy peers/proof remain usable.
F8's entered `/info`, self-inspect and inventory cancellation cases are retained
in `stream_metadata_cancellation_test.go` (derived from run380).
`stream_metadata_boundaries_test.go` adds post-delivery `Next`/`Read`, idle
watcher Close, actual consumer/idle watchdog expiry, independent transport fault
coincident with consumer cancellation, and explicit-invalidation controls; it
checks discarded output, preserved healthy peer/admission, and mandatory
revocation with zero dispatch on genuine uncertainty.
All SDK tests inject an in-memory HTTP transport; no daemon or socket is used.
These are package-level fixtures, not completed REST/MCP, deployment, NIST/FIPS
or OS×CPU qualification.
