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

P1.12 itself did not expose routes or enable the settings; the `cmd/mandatary` composition root now does (P1.19): with
`MANDATARY_DOCKER_SOCKET` it wires the real SDK adapter, with `MANDATARY_DEV_MOCK_DOCKER=true` the mock, and with
neither no Docker surface. A verifier runs `VerifySelf` at start, after every loss of proof and as a periodic inventory
heartbeat, and readiness (`/api/v1/readyz`) is true only while the proof is verified. Shared execution/rate-limiting is
owned by **P1.13**, REST/MCP transport wiring by **P1.14**, UI views by **P1.16**, and the image, Compose files and
live-container isolation evidence by **P1.19** ([deployment.md](deployment.md)).

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

Every ordinary admission is covered by a successful daemon/self continuity check
(daemon ID, own container, complete all-state inventory including uniqueness of any
instance-UUID binding) that started less than one second earlier in the current
safety epoch or after the caller began waiting (**bounded continuity freshness**,
below); package default and the in-memory mock: every caller makes its own check.
Every resolution still reads a fresh all-state inventory and checks it as a whole,
every dispatch still inspects the target, and every start/stop/restart needs a
continuity check that started after the call began. Unknown/malformed
inventory and connection/I/O failures invalidate proof and cancel all streams.
Known logical missing-target/invalid-argument denials do not by themselves imply
a disconnected daemon. Removing an overlap or reconnecting does not restore
readiness: explicit fresh `VerifySelf` is required.

Active streams are covered by a continuity check, with the same bounded freshness,
before and after each delivery (including buffered `Read` bytes); idle streams also
have a one-second safety watcher with a two-second check deadline. Explicit `InvalidateSafety` cancels immediately, without
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

## Bounded continuity freshness (P1.20, R2)

**Why.** One admitted status call used to cost 12 daemon reads and a tail-logs call 33, nine of the twelve being the
same continuity check (`/info`, inspect of the own container, all-state list), and every live stream repeated it
around each delivery and once a second. Under the approved workload the daemon was the bottleneck (the RCA in
[release-acceptance.md](release-acceptance.md)) and a single failed read dropped the endpoint-wide proof for
everybody. The check may therefore be shared for a short, fixed time.

**What is cached, and only this.** The *result of the continuity check*: the daemon `/info` ID equals the proven
daemon ID; the own container has the same ID, exact self label, `Created` and `StartedAt`; the all-state inventory
passes `VerifyInventory` (own container present, binding unique, IDs well formed and unique). No authorization
decision, policy, credential, session, lease, target resolution, name mapping or target inspect is cached anywhere;
authorization reads its own store on every request and the snapshot never answers an authorization question. Docker
labels are static for the lifetime of a container and a rename keeps its ID
([labels](https://docs.docker.com/engine/manage-resources/labels/)), so protection stays a property of the immutable
ID, kept by the monitor's sticky protected set, never by a name.

**Lifetime: 1 s** (`cmd/mandatary` constant `continuityTTL`; no environment variable or request can change it;
`SDKOptions.ContinuityTTL` accepts 0 to 1 s and refuses anything else with `ErrInvalidConfig`; the package default 0
means every caller makes its own check). Why one second: it is inside the freshness the product already accepts
(an idle stream detects a silent change at its next one-second watcher tick plus up to a two-second check deadline;
the readiness heartbeat runs every five seconds), it removes the dominant cost, and a longer value would save little
more because every call still reads a fresh list and the target. What a one-second bound defers is only the daemon-ID
equality and the own container's `StartedAt`: a daemon swap that keeps the own container's ID in the inventory needs a
cloned daemon, and a restarted own container restarts this process into `UNVERIFIED` (`SELF-09`). Host or daemon
compromise is outside the protection boundary (§S1.1).

**Freshness rule.** Age is measured on the monotonic clock from the *start* of the refresh (before its first read), so
the refresh's own duration counts against it. A snapshot covers a caller only while `0 <= age < TTL`; at exactly TTL it
is expired, and an expired or failed check is never a fallback. A snapshot also covers a caller whose call began
*before* a refresh that started *after* it arrived, however long that refresh took. Memory is O(1) per adapter; there
is no background goroutine, timer or event that can extend freshness.

**Single flight.** At most one refresh runs at a time, led by the caller that found none, on that caller's own context
and with that caller's own error classification, so a single caller behaves exactly as without the cache. Other callers
wait for it. Nobody waits for more than two refreshes, and the daemon sees one check per refresh however many callers
wait. A refresh has a 15 s ceiling (its own safety deadline).

| Caller | Event | Result |
| --- | --- | --- |
| Leader (admission) | any error, including its own cancellation or deadline | the proof is dropped (unchanged semantics) |
| Leader (stream) | pure consumer cancellation | local: no revocation; a waiter leads the next refresh |
| Leader (stream) | independent fault, also when its own cancellation coincides | revoked **before** it returns; waiters fail closed |
| Waiter | its own cancellation or caller deadline | local (it observed no daemon evidence) |
| Waiter | a deadline this process set on the check (`ErrSafetyCheckDeadline`: stream watchdog, readiness heartbeat) | revoked (`check_deadline`, step `continuity`) |
| Anyone | the proof was dropped or the epoch changed meanwhile | `ErrUnverified`; nothing is dispatched |

**Publication and invalidation** happen under the same lock that revokes the proof (`SafetyMonitor.mu`): every drop
(`InvalidateSafety`, restore, endpoint reapproval, configuration change, a verification attempt, closure, an
operation, stream or body fault, a continuity mismatch) clears the snapshot and moves the epoch; a refresh that began
in an older epoch publishes nothing and never moves the snapshot's start backwards. Only a fresh `VerifySelf` restores
the proof, and it does not seed the snapshot.

**Which calls use it.**

| Path | Continuity | Always fresh |
| --- | --- | --- |
| `ResolveTarget`, `ListContainers` | snapshot allowed | the all-state list, checked as a whole (`VerifyInventory`) before any name is matched |
| `InspectStatus`, `InspectConfig`, `Logs` | snapshot allowed | the target inspect, its labels and the epoch at dispatch |
| `Start`, `Stop`, `Restart` | a check that started after the call began | the target inspect |
| stream deliveries and the idle watcher | snapshot allowed | none |

**Bounded detection delay.** A daemon-ID-only change is detected within one TTL plus one refresh for reads and
streams, and at once for mutations. Self disappearance, recreation under a new ID, a new reserved-namespace peer, a
name taken over by a protected container and a binding overlap are detected by the fresh list of the next resolution
and the fresh target inspect of the next dispatch, with no delay. Loss of the proof (`SELF-07`) cancels streams at
once and a post-delivery check fails on epoch mismatch even inside the TTL. This replaces the earlier wording "every
admission rechecks continuity" and "streams recheck before and after each delivery"; nothing else of §S1 changes.

**Tests.** `continuity_cache_test.go` (expiry boundary, refresh duration, concurrent sharing, saturation, publication,
options, read counts, idle streams, goroutines), `continuity_cache_security_test.go` (invalidation during refresh at
each read for six invalidators, leader and waiter cancellation, fault with cancel, internal deadlines, refresh ceiling,
mutations, daemon-ID bound, name reuse and recreation, reserved peers, binding overlap, active streams, restore and
rebind), `internal/authz/continuity_independence_test.go` (revocation, quarantine, default deny while a snapshot is
fresh) and `cmd/mandatary/daemon_requests_test.go` (the production constant and the heartbeat's deadline cause). Every
existing test runs unchanged at the package default (TTL 0), and `MANDATARY_CONTINUITY_TWIN=1 go test ./internal/docker`
replays the whole existing suite, with no line changed, through the cached code path
(`continuity_twin_test.go`: TTL 1 s and a clock that has always expired the snapshot).

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
| `SELF-13` Mock isolation & no native real-socket exemption | `TestSELF13_MockIsolationAndNoImplicitSocketAccess`; composed binary: `TestSELFNativeEvidenceWithARealSocketNeverVerifies` (native cgroup v1, native cgroup v2 and an absent `/proc/self/cgroup` stay unready even with a matching binding), `TestSELFContainerEvidenceWithARealSocketStillVerifies` (positive controls) | P1.14, P1.19 |
| P1.20 R2 Bounded continuity freshness: expiry at exactly TTL, refresh duration counted, one shared check, saturation, late/regressing publication, options | `TestContinuityExpiryBoundary`, `TestContinuityRefreshDurationCountsAgainstFreshness`, `TestContinuityWaiterServedByRefreshStartedAfterArrival`, `TestContinuityConcurrentStaleAdmissionsShareOneCheck`, `TestContinuitySaturationAtMostTwoRefreshes`, `TestContinuityPublicationNeverRegressesOrCrossesEpochs`, `TestContinuityLateRefreshOfAnOlderEpochIsDiscarded`, `TestContinuityOptionsAreValidated`, `TestContinuityReadCountsWithAFreshSnapshot`, `TestContinuityIdleFollowStreamsShareTheCheck`, `TestContinuityDoesNotLeakGoroutines` | P1.20 |
| P1.20 R2 Cancellation vs. independent fault, invalidation, identity and protection inside the bound | `TestContinuityInvalidationDuringRefresh`, `TestContinuityEveryRevocationClearsTheSnapshotItself`, `TestContinuityLeaderStreamPureCancelIsLocal`, `TestContinuityLeaderFaultWithCancelRevokesBeforeReturn`, `TestContinuityWaiterPureCancelIsLocal`, `TestContinuityWaiterInternalDeadlineRevokes`, `TestContinuityRefreshCeilingBoundsAHungDaemon`, `TestContinuityAdmissionLeaderCancelStillDrops`, `TestContinuityMutationsNeedAFreshCheck`, `TestContinuityDaemonIDChangeBound`, `TestContinuityNameReuseAndRecreationWithinTheBound`, `TestContinuityNewProtectedPeerWithinTheBound`, `TestContinuityBindingOverlapWithinTheBound`, `TestContinuityActiveStreams`, `TestContinuityRestoreAndRebind`; authorization independence: `TestContinuitySnapshotNeverAnswersAnAuthorizationQuestion`, `TestContinuitySnapshotServesAnAuthorizedCallWithoutDaemonChecks` (`internal/authz`); composition: `TestComposedAdapterContinuityIsOneSecond`, `TestHeartbeatDeadlineCarriesTheSafetyCheckCause` (`cmd/mandatary`) | P1.20 |
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
