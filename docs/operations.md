# Shared operation execution service and cancellable logs (P1.13)

## Delivered scope and boundaries

`internal/ops` is the single entry point that REST (`internal/api`), MCP
(`internal/mcp`) and the later Operations UI call to run a container operation
(`TD §§1.2, 3.3`). It binds the shared `authz.Authorizer` (P1.11) to the
`DockerBackend` (P1.12) and owns nothing else: no HTTP/MCP route, no usage
accounting (P1.15), no UI. `cmd/mandatary` is unchanged and still mounts no API
route; **no caller can reach this service until P1.14 adds adapters.** P1.14 must
authenticate and map errors on top of `Service.Execute`, never around it.

`internal/ops` is a new package under the approved `internal/` module boundaries.
TD §5 lists `api` and `mcp` as callers of "the shared `authz` + `docker` services";
this package is that shared layer so neither adapter owns execution logic. It
imports `authz`, `docker` and `domain` only (not `auth`, `store`, `api` or `mcp`).

Additive change to P1.11: `Authorizer.BackendFor(Decision)` returns the backend a
decision was issued against, and only while the decision's issuing binding
(authorizer, backend revision, invalidation revision) is current and the backend is
ready and self/peer verified. This is what lets the service dispatch on the exact
instance that authorized, and refuse (zero backend calls) after a rebind, removal,
`InvalidateAll` or loss of safety proof.

No product, NIST/FIPS or runtime-compatibility claim follows from this document.
Native mock iteration remains container-build-free: every test here uses the
in-memory `MockBackend`, never a Docker socket, and no Unraid, image, volume or
network operation is performed.

## API surface

| Symbol | Purpose |
| --- | --- |
| `ops.Operations()` | The exact six permission keys: `container:logs`, `container:inspect_status`, `container:inspect_config`, `container:start`, `container:stop`, `container:restart`. Anything else is absent (not merely denied). |
| `Service.Execute(ctx, Request) (Result, error)` | The only operation entry point. |
| `Service.NotifyAuthorityChange(ctx)` | Push: revalidate every active lease and stream now. Call it after committing any change that can end authority. |
| `LogStream.Next / Close / Done / Revalidate` | Typed, labelled frames only. There is no `Read`, no raw byte pipe. |

`Request` carries credentials, the endpoint UUID, a target reference (container name
or full 64-hex ID), the operation key and that operation's own typed options. It has
**no** Docker path, query, HTTP method or body field; a reflection test pins the
field set and the exported method set so an `Exec`, raw-proxy or discovery entry
point cannot be added by accident. Credentials are redacted in every `fmt` verb,
JSON encoding and `slog` handler (`Request`, `LogStream`), and never appear in an
error.

`Result` holds the typed outcome: at most one of `Status` (`InspectStatus`),
`Config` (`InspectConfig`, secret-redacted by the P1.12 sanitizer) or `Logs`; start,
stop and restart return none. The service returns the backend's already-sanitized,
allowlisted structures unchanged.

### Order of evaluation (fixed)

1. **Input validation, pure.** Context live; operation key in the six; endpoint is a
   canonical UUID; target is a Docker-valid name (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`,
   optional single leading `/`, at most 255 bytes) or a full ID; option blocks belong
   to the operation and are inside the bounds (`tail` 1-10000, no `TailAll`, a stream
   selected, `since <= until`, stop/restart timeout 1-300 s). Failure returns
   `ops.ErrInvalidRequest` with **no** authorizer, storage or backend interaction
   (not even a target lookup). Paths, queries, sub-resources, wildcards, whitespace,
   control and non-ASCII characters never reach a backend.
2. **Credential shape.** Exactly one of session or agent credentials; none or both is
   `401` with no backend interaction.
3. **`authz.AcquireLease`**: self-protection and safety state, credential/session
   validity, restore quarantine, endpoint state, explicit `DENY` across direct and
   group rules, explicit `ALLOW` with parameter caps, default deny, then a
   revalidation under the registered lease. The target name is resolved exactly
   once, here.
4. **`Authorizer.BackendFor`**, then **dispatch using only the `Decision`**: the
   immutable `TargetIdentity` and the *normalized* options (never the caller's
   pointers). A name is never resolved again; the lease's own revalidation resolves
   only the 64-hex ID.

### What "backend call count is zero" means

The card's zero-call acceptance is measured with an **attempt-counting spy** wrapped
around `MockBackend` (C1 O2: the mock's own counters increment only after its checks
pass, so they cannot prove an attempt did not happen). The spy counts every
`DockerBackend` method before delegating. For every permission key, on every deny
condition, the number of **operational** attempts (`InspectStatus`, `InspectConfig`,
`Logs`, `Start`, `Stop`, `Restart`) is zero. `ResolveTarget` is the authorizer's
read-only identity lookup needed to bind the immutable ID; it is counted separately
and is itself skipped for input rejected in steps 1-2 and for an endpoint with no
backend (those assert **zero calls of any kind**).

### Error taxonomy (for P1.14 mapping)

| Error | Meaning |
| --- | --- |
| `authz.ErrUnauthenticated` (`authz.StatusCode` = 401) | credential/session/token not acceptable (also anonymous or ambiguous credentials). |
| `authz.ErrForbidden` (403, `authz.ReasonOf`) | self/peer, safety unverified, quarantine, endpoint, explicit deny, default deny, cap exceeded, target missing, decision stale. |
| `ops.ErrInvalidRequest` | malformed or unsupported input (400-class). |
| `ops.ErrInvalidConfig` | nil/zero service. |
| `ops.ErrStreamRevoked`, `ops.ErrStreamClosed` | stream ended by revoked/expired authorization, or by its consumer. |
| `docker.Error` sentinels, `io.EOF`, `context.Canceled/DeadlineExceeded` | sanitized backend or caller outcomes. Raw SDK, SQL or credential material is never wrapped. |

An authorization that ends while a one-shot call is in flight cancels the backend
call's context; an inspect result that completes after that is **withheld**.

## Stop, restart and dispatch bounds

* stop/restart forward only the normalized timeout (default 10 s, 1-300 s), as a
  fresh integer, never the caller's pointer; a policy's `stop_timeout_max` is enforced
  by the authorizer before dispatch.
* Every one-shot dispatch runs under a deadline derived from the lease: the daemon
  stop timeout plus `StopGrace` (default 15 s) for stop/restart, `OperationTimeout`
  (default 30 s) otherwise. An already-expired bound dispatches nothing. Logs are
  exempt: the stream's context is the lease.
* Configuration is validated fail-closed (`RevalidateInterval` 10 ms-30 s default
  1 s, `RevalidateTimeout` default 10 s, `AcquireTimeout` 1 ms-1 min default 10 s,
  `OperationTimeout` up to 10 min, `StopGrace` up to 5 min).

## Caller cancellation

A caller leaving is a local event; it must never be mistaken for a fault of the
shared authorization or backend state.

* **Acquisition is detached.** `Execute` runs the whole lease acquisition
  (authorization, `ResolveTarget` by name, then the revalidation by immutable ID under
  the registered lease) on a context that carries the caller's values but not its
  cancellation, bounded by `AcquireTimeout`. The caller's cancellation therefore never
  reaches the authorizer or the backend's name/ID resolution: it cannot fail-close the
  same principal's sibling streams and in-flight operations on the target, and it
  cannot make the SDK adapter invalidate its global safety proof there (P1.11 L4,
  reviewer F1/F2).
* **The result is the caller's own.** A caller that left during acquisition gets its
  context error (`context.Canceled`/`DeadlineExceeded`), never a 403, and the lease it
  won is released before any backend operation. Expiry of `AcquireTimeout` is a real
  fault: it fails closed with `context.DeadlineExceeded`.
* **Real denials are unaffected.** A revocation or shared fault in the acquisition
  window still denies the call and still cancels the authorizer's matching leases;
  only the pure caller-cancellation classification is removed.
* **Backend calls are not bound to the caller (reviewer F3).** Every backend call
  (`InspectStatus`, `InspectConfig`, `Start`, `Stop`, `Restart` and the `Logs` open
  call) runs under the lease context, which only a revocation, a release or the
  dispatch deadline can cancel. A caller that leaves while one is in flight does not
  cancel its context (the SDK adapter reads a canceled operational context as a fault
  and would invalidate the endpoint's global safety proof). `Execute` waits for the
  call to finish (bounded by the dispatch deadline: daemon stop timeout plus
  `StopGrace` for stop/restart, `OperationTimeout` otherwise; a revocation still
  cancels it at once), **withholds** its outcome (a log stream opened meanwhile is
  closed) and returns the caller's own context error. The error does not mean the
  daemon did not perform a start, stop or restart: the caller is told only that it
  left. The lease is released when the call returns, so nothing leaks and no sibling
  is touched.
* **The Logs open call is bounded too (reviewer F4).** It runs under the same
  `OperationTimeout` deadline as an inspect. The deadline ends only the *open*: a
  watcher releases the lease (which cancels the open call) if the open has not
  returned when the deadline fires, `Execute` then returns the deadline's context
  error with no stream and no lease, and a stream that finishes opening only after
  that is closed and never handed out. The watcher is retired the moment the open
  returns, so the deadline can never end a handed-off stream (its lifetime is the
  lease, not a deadline).
* **An open stream is bound to the caller.** Once a log stream has been handed off, the
  request context ending releases its lease and ends the stream with the request's
  context error as its terminal error. Canceling an already-open stream is a local
  event for the adapter (reviewer RP-05: it keeps the endpoint verified).

## Cancellable logs: termination contract

A `container:logs` request keeps its authorizer lease for the life of the
`LogStream`. A stream ends, and never yields another frame, when its authorization
ends:

| Cause | Detected by |
| --- | --- |
| token revoked, expired, rotated out (overlap end), agent disabled, credential generation bump | push (`NotifyAuthorityChange`; P1.10 administration already notifies, so revocation is applied before `RevokeCredential` returns) or pull |
| session revoked (logout, saved-code recovery entry, MFA-reset issuance, protective reports), idle or absolute expiry, MFA/assurance floor raised, user disabled/quarantined/compromised, session generation bump | push, or pull |
| policy: allow removed, explicit deny added, caps tightened, quarantined/stale-generation allow, group membership disabled | push (`NotifyPolicyChange`) or pull |
| restore quarantine, endpoint disabled | push or pull |
| target removed, renamed out of its selector, recreated under the same name | push or pull (revalidated by immutable ID) |
| backend loses self/peer proof, backend removed or rebound | the authorizer cancels the lease; the backend also fails the stream |
| consumer `Close`, request context ended | immediately |

**C2 observation O1 (disposition).** Only agent administration calls the
authorizer's `NotifyPolicyChange`. Session-revocation paths in `internal/auth`
(logout, saved-code recovery entry, MFA-reset issuance, protective reports) and pure
expiry do **not** notify; `internal/auth` is unchanged by this task. Termination on
those paths is therefore guaranteed by the **pull path**: every stream runs its own
watcher that calls `Lease.Revalidate` every `RevalidateInterval` (default 1 s), so a
stream outlives such a revocation by at most one interval plus one pass (bounded by
`RevalidateTimeout`, fail-closed). Any adapter that revokes authority should also
call `Service.NotifyAuthorityChange` after commit for immediate effect; wiring
this into the logout and recovery routes is P1.14/P1.16 adapter work, not
inferred here. `NotifyAuthorityChange` is detached from the caller's cancellation
(P1.11 L1: a request context that ends mid-sweep must not fail-close healthy
streams) and bounded by its own timeout.

**Activity and expiry (N63B4-SESSION-CLOCKS S06, E13).** A log stream is not human
activity. Revalidation uses the read-only credential verifier and never updates
`last_activity_at`; a follow stream cannot keep a session alive. It ends exactly at
the idle timeout, the absolute lifetime or the token expiry (tested one second
before and at each boundary on the synthetic clock). The session's idle and absolute
limits are the P1.08 values; this task adds none.

Other stream properties:

* Termination is by **deterministic context cancellation**: the lease context is
  canceled, which cancels a pending `Next`, and a transport read that ignores its
  context is unblocked because the service closes the backend stream when the lease
  ends. Tests order every step with channels; none sleeps or polls.
* A frame read concurrently with the end of authorization is discarded (post-I/O
  fence).
* Cancelling a `Next` context while the read is in progress ends the stream, because
  a backend stream cannot resume after an interrupted read; cancelling it while
  merely queued behind another reader does not.
* Closing one stream never cancels a sibling stream of the same principal
  (revalidation runs detached from caller cancellation; the authorizer cancels
  matching leases only on a real principal-specific failure).
* A finite (non-follow) stream ends with `io.EOF` and releases its lease and watcher.
* Not in this task: a cap on concurrent streams per principal and usage accounting
  (P1.15). Each stream costs one goroutine, one lease and one DB read per interval.

## Requirement-to-test map

Tests run with the container-free mock only. "Fixture IDs" follow the C2 checkpoint
(`C2R-*`) and the security contracts (`SELF-*`, `RESTORE-*`).

| Requirement | Tests |
| --- | --- |
| Exact six permission keys, two inspect variants; unsupported ops absent, no raw forwarding | `TestOperationCatalogIsExactlyTheSixApprovedKeys`, `TestServiceSurfaceHasNoUnsupportedOrRawForwardingEntryPoint`, `TestUnsupportedOperationKeysTouchNothing` (`internal/ops`) |
| Authorized target only; immutable ID; name never re-resolved after authorization | `TestEveryPermissionKeyDispatchesOnceOnTheImmutableTarget` (6 keys x human/agent), `TestRenameAfterAuthorizationNeverRedirectsDispatch`, `TestRenameThatBreaksTheSelectorDeniesWithZeroOperationalCalls`, `TestStreamLifetimeNeverResolvesTheNameAgain`, `TestTargetGivenAsFullContainerIDIsEquivalent` |
| **Spy backend count zero for every key and each deny condition** (deny, malformed input, self/peer target) | `TestDenyMatrixCausesZeroOperationalBackendAttemptsForEveryPermissionKey`: 76 deny conditions (126 condition x principal runs); each run covers every permission key plus the logs follow variant and first proves each of them allowed in the same environment (control); `TestDenyMatrixCoversTheNamedCheckpointFamilies` |
| C2R-H / C2R-E / C2R-Q assurance, expiry and state denials through the shared authorizer | deny-matrix cases `C2R-H*`, `C2R-E*`, `C2R-Q*`; real issuers: `TestOpsServiceHumanIdentitiesFromRealIssuers` (`internal/auth`) |
| C2R-T05 token revocation cancels the lease before it returns | `TestOpsServiceAgentTokenLifecycleEndsStreams` (no tick, no wait), deny-matrix `C2R-T05`, `C2R-T06` |
| C2R-B / C2R-R bootstrap and recovery identities never authorize | `TestOpsServiceBootstrapAndHostRecoveryAreNeverOperationalIdentities`, `TestOpsServiceRecoveryCapabilityIsNotAnIdentity`; deny-matrix `C2R-B*`, `C2R-R*` |
| C2 O1 session revocation terminates follow streams (real revocation, not only token) | `TestOpsFollowStreamEndsOnEveryRealSessionRevocationPath` (real `Logout`, saved-code recovery entry, protective TOTP report; push and pull), MFA-reset issuance inside the bootstrap test |
| Active log termination on token / session / policy revocation or expiry | `TestFollowStreamTerminatesOnEveryRevocationOrExpiryCause` (24 causes, human and agent principals, push and pull detection: 76 subtests), `TestStreamActivityNeverRefreshesClocksAndEndsExactlyAtExpiry` |
| Pending follow read bounded by deterministic context cancellation (no sleeps) | `TestPendingFollowReadIsBoundedByContextCancellation`, `TestRevocationClosesTransportThatIgnoresContext`, `TestStreamRevalidateIsSynchronous` |
| Caller cancellation never cancels another lease or reaches the backend's resolution; real revocation in the same window still does (reviewer RP-01 regression + adverse control); acquisition bounded | `TestCanceledExecuteNeverCancelsSiblingLeasesOrBackendSafety`, `TestCallerCancellationNeverReachesBackendResolveTarget`, `TestRealRevocationInTheAcquisitionWindowStillCancelsPeers`, `TestAcquisitionIsBoundedByAcquireTimeout` |
| A caller leaving mid-call never cancels the backend operational context, for all six keys (reviewer RP-04 regression + control); result withheld, own ctx error, no leak, sibling intact; revocation (with or without the caller leaving) still cancels it; an open stream still ends with its request | `TestCallerLeavingMidBackendCallNeverCancelsTheBackendContext`, `TestRevocationStillCancelsAMidCallBackendContextWhenCallerAlsoLeft`, `TestAdmittedLeaseStaysBoundToTheCallerLifetime` |
| Revocation isolation; healthy streams survive | `TestRevocationIsolationBetweenStreams`, `TestHealthyStreamSurvivesTicksAndNoopNotifications`, `TestNotifyAuthorityChangeIsNotKilledByRequestContext` |
| Stop/restart bounds and dispatch deadline | `TestStopAndRestartForwardOnlyNormalizedBoundedTimeouts`, `TestPolicyStopTimeoutCapIsEnforced`, `TestOneShotDispatchIsBoundedByDeadline`, `TestDispatchDeadlineFiringReleasesInFlightOperation` |
| The Logs open call is bounded by the dispatch deadline even with the caller gone (reviewer RP-06 regression + inspect control); a late-opening stream is closed, never handed out; a handed-off stream survives the deadline | `TestHungOpenIsBoundedByTheDispatchDeadline`, `TestStreamOpenedAfterItsDeadlineIsClosedNotHandedOut`, `TestHandedOffStreamSurvivesTheOpenDeadline` |
| In-flight revocation cancels the call and withholds data; concurrency under `-race` | `TestRevocationDuringInFlightOperationCancelsItAndWithholdsData`, `TestConcurrentExecuteAndRevocation` |
| SELF-01/04/05/08/09/13 service level (SELF-07 stream loss) | deny-matrix `SELF-*` cases, `TestLossOfSafetyProofEndsStreamAndBlocksNewDispatch` (P1.11/P1.12 retain SELF-01-13 at authorizer and adapter level) |
| RESTORE-03 (quarantined allow grants nothing), restore quarantine, stale generations | deny-matrix `RESTORE-*`, `C2R-Q03` |
| N63B4 E13 / EXP / INVAL (invalid authenticator rejected incl. in-flight streams), S03 / SB-8.2 (logout), S06 / SB-5 / SB-8.4 / REAUTH (clocks, streaming expiry) | the C2R rows above and `TestStreamActivityNeverRefreshesClocksAndEndsExactlyAtExpiry` |
| TD §9.3 redaction (L3 formatting of caller-held credentials) | `TestCredentialsAreNeverFormattedByRequestsResultsStreamsOrErrors` |
| `Authorizer.BackendFor` binding | `TestBackendForReturnsOnlyTheBackendBoundToAFreshDecision`, `TestBackendForRefusesAfterRebindInvalidationRemovalOrSafetyLoss` (`internal/authz`) |

Real-Docker behavior, REST/MCP transport, usage accounting and live-container
SELF integration remain with P1.14, P1.15 and P1.19; mock success is not proof of
real-Docker behavior.

## Carried items

* P1.14: authenticate before `Execute`; map errors using the table above; wire
  `NotifyAuthorityChange` into logout, recovery and similar commit paths; add a
  concurrent-stream cap per principal; C1 O1 (self-before-auth precedence leaves an
  unauthenticated name oracle on protected names) is mitigated by the credential-shape
  check for anonymous requests only.
* P1.11 L2/L4 (closed at the `Execute` seam, still open inside the adapter): the SDK
  adapter's `ResolveTarget` invalidates the endpoint's global safety proof on *any*
  error, including a pure caller cancellation, and so do its one-shot and `Logs`-open
  calls. `Execute` never hands the caller's cancellation to the authorizer, to
  `ResolveTarget` or to any backend call (see "Caller cancellation" above; a
  *revocation* that cancels an in-flight SDK call is still classified by the adapter,
  reviewer N3), so through this service a departing caller cannot cause it. A direct
  caller of
  `Authorizer.Authorize`/`AcquireLease` with a cancellable context (for example a
  future adapter bypassing `Execute`) still can; that adapter behavior belongs to the
  docker adapter (P1.12) and is carried, not changed here.
* A caller that cancels during acquisition still waits for the acquisition to finish
  or for `AcquireTimeout` (default 10 s), and one that cancels during a backend call
  waits for that call to finish (bounded by the dispatch deadline; revocation ends it
  at once): both are detached from the caller's context by design, so the wait is
  bounded but not interruptible. A transport adapter that must answer its client
  promptly should stop waiting on its own side and let `Execute` finish.
