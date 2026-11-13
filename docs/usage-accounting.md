# Persistent usage accounting (P1.15)

TD §9.1 requires basic persistent usage counts: allowed, denied and error counts
attributed to `(user, agent, endpoint, selector, operation)`, aggregated into hourly
and daily SQLite rollups plus a bounded recent-event ring buffer, with configurable
retention (default 90 days). This row delivers the accounting, the rollups and the
exact-count fixture. The Phase 2 statistics/reporting UI, any API that reads the
counts, and the backup of usage are **not** part of it.

No product, NIST/FIPS or runtime-compatibility claim follows from this document.
Every test named here runs on the in-memory Docker mock and a temporary file-backed
SQLite store; nothing contacts a Docker socket. Mock success is not evidence of
real-Docker behavior (P1.19).

## What is delivered

| Piece | Where |
| --- | --- |
| Domain types `UsageEvent`, `UsageOutcome` (`allowed`/`denied`/`error`, no fourth category) | `internal/domain/usage.go` |
| Persistent ledger: atomic increment of both rollups + recent event + ring trim, retention, reads | `internal/store/usage.go`, `internal/store/queries/usage.sql` (generated `usage.sql.go`) |
| Schema change: a usage row may have **no selector**, for a denied outcome only | `internal/store/migrations/00013_usage_unmatched_denials.sql` |
| Secret-free attribution of authorizer outcomes (`Decision.Attribution`, `authz.AttributionOf`) | `internal/authz/attribution.go` |
| The single accounting point | `ops.Service.Execute` (`internal/ops/service.go`), `Config.Usage` |
| Committed versioned exact-count fixture | `internal/ops/testdata/usage_fixture_v1.json` |

REST, MCP and the later Operations UI all call `Service.Execute`, so they account
identically (`TestUsageIsAccountedIdenticallyOverRESTAndMCP`). `cmd/mandatary` still
mounts nothing (P1.14 composes the adapters without an executor); the composition root
that finally builds the service **must** pass a `store.UsageLedger` as `Config.Usage`.
A service built without one accounts nothing (and says so: that is its documented
behavior, not a silent fallback).

## Attribution

`(user_id, agent_id, endpoint_id, selector_id, operation)`:

* human principal: `user_id` = the user, `agent_id` empty;
* agent owned by a user: **both** `agent_id` and `user_id` (the owner), so reports can
  break down by user and by agent (TD §9.1); the owner is attribution only, never an
  implicit permission (TD §3.3);
* agent owned by a group: `agent_id` only (`user_id` empty; the group is not a user);
* `endpoint_id`: the UUID; `operation`: one of the six permission keys (SQL `CHECK` and
  the ledger both refuse anything else, including `container:exec`);
* `selector_id`: the selector of the policy that **decided** the outcome: the matched
  ALLOW for allowed/error, the DENY rule for an explicit deny, the capped ALLOW for
  `parameter_cap_exceeded`.

**Decision D1 (schema, for Nico/reviewer).** A default deny, a missing target or a
rejected parameter set matched no policy selector, so there is nothing to attribute the
denial to. Inventing a placeholder selector row (which an administrator could later
attach policies to) would be worse than NULL, so migration 13 makes `selector_id`
nullable on the three usage tables. NULL means exactly "no selector matched" and SQL
`CHECK`s allow it for **denied** outcomes only (never allowed/error); the unique rollup
index folds NULL like the nullable principal columns, so unmatched denials still roll
into one row per `(window, principal, endpoint, operation)`. The migration copies rows
verbatim; its down migration aborts while an unmatched row exists (no silent loss). This
is the only schema change.

Not stored, ever: request or response payloads, log lines, log options (tail, since,
until), container names or IDs, error text, IP addresses, tokens, session or credential
identifiers, headers, user agents. `TestUsageEventsCarryNoPayload` pins the exact column
sets of the three tables.

## The accounting point and the classification

One outcome is accounted **exactly once**, when the backend evidence is known, inside
`Service.Execute`, synchronously, detached from the caller's cancellation and bounded by
a 10 s write timeout (so a caller that left still has its outcome counted). The rule is
**execution evidence, not the HTTP/service result**: authorization alone is not execution
success, and a returned 403 is not necessarily a denial.

| Situation | Counted | Why |
| --- | --- | --- |
| Backend call (or Logs open) returned success | **allowed** | the daemon executed it |
| ...and the caller left meanwhile (Execute withholds the result, returns the caller's cancellation) | **allowed** | execution is not undone by withholding |
| ...and the authorization ended meanwhile (data withheld, caller refused) | **allowed** | the daemon completed despite the cancellation (mock mode `daemon-completes-despite-cancellation`) |
| Backend returned an error (`ErrBackendFailed`, `ErrBackendUnavailable`, ...) | **error** | authorized, Docker execution failed |
| Target gone **after** authorization: dispatch-time `ErrTargetNotFound` (REST 404) | **error** | an authorized backend failure, not a policy denial (before authorization the same target is a 403 `default_deny`, counted *denied* with no selector) |
| Dispatch deadline fired during a one-shot call, or during the Logs open (`OperationTimeout`; stop/restart bound) | **error** | the call did not finish (a fault) |
| Backend call failed and the authorization had ended (in-flight revocation cut the call) | **denied** | the lease context is the call's context; no Docker fault is evidenced |
| Authority lost between admission and dispatch (`BackendFor` refuses, lease already ended): zero backend calls | **denied** | the authorizer refused it |
| Authorizer refused a **verified** principal: explicit deny, default deny, parameter cap, missing target, invalid parameters, stale decision, endpoint inactive (post-authentication) | **denied** | attributed to the deciding selector, or none |
| ...while the caller left during acquisition | **denied** | the authorizer's refusal is real; the caller still receives its own cancellation |
| Invalid input (unsupported key, malformed endpoint/target/options), anonymous/ambiguous credentials, **any 401** | *nothing* | no verified principal, no decision, no backend |
| Self/peer-protected target, unverified safety proof, restore quarantine, endpoint without a backend (all refused **before** authentication) | *nothing* | nobody is authenticated; attributing them would require verifying credentials after a self-protection refusal, which the precedence order forbids |
| Caller left before dispatch, only the caller (no decision, no evidence) | *nothing* | |
| `AcquireTimeout` expired | *nothing* | a fault with no decision |
| Pre-expired dispatch bound (zero backend calls) | *nothing* | no execution, no Docker failure |

**Decision D2 (for Nico/reviewer).** Refusals that precede authentication are
unattributable and therefore *not counted*; they remain visible only in structured logs
at the adapter. This follows the approved precedence (self-protection first) instead of
weakening it for accounting, and keeps "denied" meaning "an authenticated principal was
blocked by policy (403)", TD §9.1. If Nico wants them counted, that needs a separate
decision about an anonymous/unattributed bucket, not a silent change here.

**Decision D3.** Where revocation and a real backend failure race, "authority ended" wins:
the lease is checked when the failed call returns. It is deterministic in the fixtures and
documented as the single tie-break.

### Streams are counted once, at open

A `container:logs` request (finite or follow) is one accounting event, made when the
backend open call returns. Frames, end of stream, `Close` (any number of times), request
cancellation, revalidation (the stream's pull ticks, `Revalidate`,
`NotifyAuthorityChange`), revocation and a terminal backend failure after the open are
**not** accounting events and never change the count. A stream whose *open* fails is an
**error** (or **denied** when authority ended); one that opened and was withheld because
the caller or the authorization left while opening is **allowed**. The stream code never
references the recorder.

### A recorder failure never changes the outcome

If the ledger returns an error (storage down), the operation's result is unchanged, no
count is invented, queued or replayed, `Service.UsageFailures()` increases and one fixed
log line (`usage accounting failed`, with only the outcome and operation key) is written:
no error text, identifier or payload (`TestAccountingFailureNeverChangesTheOutcomeAndIsSurfacedWithoutSecrets`).
Exact counts therefore hold while storage is healthy; an operator must alert on the
counter.

## Rollups, retention and the ring buffer

* Windows are UTC, epoch-aligned: hourly `unix − unix mod 3600`, daily `unix − unix mod 86400`.
* Each outcome is **one transaction** through the repository's single serialized writer:
  upsert hourly, upsert daily, append the recent event, trim the ring. A failure leaves no
  partial count; concurrent outcomes never lose an increment
  (`TestUsageConcurrentIncrementsAreExact`, and 80 concurrent requests in the fixture).
  The repository writer uses `synchronous=FULL`; no power-loss guarantee is claimed
  specifically for usage counts beyond what P1.03 documents, and hardware honoring sync
  stays a trust assumption.
* Retention (`UsageConfig.Retention`, default **90 days**, 1 h … 3650 days): an hourly
  (daily) row is removed only when its **whole window** lies before `now − retention`; a
  recent event only once its own `retain_until` (`occurred + retention`) has passed.
  Counts inside a surviving window are never altered, and a pass is idempotent. A
  surviving daily row may include events whose hourly row was already removed; the two
  tables are retained independently by design.
* Retention is applied by `UsageLedger.Prune` and, unless `DisableAutoPrune`, by the first
  successful accounted outcome after each hour (`PruneInterval`, default 1 h, best effort:
  a failed pass is retried by the next outcome and never fails the accounting).
* The **recent-event ring buffer** keeps the newest `RecentEventLimit` events (default
  **1000**, 1…1,000,000; TD gives no number, this is the documented default). It bounds
  recent events only: the rollups still hold every event.
* **Decision D4.** Retention and ring size are `store.UsageConfig` options, not new
  environment variables: TD §13 lists none, and unlisted `MANDATARY_*` switches are refused
  rather than added silently (`docs/configuration-logging.md`). Wiring them to configuration
  is composition work (P1.19/C3).

## Restart, restore and backup

Usage survives an ordinary restart (`TestUsageSurvivesRestart`, and the fixture closes and
reopens the store, then replaces the whole service, authorizer and ledger, and again at the
end). Usage is **excluded** from the approved logical backup scope (security-contracts
S2.5 / RESTORE-10): a restore does not recover it, and no document or test claims it does.
Adding usage to the export is a scope amendment, not part of this row.

## The exact-count fixture

`internal/ops/testdata/usage_fixture_v1.json` (`schema: mandatary.usage-fixture`,
`version: 1`, strict decoding) declares:

* the predetermined sequence (29 steps in the main sequence, each with the principal, operation, target, the
  injected fault, what the caller sees and the accounted outcome/selector, or `none`);
* the exact hourly and daily rows per attribution tuple at four checkpoints:
  after the sequence, after restart + a concurrent phase, after retention, after a
  replaced service;
* what retention must remove (counts of hourly/daily rows and recent events).

`TestUsageFixtureDeclaresExactTotalsThatSurviveRestartConcurrencyRetentionAndServiceChange`
executes it through `ops.Service.Execute` and compares the real ledger with the declared
totals, and checks per step that exactly the declared event (or none) was added.
`TestUsageFixtureIsSelfConsistent` recomputes the totals from the steps independently.
`TestUsageFixtureComparisonDetectsEveryKindOfWrongTotal` and
`TestUsageFixtureCatchesDroppedAndDuplicatedAccounting` prove the comparison is not
vacuous (dropped, duplicated, folded and allowed-only accounting layers are caught).
**Re-run the fixture after every change to `internal/ops`, `internal/authz` or
`internal/store`**: it is part of `go test ./...`, which CI runs on every PR.

## Requirement-to-executable-test map

Run `go test -race -count=1 ./...`. Names are real declarations
(`TestUsageCrosswalkNamesResolve` fails if one is missing).

| Requirement / contract | Tests |
| --- | --- |
| TD 9.1 exact attribution, hourly + daily, three separate counters | `TestUsageRecordAccumulatesExactHourlyAndDailyTotals`, `TestUsageFixtureDeclaresExactTotalsThatSurviveRestartConcurrencyRetentionAndServiceChange`, `TestUsageFixtureIsSelfConsistent` |
| Fixture is not vacuous | `TestUsageFixtureComparisonDetectsEveryKindOfWrongTotal`, `TestUsageFixtureCatchesDroppedAndDuplicatedAccounting` |
| Persistence across restart and service replacement | `TestUsageSurvivesRestart`, `TestUsageFixtureDeclaresExactTotalsThatSurviveRestartConcurrencyRetentionAndServiceChange` |
| Concurrent increments exact | `TestUsageConcurrentIncrementsAreExact`, `TestUsageFixtureDeclaresExactTotalsThatSurviveRestartConcurrencyRetentionAndServiceChange` |
| Retention removes only the selected windows; auto-prune | `TestUsageRetentionRemovesOnlyTheSelectedWindows`, `TestUsageAutoPruneAppliesRetentionOncePerInterval` |
| Bounded recent events | `TestUsageRecentEventsAreBoundedByCountAndRetention` |
| No payload collection | `TestUsageEventsCarryNoPayload`, `TestAccountingFailureNeverChangesTheOutcomeAndIsSurfacedWithoutSecrets`, `TestAttributionDoesNotChangeTheDenialContract` |
| Closed operation catalog, input validation, atomicity, fail-closed config | `TestLedgerAcceptsExactlyTheSixPermissionKeys`, `TestUsageRejectsInvalidEventsAtomically`, `TestUsageLedgerConfigIsValidatedFailClosed` |
| Schema: selector-less denial only; migration round trip | `TestUsageUnmatchedDenialHasNoSelectorAndNothingElseMay`, `TestUsageUnmatchedDenialMigrationKeepsRowsAndRefusesLossyDowngrade`, `TestUsageStorage` |
| Attribution of decisions and denials (user/agent/owner/group, deciding selector, none before authentication) | `TestDecisionAttributionNamesHumanAndAgentOwner`, `TestDenialAttributionExistsOnlyAfterTheVerifiedPrincipalAndCarriesTheDecidingSelector`, `TestUnauthenticatedFailuresAreNeverAttributed`, `TestLeaseDecisionCarriesAttribution` |
| Every key allowed once, human and agent | `TestEveryPermissionKeyIsCountedAllowedOnceWithExactAttribution` |
| Policy denials with the deciding selector | `TestPolicyDenialsAreCountedDeniedWithTheDecidingSelector` |
| Nothing counted without a verified principal / decision | `TestRefusalsWithoutAVerifiedPrincipalOrDecisionAreNeverCounted`, `TestDenyMatrixCausesZeroOperationalBackendAttemptsForEveryPermissionKey` (every deny condition of the matrix) |
| Execution success is not authorization; backend error | `TestBackendFailureAfterAuthorizationIsCountedErrorNotDenied` |
| Target disappearing after authorization | `TestTargetDisappearingAfterAuthorizationIsABackendErrorNotADenial` |
| Authority lost before dispatch; caller gone before dispatch | `TestAuthorityLostBeforeDispatchIsDeniedNotAnError`, `TestCallerGoneBetweenAdmissionAndDispatchIsNotCountedButARevocationIs` |
| Caller cancellation during a call that succeeds / fails; during acquisition; acquisition timeout | `TestCallerLeavingMidCallIsCountedFromTheBackendEvidence`, `TestCallerLeavingDuringAcquisitionCountsOnlyARealDenial`, `TestAcquisitionTimeoutIsNotCounted` |
| In-flight revocation (cut off vs daemon completed), Logs open revoked | `TestInFlightRevocationIsDeniedWhenCutOffAndAllowedWhenTheDaemonCompleted`, `TestLogsOpenRevokedWhileOpeningFollowsTheBackendEvidence` |
| Deadline expiry, pre-expired bound | `TestDeadlineExpiryIsAnErrorAndAPreExpiredBoundIsNotCounted` |
| No double counting across stream open/close/revalidation/revocation/terminal failure | `TestStreamsAreCountedExactlyOnceAtOpen` |
| Recorder failure never changes the outcome; optional recorder | `TestAccountingFailureNeverChangesTheOutcomeAndIsSurfacedWithoutSecrets`, `TestServiceWithoutARecorderBehavesAsBefore` |
| REST and MCP account identically | `TestUsageIsAccountedIdenticallyOverRESTAndMCP` |
| RESTORE-10 (usage survives restart, excluded from backup) | `TestUsageSurvivesRestart` and this document's scope statement |

## Carried, not delivered here

* Statistics/reporting UI and read APIs (Phase 2); usage in the backup export (scope amendment).
* Wiring `Config.Usage` and the retention options in a running service (P1.19/C3).
* Real-Docker execution evidence and throughput under the load budget (P1.19/P1.20): each
  accounted outcome is one durable write on the request path, measured only with the mock.
* The Docker adapter's classification of a revocation-driven cancel as a fault (P1.13 N3)
  is unchanged; accounting reports what was observed (a call cut off while the authorization
  had ended is *denied*).
