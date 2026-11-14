# P1.02 storage and domain contract

## Scope

This is structural persistence, not a running repository/authentication product.
The HTTP binary remains static-only and never opens SQLite, mail or Docker.
`internal/domain` supplies identifiers; `internal/store/migrations/00001_initial.sql`
is a goose up/down migration; `sqlc.yaml` and `queries/models.sql` are the source
of generated `db.go`, `models.go` and `models.sql.go`. Never edit generated Go.
Use `make generate` to update it and `make generate-check` to compare without
rewriting. Both approved Go baselines run the generator and model tests.

P1.03 adds [runtime pool/WAL/FULL and encryption](storage-repository.md).
Archive import is P1.18 ([logical backup and restore](backup-restore.md); migration
`00014` adds the local, non-importable `restore_reports`/`restore_manifest` tables).
Authenticators, authorization and delivery remain their owning later P1 rows. A valid row is
not proof of authenticated factors, a current generation, trusted UTC, an
approved manifest, successful SMTP delivery or runtime self-verification.

## Identity, scope and authority

- Endpoint identity is a canonical lowercase non-nil UUID, not its name/slug.
  Fresh migration creates one random UUIDv4 + slug `local`/transport `unix`.
  Down/up is destructive fixture reset and creates a **new** identity; ordinary
  up/reopen preserves it. Production downgrade/rollback is not authorized here.
- Names/slugs/UUIDs are unique; equal container names on different endpoints are
  distinct selectors. Policies and usage use composite selector/endpoint FKs.
  No name lookup can silently substitute another endpoint.
- Agents require exactly one owning user XOR group; FK-restricted deletion and
  updates cannot orphan them. Ownership creates neither membership nor policy.
  Memberships are separate, initially quarantined records.
- Global `super_admin` scope is SQL NULL, generated as `*domain.EndpointID`;
  endpoint-scoped `endpoint_admin` requires a non-NULL typed endpoint. Only one
  active global admin is structurally possible. Future endpoint roles and remote
  endpoints may be represented **inactive only**; no future authority activates.
- Policies have exactly one user/group/agent subject, uppercase ALLOW/DENY and
  the six Phase 1 operation keys. No exec/discovery/raw proxy policy is accepted.
  Evaluating deny precedence, selectors/guardrails and identity safety is P1.11,
  not a SQL feature. Administrator status is not an operation grant.
- Every authority-bearing record defaults to quarantine/generation zero. Current
  `installation_control` credential/session/authority/restore generations start
  at zero, quarantine true; updates cannot reduce generations. These are local
  controls **outside** any future archive mapping. No stored self-verified flag
  exists. A privileged SQL writer can still delete/reinsert records or advance
  generations: this schema is not an archive service or malicious-host defense.
  P1.03/08/10/11/18 must deny missing/mismatched controls, enforce reapproval and
  trusted time and never import current controls or accept archive state flags.

## Credential/session representation

Authenticator rows hold account/type, significant lifecycle times, unknown vs
known capability fields, verifiers/ciphertext/public-key slots, retry counts,
accepted TOTP step and WebAuthn metadata. Unknown capabilities are NULL, not
inferred from key brand. No biometric sample/template storage is introduced.
Active material has required structural slots/generation/binding; format,
entropy, key integrity, encryption and proof of possession are later services.
Agent credentials hold a unique 32-byte hash and short display ID, expiry or
explicit non-expiring approval, revocation/rotation windows and generation.
No plaintext bearer, cookie, password, TOTP or recovery-code column exists.
BLOB length/column names alone cannot guarantee ciphertext/hash authenticity.
Migration `00012` (P1.10) adds triggers that make the agent-credential lifecycle
one-way in SQLite: a revoked credential is final, the verifier/owner/issue
time/expiry/display identifier are immutable once out of quarantine, a rotation
overlap can only shorten (agent state is not trigger-coupled; the verifier refuses
credentials behind non-active agents). See the
[agent-credential contract](agent-credentials.md).

The retry ceiling is 1–100 **per authenticator**, with bounded counter and
next-attempt state; exhausted records cannot be active. SQL fixtures prove
atomic capped increments under concurrency and file reopen, without affecting
another authenticator. Evaluation, disable/rebind and appropriate-AAL reset,
pre-verification throttling and lockout-DoS resistance remain P1.05/06/08.
The TOTP step cannot regress/reset; atomic same-step acceptance remains P1.06.
8–14 code-point password metadata requires compulsory MFA; optional/password-only
requires at least 15, maximum 128. Triggers reject short-password insertion/update
and removal of the compulsory requirement without replacement. Unicode counting,
normalization, blocklist and all route/restore transitions remain P1.05–08/18.

Sessions store only a hash plus purpose, achieved assurance, factor-method mask,
auth/reauth times, expiry/idle/activity and credential/session generations.
Masks: password=1, single-factor TOTP=2, single-factor WebAuthn=4,
UV multi-factor WebAuthn=8, recovery=16. Only normal sessions can carry human
assurance: AAL1 requires password; AAL2 structurally permits 3 (password+TOTP),
5 (password+SF WebAuthn), or 8 (verified multi-factor WebAuthn). Only 8 can be
marked phishing-resistant. Setup/preauth/recovery have assurance zero. These
values record **server-verified evidence later**, never client assertions.
Account-bound session/authenticator/challenge FKs reject cross-user associations;
challenges are hashed, expiring and consumed state cannot be reset. Checking
actual factors, expiry, assurance policy and active generation is P1.06–08.

## Notification, retention and usage

Accounts support multiple versioned addresses, inactive until verified/reapproved.
Confirmation hashes have a separate account/address/version/purpose/expiry and
irreversible consumption; they are not recovery credentials. Security events are
minimal typed lifecycle records with deduplication and explicit retention deadlines,
not the Phase 3 audit log. Per-recipient outbox rows snapshot immutable destinations,
have separate dispatch quarantine, retry times/counts and restricted failure codes.
`pending`, `relay-accepted`, `failed`, `bounced` distinguish relay status, **not**
inbox/human receipt. Addresses/recipient headers reject CR/LF; full email/relay
validation is still required in the delivery service. No SMTP secrets stored here.

Tests commit synthetic lifecycle state/event/intent in one transaction and roll
back **all** state on invalid recipient/FK. A raw SQL caller can omit the event:
P1.06–09 must own the service-level transaction and fail closed if enqueue fails.
Protective revocation must not wait for SMTP/outbox availability. No dispatcher
exists here; imported addresses and old pending work must be quarantined and
explicitly classified, not blindly replayed. Last-address protection, fresh
maximum-AAL changes, old/new alerts, retries/capacity/TLS/redaction and delivery
failure visibility remain P1.06–09/16/19–20.

No unbounded optional authentication history/IP/device data is collected.
Events/outbox require retention deadlines without inheriting usage90/audit365-day
periods. Exact deployment retention/privacy/contact/redress decisions and deletion
services remain D-09/P1.19–20 release gates, not defaults invented by this schema.
Usage hourly/daily and recent events persist endpoint/selector, user/agent and
separate allowed/denied/error counts. Nullable human/group-owned attribution is
unique using expression indexes. P1.15 owns atomic accounting, retention/bounds
and exact operation fixtures. Usage survives ordinary reopen but is **excluded**
from the approved logical backup scope (S2.5/RESTORE-10).

## Requirement-to-executable-test map

Run `go test -race -count=1 ./...` (all extant regressions, not a path subset).
These are **structural portions** of named contracts; no row declares the full
NIST/RESTORE/SETUP/SELF/SUP product specification passed.

| Contract/requirement | Actual tests | Later enforcement/evidence |
| --- | --- | --- |
| UUID/local identity, TD3.4 | `TestEndpointID`, `TestFreshDownUpMigration`, `TestEndpointConstraints` | P1.03 persistent initialization; P1.12 endpoint/daemon proof |
| Goose fresh/down/up, populated FK teardown | `TestFreshDownUpMigration`, `TestPopulatedMigrationReopenAndDown` | P1.03 upgrade/durability; no production rollback promise |
| TD3.1 owner XOR/FKs/independent membership | `TestPrincipalOwnershipAndRoles`, `TestGeneratedModelsAndBoundParameters` | P1.10 service administration/no inheritance (delivered: [agent-credentials.md](agent-credentials.md)); P1.11 enforcement |
| P1.10 credential lifecycle integrity (revoked final, immutable verifier/window, shrink-only overlap) | `TestRevokedAgentCredentialIsFinal`, `TestAgentCredentialVerifierAndWindowAreImmutable`, `TestRotationOverlapCanOnlyShrink` | P1.18 restore import must keep imported credentials quarantined |
| TD11.1 nullable global/scoped roles, single admin/inactive future scope | `TestAdministrativeRoleModelNullableScope`, `TestPrincipalOwnershipAndRoles`, `TestEndpointConstraints` | P1.08/09 admin assurance; future phases remain unavailable |
| TD7 endpoint-separated selectors, policy effect/subject/catalog | `TestEndpointScopedSelectorsAndPolicies`, `TestGeneratedModelsAndBoundParameters` | P1.11 deny precedence/selector lifecycle; P1.13/14 zero-call denial |
| S2/RESTORE-01–09/11 and N63B4-RESTORE-AUTH-STATE structural substrate | `TestControlGenerationAndRevocationStructure`, `TestFreshDownUpMigration`, `TestAuthenticatorAndSessionStructure`, `TestRetryAndReplayStateSurviveReopen` | P1.03/08/10/11/18 current control/quarantine/reissue/reapproval/expiry/crash/restore service matrix |
| N2 / N63B4-PWD-MFA-ONLY | `TestAuthenticatorAndSessionStructure` | P1.05–08/16 password validation and every weaker-route transition |
| G02 / N63B4-RATE-CEILING, RATE-RESET-AAL, O03 OTP-REPLAY/WINDOW | `TestAuthenticatorAndSessionStructure`, `TestRetryAndReplayStateSurviveReopen` | P1.05/06/08/18 proof, clock, reset/rebind/DoS/restore matrix |
| E01 BINDING-RECORDS, W01 WA-CHALLENGE | `TestCredentialNullMaterialAndAccountBinding`, `TestAuthenticatorAndSessionStructure` | P1.03 encryption; P1.06/07/08 real ceremony/capability/one-use verification |
| D-01/A1 session-assurance separation; SETUP-06/09 substrate | `TestAuthenticatorAndSessionStructure`, `TestCredentialNullMaterialAndAccountBinding` | P1.08/09 proof-bound restricted capabilities; P1.14 adapter denials |
| N1/E15 NOTIFY-DELIVERY durable intent | `TestNoticeIntentTransactionRollback`, `TestNoticeFanoutAndSnapshot`, `TestPopulatedMigrationReopenAndDown` | P1.06–09/19–20 real delivery/TLS/failure/protective-revoke matrix |
| N1/E16 NOTIFY-ADDRESSES | `TestNoticeFanoutAndSnapshot` | P1.06–09/16 max-AAL address lifecycle/last-address/old-new alerts |
| A08 GOV-RETENTION / D-09 | `TestNoticeFanoutAndSnapshot`, explicit schema retention/state fields | P1.04/18–20 policy/deletion/disclosure/risk evidence, not satisfied by DDL |
| TD9.1 usage persistence/RESTORE-10 substrate | `TestUsageStorage`, `TestPopulatedMigrationReopenAndDown` | P1.15 integrated counts/retention; usage not in backup |
| SQL generation, NULL scope, binding/injection, transaction rollback | `TestGeneratedModelsAndBoundParameters`, `TestAdministrativeRoleModelNullableScope`, `scripts/generated-output.test.mjs`, `make generate-check` | Generator dependency/advisory gates in Security CI |
| SELF/SETUP runtime boundaries; all existing static-route regressions | `tests/security` and existing `negative-control` | No Docker identity/helper yet: SELF-01–13, SETUP-01–12 service/isolated checks remain owning tasks |
| D1/SUP-01/06 continuous checks | Both Go Baseline checks + Security; [sqlc remediation](sqlc-dependencies.md) | Other CPUs/OS/browser/image/device/FULL-sync qualification remains unverified |

No runtime, FIPS/NIST conformance, real Docker, real mail, deployment, supported
architecture or final release claim follows from these schema tests.
