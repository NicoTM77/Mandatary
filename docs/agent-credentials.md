# P1.10 agent credentials and identity/group administration

## Delivered scope and boundaries

`internal/auth` now contains the administrative **service** (`Admin`) and its
**route adapter** (`AdminHTTP`) for the single Phase 1 policy administrator
(TD §§3.1–3.2, R Phase 1 users/groups/agents):

- create inert human accounts, groups and agents; explicit group membership;
- agent bearer tokens: 256-bit `mdt_` tokens, shown once, hash-only persistence,
  expiry, overlap rotation, immediate revocation, agent disabling;
- additive migration `00012` making the credential lifecycle one-way inside SQLite.

**Not delivered here (owned elsewhere, no stub):**

| Not in P1.10 | Owner |
| --- | --- |
| Mounting any route in the static server (it still has no login, session, administration or API route) | P1.16 composes login/step-up adapters and the UI; P1.14 the API/MCP surface |
| REST/MCP Bearer adapters. The shared acceptance path they must call (`authz.Authorizer`) exists and is exercised end-to-end here | P1.14 |
| Policy rule CRUD, user/group *disabling*, deletion, ownership transfer | P1.17 |
| Account credential enrolment for administratively created users (they cannot sign in until enrolled) | P1.16 |
| Restore import/reactivation/reissue approval of quarantined credentials and memberships | P1.18 |
| Multiple or endpoint-scoped administrators, own-session visibility, policy audit | Phase 3 |
| Durable administrative audit trail (Phase 1 has structured logging and usage counts only) | Phase 3 |

No administrative role can be created, granted or moved by anything in this task: the
schema keeps exactly one active `super_admin` and no endpoint administrator can be
active, and **no route or service method names a role** (`TestMultiplePolicyAdministratorsStayUnavailable`,
`TestAdministrativeRouteInventoryIsExactAndExplicit`).

## Authority model

Every `Admin` method takes only the opaque session secret and decides from persisted
state inside one `Repository.Control` transaction (shared lock, FULL durability):

1. restore quarantine absent and all four control generations positive;
2. a live **normal** session (never preauth/setup/recovery) of an active, non-compromised
   account at the current credential/authority generations, backed by live factor bindings;
3. the account's required-assurance floor met — administrators always require AAL2;
4. **mutations**: authentication no older than 15 minutes, inclusive (`freshSession`, the
   same gate as the authenticator lifecycle). **Reads** apply every check except the age
   limit (`sessionWithin(..., -1)`), so listing never forces a step-up while mutation always does;
5. the account holds the **active `super_admin` role at the current authority generation**.
   The role is the only authority required and grants **no container operation** (TD §2.1).

Nothing a caller states about itself is an input. Agent tokens are never sessions: the
route layer reads only the `__Host-` session cookie, and the service has no bearer input
(N63B4-SCOPE-MACHINE, S08). Every authentication/authorization failure is the opaque
`ErrDenied`; the three request errors (`ErrAdminInvalid`, `ErrAdminNotFound`,
`ErrAdminConflict`) reach only the already proven fresh administrator.

## Identity, ownership and membership

- **Agent ownership is exactly one active user XOR one active group.** Both, neither,
  unknown, quarantined, disabled, compromised or stale-generation owners are refused by
  the service; SQLite independently enforces the XOR (`CHECK`, `ON DELETE RESTRICT`).
- **Ownership is accountability only.** It creates no membership and no permission: a
  user-owned or group-owned agent receives a permission only when a policy names the
  agent or a group it is an *explicit active member* of (`TestOwningAnAgentGrantsNothingEndToEnd`
  runs the real authorizer: owner and owning-group `ALLOW`s do not reach the agent,
  membership grants and removal revokes, an administrator's own agent gains nothing).
- Created users are active records with the compulsory-MFA default and **no authenticator,
  role, membership or policy**. Created groups are empty. Names are ASCII identifiers (the
  setup username rule: letters/digits first, then `. _ - @ +`, at most 64) so UI text, log
  lines and URLs cannot hide control or look-alike characters.
- `AddMember` is idempotent and creates/re-enables a membership at the current authority
  generation. A **quarantined or stale-generation** membership is a conflict, never silently
  re-approved (explicit per-membership reapproval belongs to restore, S2.4/P1.18). Removal is
  soft, idempotent and notifies even when nothing changed, so a failed notification can be retried.

## Token format, issuance and storage

`mdt_` + the base62 rendering of **256 uniformly drawn bits**, left-padded to a fixed 43
digits (62⁴³ > 2²⁵⁶, so no bit is discarded): 47 characters. `crypto/rand` is the only
source; a short read, an error or an all-zero draw issues nothing and there is no fallback
(`TestAgentTokenRandomnessFailureNeverIssues`, `TestRandomnessFailureIssuesNoCredential`).
**RANDOM-EVIDENCE (G16) inventory for this card.** Token bits, credential identifiers (UUIDv4 via
`domain.NewUUID`) and the display identifier all come from `crypto/rand.Reader`. Per the Go 1.27.4
source/documentation inspected for this card (`crypto/rand/rand.go`), that reader is `getrandom(2)` on
Linux and passes through an SP 800-90A Rev. 1 DRBG only in Go's FIPS 140-3 mode, which Mandatary does
not enable; the Go 1.26.11 compatibility line was not separately inspected. This is implementation
evidence, **not** a claim of a NIST-approved RBG construction with a stated security strength, FIPS
validation or an assessed deployment kernel; any such claim remains a P1.19/P1.20 evidence item.
Output length is exactly 256 bits; the base62 encoding is an exact integer rendering (no modulo
bias, no discarded or padded entropy); the all-zero draw is refused.

- **Hash-only persistence.** SQLite stores only SHA-256(token), a unique 32-byte value. The
  whole database, WAL and shm contain neither the token, its body, its hex/base64 forms nor
  its raw 256 bits (`TestIssuedTokenIsShownOnceAndOnlyItsHashIsPersisted`). A stored hash is
  not a bearer token in any encoding.
- **Display identifier.** `mdt_` + the first eight characters of the credential's own random
  UUID: independent of the secret, so it identifies a row without leaking entropy.
- **Shown once.** The plaintext exists only in the `IssuedCredential` returned **after** the
  creating transaction committed and synchronised. Every formatting, JSON, text and `slog`
  path is redacted; `ExportOnce` surrenders it once. A failure of storage, durability or the
  authorizer notification never returns a token (a rotation whose notification failed is durable
  but its token is withheld; rotate again). Listing endpoints return metadata only.
- Plaintext bytes handed to the route are cleared after the response is written (best effort:
  Go strings and the HTTP stack may hold copies; this is not a memory-forensics guarantee).

## Lifecycle semantics (exact boundaries)

All times are Unix seconds from the lifecycle clock; the authorizer's verifier applies them.

| Rule | Behaviour |
| --- | --- |
| Expiry | TTL defaults to 90 days (TD §3.2), is bounded by `MaxTTL` (default 90 days, never above 10 years) and must be whole seconds ≥ 1. A token is accepted for `[issued, expires)`; **rejected at `expires`**. |
| Non-expiring | Only when the deployment enables `AllowNonExpiring` **and** the request says `non_expiring` with no TTL. Off by default. They still die on revocation, rotation expiry and any generation change (RESTORE-01). |
| Live credentials | At most two per agent: current plus the one in overlap. `IssueCredential` refuses (conflict) while one is live; use rotation. |
| Overlap rotation | `RotateCredential` issues the new token and starts the old one's window `[now, now+overlap)`; **rejected at `now+overlap`**. Overlap defaults to 1 hour, ≤ `MaxOverlap` (24 h, never above `MaxTTL`), whole seconds. `Immediate` (or HTTP `overlap_seconds: 0`) revokes the old token at once. |
| Rotating again | A credential still in overlap is revoked immediately, so the bound of two holds and the oldest token is never extended. |
| Revocation | Immediate and permanent, idempotent, resolved only under its own agent. |
| Disable agent | Revokes every credential, then disables (the schema forbids an active credential behind a non-active agent). |
| Generations | A credential carries the control credential generation current at issue. Any later generation change, restore quarantine, agent/authority-generation mismatch or disabled agent makes the verifier reject it. The service never issues for an agent outside the current generations (conflict). |

`credentialStatus` labels rows with the *same* conditions the verifier applies, and
`TestCredentialStatusMatchesTheSharedVerifierOverTheStateMatrix` drives both over every state
and boundary second so the live-credential bound cannot drift from acceptance.

After every commit that can reduce authority (revoke, rotate, disable, membership change) the
service calls the injected notifier — the shared `authz.Authorizer.NotifyPolicyChange` — *after*
the change is durable and *before* returning, so active leases/streams of the old token are
cancelled before the caller sees success (`TestAdministrativeRevocationTerminatesActiveLeasesBeforeReturning`).
A notifier failure is reported as `ErrAdminUnavailable` and never undoes the durable change.

## Adapter applicability

Acceptance of a bearer token is implemented once, in `authz.NewStoreCredentialVerifier`, and
reached through `Authorizer.Authorize`, `AcquireLease` and `Lease.Revalidate`. The REST and
MCP adapters (P1.14) must call it and add no weaker check. P1.10 proves, over the real SQLite
state and the real service, that **old-generation, expired, revoked, rotated-out, disabled-agent
and quarantined states are refused on `Authorize` and terminate leases on revalidation**
(`TestRetiredTokensAreRejectedByTheSharedAuthorizerAndLeases`, `TestRotationOverlapKeepsTheOldTokensLeaseUntilTheBoundary`).
No REST or MCP route exists yet, so there is **no HTTP/MCP evidence for bearer acceptance**; that
matrix (including a real MCP client) remains a P1.14 acceptance item and is not claimed here.
`ValidAgentTokenFormat` lets those adapters reject malformed values before any lookup; it proves nothing about validity.

## HTTP routes (`AdminHTTP.Register(*auth.Browser)`)

| Route | Policy | Result |
| --- | --- | --- |
| `GET /api/v1/admin/{users,groups,agents}` | session | metadata only; no token or hash |
| `POST …/users`, `…/groups`, `…/agents` | session + `security-policy-change` (AAL2 ≤ 15 min) | `201` view |
| `PUT/DELETE …/groups/{group}/members/{user\|agent}/{id}` | `security-policy-change` | `204` |
| `POST …/agents/{agent}/disable` | `agent-credential-change` | `204` |
| `POST …/agents/{agent}/credentials` | `agent-credential-change` | `201` `{credential, token}` reveal-once |
| `POST …/agents/{agent}/credentials/rotate` | `agent-credential-change` | `201` `{credential, token, rotated_out}` |
| `POST …/agents/{agent}/credentials/{credential}/revoke` | `agent-credential-change` | `204` |

The Browser boundary supplies cookie, exact Origin, per-session CSRF, JSON-only bodies, the 64 KiB
body bound, the step-up gate and security headers (`Cache-Control: no-store`, CSP, …). Bodies are
single JSON objects with **unknown fields refused** (no mass assignment of state, role, generation,
verifier or token), `null`/arrays/trailing data refused, numeric fields strictly typed
(`ttl_seconds` ≥ 1; `overlap_seconds` absent = default, `0` = immediate). Errors are fixed codes
(`invalid_request`, `not_found`, `conflict`, `forbidden`, `unavailable`) that never echo input.

## Schema integrity (migration `00012`)

Additive triggers; no column, row or constraint changes. Whatever writes (service, restore import,
repair tooling) the database itself enforces: a **revoked credential is final** (no field changes);
verifier, owning agent, issue time, expiry, non-expiry approval and display identifier are
**immutable** once a credential has left quarantine; a **rotation overlap can only be shortened**,
never extended or cleared. Agent state is **not** coupled by trigger: the shared verifier refuses any
credential behind a non-active agent (its own defence-in-depth tests build that state), and the service
revokes every credential before disabling. Imported/quarantined rows stay inactive.

## Requirement-to-executable-test map

All names are real declarations; `TestAgentCredentialCrosswalkNamesResolve` fails if one is missing or
a P1.10 test is not cited here. They are component tests over a real SQLite repository, real
password/TOTP/session services and the real authorizer with the container-free mock backend. They
are not browser, MCP-client, hardware or provider evidence, and not a NIST/FIPS claim.

| Acceptance / contract | Tests |
| --- | --- |
| Exactly one owning user XOR group; invalid ownership | `TestAgentOwnershipIsExactlyOneUserXORGroup`, `TestAdministrativeIdentityCreationIsInertUntilExplicitlyGranted` |
| No inherited owner grant | `TestOwningAnAgentGrantsNothingEndToEnd`, `TestGroupMembershipIsExplicitIdempotentAndNotified` |
| 256-bit token, shown once, hash-only, redaction | `TestAgentTokenCarries256RandomBitsInCanonicalBase62`, `TestValidAgentTokenFormat`, `TestIssuedCredentialRedactsEveryFormattingPath`, `TestIssuedTokenIsShownOnceAndOnlyItsHashIsPersisted`, `TestAdministrativeViewsAreSecretFreeAndComplete`, `TestAdministrationOverHTTPEndToEndRevealsTheTokenOnce`, `TestIssuedTokenNeverReachesLogsOrErrorBodies`, `TestAdministrativeErrorsAreFixedCodesThatNeverEchoInput` |
| RANDOM-EVIDENCE fail-closed | `TestAgentTokenRandomnessFailureNeverIssues`, `TestRandomnessFailureIssuesNoCredential`, `TestNewUUIDIsCanonicalV4AndFailsClosedOnShortOrBrokenSource` |
| Expiry and TTL policy | `TestCredentialExpiryBoundaryIsExact`, `TestTokenLifetimePolicy`, `TestAdminConstructionRejectsUnsafeSettings` |
| Deterministic overlap-window boundaries, rotation | `TestOverlapWindowBoundaryIsDeterministic`, `TestRotationWithoutOverlapAndDefaultOverlap`, `TestRotatingAgainRevokesTheCredentialStillOverlapping`, `TestRotateAndIssueRulesForLiveCredentials`, `TestRotationOverlapFieldSemanticsOverHTTP`, `TestRotationOverlapKeepsTheOldTokensLeaseUntilTheBoundary` |
| Revocation, disabling, no revival | `TestRevocationIsImmediateIdempotentAndAgentScoped`, `TestRevokedAndRotatedOutCredentialsCannotBeRevived`, `TestDisablingAnAgentRevokesEveryCredentialAndBlocksReissue`, `TestRevokedAgentCredentialIsFinal`, `TestAgentCredentialVerifierAndWindowAreImmutable`, `TestRotationOverlapCanOnlyShrink`, `TestAgentCredentialHashIsUniqueAndFixedLength` |
| Old generation / quarantine (RESTORE-01/-11 substrate) | `TestOldGenerationAndQuarantineRejectEveryCredentialAndAdministration`, `TestRestoreQuarantineDeniesAdministrationAndAcceptance`, `TestIssueRefusesAnAgentOutsideTheCurrentGenerations`, `TestNonExpiringTokensDieWithTheCredentialGenerationAndRevocation` |
| Old/expired/revoked/rotated-out token rejected on the shared acceptance path | `TestRetiredTokensAreRejectedByTheSharedAuthorizerAndLeases`, `TestAdministrativeRevocationTerminatesActiveLeasesBeforeReturning`, `TestCredentialStatusMatchesTheSharedVerifierOverTheStateMatrix`, `TestNotificationFailureDoesNotUndoARevocationButIsReported` |
| Privilege escalation; single administrator | `TestOnlyTheSingleActiveAdministratorMayAdminister`, `TestPasswordPreauthCapabilityCannotAdminister`, `TestMutationsNeedFreshAAL2EvidenceButReadsDoNot`, `TestMultiplePolicyAdministratorsStayUnavailable`, `TestOrdinaryUsersAndOwnersCannotAdministerOverHTTP`, `TestAgentTokensNeverAuthenticateAdministration`, `TestAgentCredentialRoutesNeverAcceptAgentTokens`, `TestAgentTokensNeverAuthenticateTheSetupSurface` |
| Browser boundary, step-up, strict bodies, route inventory | `TestAdministrativeRouteInventoryIsExactAndExplicit`, `TestAdministrativeRoutesNeedTheBrowserBoundary`, `TestAdministrativeMutationsOverHTTPRequireFreshAAL2`, `TestAdministrativeBodiesAreStrictAndMassAssignmentIsRejected`, `TestWrongCSRFFixtureAlwaysDiffersFromTheOriginal` (P1.14 O1: the wrong-CSRF fixture is deterministic) |
| Concurrency, durability | `TestConcurrentFirstIssueYieldsExactlyOneLiveCredential`, `TestConcurrentRotationsNeverExceedTwoLiveCredentials`, `TestStorageFailureNeverReturnsATokenOrChangesState` |

Mutation controls (each deliberately breaks one rule and the suite must fail) are recorded with the review
evidence, not shipped as tests.

## Known limits and residual risks

- `authz.PrincipalCredentials.AgentTokenHash` lets an in-process caller present a stored hash instead of a
  token. Adapters (P1.14) must populate only `AgentToken` from untrusted input; P1.10 does not change P1.11 code.
- Disabling or restoring a *user or group* does not cascade to agents they own (no such operation is delivered;
  an owner's state is checked when an agent is created and when members are added). An orphaned agent
  is stopped with `DisableAgent`; automatic owner-linked suspension would be a P1.17 policy decision.
- Group membership removal also removes that group's `DENY` rules for the member, exactly as P1.11 defines
  membership; administrators must remove members knowingly.
- A restored installation keeps old rows inactive; reissue/reapproval flows are P1.18. Nothing here can
  activate an imported credential or membership.
- Rate limiting of administrative calls is the Browser/session layer's; no per-credential usage accounting
  exists until P1.15.
