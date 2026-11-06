# P1.06 authenticator lifecycle

## Scope and assurance boundary

Internal `auth.Lifecycle` methods implement TOTP binding/proof/removal, saved-code
issuance/recovery/rebinding and the N1 SMTP outbox worker. **No authentication,
mail, policy, administration or Docker route is mounted by the static server.**
P1.07 owns WebAuthn, P1.08 normal-session creation/transport/step-up integration,
P1.09 host bootstrap/emergency recovery, P1.16 browser/address management and
P1.18 restore import. Component results are not NIST/FIPS certification, a
supported-device/runtime claim, inbox-delivery proof or product AAL2 conformance.

These methods are trusted service APIs, not unauthenticated HTTP handlers.
Future adapters must enforce protected transport, request/secret redaction,
CSRF/origin protections, bounded strict input and validated peer IPs. They must
never accept client-supplied session assurance, methods or auth time. The normal
session input here is an opaque secret checked against persisted records and
live factor bindings. FactorProof is an observation, not a session/capability;
P1.08 must bind it to the same fresh authentication ceremony and recheck all
credential/control generations. No ordinary session-creation method exists here.

## Algorithms and storage

* Approved `pquerna/otp v1.5.0` is pinned with checksums. The reviewed
  `hotp.GenerateCodeCustom` primitive uses a big-endian integer counter,
  HMAC/dynamic truncation and constant six digits. We supply our own canonical
  base32 seed; library verifier trimming and floating-point time conversion are
  not authority. No HOTP/proprietary OTP feature is exposed. SHA1 and SHA256 are
  the only allowed TOTP algorithms, 30-second steps and current step ±1. SHA1 is
  HMAC for this approved protocol, not a password hash or collision-resistance
  claim. New seeds contain 32 OS-CSPRNG bytes. Negative/out-of-range civil UTC
  fails closed. Device clock drift outside this window requires correction,
  never an expanded window or replay reset. OTP is **not phishing resistant**.
* Pending seeds are session-bound, expire at min(session expiry, ten minutes),
  and cannot verify before control proof. Installation/purpose/record-bound
  repository AEAD protects seeds. Revocation clears the live encrypted seed;
  this is logical deletion, not forensic erasure of WAL/backups/cloud copies.
* Existing AAL2-capable accounts require fresh maximum-account-strength normal
  session evidence for addition/removal/list issuance. AAL1→MFA first binding is
  distinct. The 15-minute freshness boundary is inclusive; greater age denies.
  Evidence must refer to current live authenticators. Password-only, preauth,
  setup/recovery-only and agent credentials cannot masquerade as that evidence.
  Removing the final required factor denies without relaxing MFA/password rules.
* Repository.Control serializes accepted counter, verifier period, output hash
  and retry updates across processes using the shared lock/FULL writer. A given
  factor admits at most one OTP per verifier period and increasing accepted
  counters only. Retained output hashes also prevent adjacent equal-output
  collision replay; the last accepted output remains conservatively blocked
  until a different OTP succeeds/prunes old history. Restart/clock rollback
  never resets replay. Successful possession proof alone does not reset retries;
  completed appropriate-strength authentication/reset integration belongs P1.08.
* At most100 evaluated failures disable the specific TOTP (pending or active),
  with five-failure escalating non-sliding backoff reused from the password
  contract. Rejected pre-evaluation/oversized traffic does not consume a proof
  attempt or extend a deadline. Independent password/recovery methods remain
  usable. IP admission is the existing bounded ephemeral /64-aware gate; the
  durable authenticator ceiling, not an IP map, survives restart/handle churn.
* Ten recovery-only codes are issued after fresh completed MFA, including the
  first online list. Each has128 random secret bits plus a random record ID;
  exact full encoding is SHA256-hashed. This selects the ≥112-bit storage branch,
  never fast-hashing a short human password. Codes are not normal MFA substitutes.
  Results redact ordinary formatting and explicit ExportOnce clears the holder;
  callers must protect all exported bytes and cannot request stored-secret
  redisplay. Keep codes offline, separately from the authenticator/device.
* Code+still-bound password enters normal restricted recovery for all maximum-
  AAL2 accounts, including optional-MFA accounts. Code alone/two same-method
  codes/new password/notification receipt are insufficient. Consumption,
  one-code replacement, session/capability invalidation and notice commit are
  atomic. This is E08 single-code replacement, not general list regeneration;
  explicit list regeneration revokes previous batches/capabilities. A durable
  shared batch budget prevents alternating codes/IDs to evade100 failures.
* The resulting ten-minute capability can prove one replacement TOTP, never
  create normal/AAL2 authority. Rebinding revokes prior TOTP bindings and records
  replacement/recovery-completion notices. WebAuthn-only accounts cannot use
  this TOTP continuation. Fresh policy-satisfying normal authentication remains
  required afterward. Lost response does not undo consumption or allow
  redisplay: use an independently held code/factor, or later P1.09 trusted-host
  recovery when all factors are lost. There is no email-only recovery or KBA.

## N1 delivery, capacity and operational repair

Trusted NoticeSettings require secret-free configured HTTPS service origin,
explicit sender/contact, host:numeric-port relay and either implicit TLS or
mandatory STARTTLS. Certificate chain/hostname verification and TLS≥1.2 precede
SMTP authentication/DATA. No plaintext/verification-disable option exists. SMTP
passwords are read only from the encrypted repository SMTP slot. No live sender
is configured by the application; tests use an actual loopback receiver only.

Ordinary binding/list changes/recovery commit event and immutable per-recipient
address/version snapshots under the FULL writer before acknowledgement. At
least one current confirmed destination is required; ≥2 are supported/fanned
out. Confirmation/address-update/old-new alerts are P1.16's separate narrow
ceremonies, not email authentication. No recipient is resolved again on retry.
Messages contain event type/UTC/account reference, configured service origin and
repudiation contact, never codes/seeds/passwords/approval tokens/Docker content.
Contact receipt cannot cancel safeguards, grant access or prove authentication.

Protective removal/compromise reporting invalidates the named factor and normal
sessions without waiting for SMTP. A separate local protective intent retains
recipient snapshots even if ordinary event/outbox insertion fails. Expansion
can retry after storage repair/reopen, with stable event identity and no
credential reactivation. If even this marker cannot be stored, commit the actual
revocation where possible, deny acknowledgement/poison acceptance and retain a
minimal unmatched event where storage permits. Its degraded status survives
restart. Such an unmatched incident requires operator investigation/manual
independent notification; do not invent historical recipients or mark it sent.
If revocation itself cannot commit, deny through the uncertain handle until
repair. Durable-before-ack relies on real filesystem/hardware honoring sync;
no guarantee against malicious host rollback or arbitrary broken hardware.

Worker policy is fixed and bounded:

| Control | Value/meaning |
| --- | --- |
| Ordinary ready/pending queue |1024 recipient records; ordinary authority-increasing transaction rolls back when full |
| Protective backlog | retained separately, expanded in batches≤32 when queue permits; never dropped to make room |
| Invocation |1–32 records; four shared durable concurrent leases |
| Lease/network |30 seconds / ten-second transaction, five-second dial; no SMTP I/O under the control lock |
| Automatic attempts/age |8 /72 hours from event (or explicit repair cycle) |
| Delay after failed attempts1–7 |60,120,240,480,960,1920,3600 seconds; fixed durable deadline |
| Exhaustion/permanent recipient rejection | visible failed record retained, not deleted or called delivered |
| Explicit repair |RetryNotice after fresh maximum-account-strength session, own-account/current generation, no active lease, within original retention marker;≤3 additional eight-attempt cycles |
| History | stable event/Message-ID and lifetime total_attempts retained across cycles |
| Retention | provisional bounded30-day component marker; no automatic deletion of pending/failed incidents; deployment privacy/deletion qualification remains P1.19/20 |

NoticeHealth exposes only aggregate pending/failed/bounced/quarantined/protective
counts and fail-closed degraded state. P1.16/19 must wire authenticated operator
visibility/readiness; it is not a public health route here. Pending means not yet
relay-accepted, not necessarily an outage. On failure, inspect aggregate status
and trusted relay/TLS/credential/address configuration without logging secrets;
correct configuration using protected deployment/secret management, then invoke
explicit RetryNotice under qualifying fresh evidence. Do not edit snapshots,
clear counters, relax TLS/MFA, resurrect revoked credentials or blindly replay
old-generation work. Marker/outbox storage failure requires storage repair and
reopen before expansion; unmatched minimal incidents need investigation rather
than automatic retargeting. Permanent invalid addresses need the separately
assurance-gated address workflow, not changing an existing incident recipient.

`pending`, `relay-accepted`, `failed` and schema-supported `bounced` are distinct;
there is no bounce ingestion endpoint or guaranteed human-receipt detector.
SMTP250 is only relay acceptance. Ambiguous DATA/send/ack crashes may duplicate
messages with stable identity (at least once), never exactly-once delivery.
Restore/quarantine/generation checks stop new claims and stale acknowledgements.
A message already handed to a relay cannot be recalled when quarantine begins;
P1.18 must quiesce workers, quarantine/exclude all local intents/old outbox work,
classify historical incidents and explicitly reapprove addresses before resume.

## Executable acceptance crosswalk

These are component tests, not replacements for the original multi-row NIST
specifications or later integration/device/governance/release gates.

| Applicable contract | Executable evidence |
| --- | --- |
| OTP-PARAMETERS/WINDOW/REPLAY, O01–04 |TestTOTPParametersAndWindow, TestTOTPConcurrentReplayAndPeriodLimit, TestTOTPCollisionCannotExtendOutputReplay, TestTOTPSeparateProcessesAcceptOnce, TestTOTPReplaySurvivesRepositoryRestart |
| OTP-SEED, BINDING-FIRST/ADDITIONAL/RECORDS |TestTOTPBindingRequiresProof, TestTOTPLifecycleSessionDenials, TestTOTPPendingExpiryOwnerAndTamper; retained repository wrong-key/tamper/envelope/redaction tests |
| REAUTH-STRENGTH, AUTHENTICATOR-INVALIDATION, PWD-MFA-ONLY |TestTOTPRevocationRequiresFreshAssurance, TestRequiredLastFactorCannotBeRemoved, TestRecoveredCapabilityDenialsAndNoNormalAuthority; existing schema/password regressions |
| LOOKUP-ISSUE/STORAGE/ASSURANCE, RECOVERY-CODE-LIFECYCLE/AAL2/NO-SESSION |TestRecoveryCodesAtomicAndRestricted, TestRecoveryCodeEntropyHashAndRestart, TestRecoverySeparateProcessesConsumeOnce, TestRecoveryReenrollmentNeverCreatesSession, TestRecoveryCrashBeforeResponseCannotRedisplayOrReuse, TestLifecycleSecretValuesRedactedAndRevealOnce |
| RATE-CEILING, N2, RANDOM-EVIDENCE |TestTOTPExhaustionDoesNotDisableRecovery, TestFailedTOTPRetryWriteStopsFurtherAcceptance, TestFailedRecoveryBudgetWriteStopsFurtherAcceptance, TestAuthenticatorEntropyFailure, TestOversizedTOTPProofRejectedBeforeEvaluation, TestOversizedRecoveryRejectedBeforeEvaluation |
| COMPROMISE-REPORT, NOTIFY-DELIVERY protective failures |TestPasswordOnlyCompromiseReportCannotReplaceFactor, TestProtectiveRevocationSurvivesOutboxFailure, TestProtectiveIntentSurvivesRepairAndRestart, TestProtectiveMarkerFailureCannotUndoRevocation, TestProtectiveFallbackIncidentRemainsVisibleAfterRestart |
| NOTIFY-DELIVERY, TLS-BOUNDARY, N1 |TestLifecycleEventsReachIndependentTLSReceiver, TestSecurityNoticesTLSAndFanout, TestNoticesCertificateAndAuthenticationFailures, TestNoticesMissingTLSNeverSubmitOrAuthenticate, TestNoticesPartialFailureKeepsRecipientSnapshots, TestNoticeConfigurationFailsBeforeActivation |
| NOTIFY-DELIVERY retry/capacity/repair/crash |TestNoticeRetryExhaustionIsDurableAndVisible, TestNoticeBackoffBounds, TestNoticeCapacityRollsBackOrdinaryActivation, TestNoticeSharedLeaseCeilingDoesNotBlockRevocation, TestNoticeMaximumAgeAndRepairCycleBounds, TestNoticeExplicitRepairRequiresFreshAuthority, TestNoticesAmbiguousACKRetriesStableIdentity, TestNoticeCancellationAtTLSHandshakeBoundary |
| R1/RESTORE-AUTH-STATE current-component boundary |TestLifecycleSQLiteSyncFailureNeverAcknowledges (actual WAL xSync failure on9 transitions), TestNoticeRestoreRaceDoesNotAcknowledgeStaleGeneration, pending/recovery denial matrices; retained FULL/persistence-loss/repository regressions |

The full NOTIFY-ADDRESSES confirmation/change/removal browser workflow, all
privileged API/MCP/session integration, setup/host controls, actual restore,
WebAuthn/device/sync-fabric/RBG/federal evidence, branded-browser/OS/CPU product
qualification, image scanning and TD footprint budgets remain with their owning
rows. SELF tests here are existing static-exposure regressions: there is no Docker
adapter or native real-socket exception. Do not label those future targets green.

## Verification and remaining review

Exact commands, SHAs, RED/GREEN evidence, local limitations and hosted results
are recorded in the original P1.06 card/PR10 handoff. Source/graph, generated
queries, real local tests, actual loopback TLS transport and actual SQLite sync
faults are exercised. Both locked Go compiler race baselines, Node24.22.1/npm11.19.1
checks, all extant auth/storage/redaction/static-security regressions and hosted
Security must pass on the handoff head. Independent native reviewer approval is
required; coder does not self-approve, merge, deploy or release downstream work.

Ordinary local tools retain the2GiB envelope. Earlier2GiB race allocation and
lint virtual-memory failures are not passes. Any task-local4GiB race child uses
only the existing owner-approved finite allowance with physical-headroom
monitoring, never a global/runtime limit change. Tool/advisory errors stay
failed/unverified until a real successful exact-head execution is available.
