# P1.07 component acceptance crosswalk

This maps the approved P1.07 row, N1/N2/R1/D1/A1 and the applicable NIST
register to actual component fixtures. Test names are executable coverage, not
blanket product/NIST/FIPS certification. Exact-head commands/results/CI are
recorded on original card `t_180374d9` / draft PR11; a named fixture is not a
substitute for a successful recorded execution. The approved mapping remains
authoritative. No public authentication route or normal-session issuer is added.

## Component checks

All Go names below are in `internal/auth` unless stated otherwise.

| Contract | Implementation / executable coverage |
| --- | --- |
| W01 / `N63B4-WA-CHALLENGE`, G10 replay | `TestWebAuthnAssertionProvesUVAndRejectsReplay`, `TestWebAuthnConcurrentReplayAndRestart`, `TestWebAuthnCeremonyAndInputBoundaries`, `TestWebAuthnChallengeCapacityAndRetention`: account/session/purpose binding, expiry/clock rollback, consumed replay/restart, envelope substitution, atomic completion and terminal pruning. Library challenge generation uses `crypto/rand`, with no deterministic production fallback. |
| W02 / `N63B4-WA-ORIGIN`, G08 name binding | `TestWebAuthnRequiresExplicitVerifierName`, `TestWebAuthnAssertionAdversarialMatrix`, `TestWebAuthnRegistrationAdversarialMatrix`: explicit HTTPS RP/origins, suffix rejection, wrong origin/scheme/port/type/RP hash/cross-origin/top-origin. Mutated assertions are re-signed except the intentional bad-signature case, isolating each validation condition. Deployment/proxy forwarding integration is not inferred. |
| W03 / `N63B4-WA-UV`, A02–A04 factors/phishing/intent | `TestWebAuthnAssertionProvesUVAndRejectsReplay`, both adversarial matrices and `TestWebAuthnBrowserVirtualAuthenticator`: required current UP+UV and valid signature. All offered WebAuthn assertions require possession plus local activation; possession-only/password+SF-key fallback is not selected. TOTP, enrollment-time UV, account flags and recovery cannot replace a signed current UV proof. No ordinary/AAL2 session is created here. |
| W05 / `N63B4-WA-ATTESTATION`, approved algorithm boundary | `TestWebAuthnPackedAttestationSignature`: real P-256 self-attestation, correct signature accepted and well-formed bad signature rejected. Registration matrix rejects malformed attestation, unsupported credential algorithm, algorithm/curve mismatch and off-curve points even with `none` attestation. ES256 alone is requested/accepted; attestation preference is `none`, no trusted vendor/hardware identity is derived from self-attestation or certificate presence. |
| W07 / `N63B4-SYNC-FLAGS` | `TestWebAuthnBackupFlagsAndCounterPolicy`, assertion matrix and concurrent/restart test: BE=true/BS=false distinct from backup state, BS transitions persist, invalid BS-without-BE and changed BE deny, zero counters work, nonzero device-bound equal/regression denies, synced nonmonotonic counts retain the maximum. No flags/counter outcome is a hardware/nonexportability/AAL3 claim. |
| E01–E03 / binding records, first/additional binding, backup keys | `TestWebAuthnBindingRequiresFreshSessionAndProof`, `TestWebAuthnAdditionalBindingExcludesExistingKey`, `TestWebAuthnMultiKeyAndPolicyRemovalSafeguard`: no credential before proof, weak session cannot add a second factor, maximum-account fresh evidence required, multiple keys and independent remaining key. Metadata carries binding/change/revocation times and stable IDs. Initial setup-only enrollment is P1.09, not an invented normal-session exception. |
| G02 / `N63B4-RATE-CEILING`, N2 | `TestWebAuthnFailureCeilingBackoffAndIndependentKey`, `TestWebAuthnThresholdNoticeFailureAndRepair`, `TestWebAuthnProofEvaluationHoldsSharedControl`, `TestWebAuthnConcurrentCeilingHasNoSpeculativeProofs`: 99→100 atomically disables the specific key, real protocol verification holds the actual shared flock, two services with distinct pending challenges perform only one real evaluation at the remaining-one budget, denied-before-evaluation traffic does not charge or slide its wait, concurrent crossing creates one notice, independent key remains usable, restart preserves disablement. `TestWebAuthnVerifiedCandidateMismatchDenied` rejects state-update drift after real signature verification; `TestWebAuthnChallengeExpiryDuringProofDenies` rejects expiry during actual verification. Proof observation never resets stronger retry state. Appropriate-strength full-transaction reset belongs P1.08. Existing password/TOTP/recovery retry regressions continue in the full suite. |
| Abuse bounds | `TestWebAuthnKeyCapacityIsAtomic`, `TestWebAuthnWorkAdmissionDeniesWithoutConsuming`, retention and input-boundary tests: 16 bound current unrevoked keys (including disabled), 16 outstanding ceremonies/account, 32768-byte response/1024-byte key-ID bounds, four global non-waiting ceremony work slots. Capacity denial cannot consume a proof. Public request body/peer controls remain mandatory in future adapters. |
| E09–E10 / D-04 recognized restricted recovery | `TestWebAuthnRecoveredBindingRestrictedAndSingleUse`, `TestWebAuthnRecoveredBindingAdversarialAndAtomic`, `TestWebAuthnRecoveredBindingConcurrentRestartAndFreshProof`: password+saved-code capability only, no normal binding/assertion/session authority, TOTP cannot bypass WebAuthn-only, new UP+UV proof, atomic one-winner replacement, old keys invalidated, replay/restart/stale password revision/generation/quarantine/expiry/wrong-capability/origin/UV denial, fresh replacement assertion works. Existing `TestRecoveryCodesAtomicAndRestricted` / separate-process consumption fixtures prove recognized evidence entry, not a normal login. |
| G01 / E12–E13 / removal, compromise, W09 RP revocation | `TestWebAuthnCompromiseReportIsProtectiveNotReplacement`, multi-key/removal test and SQLite sync test: bound-password report promptly revokes an owned key and sessions even if last required key, without replacement/admin authority; ordinary removal requires fresh strength and preserves a policy-qualifying remaining factor. TOTP is not a remaining key for WebAuthn-only. |
| E15–E16 / N1 notices | Binding has two-recipient durable outbox assertions; recovery requires both replacement and recovery-completed intents. `TestWebAuthnThresholdNoticeFailureAndRepair` exercises an isolated certificate-verified SMTP receiver, all-recipient fanout, marker/outbox failures, restart repair and exactly-one suspension event. Shared P1.06 notification/address/SMTP/TLS/queue/retry/ack-ambiguity/retargeting tests run in every full suite; enqueue/relay acceptance is never human receipt. No real mail. |
| R1 / FULL security writers | `TestWebAuthnSQLiteSyncFailureNeverAcknowledges` exercises actual WAL xSync errors at begin/bind/good proof/bad proof/report/removal. Recovery matrix exercises actual recovered-binding xSync; threshold test exercises disablement and expansion xSync. Failure denies and poisons uncertain handle acceptance. Notice failure cannot reverse protective disablement; an authority-increasing recovery/outbox failure cannot activate the new credential. |
| RESTORE-02/05/08/11 / `N63B4-RESTORE-AUTH-STATE` component guards | Assertion/recovered-binding matrices deny quarantine and stale generations; recovery cannot clear quarantine or select policy. These are continuous component guards, **not** execution of logical backup/restore scenarios. Actual import/quiescence/current-control preservation remains P1.18/C4. |
| SETUP-06/09 / recovery/setup separation | Assertion matrix denies setup/recovery sessions; recovery capability cannot be used as normal enrollment/assertion/session. Actual one-use host authorization, initial setup and restore-administrator enrollment remain P1.09 and isolated deployment gates. No host-helper or initial-admin bypass added. |
| D1 / SUP-01/02, locked stack | Go1.27.3/1.26.10 and Node24.22.1/npm11.19.1; locked WebAuthn0.18.2/Playwright1.64.1. Existing generation/module/frontend/race/security gates retained. Native arm64 full suite is separate from cross-compilation; required final-head execution evidence is retained on the card. |
| Browser acceptance | `TestWebAuthnBrowserVirtualAuthenticator` executes a real locked Chromium CTAP2 virtual authenticator for resident and nonresident storage, valid signed UV, rejected replay and signed UV downgrade. `scripts/webauthn-browser-boundary.test.mjs` exercises exact origin/method/route admission and external-origin denial. Trusted local synthetic TLS/HTML only, service workers blocked, Playwright documented launch defaults. Browser-process sandbox hardening is distinct from RP acceptance and is not asserted as an approved mandatory baseline. |

### Review-boundary regressions

* **G02 / N2 / evaluated accounting:**
  `TestWebAuthnEvaluatedProofStatementFailureStopsAcceptance` injects real SQLite
  statement failures at bad/good challenge consumption, failed-proof accounting,
  good-proof envelope update and counter advancement. At prior count99, one
  actual verifier call occurs; rollback retains count99/unconsumed challenge but
  terminal denial prevents another evaluation. Existing shared-Control/concurrent
  remaining-one, durable failed-charge and actual WAL xSync controls still apply.
* **G02 / E03 / independent backup:**
  `TestWebAuthnPendingBackupSurvivesOtherKeyInvalidation` begins ceremonies while
  both keys are live, then disables (real wrong-key signature at99→100), expires
  or revokes the primary. Correct pending backup assertions succeed without
  changing counts0/99; primary proof and replay deny, fresh allowlists omit the
  primary, and fresh backup proofs work with advancing signed counters.
* **E12–E13 / ordinary denial versus storage uncertainty:**
  `TestProtectiveRemovalFreshnessExpiryPreservesHealthyRepository` checks both
  WebAuthn and TOTP read-at899s/write-at901s denial with independent password
  acceptance at902s. `TestProtectiveConcurrentRemovalPreservesHealthyRepository`
  races eight actual removals, observes one winner, and preserves independent
  password acceptance. `TestProtectiveReportPasswordExpiryPreservesIndependentKey`
  denies a report whose still-bound password expires during continuation without
  disabling the independent signed-UV key. Existing actual admission-timeout,
  statement/marker, sync and in-flight protective-failure regressions must pass;
  no storage uncertainty is reclassified as ordinary denial.

## Integrated and external obligations — not silently passed

* **P1.08/C2** must bind `FactorProof` observations to the same fresh server
  ceremony and live credential/session/control generations; enforce policy,
  achieved assurance, step-up, cookies, CSRF/CSP/Origin and invalidation through
  every route/authorizer. No account/recovery/setup/agent badge becomes AAL2.
  This component's test-only session/preauth records are not public issuers.
* **P1.09** owns first-admin and host-emergency/restore enrollment. Saved-code
  recovery is not host recovery or identity proofing; no all-factors-lost AAL2
  recovery claim. Restricted continuation cannot change WebAuthn-only policy.
* **P1.16/SUP-04** owns production account-security UI, meaningful user key labels,
  dark/light/accessibility, actual branded Chrome/Edge/Safari/platform passkey and
  non-biometric PIN-key qualification. Virtual resident/nonresident support does
  not establish usernameless/conditional UI, physical YubiKey, synced-provider,
  wireless/hybrid proximity, OS keychain or Safari compatibility.
* **W04/MFCTORS-8**, W06/B.2, G03–G07/G12–G17: device/firmware/provider-specific
  post-transaction activation-input/biometric erasure, activation/biometric retry
  and PAD/performance, approved key generation/RBG, export encryption, local
  key operation, all-path sync MFA/recovery, physical transports/proximity and
  nonexportability evidence remain **UNKNOWN/partial**, as specified in
  [webauthn.md](webauthn.md). Valid UV is not erasure proof. Persistent private
  key/reference/PIN-verifier deletion is not required after every transaction.
  No RP PIN/biometric capture, wallet, custom tunnel, blanket provider ban or
  hardware allowlist is introduced. Missing applicable evidence blocks that
  release/conformance profile; independent P1.19/20 review must not waive it.
* **AAL3/federal enterprise/FIPS/IAL** profiles are unselected and unclaimed;
  consumer sync flags and library names cannot establish these properties.
* **P1.18/C4** owns full RESTORE cases, **P1.19/20** own supported
  OS×CPU/Compose/Unraid/TLS/storage/hardware runtime qualification, real packaging
  scanners/SBOM/digests, production budgets, deployment governance/privacy/
  retention/redress and final integrated acceptance. SELF-01–13 are not exercised
  against real Docker here: no Docker adapter or route is added, and all existing
  no-exposed-product-route/static/redaction regressions remain mandatory.
* Existing public-source evidence links and unresolved device/provider limitations
  are evidence inputs, not certification. This card cannot erase these later
  gates, release downstream tasks, merge PR11 or deploy.
