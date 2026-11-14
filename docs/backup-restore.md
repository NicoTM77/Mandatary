# P1.18 logical backup, transactional restore and the UI safety contract

Contribution P1.18.1 (`t_17ea8437`) to P1.18 (`t_d57c6741`). It implements `security-contracts.md` §S2
(RESTORE-01…11) and `technical-decisions.md` §6.3. It is a **service and an HTTP safety contract, not a
finished product feature**: the host recovery ceremony and real-installation runbook
verification are outstanding (§11); browser integration, the runbook and its evidence are §9–§10 (P1.18.3). Nothing here is a NIST, FIPS, accessibility or product-conformance
claim. There is **no dry-run or preview API**: the only operations are export, restore, read the
manifest, and approve named manifest entries.

Code: `internal/backup` (archive, service, restore, approval), `internal/auth/backup_admin.go` and
`backup_http.go` (authority and routes), migration `00014_restore_manifest.sql`, queries
`internal/store/queries/backup.sql`.

## 1. Authority model

* An HMAC-valid archive is **provenance, never fresh authorization** and never carries authority. Every
  imported record is written `quarantined` at generation 0, whatever the archive said. The archive format
  has no field for a state, a generation, a quarantine flag, a session, a setup or recovery control or a
  role decision; strict decoding refuses any unknown field (`TestNoLocalControlOrStateFieldCanBeSmuggledIn`,
  `TestArchiveTypesCannotNameLocalControlState`). `source_state` is displayed to the reviewer and never read
  to decide a state.
* Export and restore are administrator-only, fresh-AAL2 (≤ 15 minutes) operations (`OpBackupExport`,
  `OpBackupRestore`), re-verified from persisted state **inside** the transaction that reads or changes state.
* A restore ends in persisted `RESTORE_QUARANTINE`: every session (the initiator's too) is revoked, the
  credential, session, authority and restore generations are rotated, and no imported record is effective.
  The administrator who restored is signed out and cannot sign back in: ending quarantine is the
  **host-authorized restore-administrator recovery** (RESTORE-08, S2.2.5: a host helper, never a web route; see
  [setup-recovery.md](setup-recovery.md)). It enrolls ONE new administrator with a fresh password and a fresh
  authenticator and revives nothing the backup carried.
* After the ceremony each record is made effective only by **explicit approval of the named manifest
  entry** (`POST …/restore/approvals`). Approval grants no credential: tokens and factors are reissued by
  their own flows.

## 2. Scope (RESTORE-11, S2.2.1)

| In the archive | Excluded (never read, never written by a restore) |
| --- | --- |
| endpoints (identity, name; never a remote credential), users, groups, agents, memberships, the administrative role, container selectors, policies/rules, notification addresses | sessions, rate-limit state, usage statistics (RESTORE-10), setup/recovery state, security notices, `installation_control` generations and quarantine, the master key and installation binding, `restore_reports`, `restore_manifest` |
| **full** mode only: authenticator and agent-credential records and TOTP/WebAuthn state, sealed under a key derived from the master key (HKDF `mandatary/backup/secrets/v1`) | **clean** mode carries no credential at all |

`TestRestoreControlStateIsNotPartOfAnyExportSurface` proves the restore control tables and generations never
appear in an export. A restore **never deletes**: local records that the archive does not name are retained
quarantined (`origin: local_retained`) and listed in the manifest.

## 3. Archive format and validation (RESTORE-06)

`format: mandatary-logical-backup`, `schema_version: 1`, `database_schema_version: 14`, `backup_id`,
`created_at`, `mode`, `hmac_salt`, `scope`, `secrets` (full only), `content_digest`, `integrity_hmac`.
Order of checks, all before any state change: size bound (16 MiB) → single strict JSON object (no trailing
data, no unknown field) → format and version names → header/mode shape → HMAC over an unambiguous encoding
of **every** field (key HKDF `mandatary/backup/integrity/v1`, constant-time compare) or, for a clean archive
this key cannot authenticate, the content digest → envelope AEAD (full) → structural consistency (unique
ids/names, every reference resolves, one subject per rule, catalogue operations only, token timing sane,
one local Phase 1 endpoint). Every failure returns a fixed class; the cause is never reflected. A rejected
archive changes nothing and **does not enter quarantine** (the transition happens after verification).

| Mode | Key | Provenance | Restore needs |
| --- | --- | --- | --- |
| full, same master key | same | `authenticated` | admin step-up |
| full, other key | different | rejected (`archive_integrity_failed`) | — |
| clean, any key | any | `authenticated` if the tag verifies under this key, else `unauthenticated` | for `unauthenticated`: `acknowledge_unauthenticated_provenance: true` |

An attacker holding the master key can mint an authentic archive. Authenticity is not authority: the same
inactive-import and explicit-approval rules apply, and structurally impossible content is still refused.

## 4. Restore transaction model (RESTORE-05)

Two durable control transactions, each atomic under SQLite FULL synchronous commit:

1. **Transition.** Authorize the initiator *in this transaction*, enter quarantine (`BackupEnterQuarantine`
   is the only writer of `installation_control` here and only moves toward quarantine, never reduces a
   generation), bump all four generations, revoke every session. Committed before any record changes.
2. **Import.** Check `quarantined = 1 AND restore_generation = N` (else `ErrSuperseded`: a competing restore
   won; nothing applied), retire local authority, upsert archive records inactive, write the report and the
   manifest, then run the post-import integrity check (foreign keys, **zero** effective authority records,
   `ErrConsistency` otherwise). Any failure rolls the whole import back.

A crash or failure between or inside the steps leaves the installation **quarantined with no partial
import**, never active with a partial one; the same archive can be retried
(`TestAFailureAfterTheTransitionLeavesQuarantineAndNoPartialImport`, `TestADatabaseFailureMidImportRollsEverythingBack`,
`TestThePostRestoreIntegrityCheckRefusesToCommitAnEffectiveRecord`, `TestParallelRestoresLeaveOneConsistentInactiveState`).
`backup.Quarantined(err)` / the HTTP field `installation_state: "restore_quarantine"` tell a caller that the
transition committed even though the import did not.

## 5. Reapproval rules (RESTORE-01/02/03/04)

| Record | Imported as | Effective rule |
| --- | --- | --- |
| user, group, agent, memberships, endpoint, rule | inactive | approvable by name, in dependency order inside one all-or-nothing request |
| rule effect | inactive; a local DENY is **never overwritten** by an imported ALLOW | the more restrictive of imported and local stays |
| MFA requirement | inactive | an imported weaker setting never becomes effective; the manifest shows imported vs effective |
| administrative role | inactive | not approvable here (`single_administrator`): the recovery ceremony owns it |
| notification address | inactive, unverified | not approvable here (`needs_reverification`) |
| authenticator / agent credential | retained inactive for provenance; token issue/expiry kept exactly | never approvable; reissue through the credential flows (RESTORE-04 historical expiry never becomes a fresh lifetime) |
| compromised principal | — | refused (`compromised`); listed with that reason, **not selectable** in the interface (P1.18.4), and a crafted approval is still refused by the server |

Refusal reasons are fixed codes, each with a safe, input-free meaning:

| Code | Meaning |
| --- | --- |
| `not_in_manifest` | The named kind and ID are not in the latest restore's manifest. |
| `already_approved` | The entry was approved earlier; approving it again grants nothing more. |
| `subject_not_active` | A rule or membership names a principal or group that has not been approved yet; approve that first (dependencies are applied in order inside one request). |
| `owner_not_active` | An agent's owner (user or group) has not been approved yet; approve the owner first. An agent never becomes effective without an active owner. |
| `not_quarantined` | The record is no longer in the quarantined state the approval expects (it changed after the restore, for example a local change or an earlier approval), so nothing is activated; reload the manifest and review what is in force. |
| `stale_details` | The approval named the digest of what was reviewed (see below) and the stored record changed since; nothing is approved. Reload and review again. |
| `compromised` | The principal is known compromised; it is never approved by this flow. |
| `single_administrator` | Roles are not approvable: the recovery ceremony owns the administrator. |
| `needs_reverification` | A notification address is proven by its owner again, never approved. |
| `unsupported` | The kind cannot be approved in Phase 1. |

**What an approval identifies (P1.18.4 FC4-1).** Each rule and membership entry of the manifest carries a `detail` resolved
from the stored rows by their stable IDs (never by display name or position): for a rule the effect, operation, subject
(kind, ID, display name), endpoint (ID and slug), and the selector with every constraint (exact or glob name, compose project
and service, image pattern, pinned container and image digest) and any limits; for a membership **both** the named user or
agent and the group. A record that cannot be found falls back to its ID and is flagged `missing`. The entry also carries the
imported and effective claims (an imported ALLOW over a kept local DENY shows both) and a `digest` that fingerprints exactly
what was shown. The interface sends that digest with each selected record; an approval whose stored state no longer matches is
refused as `stale_details` and changes nothing. The digest is optional on the API (record kind plus ID selection, quarantine,
fresh step-up, dependency validation and atomic approval are unchanged). No detail contains a credential, verifier, token hash or
secret configuration. Tests: `TestManifestNamesTheExactAuthorityOfEveryRuleAndMembership`,
`TestDetailFallsBackToStableIDsWhenARecordIsMissing`, `TestApprovalBoundToAReviewedDigestIsRefusedWhenTheRecordChangedSinceReview`,
`TestACompromisedPrincipalIsShownButNeverSelectableAndStillRefusedByTheServer`.

## 6. HTTP contract (routes exist only when `Admin.SetBackup` was called)

All routes sit on `auth.Browser`: session cookie, exact Origin, per-session CSRF token, JSON only and the
class step-up gate run **before** the handler. Request bodies are single JSON objects with unknown fields
refused. Only the restore route raises its body bound (to the 16 MiB archive plus 64 KiB), and a route may
raise its bound only for an unsafe session route up to 32 MiB (`RoutePolicy.MaxBody`).

| Route | Class / step-up | Request | Success | Notable errors |
| --- | --- | --- | --- | --- |
| `POST /api/v1/admin/backup/export` | `backup-export`, fresh AAL2 | `{"mode":"full"\|"clean"}` | archive as an attachment (`Content-Disposition`, `X-Backup-Id`, `X-Backup-Mode`, `no-store`) | 400 `invalid_request`, 403 `step_up_required`/`forbidden` |
| `POST /api/v1/admin/restore` | `backup-restore`, fresh AAL2 | `{"archive":{…},"confirm":"RESTORE","acknowledge_unauthenticated_provenance":bool}` | 200 `{"report":Report,"authorizer_notified":bool,"session_ended":true}` | 400, 403, 409 `provenance_unverified`/`restore_superseded`, 422 `archive_malformed`/`archive_unsupported_version`/`archive_integrity_failed`/`archive_inconsistent`, 503 `unavailable` (+ `installation_state:"restore_quarantine"` after the transition) |
| `GET /api/v1/admin/restore/manifest` | session only | — | 200 `ManifestView` | 404 `no_restore`, 401/403 while quarantined |
| `POST /api/v1/admin/restore/approvals` | `security-policy-change`, fresh AAL2 | `{"items":[{"kind","id","digest"?}…]}` (≤ 500, no duplicates by kind+ID) | 200 `{"approved":[…]}` | 409 `conflict` with `items:[{kind,id,reason}]`, 400 |

No response contains a credential, verifier, token hash, ciphertext, archive content, key or the text of
the failing check. `ManifestView` carries labels (names, the endpoint slug) and imported/effective
*settings* only.

## 7. Frontend interaction contract (the design input that §9 implements)

Decisions and what each needs. **Step-up** means fresh AAL2 within 15 minutes (the existing P1.16 step-up
panel; a `403 step_up_required` is answered by that panel, then the same request is retried once).
**Explicit approval** means a separate, deliberate user action naming the item, never a default or "select all".

| Decision | Needs |
| --- | --- |
| Export a full or clean backup | step-up; the screen states that *full* contains credential material sealed to this installation's key and is useless elsewhere, and that *clean* carries no credential |
| Restore | step-up **and** typing the confirmation phrase `RESTORE`; the screen states, before the request, that the restore signs everyone out (including you), puts the installation in quarantine, makes nothing effective until reapproval, and that recovery needs the host |
| Restore of a clean archive from another key | the above **and** an explicit checkbox: "I understand this file's origin cannot be verified" (`acknowledge_unauthenticated_provenance`) |
| Approve a user / group / agent / membership / endpoint | step-up and explicit per-item approval; one request may carry a dependency chain |
| Approve a rule, or any entry whose imported value is weaker than the effective one | step-up and explicit per-item approval after showing imported vs effective side by side |
| Administrator role, notification address, credentials | **no approval exists**: show the fixed reason (`single_administrator`, `needs_reverification`) and the flow that reissues them |

State the UI must render: after a successful restore, a terminal "restore complete — installation is in
quarantine, sign-in is closed, run the host recovery" page (the session is already gone; do not auto-retry);
after a `503` carrying `installation_state: restore_quarantine`, the same page with "the import did not
complete, nothing was applied"; after any other error, "nothing changed". `authorizer_notified: false`
means the shared authorizer's cached decisions lapse at its next revalidation tick; quarantine is in force
either way. The UI must never infer authority from a manifest `source_state`, never offer a preview of an
archive before restore (no such API exists), never offer approval of an item with `approvable: false`, and
never display or store archive content beyond the manifest fields above.

## 8. Evidence and fixtures

`internal/backup` runs against a real SQLite repository: fresh-instance and live-instance fixtures,
same-key full and clean/new-key restores, excluded sessions, historical expiry, local DENY retention,
weaker-MFA refusal, credential retention without reissuance, tamper/structure/version cases,
authentic-but-inconsistent (re-signed) archives, smuggled-control cases, crash points, a real mid-import database
failure, a competing-restore race and reopen persistence. `internal/auth/backup_admin_test.go` covers the
routes: absence without a service, the declared step-up classes, ordinary-user and stale-evidence refusal,
body bounds, session end, post-failure quarantine reporting and manifest/approval after the real
restore-administrator recovery.


## 9. Browser integration and evidence (P1.18.3)

Contribution P1.18.3 (`t_dda7b4e2`) binds the P1.18.2 screens (`docs/ui/p1.18-restore-ux-contract.md`) to the routes of §6.
Everything the client does is presentation: it never reads, parses or validates an archive, never decides
whether a restore is allowed and never decides what is approvable. The server decides each of those and the
client renders the fixed code it returns.

* Pages (administrators only in the navigation; the server enforces this independently): `/backup`, `/restore`,
  `/restore/review`, in the SPA allowlist of `web/assets.go` (unknown paths remain 404).
* `web/src/api/recovery.ts` (`RecoveryApi`): export (the response body is saved under the **server-issued** name,
  and only when the `X-Backup-Mode` header matches the request), restore (the file's text is wrapped in the request
  as the `archive` value, never parsed by the client), manifest and approvals. Every decoder fails closed.
* `web/src/api/http.ts`: carries `installation_state` only when it is exactly `restore_quarantine` and conflict
  `items` only when strictly valid (≤ 500, token-shaped). Without the first, a failure *after* the quarantine
  transition would read as "nothing changed" (§7). A restore has its own time bound; a client abort is an
  `unconfirmed` outcome, never a failure and never a retry.
* Step-up uses the existing P1.16 panel for `backup-export`, `backup-restore` and `security-policy-change`.
  A blocked request is **not replayed**: the person presses the button again once verified.
* A restore ends on a pre-session page that replaces the signed-in shell (complete, incomplete or unconfirmed).
  None offers a retry button.

### Evidence executed for this contribution

| Layer | Where | What it pins |
| --- | --- | --- |
| Transport/client/containers (Vitest) | `web/src/api/{http-recovery,recovery}.test.ts`, `web/src/containers/recovery.test.tsx` | wire shapes, fail-closed decoding, timeouts, step-up without replay, every outcome page, no select-all, nothing sent for a wrong phrase / empty / oversized file |
| REST + MCP over the real stack | `internal/auth/restore_e2e_test.go` | RESTORE-01, 03, 09, 11 (below) |
| Direct requests | `internal/auth/backup_direct_test.go` | boundary violations on every route (no session, no CSRF, foreign Origin, form post, ordinary user), tamper and misversion, unverifiable clean archive, parallel restore, export scope |
| Real browser (Chromium, light and dark) | `web/tests/recovery-ui-browser.mjs` driven by `internal/auth/recovery_ui_browser_test.go` (`make browser-test`) | export both modes, step-up without replay, local refusals, five tamper variants, acknowledgement, terminal page, closed sign-in, reapproval by name, credential reissuance, injected database failure and retry, two tabs restoring at once, an ordinary signed-in person and crafted requests, dependency-free structural accessibility audit (`a11y-audit.mjs`) of each state, both themes and a phone-sized run (`MANDATARY_VIEWPORT=390x844`), no secret in console/URL/log/database |

Mutation checks (real source mutated, the named test must fail, source restored): step-up treated as failure, a
quarantine-state failure read as "nothing changed", a lost answer read as a failure, a spliced instead of wrapped
file, no restore timeout, acknowledgement defaulting to true, extra fields sent on approval, shell kept after a
restore, export mode mismatch accepted, a guessed comparison for an unreadable manifest (all 10 killed by the
web tests), and CSRF skipped, confirmation phrase ignored, integrity tag not compared, quarantine state not
reported (all 4 killed by the Go tests).

The host recovery ceremony is the **real** one (`PolicyE2E.RecoveryCeremony` and the browser fixture's control action both
drive the production setup service through issue, reveal, exchange, account, address proof, fresh TOTP and completion): a NEW
administrator is enrolled and quarantine ends in that transaction, and the scenarios then sign in as that administrator. The
backup administrator, its factors and its revoked session stay dead (the earlier model that re-activated them is gone). Only the
mail transport (the proof is captured instead of mailed) and, in the Go fixtures, the new administrator's AAL2 session row are
synthetic; the browser signs in through the real login.

### RESTORE-xx crosswalk

Tests are named so each can be run on its own (`go test ./internal/auth ./internal/backup -run '<name>'`).

| ID | Evidence | Status for this contribution |
| --- | --- | --- |
| RESTORE-01 | `TestRestoreNeverRevivesAuthorityOverRESTAndMCP` (the pre-revocation token fails every REST and MCP operation after restore; a **new** token works only with newly approved rules; no operational call reaches the mock Docker); `TestHistoricalExpiryIsKeptAndNeverBecomesAFreshLifetime`; browser `restore-flows` (old token never revived; a reissued token is accepted by the shared verifier) | covered |
| RESTORE-02 | `TestSameKeyRestoreIntoAFreshInstanceImportsOnlyInactiveRecords`, `TestRestoreOverALiveInstallationRetiresLocalAuthorityAndNeverRevivesAnything`, `TestCleanRestoreOntoANewKeyStripsEveryCredentialAndIsAcknowledgedAsUnauthenticated` (`internal/backup`); the reinstated administrator role is `single_administrator` and not approvable | covered at the service level; the browser does not exercise a password/MFA login with a reverted credential |
| RESTORE-03 | `TestRestoreNeverDiscardsALocalDenyDuringPartialReview`; `TestAnImportedAllowNeverOverwritesALocalDenyForTheSameRule`; browser `restore-flows` (a post-backup person and DENY are kept, switched off, shown as "Not in the file") | covered |
| RESTORE-04 | `TestHistoricalExpiryIsKeptAndNeverBecomesAFreshLifetime` | **partial**: no temporary grants exist in Phase 1; clock-rollback and restart behaviour is not exercised here (Phase 2) |
| RESTORE-05 | `TestParallelRestoreRequestsOverHTTPLeaveOneConsistentInactiveState`, `TestAFailureAfterTheTransitionLeavesQuarantineAndNoPartialImport`, `TestADatabaseFailureMidImportRollsEverythingBack`, `TestARestoreOvertakenByANewerOneAppliesNothing`, `TestQuarantinePersistsAcrossReopen`; browser `restore-failure` (a real database fault inside the import: quarantine in force, sessions ended, no import kept, the page never says "nothing changed", the same file restores after recovery) and `parallel-restore` (two tabs, exactly one completes) | covered; a process crash/restart of `cmd/mandatary` is not exercised (the binary composes no backend, §10) |
| RESTORE-06 | `TestTamperedAndMisversionedArchivesAreRefusedOverHTTPWithoutQuarantine`, `TestAnUnauthorizedInitiatorChangesNothingAndCannotTriggerQuarantine`, `TestRestoreRefusalsChangeNothingAndNeverEnterQuarantine`; browser five tamper variants, a non-JSON file that tries to set the acknowledgement itself, and the denial scenario; `TestARestoreAndTheEndpointReapprovalDropTheSelfProtectionProofUntilItIsVerifiedAgain` (a committed restore and the endpoint reapproval each drop the shared self-protection proof through `Admin.WithSafetyReset` → `Authorizer.InvalidateSelfProtection`; nothing dispatches, `safety_unverified`, until a fresh `VerifySelf`) | covered over the mock backend. The composition root (P1.19) must pass `InvalidateSelfProtection` to `WithSafetyReset`; until it does, nothing in the binary reaches Docker at all (§10) |
| RESTORE-07 | none: no external checkpoint or ledger exists. Quarantine remains the default | not applicable to this contribution |
| RESTORE-08 | `TestRestoreRecoveryIsIssuedOnlyInsideARestoreQuarantine`, `TestRestoreRecoveryEnrollsExactlyOneFreshAdministratorAndApprovesNothing`, `TestBackupCredentialsAndOrdinaryPathsCannotLeaveRestoreQuarantine`, `TestRestoreRecoverySessionIsNotASessionAndCannotDoAnythingElse`, `TestRestoreRecoveryTokenWinsOnceAndIsBounded`, `TestRestoreRecoveryRefusesWhenTheQuarantineIsNoLongerThere`, `TestRestoreRecoveryWorksAfterAFailedImport`, `TestRestoreRecoveryCrashPoints`, `TestRestoreRecoveryOverHTTPEndsQuarantineAndIssuesNoSession` (`internal/auth`); `TestCLIRestoreAdministratorRecoveryProtocol`, `TestCLIUsageAndRefusals` (`cmd/mandatary`); `web` containers test and browser `restore-flows` / `restore-failure` (the backup administrator's own password cannot reach the second factor; the new administrator signs in through the ordinary login) | covered: the token enrolls one new administrator, no restored factor/session/authority is revived or approved, backup password/MFA alone cannot leave quarantine; not run on a real host or with a real mail relay |
| RESTORE-09 | `TestRestoreNeverDiscardsALocalDenyDuringPartialReview` and the manifest comparison (`imported` beside `effective`); browser `restore-flows` (a fresh-instance-style restore: nothing effective until named, no rule becomes effective by approving its group, only the named rule is effective) | covered, with no invented historical rollback |
| RESTORE-10 | `TestNoExportCarriesSessionsOrSetupAndRecoveryState`; usage aggregates are outside the backup scope and the pages say so; no recovery is claimed | covered as an exclusion |
| RESTORE-11 | `TestAWeakerImportedSecuritySettingNeverBecomesEffective`, `TestNoLocalControlOrStateFieldCanBeSmuggledIn`, the smuggled-field tamper case in the browser, and the manifest comparison | covered |

## 10. Operator runbook

For an administrator restoring Mandatary from a logical backup. A backup is a snapshot of what it knew, not
a rollback: it can neither re-create a revocation or a DENY that happened after it was taken nor restore a
credential. Nothing below is a conformance claim, and there is no dry run: **the restore is the first step that
changes anything**.

### Before

1. Decide the mode when exporting. **Full** is sealed to this installation's key and carries credential
   records; it only authenticates on the same installation key. **Clean** carries no credential and can be
   restored anywhere, with an acknowledgement that its origin cannot be verified. Keep either file as
   confidential: a full file is useless without the key, a clean file is not secret but is not proof of anything.
2. Keep the file you restore from. Every failure before the first change leaves it untouched, and the same
   file can be restored again.
3. Know that **everyone is signed out, including you**, and that sign-in stays closed until the host recovery.

### Restore

1. Open **Restore from backup**, choose the file, press **Restore from this file…**, type `RESTORE`, confirm.
   If a fresh verification is needed, complete it and press the button again (the request is never replayed).
2. **A refusal** (integrity, malformed, unsupported version, inconsistent, wrong phrase, not an administrator)
   says nothing was changed, and you stay signed in. Fix the cause or use another file.
3. **Restore complete**: the installation is in restore quarantine. Nothing from the file is effective.
4. **The restore didn't finish**: quarantine is already in force but nothing from the file was kept. Run the
   host recovery, then restore the same file again; that is safe. After this host recovery the **Rules** and **Agents**
   pages can still show records that existed before the restore as active at older generations. That display is **not
   evidence of current effective authority**: those records are inert (their generations no longer match), nothing was
   reactivated or rewritten to match the display, and retrying the same restore is safe. Only what the new manifest shows
   as approved is in force (P1.18.4 P118-Oa).
5. **Couldn't confirm what happened** (the connection ended with no answer): do not assume either result.
   Reload; if the sign-in page is closed, a restore began. Run the host recovery and read the manifest.

### Host recovery

Ending quarantine and re-establishing the administrator is a **host-authorized** action that no browser can
perform; backup passwords or factors alone cannot leave quarantine. On the host, as the service identity (full
reference and guarantees: [setup-recovery.md](setup-recovery.md), "Restore-administrator recovery"):

1. `mandatary recovery restore-admin --acknowledge-restore-recovery` (the flag records that this is a trusted-host
   procedure, not NIST AAL2 account recovery). It refuses outside a restore quarantine.
2. `mandatary recovery reveal --restore-admin` on a real terminal: the token is written once to that terminal and
   expires in 30 minutes. If it expires or a step fails, run step 1 again.
3. Open the setup page the log or runbook names, enter the token, then choose a **new** username and password, confirm a
   notification address and enroll a fresh authenticator, and press **Finish recovery**. Quarantine ends in that step.
   Nothing the backup carried is switched on, no one is signed in, and the restored administrator's own password and
   authenticator never work again unless you approve them below.

### After: reapproval and credential reissuance

1. Sign in as the administrator and open **Review restored access**. Every record is listed as switched off, with
   what the file held beside what is in force. Records that were in this installation but not in the file are
   kept switched off and marked "Not in the file".
2. Approve **by name, one record at a time**; the confirmation lists exactly what will become effective: for a rule the
   effect, operation, subject, endpoint and selector; for a membership both the principal and the group. A record that
   changed since you looked is refused as stale. Known-compromised records are listed with their reason and cannot be selected. There
   is no approve-everything. A rule is approved only after you have looked at it; approving a group makes no rule
   effective, and approving an agent grants no credential. Refused records show a fixed reason.
3. **Reissue credentials** through their own flows: issue a new token for each agent that needs one (**Agents**,
   shown once), re-enroll sign-in methods, re-verify notification addresses. A token from before is never
   revived, whatever the file says. The administrator role is established by the host recovery, not by approval.
4. Check **Agents** and **Policy** against what you intended before restoring any workload. Anything not
   approved by name remains denied.

### What this runbook does not do

It does not recover usage counters, sessions, setup or recovery state or the installation key (§2), does not roll
back to a point in time, and was exercised only against a test installation with synthetic data, not on a real
Docker or Unraid host or with a real mail relay.

## 11. Outstanding (not part of this contribution)

* Operator verification of the runbook on a real installation; an application-level restart/crash test of
  `cmd/mandatary` (the binary composes no backend yet). Evidence here is component and integration over a mock
  backend.
* RESTORE-04 clock behaviour with real temporary grants (Phase 2) and RESTORE-07.
* Wiring `SetBackup`, `Admin.WithSafetyReset(authorizer.InvalidateSelfProtection)` and `ops.NotifyAuthorityChange` in the
  composition root (P1.19), and a real-host run of the restore-administrator recovery.
* Hosted CI evidence, including the ARM64 timeout adjustment of owner decision O1 (committed separately).
* A link from the terminal pages to the runbook is not wired (`runbookHref` is unset: no route serves documents).
