# P1.18 logical backup, transactional restore and the UI safety contract

Contribution P1.18.1 (`t_17ea8437`) to P1.18 (`t_d57c6741`). It implements `security-contracts.md` §S2
(RESTORE-01…11) and `technical-decisions.md` §6.3. It is a **service and an HTTP safety contract, not a
finished product feature**: browser integration, the host recovery ceremony and the operator runbook
verification are outstanding (§9). Nothing here is a NIST, FIPS, accessibility or product-conformance
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
  **host-authorized recovery ceremony** (a host helper, never a web route, owned by a later card).
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
| compromised principal | — | refused (`compromised`) |

Refusal reasons are fixed codes: `not_in_manifest`, `already_approved`, `subject_not_active`, `compromised`,
`single_administrator`, `needs_reverification`, `unsupported`.

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
| `POST /api/v1/admin/restore/approvals` | `security-policy-change`, fresh AAL2 | `{"items":[{"kind","id"}…]}` (≤ 500, no duplicates) | 200 `{"approved":[…]}` | 409 `conflict` with `items:[{kind,id,reason}]`, 400 |

No response contains a credential, verifier, token hash, ciphertext, archive content, key or the text of
the failing check. `ManifestView` carries labels (names, the endpoint slug) and imported/effective
*settings* only.

## 7. Frontend interaction contract (bounded; a design input, not implemented UI)

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
body bounds, session end, post-failure quarantine reporting and manifest/approval after a modeled
recovery ceremony.

## 9. Outstanding (not part of this contribution)

* Browser integration of §7 and its accessibility/browser verification.
* The host recovery ceremony that ends quarantine and re-establishes the administrator (`mandatary recovery
  restore-admin` stays refused until then); the restore tests model it only as direct SQL.
* Operator runbook verification of a restore on a real installation; an application-level restart test of
  `cmd/mandatary` (the binary composes no backend yet).
* Wiring `SetBackup` and `ops.NotifyAuthorityChange` in the composition root (P1.19).
* Hosted CI evidence, including the ARM64 timeout adjustment of owner decision O1 (committed separately).
