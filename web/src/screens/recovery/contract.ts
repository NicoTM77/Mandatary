/**
 * Presentation contract for the P1.18 export, restore and reapproval screens (P1.18.2).
 *
 * Same rules as the P1.16 and P1.17 contracts: every screen is a STATELESS function of (`state`, data, callbacks). The
 * containers written in P1.18.3 own fetching, CSRF, step-up, the long-running request, reading the chosen file, timers,
 * routing and every security decision, and translate HTTP outcomes into these states with `outcomes.ts` and the table in
 * docs/ui/p1.18-restore-ux-contract.md §6. A screen never calls `fetch`, reads a file, parses an archive, interprets a
 * status code, or decides whether anything is permitted.
 *
 * Authority: nothing in this file grants, evaluates or enforces anything. A restore is made safe by the service
 * (docs/backup-restore.md): every imported record arrives inactive, quarantine ends only on the host, approval is per item.
 * What the screens add is comprehension: they say, before the request and again after it, what will happen, what already
 * happened, what is still switched off and what a person has to do next. They never imply that a backup is a rollback
 * point or that it carries a trustworthy history of what was revoked.
 *
 * Secrets: the archive is never displayed, held in state or echoed. A screen sees only the browser's `File` handle (name and
 * size) and hands it to the container. A `full` archive contains sealed credential material; this contract has no field for
 * archive content, a verifier, a token or a key, so none can reach a screen by accident. `source.test.ts` asserts that.
 */
import type { Load } from '../policy/contract';
import type { Operation } from '../policy/selector';

export type { Load };

/** The two archive modes of `POST /api/v1/admin/backup/export`. `full` is the same-installation-key mode. */
export type BackupMode = 'full' | 'clean';

/** The exact phrase a restore request must carry (`auth.RestoreConfirmation`). The screen makes the person type it; the container sends it. */
export const RESTORE_PHRASE = 'RESTORE';

/** `backup.MaxArchiveBytes`. Mirrored only to give a file that is certain to be refused an early, plain message. The server is the authority. */
export const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;

/** `backup.MaxApprovalsPerRequest`. */
export const MAX_APPROVALS = 500;

// ───────────────────────── export ─────────────────────────

/**
 * Why an export did not produce a file. Export changes nothing, so every one of them is safe to retry. `step_up_required` is NOT a
 * reason: the container opens the P1.16 StepUpGate in place and the person presses Export again. A 401 never reaches a screen.
 */
export type ExportReason = 'denied' | 'invalid_request' | 'rate_limited' | 'unavailable';

export type ExportState =
  | { kind: 'idle' }
  | { kind: 'working'; mode: BackupMode }
  /** The response was received and handed to the browser as a download. `backupId` is the `X-Backup-Id` header; `fileName` is the saved name. */
  | { kind: 'done'; mode: BackupMode; backupId: string; fileName: string }
  | { kind: 'rejected'; reason: ExportReason };

export interface ExportScreenProps {
  state: ExportState;
  /** Initial local choice. Exists so the synthetic gallery and tests can show the screen mid-flow; a container never passes it (the default is `clean`). */
  initialMode?: BackupMode;
  /** Called once, at submit, with the mode the person chose. Never called while `state` is `working`. */
  onExport: (mode: BackupMode) => void;
}

// ───────────────────────── restore ─────────────────────────

/**
 * Failures that happen BEFORE the installation changes. Each is a fixed class from the service (the failing check is never
 * reflected). `archive_*` map 1:1 to the 422 codes of `POST /api/v1/admin/restore`.
 */
export type RestoreRejection =
  | 'archive_malformed'
  | 'archive_unsupported_version'
  | 'archive_integrity_failed'
  | 'archive_inconsistent'
  | 'invalid_request'
  | 'denied'
  | 'rate_limited'
  | 'unavailable';

/**
 * State of the restore form, which is the screen a person can still act on. Anything that ended or may have ended the session
 * is NOT here: it is a `RestoreEnded`, rendered by a different component outside the signed-in shell.
 *
 *  - `needs_acknowledgement`: HTTP 409 `provenance_unverified`. The service verified nothing could be applied (it checks before any
 *    state change). The confirmation stays open and gains the "origin cannot be verified" checkbox; the same file is sent again.
 *  - `rejected`: nothing was changed and the person is still signed in. The screen says so.
 */
export type RestoreFormState = { kind: 'idle' } | { kind: 'working' } | { kind: 'needs_acknowledgement' } | { kind: 'rejected'; reason: RestoreRejection };

export interface RestoreRequest {
  /** The browser's own handle. The container reads it; the screen has only looked at its name and size. */
  file: File;
  /** True only when the person ticked the box shown after a `provenance_unverified` answer. Never pre-set, never remembered. The server does not trust it blindly either. */
  acknowledgeUnauthenticatedProvenance: boolean;
}

export interface RestoreScreenProps {
  state: RestoreFormState;
  /** Initial local state (the chosen file and whether the confirmation is open). Gallery and tests only: a container never passes it. */
  initial?: { file: File; confirming?: boolean };
  /** Called once, after the file and the typed phrase check out. The container adds `confirm: RESTORE_PHRASE`. Not called while `working`. */
  onRestore: (request: RestoreRequest) => void;
}

/** Non-secret result of a committed restore (`backup.Report`, HTTP 200 `report`). Counts are by record kind. */
export interface RestoreReportView {
  backupId: string;
  mode: BackupMode;
  /** `authenticated`: the integrity tag verified under this installation's key. `unauthenticated`: a clean file it could not verify, restored after acknowledgement. */
  provenance: 'authenticated' | 'unauthenticated';
  initiator: 'admin' | 'host';
  imported: Readonly<Record<string, number>>;
  /** Records already here that the file did not name. Never deleted; kept inactive. */
  retainedLocal: Readonly<Record<string, number>>;
  /** Credential records kept inactive for provenance. Always empty for a clean file. Never reactivated. */
  inactiveCredentials: Readonly<Record<string, number>>;
  credentialsStripped: boolean;
  /** Fixed scope codes the service lists as neither read nor written. */
  excluded: readonly string[];
}

/**
 * How a restore request ended when the session is gone or may be gone. There is no retry button on any of them: a restore is not
 * repeated blindly, and the next step is on the host.
 *
 *  - `complete`: HTTP 200. Quarantine is in force, every session ended, everything imported is inactive.
 *  - `incomplete`: a failure that carried `installation_state: "restore_quarantine"`. The first transaction committed (sessions ended,
 *    sign-in closed) and the import did not apply: NOTHING from the file is in place. `superseded` is the 409 `restore_superseded`
 *    case: another restore took precedence.
 *  - `unconfirmed`: no usable answer (connection lost, timeout, a proxy error). The restore may have started. The page says how to find out.
 */
export type RestoreEnded =
  | { kind: 'complete'; report: RestoreReportView; authorizerNotified: boolean }
  | { kind: 'incomplete'; cause: 'failed' | 'superseded' }
  | { kind: 'unconfirmed' };

export interface RestoreEndedProps {
  ended: RestoreEnded;
  /** The operator runbook, if the container has a URL for it. Omitted otherwise; the page never invents one. */
  runbookHref?: string;
  /** Where "Go to the sign-in page" leads. Defaults to `/login`. */
  signInHref?: string;
  /** For `unconfirmed`: reload the page to find out where things stand. The container decides what a reload does. */
  onReload?: () => void;
}

// ───────────────────────── reapproval (the manifest) ─────────────────────────

/** Record kinds a manifest can name (`internal/backup/approve.go`). */
export type ManifestKind = 'endpoint' | 'user' | 'group' | 'agent' | 'user_membership' | 'agent_membership' | 'policy' | 'role' | 'address';

export const MANIFEST_KINDS: readonly ManifestKind[] = ['endpoint', 'user', 'group', 'agent', 'user_membership', 'agent_membership', 'policy', 'role', 'address'];

/** Why the service will never approve an entry here (`blocked_reason`). `approvable: false` is the server's decision and the only thing that hides the checkbox. */
export type BlockedReason = 'single_administrator' | 'needs_reverification' | 'unsupported' | 'compromised';

/** What an entry still needs, besides approval, before it works (`needs`). Approval never issues a credential. */
export type ManifestNeeds = 'approval' | 'credential_enrollment' | 'token_reissue' | 'reverification' | 'none_in_phase_1';

export type MfaRequirement = 'optional' | 'required' | 'webauthn';

/**
 * Imported-versus-effective, ONLY where the service exposes both (`imported` / `effective` of the manifest item). The container maps the
 * two JSON objects onto exactly these cases and onto `none` for everything else: there is no generic key/value escape hatch, so a field
 * the service does not define cannot be displayed as if it were a comparison.
 *
 *  - `mfa` (kind `user`): the imported second-factor requirement and the one in force. The service never lets a weaker imported setting
 *    become effective, so `effective` can be stricter than `imported` and never weaker. `compromised` is the file's own flag.
 *  - `rule` (kind `policy`): the imported Allow/Deny and the one in force. `localDenyKept`: a Deny already here was kept over an imported Allow.
 */
export type Comparison =
  | { kind: 'none' }
  | { kind: 'mfa'; imported: MfaRequirement; effective: MfaRequirement; compromised: boolean }
  | { kind: 'rule'; imported: 'allow' | 'deny'; effective: 'allow' | 'deny'; localDenyKept: boolean };

/**
 * A record the service names by its stable id (P1.18.4 FC4-1). `name` is the display name and equals `id` when the record could not be found
 * (`missing`). Names are resolved by the service from stored ids, never by this page, never by display-name equality and never by order.
 */
export interface NamedRef {
  kind: 'user' | 'group' | 'agent' | 'endpoint';
  id: string;
  name: string;
  missing: boolean;
}

/** The exact container selector of a rule, every constraint as the service stored it (empty string: not set). */
export interface SelectorDetail {
  id: string;
  /** `glob`: the name is a pattern. `exact`: it is a literal name. */
  nameType: 'exact' | 'glob';
  containerName: string;
  composeProject: string;
  composeService: string;
  imagePattern: string;
  pinnedContainerId: string;
  pinnedImageDigest: string;
}

/** What approving a rule would make effective: effect, operation, subject, endpoint, selector and any limits. */
export interface RuleDetail {
  kind: 'rule';
  effect: 'allow' | 'deny';
  operation: Operation;
  subject: NamedRef;
  endpoint: NamedRef;
  selector: SelectorDetail;
  logTailMax: number | null;
  stopTimeoutMax: number | null;
}

/** What approving a membership would make effective: BOTH the named principal and the group. */
export interface MembershipDetail {
  kind: 'membership';
  member: NamedRef;
  group: NamedRef;
}

export type RowDetail = RuleDetail | MembershipDetail;

export interface ManifestRow {
  kind: ManifestKind;
  /** The service's item id. Memberships are `<member id>:<group id>`. Sent back verbatim in an approval; never parsed or displayed. */
  id: string;
  /** A name or the endpoint slug, as the service sent it (≤ 300 characters). Rendered as plain text. */
  label: string;
  /** `local_retained`: not in the file; already here, retired by the restore and kept (a restore never deletes). */
  origin: 'imported' | 'local_retained';
  /**
   * `source_state`: what the file said the record's state was. Shown as a reference for the reviewer and labelled as granting nothing. It is
   * never read to decide anything. Null for records the file did not name.
   */
  sourceState: string | null;
  decision: 'pending' | 'approved';
  approvable: boolean;
  blockedReason: BlockedReason | null;
  needs: ManifestNeeds;
  comparison: Comparison;
  /**
   * The exact authority a rule or membership would restore (FC4-1). Null for every other kind. A rule or membership whose detail is null,
   * or names a record that no longer exists, is NOT selectable: the page never asks for an approval it cannot describe exactly.
   */
  detail: RowDetail | null;
  /** The service's fingerprint of what was shown for this record. Sent back with the approval; a record that changed since is refused as stale. */
  digest: string;
}

export interface ManifestData {
  backupId: string;
  mode: BackupMode;
  provenance: 'authenticated' | 'unauthenticated';
  initiator: 'admin' | 'host';
  /** Unix seconds (`restored_at`). Formatted by the screen with Intl. */
  restoredAt: number;
  credentialsStripped: boolean;
  /** `inactive_credentials`: how many credential records are being kept inactive. Counts only. */
  inactiveCredentials: { authenticators: number; agentCredentials: number };
  items: readonly ManifestRow[];
}

/** Manifest load: the P1.17 `Load`, plus the 404 `no_restore` answer (nothing has been restored, so there is nothing to review). */
export type ManifestLoad = Load<ManifestData> | { kind: 'no_restore' };

/** Fixed refusal codes of `POST /api/v1/admin/restore/approvals`, plus the ones the service sends that the doc table omits (`owner_not_active`, `not_quarantined`). Unknown codes render as `other`. */
export type ApprovalRefusal =
  | 'not_in_manifest'
  | 'already_approved'
  | 'subject_not_active'
  | 'owner_not_active'
  | 'not_quarantined'
  | 'stale_details'
  | 'compromised'
  | 'single_administrator'
  | 'needs_reverification'
  | 'unsupported'
  | 'other';

export interface ApprovalFailure {
  kind: ManifestKind;
  id: string;
  reason: ApprovalRefusal;
}

export interface ItemRef {
  kind: ManifestKind;
  id: string;
  /** The digest the person reviewed (`ManifestRow.digest`). Optional on the wire; the review screen always sends it. */
  digest?: string;
}

/**
 * Outcome of the last approval request. The request is all-or-nothing, so `conflict` means NOTHING was approved.
 * `outcome_unknown` is any 5xx or lost connection: the approval transaction may have committed before a notification failed
 * (the same reason P1.17 has it), so the page asks for a reload before anyone repeats it. `still_quarantined` is 409 `restore_quarantine`.
 */
export type ApprovalState =
  | { kind: 'idle' }
  | { kind: 'working' }
  | { kind: 'done'; count: number }
  | { kind: 'conflict'; failures: readonly ApprovalFailure[] }
  | { kind: 'rejected'; reason: 'denied' | 'invalid' | 'rate_limited' | 'still_quarantined' | 'outcome_unknown' };

export interface ReviewScreenProps {
  load: ManifestLoad;
  approval: ApprovalState;
  /** Where "See it in …" leads. The container decides the URL (the P1.17 management pages); omit to show no link. */
  inspectHref?: (kind: ManifestKind, id: string) => string | undefined;
  /** The P1.16 Agent tokens page, where a token is issued and revealed once. Never reimplemented here. */
  credentialsHref: (agentId: string) => string;
  /** Initial local state (the ticked records and whether the confirmation is open). Gallery and tests only: a container never passes it. */
  initial?: { selected: readonly ItemRef[]; confirming?: boolean };
  onRetry: () => void;
  /** Called once, at confirmation, with the named entries the person selected (1 to `MAX_APPROVALS`, no duplicates). */
  onApprove: (items: readonly ItemRef[]) => void;
}
