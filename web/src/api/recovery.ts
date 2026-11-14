import type { AccountApi } from './account';
import { isRecord, type ApiResult } from './http';
import type { BackupMode, Comparison, ItemRef, ManifestData, ManifestKind, ManifestNeeds, ManifestRow, MfaRequirement, NamedRef, RestoreReportView, RowDetail, SelectorDetail } from '../screens/recovery/contract';
import { OPERATIONS, type Operation } from '../screens/policy/selector';
import { MANIFEST_KINDS, MAX_APPROVALS, RESTORE_PHRASE } from '../screens/recovery/contract';

/**
 * Browser client of the four P1.18 administrative routes (`internal/auth/backup_http.go`). Every path is a constant of this module (there is no
 * dynamic segment), the CSRF token stays inside AccountApi, and nothing here keeps, logs or stores a response.
 *
 * What the client does NOT do: it never reads, verifies, decrypts or validates an archive, never decides whether a restore is allowed, and never
 * decides what is approvable. The single thing it does to a chosen file is to place it in the request as a value (see `restore`), so that the
 * file cannot add or override a request field. Whether it is a backup, whether it is authentic and what it contains is the server's.
 *
 * Decoders fail closed: a success body that is not exactly the documented shape is `invalid_response`, which the restore mapping treats as
 * "no usable answer" (never as "nothing changed") and the other screens treat as a failed load.
 */

const BASE = '/api/v1/admin';
const EXPORT_PATH = `${BASE}/backup/export`;
const RESTORE_PATH = `${BASE}/restore`;
const MANIFEST_PATH = `${BASE}/restore/manifest`;
const APPROVALS_PATH = `${BASE}/restore/approvals`;

/**
 * A restore may carry a 16 MiB archive and runs two durable transactions; the 20 s default would turn a slow success into a false failure.
 * Giving up is a status-0 outcome, which the restore mapping presents as "couldn't confirm what happened", never as a failure.
 */
export const RESTORE_TIMEOUT_MS = 5 * 60_000;
export const EXPORT_TIMEOUT_MS = 2 * 60_000;

const BACKUP_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const COUNT_KEY = /^[a-z][a-z_]{0,39}$/;
const MFA: readonly string[] = ['optional', 'required', 'webauthn'];
const NEEDS: readonly string[] = ['approval', 'credential_enrollment', 'token_reissue', 'reverification', 'none_in_phase_1'];
const BLOCKED: readonly string[] = ['single_administrator', 'needs_reverification', 'unsupported', 'compromised'];
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_NAME = 300;
const MAX_LABEL = 300;

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isMode(value: unknown): value is BackupMode {
  return value === 'full' || value === 'clean';
}

// ───────────────────────── export ─────────────────────────

/** What a successful export hands to the container: the bytes (for the browser to save) and the facts the screen reports. */
export interface ExportedFile {
  blob: Blob;
  backupId: string;
  mode: BackupMode;
  fileName: string;
}

/**
 * The saved file name. The server's `Content-Disposition` is used only when it is EXACTLY `attachment; filename="mandatary-backup-<id>-<mode>.json"`
 * for the id and mode already validated; anything else (a path, a quote, another mode) falls back to the same name built locally.
 */
export function downloadName(disposition: string | null, backupId: string, mode: BackupMode): string {
  const expected = `mandatary-backup-${backupId}-${mode}.json`;
  return disposition === `attachment; filename="${expected}"` ? disposition.slice('attachment; filename="'.length, -1) : expected;
}

function exportReader(requested: BackupMode): (response: Response) => Promise<ExportedFile | null> {
  return async (response) => {
    const backupId = response.headers.get('X-Backup-Id');
    const mode = response.headers.get('X-Backup-Mode');
    // A file that does not say what it is, or is not what was asked for, is never offered for saving.
    if (backupId === null || !BACKUP_ID.test(backupId) || mode !== requested) return null;
    return { blob: await response.blob(), backupId, mode: requested, fileName: downloadName(response.headers.get('Content-Disposition'), backupId, requested) };
  };
}

// ───────────────────────── restore ─────────────────────────

export interface RestoreResult {
  report: RestoreReportView;
  /** False means the shared authorizer's cached decisions lapse at its next revalidation tick; quarantine is in force either way. */
  authorizerNotified: boolean;
}

function counts(value: unknown): Record<string, number> | null {
  if (!isRecord(value)) return null;
  const entries: Array<[string, number]> = [];
  for (const [key, count] of Object.entries(value)) {
    if (!COUNT_KEY.test(key) || !isCount(count)) return null;
    entries.push([key, count]);
  }
  return Object.fromEntries(entries);
}

function decodeReport(value: unknown): RestoreReportView | null {
  if (!isRecord(value)) return null;
  const imported = counts(value.imported);
  const retained = counts(value.retained_local);
  const inactive = counts(value.inactive_credentials);
  if (imported === null || retained === null || inactive === null) return null;
  if (typeof value.backup_id !== 'string' || !BACKUP_ID.test(value.backup_id) || !isMode(value.mode) || typeof value.credentials_stripped !== 'boolean') return null;
  if (value.provenance !== 'authenticated' && value.provenance !== 'unauthenticated') return null;
  if (value.initiator !== 'admin' && value.initiator !== 'host') return null;
  if (!Array.isArray(value.excluded) || value.excluded.length > 40 || !(value.excluded as unknown[]).every((entry) => typeof entry === 'string' && COUNT_KEY.test(entry))) return null;
  return {
    backupId: value.backup_id,
    mode: value.mode,
    provenance: value.provenance,
    initiator: value.initiator,
    imported,
    retainedLocal: retained,
    inactiveCredentials: inactive,
    credentialsStripped: value.credentials_stripped,
    excluded: value.excluded as string[],
  };
}

function decodeRestore(value: unknown): RestoreResult | null {
  if (!isRecord(value) || typeof value.authorizer_notified !== 'boolean' || value.session_ended !== true) return null;
  const report = decodeReport(value.report);
  return report === null ? null : { report, authorizerNotified: value.authorizer_notified };
}

/**
 * The chosen file's text becomes the request's `archive` VALUE. If it parses as JSON, the parsed value is embedded. If it does not, the text is
 * embedded as a plain string: the server refuses it as a malformed archive (422), which is the server's decision, and the text cannot break
 * out of its value. Splicing the raw text into the body instead would let a crafted file set `acknowledge_unauthenticated_provenance` itself
 * (a duplicate key wins in the server's decoder), silently bypassing the acknowledgement the person is asked for.
 */
function archiveValue(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

// ───────────────────────── manifest ─────────────────────────

function mfa(value: unknown): MfaRequirement | null {
  return typeof value === 'string' && MFA.includes(value) ? (value as MfaRequirement) : null;
}

function effectOf(value: unknown): 'allow' | 'deny' | null {
  return value === 'ALLOW' ? 'allow' : value === 'DENY' ? 'deny' : null;
}

/**
 * Imported-versus-effective ONLY where the service exposes both, and only for a record still waiting for approval that came from the file:
 * a user's second-factor requirement and a rule's effect. Every other kind and every other state is `none`. A pending imported record of those
 * two kinds whose two settings are not both readable fails the whole manifest closed (null): a comparison is never guessed.
 */
function comparisonOf(row: { kind: ManifestKind; origin: ManifestRow['origin']; decision: ManifestRow['decision'] }, imported: unknown, effective: unknown): Comparison | null {
  if (row.origin !== 'imported' || row.decision !== 'pending' || (row.kind !== 'user' && row.kind !== 'policy')) return { kind: 'none' };
  if (!isRecord(imported) || !isRecord(effective)) return null;
  if (row.kind === 'user') {
    const was = mfa(imported.mfa_requirement);
    const now = mfa(effective.mfa_requirement);
    if (was === null || now === null || typeof imported.compromised !== 'boolean') return null;
    return { kind: 'mfa', imported: was, effective: now, compromised: imported.compromised };
  }
  const was = effectOf(imported.effect);
  const now = effectOf(effective.effect);
  if (was === null || now === null) return null;
  return { kind: 'rule', imported: was, effective: now, localDenyKept: typeof effective.note === 'string' || (was === 'allow' && now === 'deny') };
}

function text(value: unknown, max = MAX_NAME): string | null {
  return typeof value === 'string' && value.length <= max ? value : null;
}

function optionalText(value: unknown, max = MAX_NAME): string | null {
  return value === undefined || value === null ? '' : text(value, max);
}

function optionalLimit(value: unknown): number | null | undefined {
  if (value === undefined || value === null) return null;
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function namedRef(value: unknown, kind: NamedRef['kind']): NamedRef | null {
  if (!isRecord(value) || value.kind !== kind) return null;
  const id = text(value.id);
  const name = text(value.name);
  if (id === null || id === '' || name === null || (value.missing !== undefined && typeof value.missing !== 'boolean')) return null;
  return { kind, id, name: name === '' ? id : name, missing: value.missing === true };
}

function selectorOf(value: unknown): SelectorDetail | null {
  if (!isRecord(value) || (value.name_type !== 'exact' && value.name_type !== 'glob')) return null;
  const id = text(value.id);
  const containerName = text(value.container_name);
  const composeProject = optionalText(value.compose_project);
  const composeService = optionalText(value.compose_service);
  const imagePattern = optionalText(value.image_pattern);
  const pinnedContainerId = optionalText(value.pinned_container_id, 128);
  const pinnedImageDigest = optionalText(value.pinned_image_digest, 128);
  if (id === null || containerName === null || composeProject === null || composeService === null || imagePattern === null || pinnedContainerId === null || pinnedImageDigest === null) return null;
  return { id, nameType: value.name_type, containerName, composeProject, composeService, imagePattern, pinnedContainerId, pinnedImageDigest };
}

const OPERATION_KEYS: readonly string[] = OPERATIONS.map((op) => op.key);

/**
 * The identifying detail of a rule or membership, decoded strictly. A detail the service did not send is null (the row is then not selectable);
 * a detail that is present but malformed fails the whole manifest closed, so a half-understood description is never shown beside a checkbox.
 */
function detailOf(kind: ManifestKind, value: unknown): RowDetail | null | undefined {
  if (value === undefined || value === null) return null;
  if (!isRecord(value)) return undefined;
  if (kind === 'user_membership' || kind === 'agent_membership') {
    const member = namedRef(value.member, kind === 'user_membership' ? 'user' : 'agent');
    const group = namedRef(value.group, 'group');
    return member && group ? { kind: 'membership', member, group } : undefined;
  }
  if (kind === 'policy') {
    const effect = effectOf(value.effect);
    const subjectKind = isRecord(value.subject) && (value.subject.kind === 'user' || value.subject.kind === 'group' || value.subject.kind === 'agent') ? value.subject.kind : null;
    const subject = subjectKind ? namedRef(value.subject, subjectKind) : null;
    const endpoint = namedRef(value.endpoint, 'endpoint');
    const selector = selectorOf(value.selector);
    const logTailMax = optionalLimit(value.log_tail_max);
    const stopTimeoutMax = optionalLimit(value.stop_timeout_max);
    if (effect === null || typeof value.operation !== 'string' || !OPERATION_KEYS.includes(value.operation) || !subject || !endpoint || !selector || logTailMax === undefined || stopTimeoutMax === undefined) return undefined;
    return { kind: 'rule', effect, operation: value.operation as Operation, subject, endpoint, selector, logTailMax, stopTimeoutMax };
  }
  // Users carry only `compromised` (shown through the comparison and blocked_reason); other kinds carry no detail.
  return null;
}

function decodeRow(value: unknown): ManifestRow | null {
  if (!isRecord(value)) return null;
  const { kind, id, label, origin, decision } = value;
  if (typeof kind !== 'string' || !(MANIFEST_KINDS as readonly string[]).includes(kind) || typeof id !== 'string' || id.length === 0 || id.length > 257) return null;
  if (typeof label !== 'string' || label.length > MAX_LABEL || (origin !== 'imported' && origin !== 'local_retained') || (decision !== 'pending' && decision !== 'approved')) return null;
  if (typeof value.approvable !== 'boolean' || typeof value.needs !== 'string' || !NEEDS.includes(value.needs)) return null;
  const sourceState = value.source_state;
  if (sourceState !== null && sourceState !== undefined && (typeof sourceState !== 'string' || sourceState.length > 40)) return null;
  const blocked = value.blocked_reason;
  if (blocked !== undefined && blocked !== null && blocked !== '' && (typeof blocked !== 'string' || !BLOCKED.includes(blocked))) return null;
  const comparison = comparisonOf({ kind: kind as ManifestKind, origin, decision }, value.imported, value.effective);
  if (comparison === null) return null;
  const detail = detailOf(kind as ManifestKind, value.detail);
  if (detail === undefined || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) return null;
  return {
    kind: kind as ManifestKind,
    id,
    label,
    origin,
    sourceState: typeof sourceState === 'string' ? sourceState : null,
    decision,
    approvable: value.approvable,
    blockedReason: typeof blocked === 'string' && blocked !== '' ? (blocked as ManifestRow['blockedReason']) : null,
    needs: value.needs as ManifestNeeds,
    comparison,
    detail,
    digest: value.digest,
  };
}

function decodeManifest(value: unknown): ManifestData | null {
  if (!isRecord(value) || !Array.isArray(value.items) || value.items.length > 20_000) return null;
  if (typeof value.backup_id !== 'string' || !BACKUP_ID.test(value.backup_id) || !isMode(value.mode) || !isCount(value.restored_at)) return null;
  if (value.provenance !== 'authenticated' && value.provenance !== 'unauthenticated') return null;
  if (value.initiator !== 'admin' && value.initiator !== 'host') return null;
  if (!isRecord(value.summary) || typeof value.summary.credentials_stripped !== 'boolean') return null;
  const inactive = value.inactive_credentials;
  if (!isRecord(inactive) || !isCount(inactive.authenticators) || !isCount(inactive.agent_credentials)) return null;
  const items: ManifestRow[] = [];
  for (const raw of value.items as unknown[]) {
    const row = decodeRow(raw);
    if (row === null) return null;
    items.push(row);
  }
  return {
    backupId: value.backup_id,
    mode: value.mode,
    provenance: value.provenance,
    initiator: value.initiator,
    restoredAt: value.restored_at,
    credentialsStripped: value.summary.credentials_stripped,
    inactiveCredentials: { authenticators: inactive.authenticators, agentCredentials: inactive.agent_credentials },
    items,
  };
}

// ───────────────────────── approvals ─────────────────────────

function decodeApproved(value: unknown): number | null {
  if (!isRecord(value) || !Array.isArray(value.approved)) return null;
  const approved = value.approved as unknown[];
  return approved.every((entry) => isRecord(entry) && typeof entry.kind === 'string' && typeof entry.id === 'string' && entry.result === 'approved') ? approved.length : null;
}

export class RecoveryApi {
  readonly #account: AccountApi;

  constructor(account: AccountApi) {
    this.#account = account;
  }

  /** Needs a recent verification (class `backup-export`); a 403 `step_up_required` is answered by the caller's step-up panel and is not replayed. */
  exportBackup(mode: BackupMode): Promise<ApiResult<ExportedFile>> {
    return this.#account.request(EXPORT_PATH, { body: { mode }, read: exportReader(mode), timeoutMs: EXPORT_TIMEOUT_MS });
  }

  /**
   * `archiveText` is the chosen file's text, untouched. The phrase is the service's own exact confirmation (the screen has already made the person
   * type it); the acknowledgement is whatever the person ticked and is never defaulted to true.
   */
  restore(archiveText: string, acknowledgeUnauthenticatedProvenance: boolean): Promise<ApiResult<RestoreResult>> {
    return this.#account.request(RESTORE_PATH, {
      body: { archive: archiveValue(archiveText), confirm: RESTORE_PHRASE, acknowledge_unauthenticated_provenance: acknowledgeUnauthenticatedProvenance },
      decode: decodeRestore,
      timeoutMs: RESTORE_TIMEOUT_MS,
    });
  }

  manifest(): Promise<ApiResult<ManifestData>> {
    return this.#account.read(MANIFEST_PATH, decodeManifest);
  }

  /** Resolves with the number of records approved. All-or-nothing on the server. Only the named kind, id and the reviewed digest are sent. */
  approve(items: readonly ItemRef[]): Promise<ApiResult<number>> {
    const seen = new Set(items.map((item) => `${item.kind}\u0000${item.id}`));
    if (items.length === 0 || items.length > MAX_APPROVALS || seen.size !== items.length) return Promise.resolve({ ok: false, status: 400, code: 'invalid_request' });
    return this.#account.request(APPROVALS_PATH, { body: { items: items.map((item) => (item.digest ? { kind: item.kind, id: item.id, digest: item.digest } : { kind: item.kind, id: item.id })) }, decode: decodeApproved });
  }
}
