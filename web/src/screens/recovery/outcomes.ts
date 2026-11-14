import type { ApprovalFailure, ApprovalRefusal, ApprovalState, ExportReason, ManifestKind, RestoreEnded, RestoreFormState, RestoreRejection } from './contract';
import { MANIFEST_KINDS } from './contract';

/**
 * How a FAILED call to the P1.18 routes becomes a screen state (P1.18.2). Pure presentation mapping, no I/O and no decision: it turns what the
 * service said into which words a person reads. It is the one place that knows which failures mean "nothing changed" and which mean "the session may
 * be gone", so the containers (P1.18.3) cannot get that distinction wrong in three places.
 *
 * Callers handle these BEFORE calling here, exactly as P1.17 does: a 401 is "your session ended" (signed-in frame), and a 403 `step_up_required` /
 * `assurance_unavailable` opens the P1.16 step-up panel and replays nothing (`outcomeOf` in containers/outcome.ts). Everything else comes here.
 *
 * The extra fields (`installationState`, `items`) are NOT yet carried by `ApiResult` (api/http.ts keeps only `status`, `code` and `guidance`): the
 * transport must be extended to keep the two documented fields, validated strictly, before these mappings can see them. Until then every
 * post-transition failure would be misread as "nothing changed". See docs/ui/p1.18-restore-ux-contract.md §7.
 */
export interface FailedCall {
  /** 0 for a connection failure or a timeout (`code: 'network'`). */
  status: number;
  /** The service's short error code, or '' when the body was not a documented error. `invalid_response` is the transport's own code for a 2xx body that did not decode. */
  code: string;
  /** `installation_state` of the body; only the value `restore_quarantine` is meaningful. */
  installationState?: string | undefined;
  /** `items` of a 409 `conflict` from the approvals route. */
  items?: ReadonlyArray<{ kind: string; id: string; reason: string }> | undefined;
}

/** The server never answered, or answered in a way that proves nothing about whether it acted. */
function unanswered(call: FailedCall): boolean {
  if (call.status === 0 || call.code === 'invalid_response' || call.code === 'network') return true;
  // A documented `unavailable` 503 is the service itself saying it did not start. Any other 5xx (a proxy, a crash) says nothing.
  return call.status >= 500 && !(call.status === 503 && call.code === 'unavailable');
}

// ───────────────────────── export ─────────────────────────

/** Export is read-only, so even a lost connection means only "no file". */
export function exportReasonOf(call: FailedCall): ExportReason {
  if (call.status === 403) return 'denied';
  if (call.status === 400 || call.status === 415) return 'invalid_request';
  if (call.status === 429) return 'rate_limited';
  return 'unavailable';
}

// ───────────────────────── restore ─────────────────────────

export type RestoreOutcome = { kind: 'form'; state: RestoreFormState } | { kind: 'ended'; ended: RestoreEnded };

function archiveRejection(code: string): RestoreRejection {
  switch (code) {
    case 'archive_unsupported_version':
      return 'archive_unsupported_version';
    case 'archive_integrity_failed':
      return 'archive_integrity_failed';
    case 'archive_inconsistent':
      return 'archive_inconsistent';
    default:
      return 'archive_malformed';
  }
}

/**
 * The order matters, and each rule is a sentence in docs/ui/p1.18-restore-ux-contract.md §6:
 *  1. `installation_state: restore_quarantine` on ANY failure: the first transaction committed. Sessions are gone, sign-in is closed, nothing was imported.
 *  2. No usable answer: the restore may have started. Never "nothing changed".
 *  3. 409 `provenance_unverified`: nothing was applied; ask for the acknowledgement.
 *  4. Everything else changed nothing and left the session alone.
 */
export function restoreOutcomeOf(call: FailedCall): RestoreOutcome {
  if (call.installationState === 'restore_quarantine' || call.code === 'restore_superseded') {
    return { kind: 'ended', ended: { kind: 'incomplete', cause: call.code === 'restore_superseded' ? 'superseded' : 'failed' } };
  }
  if (unanswered(call)) return { kind: 'ended', ended: { kind: 'unconfirmed' } };
  if (call.status === 409 && call.code === 'provenance_unverified') return { kind: 'form', state: { kind: 'needs_acknowledgement' } };
  const rejected = (reason: RestoreRejection): RestoreOutcome => ({ kind: 'form', state: { kind: 'rejected', reason } });
  if (call.status === 422) return rejected(archiveRejection(call.code));
  if (call.status === 403) return rejected('denied');
  if (call.status === 429) return rejected('rate_limited');
  if (call.status === 503) return rejected('unavailable');
  if (call.status === 409) return rejected('unavailable'); // `restore_quarantine` without a session cannot normally be seen; never claim an import happened
  return rejected('invalid_request');
}

// ───────────────────────── approvals ─────────────────────────

const REFUSALS = new Set<string>(['not_in_manifest', 'already_approved', 'subject_not_active', 'owner_not_active', 'not_quarantined', 'compromised', 'single_administrator', 'needs_reverification', 'unsupported']);

export function refusalOf(code: string): ApprovalRefusal {
  return REFUSALS.has(code) ? (code as ApprovalRefusal) : 'other';
}

function manifestKind(value: string): ManifestKind | null {
  return (MANIFEST_KINDS as readonly string[]).includes(value) ? (value as ManifestKind) : null;
}

export type ApprovalFailureState = Exclude<ApprovalState, { kind: 'idle' | 'working' | 'done' }>;

/** A conflict names every refused entry; an entry of a kind the page does not know is dropped (never displayed), and a conflict with none left is a plain refusal. */
export function approvalOutcomeOf(call: FailedCall): ApprovalFailureState {
  // Unlike a restore, EVERY 5xx is unknown here, including the documented 503: an approval can commit and then fail to notify the authorizer
  // (the same reason P1.17 maps a mutation 503 to `outcome_unknown`), so a 503 never proves nothing was approved.
  if (call.status === 0 || call.status >= 500 || call.code === 'invalid_response' || call.code === 'network') return { kind: 'rejected', reason: 'outcome_unknown' };
  if (call.status === 409 && call.code === 'restore_quarantine') return { kind: 'rejected', reason: 'still_quarantined' };
  if (call.status === 409 && call.code === 'conflict') {
    const failures: ApprovalFailure[] = [];
    for (const item of call.items ?? []) {
      const kind = manifestKind(item.kind);
      if (kind !== null && typeof item.id === 'string') failures.push({ kind, id: item.id, reason: refusalOf(item.reason) });
    }
    return failures.length > 0 ? { kind: 'conflict', failures } : { kind: 'rejected', reason: 'invalid' };
  }
  if (call.status === 403) return { kind: 'rejected', reason: 'denied' };
  if (call.status === 429) return { kind: 'rejected', reason: 'rate_limited' };
  return { kind: 'rejected', reason: 'invalid' };
}
