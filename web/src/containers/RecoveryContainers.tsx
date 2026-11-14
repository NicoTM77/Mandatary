import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AccountApi } from '../api/account';
import type { ApiResult } from '../api/http';
import { RecoveryApi, type ExportedFile } from '../api/recovery';
import { SecurityApi } from '../api/security';
import { ExportScreen } from '../screens/recovery/export';
import type { ApprovalState, BackupMode, ExportState, ItemRef, ManifestKind, ManifestLoad, RestoreEnded, RestoreFormState, RestoreRequest } from '../screens/recovery/contract';
import { RestoreEndedPage, RestoreScreen } from '../screens/recovery/restore';
import { ReviewScreen } from '../screens/recovery/review';
import { AGENT_TOKENS_ROUTE, POLICY_ROUTES } from '../screens/policy/nav';
import { approvalOutcomeOf, exportReasonOf, restoreOutcomeOf } from '../screens/recovery/outcomes';
import type { Navigate } from './LoginContainer';
import { outcomeOf } from './outcome';
import { SignedIn, type SignedInContext } from './SignedIn';
import { StepUpGate, useStepUp } from './StepUpGate';

/**
 * Export, restore and reapproval (P1.18.3) over `/api/v1/admin/{backup/export,restore,restore/manifest,restore/approvals}`.
 *
 * The screens are stateless presentation (P1.18.2). These containers own fetching, the CSRF token (inside AccountApi), step-up and the mapping
 * of HTTP outcomes to screen states (docs/ui/p1.18-restore-ux-contract.md §6). Every decision is the server's: a hidden link, a disabled button
 * or a page shown to the wrong person grants and protects nothing, because the same routes refuse everyone who is not the fresh, second-factor
 * administrator, whatever this code sends. Nothing here reads, verifies or interprets an archive: the chosen file is handed to the API client,
 * which places it in the request as one value; whether it is a backup, is authentic or is consistent is the service's answer.
 *
 * Three rules every handler below follows:
 *  - A step-up (403 `step_up_required` / `assurance_unavailable`) opens the P1.16 panel in place and the blocked request is NOT replayed.
 *  - A restore answer that is missing, late or unreadable is "couldn't confirm", never "nothing changed" (the service may have committed).
 *  - A restore that reached the first transaction, or finished, replaces the whole page: the session behind the shell is gone.
 */

// ───────────────────────── step-up plumbing ─────────────────────────

/** What a handler does after a failed call's common prefix (session ended, step-up) has been handled. True means it was handled here. */
function useRecoveryGate(context: SignedInContext, onOpen: () => void) {
  const { api, view, navigate, refresh } = context;
  const sec = useMemo(() => new SecurityApi(api), [api]);
  const stepUp = useStepUp(sec, view, refresh, onOpen);
  /** True when the failure was an ended session or a step-up request, both fully handled; the caller then shows nothing more. */
  function intercept(result: ApiResult<unknown>, label: string): boolean {
    const outcome = outcomeOf(result);
    if (outcome.kind === 'ended') {
      navigate('/login');
      return true;
    }
    if (outcome.kind === 'step_up' || outcome.kind === 'assurance_unavailable') {
      stepUp.show(label, outcome.kind === 'assurance_unavailable');
      return true;
    }
    return false;
  }
  return { intercept, gate: <StepUpGate controls={stepUp} view={view} /> };
}

function failed(result: ApiResult<unknown>) {
  if (result.ok) return { status: 200, code: '' };
  return { status: result.status, code: result.code, installationState: result.installationState, items: result.items };
}

// ───────────────────────── export ─────────────────────────

/** Turns the response body into a download and retains nothing: the object URL is revoked at once. */
export function saveToDisk(file: ExportedFile): void {
  const url = URL.createObjectURL(file.blob);
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = file.fileName;
    link.rel = 'noopener';
    document.body.append(link);
    link.click();
    link.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function ExportContainer({ api, navigate, save = saveToDisk }: { api?: AccountApi; navigate?: Navigate; save?: (file: ExportedFile) => void }) {
  return (
    <SignedIn api={api} navigate={navigate} current="backup-export">
      {(context) => <ExportPage {...context} save={save} />}
    </SignedIn>
  );
}

function ExportPage({ api, save, ...context }: SignedInContext & { save: (file: ExportedFile) => void }) {
  const recovery = useMemo(() => new RecoveryApi(api), [api]);
  const [state, setState] = useState<ExportState>({ kind: 'idle' });
  const running = useRef(false);
  const { intercept, gate } = useRecoveryGate({ api, ...context }, () => setState({ kind: 'idle' }));

  function onExport(mode: BackupMode) {
    if (running.current) return;
    running.current = true;
    setState({ kind: 'working', mode });
    void recovery
      .exportBackup(mode)
      .then((result) => {
        if (result.ok) {
          save(result.data);
          setState({ kind: 'done', mode: result.data.mode, backupId: result.data.backupId, fileName: result.data.fileName });
          return;
        }
        if (intercept(result, 'Export a backup')) {
          setState({ kind: 'idle' });
          return;
        }
        // Export is read-only: every failure, including a lost connection, means only "no file".
        setState({ kind: 'rejected', reason: exportReasonOf(failed(result)) });
      })
      .finally(() => {
        running.current = false;
      });
  }

  return (
    <>
      {gate}
      <ExportScreen state={state} onExport={onExport} />
    </>
  );
}

// ───────────────────────── restore ─────────────────────────

export function RestoreContainer({ api, navigate, reload = () => globalThis.location.reload() }: { api?: AccountApi; navigate?: Navigate; reload?: () => void }) {
  const [ended, setEnded] = useState<RestoreEnded | null>(null);
  // Once the restore has closed or may have closed the session, the signed-in shell is unmounted: its timers, its 401 handling and its
  // account strip all describe a session that no longer exists. Nothing re-reads the session and nothing offers a retry.
  if (ended !== null) return <RestoreEndedPage ended={ended} onReload={reload} />;
  return (
    <SignedIn api={api} navigate={navigate} current="backup-restore">
      {(context) => <RestorePage {...context} onEnded={setEnded} />}
    </SignedIn>
  );
}

function RestorePage({ api, onEnded, ...context }: SignedInContext & { onEnded: (ended: RestoreEnded) => void }) {
  const recovery = useMemo(() => new RecoveryApi(api), [api]);
  const [state, setState] = useState<RestoreFormState>({ kind: 'idle' });
  const running = useRef(false);
  const { intercept, gate } = useRecoveryGate({ api, ...context }, () => setState({ kind: 'idle' }));

  async function run({ file, acknowledgeUnauthenticatedProvenance }: RestoreRequest) {
    let text: string;
    try {
      text = await file.text();
    } catch {
      // Nothing was sent, so nothing changed: the same words as any refusal before the transition.
      setState({ kind: 'rejected', reason: 'invalid_request' });
      return;
    }
    const result = await recovery.restore(text, acknowledgeUnauthenticatedProvenance);
    if (result.ok) {
      api.forget(); // the session is gone with the restore: its CSRF token is dead
      onEnded({ kind: 'complete', report: result.data.report, authorizerNotified: result.data.authorizerNotified });
      return;
    }
    if (intercept(result, 'Restore a backup')) {
      setState({ kind: 'idle' });
      return;
    }
    const outcome = restoreOutcomeOf(failed(result));
    if (outcome.kind === 'ended') {
      api.forget();
      onEnded(outcome.ended);
      return;
    }
    setState(outcome.state);
  }

  function onRestore(request: RestoreRequest) {
    if (running.current) return;
    running.current = true;
    setState({ kind: 'working' });
    void run(request).finally(() => {
      running.current = false;
    });
  }

  return (
    <>
      {gate}
      <RestoreScreen state={state} onRestore={onRestore} />
    </>
  );
}

// ───────────────────────── reapproval ─────────────────────────

/** Where a restored record can be inspected in the P1.17 management pages; a role or an address has no page. */
export function inspectHref(kind: ManifestKind): string | undefined {
  switch (kind) {
    case 'user':
      return POLICY_ROUTES.users;
    case 'group':
    case 'user_membership':
    case 'agent_membership':
      return POLICY_ROUTES.groups;
    case 'agent':
      return POLICY_ROUTES.agents;
    case 'policy':
      return POLICY_ROUTES.rules;
    default:
      return undefined;
  }
}

export function ReviewContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="backup-review">
      {(context) => <ReviewPage {...context} />}
    </SignedIn>
  );
}

function ReviewPage({ api, navigate, ...context }: SignedInContext) {
  const recovery = useMemo(() => new RecoveryApi(api), [api]);
  const [load, setLoad] = useState<ManifestLoad>({ kind: 'loading' });
  const [approval, setApproval] = useState<ApprovalState>({ kind: 'idle' });
  const latest = useRef(0);
  const running = useRef(false);
  const { intercept, gate } = useRecoveryGate({ api, navigate, ...context }, () => setApproval({ kind: 'idle' }));

  /** Reads the manifest, keeping the page (and the selection) in place; a response older than the latest request is ignored. */
  const fetchManifest = useCallback(() => {
    const ticket = ++latest.current;
    void recovery.manifest().then((result) => {
      if (ticket !== latest.current) return;
      if (result.ok) setLoad({ kind: 'ready', data: result.data });
      else if (result.status === 401) navigate('/login');
      else if (result.status === 404 && result.code === 'no_restore') setLoad({ kind: 'no_restore' });
      else if (result.status === 403) setLoad({ kind: 'denied' });
      else setLoad({ kind: 'failed' });
    });
  }, [recovery, navigate]);

  useEffect(() => {
    fetchManifest(); // the state is already `loading`; only the answer sets state
  }, [fetchManifest]);

  function onApprove(items: readonly ItemRef[]) {
    if (running.current) return;
    running.current = true;
    setApproval({ kind: 'working' });
    void recovery
      .approve(items)
      .then((result) => {
        if (result.ok) {
          setApproval({ kind: 'done', count: result.data });
          fetchManifest();
          return;
        }
        if (intercept(result, 'Approve restored records')) {
          setApproval({ kind: 'idle' });
          return;
        }
        const outcome = approvalOutcomeOf(failed(result));
        setApproval(outcome);
        // A conflict or an unknown outcome means the list may differ from what the person saw: read it again, keeping the page in place.
        if (outcome.kind === 'conflict' || (outcome.kind === 'rejected' && (outcome.reason === 'outcome_unknown' || outcome.reason === 'still_quarantined'))) fetchManifest();
      })
      .finally(() => {
        running.current = false;
      });
  }

  return (
    <>
      {gate}
      <ReviewScreen
        load={load}
        approval={approval}
        inspectHref={(kind) => inspectHref(kind)}
        credentialsHref={(agentId) => `${AGENT_TOKENS_ROUTE}#agent=${encodeURIComponent(agentId)}`}
        onRetry={() => {
          setApproval({ kind: 'idle' });
          setLoad({ kind: 'loading' });
          fetchManifest();
        }}
        onApprove={onApprove}
      />
    </>
  );
}
