import { useState } from 'react';
import { Alert, Badge, Button, CheckboxField, ConfirmPanel, EmptyState, Icon, PageHeader, Panel, Skeleton } from '../../ui';
import { formatDate } from '../../ui/format';
import { AccountStateBadge, AdminOnlyNotice, Fact, Facts } from '../policy/shared';
import { RejectionAlert, commonRejection, useFocusWhen, type Rejection } from '../shared';
import { MAX_APPROVALS, type ApprovalFailure, type ApprovalRefusal, type ApprovalState, type Comparison, type ItemRef, type ManifestData, type ManifestKind, type ManifestRow, type ReviewScreenProps } from './contract';
import { DetailBlock, exactText, reviewable, reviewableCopy } from './detail';
import { Ident, KIND_LABEL, MODE_NAME, countsSentence } from './shared';

const keyOf = (item: ItemRef): string => `${item.kind}\u0000${item.id}`;

// ───────────────────────── copy ─────────────────────────

/** Why the service refused one entry. These are the fixed codes; the page never shows more than the code explains. */
function refusalCopy(reason: ApprovalRefusal): string {
  switch (reason) {
    case 'not_in_manifest':
      return 'It isn’t in this restore’s list any more. Reload the page.';
    case 'already_approved':
      return 'It is already approved.';
    case 'subject_not_active':
      return 'The user, group or agent it belongs to isn’t approved yet. Approve that one first, or select it in the same request.';
    case 'owner_not_active':
      return 'Its owner isn’t approved yet. Approve the owner first, or select it in the same request.';
    case 'not_quarantined':
      return 'It changed since this page loaded. Reload the page.';
    case 'stale_details':
      return 'It changed after you reviewed it, so it was not approved. Reload the list and review it again.';
    case 'compromised':
      return 'It is marked compromised, so it can’t be approved.';
    case 'single_administrator':
      return 'The administrator role can’t be approved here.';
    case 'needs_reverification':
      return 'A notification address has to be verified again by the person it belongs to.';
    case 'unsupported':
      return 'This kind of record can’t be approved in this version.';
    case 'other':
      return 'Mandatary refused it.';
  }
}

function blockedCopy(row: ManifestRow): string {
  switch (row.blockedReason) {
    case 'single_administrator':
      return 'Can’t be approved here. This installation has one administrator, and the host recovery sets who it is.';
    case 'needs_reverification':
      return 'Can’t be approved. The address has to be verified again by the person it belongs to.';
    case 'compromised':
      return 'Marked compromised, so it can’t be approved. Mandatary also refuses any attempt to approve it.';
    case 'unsupported':
    case null:
      return 'Can’t be approved in this version.';
  }
}

function rejection(reason: Extract<ApprovalState, { kind: 'rejected' }>['reason']): Rejection {
  switch (reason) {
    case 'denied':
      return { title: 'That wasn’t allowed', body: 'Only the administrator, signed in with a recent second factor, can approve restored records. Nothing was approved.' };
    case 'invalid':
      return { title: 'That request couldn’t be read', body: `Select between 1 and ${MAX_APPROVALS} records and try again. Nothing was approved.` };
    case 'rate_limited':
      return { ...commonRejection('rate_limited'), body: 'Wait a minute, then try again. Nothing was approved.' };
    case 'still_quarantined':
      return { title: 'Mandatary is still in restore quarantine', body: 'Records can be approved only after the host recovery has ended quarantine. Nothing was approved.' };
    case 'outcome_unknown':
      return { title: 'Mandatary couldn’t confirm the result', body: 'Some or all of the records may have been approved. Reload the list and check before you approve again.' };
  }
}

// ───────────────────────── outcome of the last approval ─────────────────────────

function Outcome({ approval, data, onRetry }: { approval: ApprovalState; data: ManifestData; onRetry: () => void }) {
  const ref = useFocusWhen(approval.kind === 'done' || approval.kind === 'conflict');
  if (approval.kind === 'done') {
    return (
      <Alert ref={ref} tone="success" title={`Approved ${approval.count} ${approval.count === 1 ? 'record' : 'records'}`}>
        They are active now. Approving never restores a sign-in method or an agent token: set those up again where a record below says so.
      </Alert>
    );
  }
  if (approval.kind === 'conflict') {
    const label = (failure: ApprovalFailure) => {
      const row = data.items.find((item) => item.kind === failure.kind && item.id === failure.id);
      return row ? `${KIND_LABEL[row.kind]} ${row.label}` : KIND_LABEL[failure.kind];
    };
    const count = approval.failures.length;
    return (
      <Alert ref={ref} tone="danger" title="Nothing was approved">
        <p>
          Approval is all-or-nothing, so none of the records you selected was approved. {count} {count === 1 ? 'record' : 'records'} couldn’t be:
        </p>
        <ul className="mt-1.5 list-disc space-y-1 pl-5">
          {approval.failures.map((failure) => (
            <li key={keyOf(failure)}>
              <span className="font-medium">{label(failure)}.</span> {refusalCopy(failure.reason)}
            </li>
          ))}
        </ul>
        <p className="mt-1.5">Your selection is kept. Change it and try again.</p>
        {approval.failures.some((failure) => failure.reason === 'stale_details' || failure.reason === 'not_quarantined' || failure.reason === 'not_in_manifest') ? (
          <div className="mt-2">
            <Button variant="secondary" onClick={onRetry}>
              Reload the list
            </Button>
          </div>
        ) : null}
      </Alert>
    );
  }
  if (approval.kind === 'rejected') {
    return (
      <RejectionAlert rejection={rejection(approval.reason)} active>
        {approval.reason === 'outcome_unknown' ? (
          <Button variant="secondary" onClick={onRetry}>
            Reload the list
          </Button>
        ) : null}
      </RejectionAlert>
    );
  }
  return null;
}

// ───────────────────────── one record ─────────────────────────

function EffectWord({ effect }: { effect: 'allow' | 'deny' }) {
  return (
    <span className="inline-flex items-center gap-1.5 font-medium">
      <Icon name={effect === 'allow' ? 'check' : 'ban'} className="size-4" />
      {effect === 'allow' ? 'Allow' : 'Deny'}
    </span>
  );
}

const MFA_LABEL = { optional: 'Second factor optional', required: 'Second factor required', webauthn: 'Security key required' } as const;

/** Imported against effective, side by side, with the difference written out. Rendered only for the two comparisons the service exposes. */
function CompareBlock({ comparison }: { comparison: Exclude<Comparison, { kind: 'none' }> }) {
  const differs = comparison.imported !== comparison.effective;
  const left = comparison.kind === 'mfa' ? MFA_LABEL[comparison.imported] : <EffectWord effect={comparison.imported} />;
  const right = comparison.kind === 'mfa' ? MFA_LABEL[comparison.effective] : <EffectWord effect={comparison.effective} />;
  return (
    <div className="mt-2 space-y-1.5">
      <dl className="grid gap-2 sm:grid-cols-2">
        <div className="rounded-control border border-line bg-sunken p-3">
          <dt className="text-xs font-semibold text-muted">In the file</dt>
          <dd className="mt-0.5">{left}</dd>
        </div>
        <div className={`rounded-control border p-3 ${differs ? 'border-warn bg-warn-soft' : 'border-line bg-sunken'}`}>
          <dt className="text-xs font-semibold text-muted">Applied when approved</dt>
          <dd className="mt-0.5">{right}</dd>
        </div>
      </dl>
      {differs ? (
        <p className="flex items-start gap-1.5 text-sm font-medium text-warn">
          <Icon name="alert" className="mt-0.5 size-4" />
          <span>
            {comparison.kind === 'rule' && comparison.localDenyKept
              ? 'A Deny rule with this id already existed here and was kept. An Allow from the file never replaces it.'
              : 'These differ. Approving applies the setting on the right, not the one in the file.'}
          </span>
        </p>
      ) : null}
    </div>
  );
}

interface RowProps {
  row: ManifestRow;
  selectable: boolean;
  checked: boolean;
  failure?: ApprovalFailure | undefined;
  inspectHref: ReviewScreenProps['inspectHref'];
  credentialsHref: ReviewScreenProps['credentialsHref'];
  onToggle: (checked: boolean) => void;
}

function followUp(row: ManifestRow, credentialsHref: ReviewScreenProps['credentialsHref']) {
  const approved = row.decision === 'approved';
  if (row.kind === 'user' && row.needs === 'credential_enrollment') return approved ? 'Approved. It has no sign-in method yet; none is restored.' : 'Approving doesn’t bring back a sign-in method.';
  if (row.kind === 'agent' && row.needs === 'token_reissue') {
    return approved ? (
      <>
        Approved. It has no token. Issue one on the{' '}
        <a href={credentialsHref(row.id)} className="font-medium text-accent-text underline underline-offset-2">
          Agent tokens page <span className="sr-only">for {row.label}</span>
        </a>
        .
      </>
    ) : (
      'Approving doesn’t bring back its tokens; a new one is issued afterwards.'
    );
  }
  return null;
}

function RecordRow({ row, selectable, checked, failure, inspectHref, credentialsHref, onToggle }: RowProps) {
  // For a rule or membership the heading IS the exact sentence (effect, operation, subject, endpoint, selector, or principal and group): the
  // same text is the checkbox's accessible name, the row and the confirmation (FC4-1). Other kinds keep the service's label.
  const exact = exactText(row);
  const heading = (
    <>
      <span className="text-sm text-muted">{KIND_LABEL[row.kind]}</span> <span className="font-medium">{exact ?? row.label}</span>
    </>
  );
  const blockedByDetail = row.decision === 'pending' && row.approvable ? reviewable(row) : ({ ok: true } as const);
  const href = inspectHref?.(row.kind, row.id);
  const note = followUp(row, credentialsHref);
  return (
    <li className="py-4 first:pt-0 last:pb-0" data-record={`${row.kind}:${row.id}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          {selectable ? <CheckboxField label={heading} checked={checked} onChange={onToggle} /> : <p className="break-words">{heading}</p>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {row.decision === 'approved' ? (
            <Badge tone="success" icon="check">
              Approved
            </Badge>
          ) : (
            <AccountStateBadge state="quarantined" />
          )}
          {row.origin === 'local_retained' ? (
            <Badge tone="neutral" icon="info">
              Not in the file
            </Badge>
          ) : null}
          {row.comparison.kind === 'mfa' && row.comparison.compromised ? (
            <Badge tone="danger" icon="error">
              Marked compromised in the file
            </Badge>
          ) : null}
        </div>
      </div>
      <div className={selectable ? '-mt-1 ml-8' : ''}>
        {row.origin === 'local_retained' ? <p className="mt-1 text-sm text-muted">It was here before the restore and has been switched off. A restore never deletes anything.</p> : null}
        {/* Only an unusual source state is worth a line: "active" in the file would read as if it were active now. It is reference only. */}
        {row.origin === 'imported' && row.sourceState && row.sourceState !== 'active' ? <p className="mt-1 text-sm text-muted">In the file it was {row.sourceState}. That is for reference only and grants nothing.</p> : null}
        {exact !== null ? <DetailBlock row={row} /> : null}
        {row.comparison.kind !== 'none' && row.decision === 'pending' ? <CompareBlock comparison={row.comparison} /> : null}
        {note ? <p className="mt-1 text-sm text-muted">{note}</p> : null}
        {!blockedByDetail.ok ? (
          <p className="mt-1 flex items-start gap-1.5 text-sm font-medium">
            <Icon name="lock" className="mt-0.5 size-4 text-muted" />
            <span>{reviewableCopy(blockedByDetail.why)}</span>
          </p>
        ) : null}
        {row.decision === 'pending' && !row.approvable ? (
          <p className="mt-1 flex items-start gap-1.5 text-sm font-medium">
            <Icon name="lock" className="mt-0.5 size-4 text-muted" />
            <span>{blockedCopy(row)}</span>
          </p>
        ) : null}
        {failure ? (
          <p className="mt-1 flex items-start gap-1.5 text-sm font-medium text-danger">
            <Icon name="error" className="mt-0.5 size-4" />
            <span>Not approved. {refusalCopy(failure.reason)}</span>
          </p>
        ) : null}
        {href ? (
          <p className="mt-1 text-sm">
            <a href={href} className="font-medium text-accent-text underline underline-offset-2">
              See details <span className="sr-only">of {KIND_LABEL[row.kind]} {row.label}</span>
            </a>
          </p>
        ) : null}
      </div>
    </li>
  );
}

// ───────────────────────── sections ─────────────────────────

const SECTIONS: ReadonlyArray<readonly [title: string, kinds: readonly ManifestKind[]]> = [
  ['Endpoint', ['endpoint']],
  ['Users', ['user']],
  ['Groups', ['group']],
  ['Agents', ['agent']],
  ['Group members', ['user_membership', 'agent_membership']],
  ['Rules', ['policy']],
];

function Summary({ data }: { data: ManifestData }) {
  const pending = data.items.filter((item) => item.decision === 'pending').length;
  const approved = data.items.length - pending;
  const credentials = countsSentence({ authenticators: data.inactiveCredentials.authenticators, agent_credentials: data.inactiveCredentials.agentCredentials });
  return (
    <Panel title="This restore" description="The latest restore on this installation.">
      <Facts>
        <Fact label="Backup">
          <Ident>{data.backupId}</Ident> ({MODE_NAME[data.mode].toLowerCase()})
        </Fact>
        <Fact label="Restored">{formatDate(data.restoredAt) || 'Time unknown'}</Fact>
        <Fact label="Origin">{data.provenance === 'authenticated' ? 'Verified with this installation’s key.' : 'Not verifiable with this installation’s key; restored after it was acknowledged.'}</Fact>
        <Fact label="Records">
          {pending} waiting for approval, {approved} approved
        </Fact>
        <Fact label="Credentials">{data.credentialsStripped ? 'None. The file was a clean backup.' : credentials ? `${credentials}, kept switched off for reference. They can’t be switched back on.` : 'None.'}</Fact>
      </Facts>
    </Panel>
  );
}

function Review({ data, approval, inspectHref, credentialsHref, initial, onRetry, onApprove }: Omit<ReviewScreenProps, 'load'> & { data: ManifestData }) {
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set((initial?.selected ?? []).map(keyOf)));
  const [confirming, setConfirming] = useState(initial?.confirming ?? false);
  const [lastKind, setLastKind] = useState(approval.kind);
  const triggerId = 'review-approve-open';

  // Adjusting state while rendering (not in an effect): an answer closes the confirmation so the answer is what the person lands on, and a
  // successful approval empties the selection. A refusal keeps the selection so it can be changed.
  if (approval.kind !== lastKind) {
    setLastKind(approval.kind);
    if (approval.kind === 'done' || approval.kind === 'conflict' || approval.kind === 'rejected') setConfirming(false);
    if (approval.kind === 'done') setSelected(new Set());
  }

  const pending = data.items.filter((row) => row.decision === 'pending');
  const approved = data.items.filter((row) => row.decision === 'approved');
  // Selectable = the server says approvable AND the page can describe exactly what approving it restores (FC4-1).
  const selectableRows = pending.filter((row) => row.approvable && reviewable(row).ok);
  const chosen = selectableRows.filter((row) => selected.has(keyOf(row)));
  const blocked = pending.filter((row) => !row.approvable);
  const working = approval.kind === 'working';
  const tooMany = chosen.length > MAX_APPROVALS;
  const failures = new Map<string, ApprovalFailure>(approval.kind === 'conflict' ? approval.failures.map((failure) => [keyOf(failure), failure]) : []);

  const toggle = (row: ManifestRow, on: boolean) =>
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(keyOf(row));
      else next.delete(keyOf(row));
      return next;
    });

  const rowFor = (row: ManifestRow, selectable: boolean) => (
    <RecordRow key={keyOf(row)} row={row} selectable={selectable} checked={selected.has(keyOf(row))} failure={failures.get(keyOf(row))} inspectHref={inspectHref} credentialsHref={credentialsHref} onToggle={(on) => toggle(row, on)} />
  );

  const count = chosen.length;
  const noun = count === 1 ? 'record' : 'records';
  return (
    <div className="space-y-6">
      <PageHeader title="Review restored access" description="A restore switches records off. Approve each one you still want, by name." />
      <Alert tone="info" role="none" title="Nothing listed here is active until you approve it">
        Approving a record gives back its access and nothing else: it never restores a sign-in method or an agent token. A record you don’t approve stays switched off.
      </Alert>
      <Summary data={data} />
      <Outcome approval={approval} data={data} onRetry={onRetry} />
      <Panel title="Waiting for approval" description={`${pending.length} ${pending.length === 1 ? 'record' : 'records'}`}>
        {pending.length === 0 ? (
          <EmptyState title="Nothing is waiting for approval" description="Every record from this restore has been approved." headingLevel={3} />
        ) : (
          <>
            {selectableRows.length > 0 ? (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-control border border-line bg-sunken p-3">
                  <p role="status" className="text-sm">
                    {count === 0 ? 'Nothing selected. Tick the records you want to approve.' : `${count} ${noun} selected.`}
                    {tooMany ? ` Select at most ${MAX_APPROVALS} at a time.` : ''}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="quiet" disabled={count === 0 || working} onClick={() => setSelected(new Set())}>
                      Clear selection
                    </Button>
                    <Button id={triggerId} icon="check" disabled={count === 0 || tooMany || working} aria-expanded={confirming} onClick={() => setConfirming(true)}>
                      {count === 0 ? 'Approve selected…' : `Approve ${count} selected…`}
                    </Button>
                  </div>
                </div>
                <p className="text-sm text-muted">Approve a user, group or agent together with the memberships and rules that depend on it. Mandatary applies them in dependency order, and refuses a record whose user, group or agent isn’t approved.</p>
                {confirming && count > 0 ? (
                  <ConfirmPanel
                    title={`Approve ${count} ${noun}?`}
                    confirmLabel={`Approve ${count} ${noun}`}
                    busyLabel="Approving…"
                    cancelLabel="Not yet"
                    tone="warning"
                    busy={working}
                    returnFocusId={triggerId}
                    onCancel={() => setConfirming(false)}
                    onConfirm={() => onApprove(chosen.map(({ kind, id, digest }) => ({ kind, id, digest })))}
                  >
                    <p>These become effective straight away. Approval is all-or-nothing: if any one can’t be approved, none is. It never restores a sign-in method or an agent token.</p>
                    <ul tabIndex={0} aria-label="Records to approve" className="mt-2 max-h-64 list-disc space-y-0.5 overflow-y-auto rounded-control pl-5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus">
                      {chosen.map((row) => (
                        <li key={keyOf(row)} className="break-words">
                          {KIND_LABEL[row.kind]} <span className="font-medium">{exactText(row) ?? row.label}</span>
                        </li>
                      ))}
                    </ul>
                  </ConfirmPanel>
                ) : null}
              </div>
            ) : null}
            {SECTIONS.map(([title, kinds]) => {
              const rows = pending.filter((row) => row.approvable && kinds.includes(row.kind));
              if (rows.length === 0) return null;
              return (
                <section key={title} aria-label={title}>
                  <h3 className="mb-2 text-base font-semibold">{title}</h3>
                  <ul className="divide-y divide-line">{rows.map((row) => rowFor(row, reviewable(row).ok))}</ul>
                </section>
              );
            })}
            {blocked.length > 0 ? (
              <section aria-label="Not approved here">
                <h3 className="mb-1 text-base font-semibold">Not approved here</h3>
                <p className="mb-2 text-sm text-muted">These stay switched off. The service never approves them from this page.</p>
                <ul className="divide-y divide-line">{blocked.map((row) => rowFor(row, false))}</ul>
              </section>
            ) : null}
          </>
        )}
      </Panel>
      {approved.length > 0 ? (
        <Panel title="Approved" description={`${approved.length} ${approved.length === 1 ? 'record' : 'records'}`}>
          <ul className="divide-y divide-line">{approved.map((row) => rowFor(row, false))}</ul>
        </Panel>
      ) : null}
    </div>
  );
}

/**
 * Review restored access and approve it, one named record at a time (P1.18.2). It renders the manifest the service exposes and nothing more: the
 * label, the kind, whether the file or this installation was the source, and imported-versus-effective only for the two comparisons the service
 * defines. There is no select-all, no default selection and no approve-everything button, because the service has no such operation. A record the
 * service marks `approvable: false` has no checkbox and says why. The page never decides that a record is safe: the server refuses what it must,
 * and a refusal is shown per record.
 */
export function ReviewScreen({ load, ...rest }: ReviewScreenProps) {
  switch (load.kind) {
    case 'loading':
      return (
        <div className="space-y-6">
          <PageHeader title="Review restored access" />
          <Skeleton label="restored records" lines={4} />
        </div>
      );
    case 'denied':
      return (
        <div className="space-y-6">
          <PageHeader title="Review restored access" />
          <AdminOnlyNotice area="restored access" />
        </div>
      );
    case 'failed':
      return (
        <div className="space-y-6">
          <PageHeader title="Review restored access" />
          <Alert tone="danger" title="Couldn’t load the restored records" actions={<Button onClick={rest.onRetry}>Try again</Button>}>
            Nothing was changed. Try again in a moment; if it keeps happening, check the server log.
          </Alert>
        </div>
      );
    case 'no_restore':
      return (
        <div className="space-y-6">
          <PageHeader title="Review restored access" />
          <EmptyState title="No restore to review" description="Nothing has been restored on this installation, so there is nothing to approve. After a restore and the host recovery, the records it switched off are listed here." />
        </div>
      );
    case 'ready':
      return <Review data={load.data} {...rest} />;
  }
}
