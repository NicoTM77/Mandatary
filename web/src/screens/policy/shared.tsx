import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, Badge, Button, ConfirmPanel, Skeleton, TextField } from '../../ui';
import { RejectionAlert, commonRejection, useFocusWhen, type Rejection } from '../shared';
import type { AccountState, Load, Mutation, MutationReason, Removal } from './contract';
import { validateIdentifier } from './names';

// ───────────────────────── authority vs. operation ─────────────────────────

/**
 * The one statement every management page repeats where it matters: running Mandatary and deciding who may do what
 * is a different power from doing it. Present on every page (not collapsible) because the administrator is exactly
 * the person who would otherwise assume the role lets them operate containers.
 */
export function AuthorityNote() {
  return (
    <Alert tone="info" role="none" title="Managing access isn’t the same as having it">
      The policy administrator decides who may do what, but the role allows no container operation by itself. Owning an agent allows none either. Only a rule that names an account, a group or an agent does.
    </Alert>
  );
}

/** The page for anyone who isn't the policy administrator signed in with a second factor. Says nothing about who is. */
export function AdminOnlyNotice({ area }: { area: string }) {
  return (
    <Alert tone="warning" role="alert" title="Policy administration isn’t available to this session">
      Only the policy administrator, signed in with a second factor, can manage {area}. Nothing is shown here. Hiding this page from other accounts is a convenience: Mandatary refuses every request from them whatever
      their browser sends.
    </Alert>
  );
}

// ───────────────────────── load states ─────────────────────────

/** Renders loading, failure and denial the same way for every list; `children` only ever sees data that loaded. */
export function ManagedLoad<T>({ load, label, area, onRetry, children }: { load: Load<T>; label: string; area: string; onRetry: () => void; children: (data: T) => ReactNode }) {
  switch (load.kind) {
    case 'loading':
      return <Skeleton label={label} lines={4} />;
    case 'denied':
      return <AdminOnlyNotice area={area} />;
    case 'failed':
      return (
        <Alert tone="danger" title={`Couldn’t load ${label}`} actions={<Button onClick={onRetry}>Try again</Button>}>
          Nothing was changed. Try again in a moment; if it keeps happening, check the server log.
        </Alert>
      );
    case 'ready':
      return <>{children(load.data)}</>;
  }
}

// ───────────────────────── outcomes ─────────────────────────

function reasonCopy(reason: MutationReason): Rejection {
  switch (reason) {
    case 'denied':
      return { title: 'That change wasn’t allowed', body: 'Mandatary refused it. You may not be the policy administrator, or the item is in a state that can’t be changed. Nothing was changed.' };
    case 'not_found':
      return { title: 'That no longer exists', body: 'It may have been removed in another window. Reload the list to see what is there now. Nothing was changed.' };
    case 'conflict':
      return { title: 'That conflicts with what exists', body: 'For example the name is already used, an account involved is disabled, or something still refers to it. Nothing was changed.' };
    case 'invalid':
      return { title: 'That wasn’t accepted', body: 'Check what you entered and try again. Nothing was changed.' };
    case 'outcome_unknown':
      return { title: 'Mandatary couldn’t confirm the result', body: 'The change may or may not have been saved. Reload the list and check before trying again; if you were removing access, make sure it is really gone.' };
    case 'rate_limited':
      return commonRejection('rate_limited');
  }
}

/**
 * Shows the outcome of the last command where it belongs: `target` is the row id, `create` or `editor` this
 * instance stands for, or undefined for the page. Moves focus to the outcome when it appears, so a keyboard or
 * screen-reader user lands on the result (and is not left on a control that has just disappeared).
 */
export function MutationNotice({ mutation, target, onReload }: { mutation: Mutation; target?: string; onReload?: () => void }) {
  const mine = (mutation.kind === 'done' || mutation.kind === 'rejected') && mutation.target === target;
  const ref = useFocusWhen(mine);
  if (!mine) return null;
  if (mutation.kind === 'done') {
    return (
      <Alert ref={ref} tone="success" title={mutation.message}>
        {null}
      </Alert>
    );
  }
  if (mutation.kind !== 'rejected') return null;
  const copy = reasonCopy(mutation.reason);
  return (
    <RejectionAlert rejection={copy} active>
      {mutation.reason === 'outcome_unknown' && onReload ? (
        <Button variant="secondary" onClick={onReload}>
          Reload the list
        </Button>
      ) : null}
    </RejectionAlert>
  );
}

export function isWorking(mutation: Mutation, target?: string): boolean {
  return mutation.kind === 'working' && mutation.target === target;
}

// ───────────────────────── badges ─────────────────────────

export function AccountStateBadge({ state }: { state: AccountState }) {
  switch (state) {
    case 'active':
      return (
        <Badge tone="success" icon="check">
          Active
        </Badge>
      );
    case 'disabled':
      return (
        <Badge tone="neutral" icon="ban">
          Disabled
        </Badge>
      );
    case 'quarantined':
      return (
        <Badge tone="warning" icon="clock">
          Waiting for approval
        </Badge>
      );
  }
}

export function AdministratorBadge() {
  return (
    <Badge tone="info" icon="shield">
      Policy administrator
    </Badge>
  );
}

// ───────────────────────── lifecycle confirmations ─────────────────────────

export type Noun = 'user' | 'group' | 'agent';

interface LifecycleCopy {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  busyLabel: string;
  tone: 'danger' | 'warning';
}

/** Copy for disabling, enabling and deleting. Each confirmation names the object and states the consequence. */
export function lifecycleCopy(noun: Noun, action: 'disable' | 'enable' | 'delete', name: string): LifecycleCopy {
  if (action === 'delete') {
    const dependents = noun === 'user' ? 'Mandatary refuses to delete an account that still owns an agent, has a rule or belongs to a group.' : noun === 'group' ? 'Mandatary refuses to delete a group that still has members, owns an agent or has a rule.' : 'Its token records go with it.';
    return { title: `Delete ${name}?`, body: <>This permanently removes the {noun}. It can’t be undone. {dependents}</>, confirmLabel: `Delete ${name}`, busyLabel: 'Deleting…', tone: 'danger' };
  }
  if (action === 'enable') {
    const body =
      noun === 'user' ? `${name} can sign in again. Their rules and group memberships apply again.` : noun === 'group' ? `Rules for ${name} apply to its members again, including any Deny rules.` : `${name} can authenticate again once it has a token. Issue one on the Agent tokens page; none is restored.`;
    return { title: `Enable ${name}?`, body, confirmLabel: `Enable ${name}`, busyLabel: 'Enabling…', tone: 'warning' };
  }
  const body =
    noun === 'user'
      ? `${name} can’t sign in or use Mandatary while disabled. Their rules and group memberships are kept but grant nothing until you enable them again.`
      : noun === 'group'
        ? `Rules for ${name} stop applying to its members. Deny rules in it may stop applying too, so members could gain access that another rule allows. Members and rules are kept.`
        : `Every token for ${name} is revoked for good, and any stream it has open is cut off. Rules that name it are kept but grant nothing.`;
  return { title: `Disable ${name}?`, body, confirmLabel: `Disable ${name}`, busyLabel: 'Disabling…', tone: 'danger' };
}

export function LifecycleConfirm({ noun, action, name, returnFocusId, busy, onConfirm, onCancel }: { noun: Noun; action: 'disable' | 'enable' | 'delete'; name: string; returnFocusId: string; busy: boolean; onConfirm: () => void; onCancel: () => void }) {
  const copy = lifecycleCopy(noun, action, name);
  return (
    <div className="mt-3">
      <ConfirmPanel title={copy.title} confirmLabel={copy.confirmLabel} busyLabel={copy.busyLabel} tone={copy.tone} busy={busy} onConfirm={onConfirm} onCancel={onCancel} returnFocusId={returnFocusId}>
        {copy.body}
      </ConfirmPanel>
    </div>
  );
}

/** A Delete button that cannot be pressed shows WHY, in text beside it, rather than just looking greyed out. */
export function RemovalBlockers({ removal }: { removal: Removal }) {
  if (removal.allowed) return null;
  return (
    <p className="mt-2 text-sm text-muted">
      Can’t be deleted yet: {removal.blockers.join('; ')}.
    </p>
  );
}

/** Small label/value list for a row. Values are plain text; an empty list reads "None", never a blank. */
export function Facts({ children }: { children: ReactNode }) {
  return <dl className="mt-2 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[auto_minmax(0,1fr)]">{children}</dl>;
}

export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words text-fg">{children}</dd>
    </>
  );
}

export function names(values: readonly string[]): string {
  return values.length === 0 ? 'None' : values.join(', ');
}

export function plural(count: number, one: string, many: string = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** A link to the rules for one subject; absent when the container offers none. */
export function RulesLink({ count, subjectName, href }: { count: number; subjectName: string; href?: string }) {
  return (
    <>
      {plural(count, 'rule')} naming {subjectName} directly
      {href ? (
        <>
          {' · '}
          <a href={href} className="font-medium text-accent-text underline underline-offset-2">
            View rules<span className="sr-only"> for {subjectName}</span>
          </a>
        </>
      ) : null}
    </>
  );
}

// ───────────────────────── create-by-name form ─────────────────────────

/**
 * One-field create form for users and groups. The name is checked against the identifier rule inline (convenience:
 * the server applies it too), the field is cleared when the create succeeded, and focus stays where it was.
 */
export function CreateNameForm({ ariaLabel, label, noun, hint, submitLabel, busyLabel, mutation, onSubmit, onReload }: { ariaLabel: string; label: string; noun: string; hint: ReactNode; submitLabel: string; busyLabel: string; mutation: Mutation; onSubmit: (name: string) => void; onReload?: () => void }) {
  const form = useRef<HTMLFormElement>(null);
  const [error, setError] = useState<string | undefined>();
  const busy = isWorking(mutation, 'create');
  const done = mutation.kind === 'done' && mutation.target === 'create';

  useEffect(() => {
    if (done) form.current?.reset();
  }, [done, mutation]);

  return (
    <form
      ref={form}
      method="post"
      noValidate
      aria-label={ariaLabel}
      onSubmit={(event) => {
        event.preventDefault();
        const value = String(new FormData(event.currentTarget).get('name') ?? '');
        const problem = validateIdentifier(value, noun);
        setError(problem);
        if (problem) {
          event.currentTarget.querySelector('input')?.focus();
          return;
        }
        onSubmit(value.trim());
      }}
      className="space-y-3"
    >
      <MutationNotice mutation={mutation} target="create" onReload={onReload} />
      <TextField name="name" label={label} hint={hint} error={error} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} mono readOnly={busy} className="max-w-sm" />
      <Button type="submit" icon="plus" busy={busy} busyLabel={busyLabel}>
        {submitLabel}
      </Button>
    </form>
  );
}
