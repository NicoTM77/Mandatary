import { useState } from 'react';
import { Alert, Badge, Button, CodeField, Icon, Panel, PasswordField, SecretReveal, TextField, type StepItem } from '../ui';
import type { AccountFormValues, AddressRow, ProofState, SetupAccountProps, SetupAddressesProps, SetupClock, SetupCompleteProps, SetupExchangeProps, TotpEnrollmentProps } from './contract';
import { Command, RejectionAlert, commonRejection, useRequiredForm, type Rejection } from './shared';

export const SETUP_STEPS: readonly StepItem[] = [
  { id: 'token', label: 'Token' },
  { id: 'account', label: 'Account' },
  { id: 'addresses', label: 'Addresses' },
  { id: 'totp', label: 'Authenticator' },
  { id: 'complete', label: 'Finish' },
];

/** Absolute-deadline notice shown on every setup screen after the token exchange. */
export function SetupClockNotice({ clock }: { clock: SetupClock }) {
  if (clock.kind === 'expired') {
    return (
      <Alert tone="danger" title="This setup session has expired">
        Nothing you entered was saved. On the host, run <Command>mandatary setup rotate</Command> and then <Command>mandatary setup reveal</Command> for a new token, and start again.
      </Alert>
    );
  }
  const minutes = `${clock.minutesLeft} ${clock.minutesLeft === 1 ? 'minute' : 'minutes'}`;
  return clock.kind === 'expiring' ? (
    <Alert tone="warning" title={`Setup session ends in ${minutes}`}>
      Finish soon. The deadline is fixed; it does not extend when you are active.
    </Alert>
  ) : (
    <p className="flex items-center gap-1.5 text-sm text-muted">
      <Icon name="clock" className="size-4" />
      Setup session ends in {minutes}.
    </p>
  );
}

// ───────────────────────── token exchange ─────────────────────────

function exchangeRejection(reason: 'invalid_token' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  if (reason === 'invalid_token') {
    return {
      title: 'That token wasn’t accepted',
      body: (
        <>
          It may be mistyped, expired or already used. Tokens work once and expire 30 minutes after they were issued. On the host, run <Command>mandatary setup rotate</Command>, then{' '}
          <Command>mandatary setup reveal</Command> for a new one.
        </>
      ),
    };
  }
  return commonRejection(reason);
}

export function SetupExchange({ state, onSubmit }: SetupExchangeProps) {
  const rejected = state.kind === 'rejected';
  const busy = state.kind === 'submitting';
  const form = useRequiredForm([['token', 'the setup token']], (data) => onSubmit({ token: String(data.get('token')).trim() }), { rejected, clearOnReject: ['token'] });

  if (state.kind === 'closed') {
    return (
      <Panel title="Setup isn’t open">
        <Alert tone="info" role="none" title="This server isn’t accepting setup right now">
          If you are the administrator, check the state on the host with <Command>mandatary setup status</Command>.
        </Alert>
      </Panel>
    );
  }
  return (
    <Panel title="Set up Mandatary" description="Create the first administrator. You’ll need a one-time token from the host terminal.">
      <form {...form.formProps} aria-label="Enter setup token" className="space-y-4">
        {state.kind === 'rejected' ? <RejectionAlert rejection={exchangeRejection(state.reason)} active /> : null}
        <CodeField
          kind="setup-token"
          name="token"
          label="Setup token"
          hint={
            <>
              On the host, run <Command>mandatary setup reveal</Command> and paste the result. Pasting is fine.
            </>
          }
          error={form.errorFor('token')}
          required
          readOnly={busy}
        />
        <Button type="submit" busy={busy} busyLabel="Checking token…" className="w-full">
          Verify token
        </Button>
      </form>
    </Panel>
  );
}

// ───────────────────────── account ─────────────────────────

function accountRejection(state: { kind: 'rejected'; reason: string; guidance?: string }): Rejection | null {
  switch (state.reason) {
    case 'password_rejected':
      return null; // shown on the password field itself
    case 'denied':
      return { title: 'The administrator account wasn’t created', body: 'The setup session may have expired, or the details can’t be used. Check them and try again; if it keeps failing, start setup again.' };
    case 'rate_limited':
    case 'unavailable':
    case 'invalid_request':
      return commonRejection(state.reason);
    default:
      return commonRejection('unavailable');
  }
}

const PASSWORD_HINT = 'Use 8 to 128 characters. Password managers and pasting are welcome. We check it against common and previously exposed passwords when you continue.';
const PASSWORD_ENDPOINT_NOTE = 'If you will sign in from other devices, note that accents and emoji can be typed differently on other keyboards.';

export function SetupAccount({ purpose, targetUser, replacePassword, mailConfigured, maxAddresses, state, onSubmit }: SetupAccountProps) {
  const initial = purpose === 'initial_setup';
  const [addressCount, setAddressCount] = useState(1);
  const rejected = state.kind === 'rejected';
  const busy = state.kind === 'submitting';
  const required: Array<readonly [string, string]> = [
    ...(initial ? ([['username', 'a username']] as const) : []),
    ['password', 'a password'],
    ...(initial ? ([['address-0', 'a notification address']] as const) : []),
  ];
  const form = useRequiredForm(
    required,
    (data) => {
      const values: AccountFormValues = {
        username: initial ? String(data.get('username')).trim() : (targetUser ?? ''),
        password: String(data.get('password')),
        addresses: Array.from({ length: addressCount }, (_, index) => String(data.get(`address-${index}`) ?? '').trim()).filter((value) => value !== ''),
      };
      onSubmit(values);
    },
    { rejected, clearOnReject: ['password'], untrimmed: ['password'] },
  );
  const rejection = state.kind === 'rejected' ? accountRejection(state) : null;

  if (!mailConfigured && initial) {
    return (
      <Panel title="Mail relay isn’t configured">
        <Alert tone="warning" role="none" title="Setup can’t be completed yet">
          Mandatary must email a confirmation code to prove at least one notification address. Configure the mail relay for this installation, then run <Command>mandatary setup rotate</Command> to get a
          fresh setup window.
        </Alert>
      </Panel>
    );
  }
  if (!initial && !replacePassword) return null;

  return (
    <Panel
      title={initial ? 'Create the administrator account' : 'Choose a new password'}
      description={initial ? 'This account manages users, groups, agents and policies. It has no access to containers by default.' : `Replacing the password for ${targetUser ?? 'the administrator'}.`}
    >
      <form {...form.formProps} aria-label={initial ? 'Create administrator' : 'Replace password'} className="space-y-4">
        {rejection ? <RejectionAlert rejection={rejection} active /> : null}
        {initial ? (
          <TextField name="username" label="Username" autoComplete="username" autoCapitalize="none" autoCorrect="off" spellCheck={false} required error={form.errorFor('username')} readOnly={busy} />
        ) : (
          <TextField name="username" label="Username" autoComplete="username" defaultValue={targetUser ?? ''} readOnly spellCheck={false} />
        )}
        <PasswordField
          name="password"
          label="Password"
          autoComplete="new-password"
          hint={
            <>
              {PASSWORD_HINT} {PASSWORD_ENDPOINT_NOTE}
            </>
          }
          error={state.kind === 'rejected' && state.reason === 'password_rejected' ? state.guidance : form.errorFor('password')}
          required
          readOnly={busy}
        />
        {initial ? (
          <fieldset className="space-y-3">
            <legend className="text-sm font-medium">Notification addresses</legend>
            <p className="text-sm text-muted">Security notices go to every address you add. Add at least one now, and a second so you still get notices if one mailbox is unavailable. You’ll confirm them next.</p>
            {Array.from({ length: addressCount }, (_, index) => (
              <TextField
                key={index}
                name={`address-${index}`}
                label={`Email address ${index + 1}${index === 0 ? '' : ' (optional)'}`}
                type="email"
                autoComplete="email"
                autoCapitalize="none"
                spellCheck={false}
                required={index === 0}
                error={index === 0 ? form.errorFor('address-0') : undefined}
                readOnly={busy}
              />
            ))}
            {addressCount < maxAddresses ? (
              <Button variant="quiet" icon="plus" onClick={() => setAddressCount((count) => Math.min(count + 1, maxAddresses))}>
                Add another address
              </Button>
            ) : (
              <p className="text-sm text-muted">You’ve added the maximum of {maxAddresses} addresses.</p>
            )}
          </fieldset>
        ) : null}
        <Button type="submit" busy={busy} busyLabel="Checking…" className="w-full">
          {initial ? 'Save account' : 'Save password'}
        </Button>
      </form>
    </Panel>
  );
}

// ───────────────────────── address proof ─────────────────────────

function ProofControls({ row, onSendProof, onConfirm }: { row: AddressRow; onSendProof: (id: string) => void; onConfirm: (id: string, code: string) => void }) {
  const proof: ProofState = row.proof;
  const sentOrLater = proof.kind === 'sent' || proof.kind === 'confirming' || (proof.kind === 'error' && proof.reason === 'wrong_code');
  const form = useRequiredForm([['code', 'the code from the email']], (data) => onConfirm(row.id, String(data.get('code')).replace(/[\s-]/g, '')), { rejected: proof.kind === 'error', clearOnReject: ['code'] });
  if (row.confirmed) return null;
  const rejection: Rejection | null =
    proof.kind === 'error'
      ? proof.reason === 'wrong_code'
        ? { title: 'That code didn’t match', body: 'Check the latest email and try again. Codes expire, and asking for a new one replaces the old one.' }
        : commonRejection(proof.reason)
      : null;
  return (
    <div className="mt-3 space-y-3">
      {rejection ? <RejectionAlert rejection={rejection} active /> : null}
      {sentOrLater ? (
        <form {...form.formProps} aria-label={`Confirm ${row.address}`} className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <CodeField kind="mailed-proof" name="code" label="Code from the email" error={form.errorFor('code')} className="sm:flex-1" readOnly={proof.kind === 'confirming'} />
          <div className="flex gap-2 sm:pt-[1.625rem]">
            <Button type="submit" busy={proof.kind === 'confirming'} busyLabel="Confirming…">
              Confirm
            </Button>
            <Button variant="quiet" onClick={() => onSendProof(row.id)} disabled={proof.kind === 'confirming'}>
              Send a new code
            </Button>
          </div>
        </form>
      ) : (
        <Button variant="secondary" icon="mail" busy={proof.kind === 'sending'} busyLabel="Sending…" onClick={() => onSendProof(row.id)}>
          Send confirmation code
        </Button>
      )}
    </div>
  );
}

export function SetupAddresses({ addresses, mailConfigured, onSendProof, onConfirm }: SetupAddressesProps) {
  const confirmed = addresses.filter((row) => row.confirmed).length;
  return (
    <Panel title="Confirm a notification address" description="Mandatary emails security notices (new sign-in methods, recovery, removals). Prove you control at least one address to continue.">
      {!mailConfigured ? (
        <Alert tone="warning" role="none" title="Confirmation emails can’t be sent">
          The mail relay isn’t configured, so no address can be confirmed. Configure it, then run <Command>mandatary setup rotate</Command>.
        </Alert>
      ) : null}
      <ul className="divide-y divide-line">
        {addresses.map((row) => (
          <li key={row.id} className="py-4 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="min-w-0 break-all font-medium">{row.address}</p>
              {row.confirmed ? (
                <Badge tone="success" icon="check">
                  Confirmed
                </Badge>
              ) : (
                <Badge tone="neutral">Not confirmed</Badge>
              )}
            </div>
            <ProofControls row={row} onSendProof={onSendProof} onConfirm={onConfirm} />
          </li>
        ))}
      </ul>
      <p role="status" className={`text-sm ${confirmed > 0 ? 'text-success' : 'text-muted'}`}>
        {confirmed > 0 ? `${confirmed} of ${addresses.length} addresses confirmed. You can continue.` : 'Confirm at least one address to continue.'}
      </p>
    </Panel>
  );
}

// ───────────────────────── TOTP enrolment (setup, post-login, recovery) ─────────────────────────

function totpRejection(reason: 'wrong_code' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  if (reason === 'wrong_code') {
    return { title: 'That code didn’t match', body: 'Enter the current 6-digit code from your authenticator app. If it keeps failing, check that your device clock is correct. Each code can be used once.' };
  }
  return commonRejection(reason);
}

export function TotpEnrollment({ state, algorithmLabel, digits, periodSeconds, onBegin, onConfirm, onRestart, synthetic }: TotpEnrollmentProps) {
  const withSeed = state.kind === 'seed_shown' || state.kind === 'confirming' || state.kind === 'rejected';
  const busy = state.kind === 'confirming';
  const rejected = state.kind === 'rejected';
  const form = useRequiredForm([['code', 'the code from your app']], (data) => onConfirm(String(data.get('code')).replace(/[\s-]/g, '')), { rejected, clearOnReject: ['code'] });

  if (state.kind === 'proven') {
    return (
      <Panel title="Authenticator confirmed">
        <Alert tone="success" role="status" title="Your authenticator app is ready">
          The key is no longer available on this page. It can’t be shown again.
        </Alert>
      </Panel>
    );
  }
  if (state.kind === 'not_started' || state.kind === 'starting') {
    return (
      <Panel title="Add an authenticator app" description="Use an app such as your phone’s authenticator or a password manager that supports one-time codes.">
        <Button icon="phone" busy={state.kind === 'starting'} busyLabel="Creating key…" onClick={onBegin}>
          Create authenticator key
        </Button>
      </Panel>
    );
  }
  if (state.kind === 'seed_lost') {
    return (
      <Panel title="Add an authenticator app">
        <Alert
          tone="warning"
          role="none"
          title="The key can’t be shown again"
          actions={
            onRestart ? (
              <Button variant="secondary" onClick={onRestart}>
                Start over with a new key
              </Button>
            ) : undefined
          }
        >
          Enrolment was started but this page was reloaded, and for your security the key is never displayed twice.{' '}
          {onRestart ? 'Start over to create a new one.' : 'Ask the host operator to restart the setup session.'}
        </Alert>
      </Panel>
    );
  }
  return (
    <div className="space-y-5">
      {withSeed ? (
        <SecretReveal
          heading="Your authenticator key"
          synthetic={synthetic}
          value={state.seed}
          groupEvery={4}
          copyLabel="Copy key"
          intro={
            <>
              In your authenticator app choose “Enter a setup key” and paste this key. Type: time-based, {algorithmLabel}, {digits} digits, {periodSeconds}-second period. It disappears once your first code
              is confirmed.
            </>
          }
        />
      ) : null}
      <Panel title="Confirm with a code" headingLevel={3}>
        <form {...form.formProps} aria-label="Confirm authenticator code" className="space-y-4">
          {state.kind === 'rejected' ? <RejectionAlert rejection={totpRejection(state.reason)} active /> : null}
          <CodeField kind="totp" name="code" label={`${digits}-digit code`} error={form.errorFor('code')} required readOnly={busy} />
          <Button type="submit" busy={busy} busyLabel="Checking code…" className="w-full">
            Confirm code
          </Button>
        </form>
      </Panel>
    </div>
  );
}

// ───────────────────────── complete ─────────────────────────

export function SetupComplete({ accountStaged, confirmedAddressCount, totpProven, state, onComplete, signInHref }: SetupCompleteProps) {
  if (state.kind === 'done') {
    return (
      <Panel title="Setup is complete">
        <Alert tone="success" role="status" title={`${state.username} is ready`}>
          Setup does not sign you in. Sign in with your password and authenticator code to continue.
        </Alert>
        <a href={signInHref} className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-4 font-medium text-accent-fg hover:bg-accent-hover">
          Go to sign in
        </a>
      </Panel>
    );
  }
  const items = [
    { done: accountStaged, label: 'Administrator account saved' },
    { done: confirmedAddressCount > 0, label: confirmedAddressCount > 0 ? `${confirmedAddressCount} notification ${confirmedAddressCount === 1 ? 'address' : 'addresses'} confirmed` : 'Confirm a notification address' },
    { done: totpProven, label: 'Authenticator app confirmed' },
  ];
  const ready = items.every((item) => item.done);
  return (
    <Panel title="Finish setup" description="Mandatary stays locked until every item below is done.">
      {state.kind === 'rejected' ? <RejectionAlert rejection={state.reason === 'denied' ? { title: 'Setup couldn’t be completed', body: 'A requirement is missing or the setup session ended. Review the list and try again.' } : commonRejection(state.reason)} active /> : null}
      <ul className="space-y-2">
        {items.map((item) => (
          <li key={item.label} className="flex items-center gap-2.5">
            <Icon name={item.done ? 'check' : 'clock'} className={`size-5 ${item.done ? 'text-success' : 'text-muted'}`} />
            <span className={item.done ? '' : 'text-muted'}>
              {item.label}
              {item.done ? <span className="sr-only"> (done)</span> : <span className="sr-only"> (still needed)</span>}
            </span>
          </li>
        ))}
      </ul>
      <Button className="w-full" disabled={!ready && state.kind !== 'submitting'} busy={state.kind === 'submitting'} busyLabel="Finishing…" onClick={onComplete}>
        Finish setup
      </Button>
    </Panel>
  );
}
