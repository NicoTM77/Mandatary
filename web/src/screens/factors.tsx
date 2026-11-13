import { useId } from 'react';
import { Alert, Badge, Button, CodeField, Icon, Panel, PasswordField, SecretReveal, TextField } from '../ui';
import type { RecoveryCodesProps, RestrictedRecoveryProps, SignInMethodsProps, WebAuthnRegisterProps } from './contract';
import { Command, RejectionAlert, commonRejection, useRequiredForm, type Rejection } from './shared';
import { TotpEnrollment } from './setup';

// ───────────────────────── sign-in methods list ─────────────────────────

function RemoveConfirm({ label, busy, onCancel, onConfirm }: { label: string; busy: boolean; onCancel: () => void; onConfirm: () => void }) {
  return (
    <div role="group" aria-label={`Confirm removing ${label}`} className="mt-3 rounded-control border border-danger bg-danger-soft p-3.5">
      <p className="font-medium text-danger">Remove {label}?</p>
      <p className="mt-1 text-sm">You won’t be able to use it to sign in. If it’s your last second factor you’ll need a saved recovery code to get back in. We’ll email your other notification addresses.</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button variant="danger" busy={busy} busyLabel="Removing…" onClick={onConfirm}>
          Remove {label}
        </Button>
        <Button variant="secondary" onClick={onCancel} disabled={busy}>
          Keep it
        </Button>
      </div>
    </div>
  );
}

export function SignInMethods({ totp, keys, maxKeys, keysSupported = true, confirmingRemoval, removing = false, onAddTotp, onAddKey, onAskRemove, onCancelRemove, onConfirmRemove }: SignInMethodsProps) {
  const prefix = useId();
  const totpHeading = `${prefix}-totp`;
  const keysHeading = `${prefix}-keys`;
  return (
    <Panel title="Sign-in methods" description="Your password plus one of these proves it’s you. Adding or removing a method needs a recent verification.">
      <section aria-labelledby={totpHeading}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 id={totpHeading} className="font-semibold">
            Authenticator apps
          </h3>
          <Button variant="secondary" icon="plus" onClick={onAddTotp}>
            Add authenticator app
          </Button>
        </div>
        {totp.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No authenticator app yet.</p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {totp.map((row) => (
              <li key={row.id} className="py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-medium">{row.label}</p>
                    <p className="text-sm text-muted">Added {row.addedOn}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {row.status === 'disabled' ? <Badge tone="danger" icon="alert">Disabled after too many failed codes</Badge> : <Badge tone="success" icon="check">Active</Badge>}
                    <Button variant="danger" onClick={() => onAskRemove('totp', row.id)} aria-label={`Remove ${row.label}`}>
                      Remove
                    </Button>
                  </div>
                </div>
                {confirmingRemoval?.kind === 'totp' && confirmingRemoval.id === row.id ? <RemoveConfirm label={row.label} busy={removing} onCancel={onCancelRemove} onConfirm={onConfirmRemove} /> : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section aria-labelledby={keysHeading} className="border-t border-line pt-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 id={keysHeading} className="font-semibold">
            Security keys and passkeys
          </h3>
          <Button variant="secondary" icon="plus" onClick={onAddKey} disabled={!keysSupported || keys.length >= maxKeys}>
            Add security key
          </Button>
        </div>
        {!keysSupported ? <p className="mt-2 text-sm text-muted">Security keys aren’t available on this installation: its public address can’t be used as a security-key identity.</p> : null}
        {keysSupported && keys.length >= maxKeys ? <p className="mt-2 text-sm text-muted">You’ve reached the limit of {maxKeys} keys. Remove one to add another.</p> : null}
        {keys.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No security keys yet. Keys resist phishing and are the strongest option.</p>
        ) : (
          <ul className="mt-2 divide-y divide-line">
            {keys.map((row) => (
              <li key={row.id} className="py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="break-words font-medium">{row.name}</p>
                    <p className="text-sm text-muted">Added {row.addedOn}</p>
                  </div>
                  <Button variant="danger" onClick={() => onAskRemove('webauthn', row.id)} aria-label={`Remove ${row.name}`}>
                    Remove
                  </Button>
                </div>
                {confirmingRemoval?.kind === 'webauthn' && confirmingRemoval.id === row.id ? <RemoveConfirm label={row.name} busy={removing} onCancel={onCancelRemove} onConfirm={onConfirmRemove} /> : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </Panel>
  );
}

// ───────────────────────── WebAuthn registration ─────────────────────────

function registerRejection(reason: 'webauthn_cancelled' | 'webauthn_unsupported' | 'insecure_context' | 'limit_reached' | 'denied' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  switch (reason) {
    case 'webauthn_cancelled':
      return { title: 'The security key request ended', body: 'It was cancelled or timed out. Nothing was added. Try again and follow your browser’s prompt.' };
    case 'webauthn_unsupported':
      return { title: 'This browser can’t register security keys', body: 'Try a current version of Chrome, Edge, Firefox or Safari.' };
    case 'insecure_context':
      return { title: 'Security keys need a secure connection', body: 'Open Mandatary over HTTPS at its configured address, then try again.' };
    case 'limit_reached':
      return { title: 'You’ve reached the key limit', body: 'Remove a key you no longer use, then add this one.' };
    case 'denied':
      return { title: 'The key wasn’t added', body: 'The registration could not be verified, or you need to verify again first. Try again.' };
    default:
      return commonRejection(reason);
  }
}

export function WebAuthnRegister({ state, onSubmit }: WebAuthnRegisterProps) {
  const waiting = state.kind === 'waiting';
  if (state.kind === 'registered') {
    return (
      <Panel title="Security key added">
        <Alert tone="success" role="status" title="Your security key is ready to use">
          We emailed your notification addresses to say a sign-in method was added. For your security, signing in with it needs your PIN, fingerprint or face.
        </Alert>
      </Panel>
    );
  }
  return (
    <Panel title="Add a security key" description="A hardware key or a passkey that asks for your PIN, fingerprint or face.">
      <div className="space-y-4">
        {state.kind === 'rejected' ? <RejectionAlert rejection={registerRejection(state.reason)} active /> : null}
        {waiting ? (
          <Alert tone="info" role="status" title="Waiting for your security key…">
            Follow your browser’s prompt. You have 5 minutes.
          </Alert>
        ) : null}
        <Button icon="usb" busy={waiting} busyLabel="Waiting for key…" onClick={onSubmit}>
          Register security key
        </Button>
      </div>
    </Panel>
  );
}

// ───────────────────────── saved recovery codes ─────────────────────────

export function RecoveryCodes({ state, onIssue, onAskRegenerate, onCancelRegenerate, onConfirmRegenerate, onHidden, synthetic }: RecoveryCodesProps) {
  if (state.kind === 'reveal') {
    return (
      <SecretReveal
        heading="Your recovery codes"
        synthetic={synthetic}
        items={state.codes}
        intro="Each code works once and can restore access if you lose your authenticator or key. Keep them offline, apart from your devices — a password manager vault is fine; a screenshot is not."
        acknowledge={{ confirmLabel: 'I have stored these codes somewhere safe.', doneLabel: 'Hide the codes', onDone: onHidden }}
      />
    );
  }
  return (
    <Panel title="Recovery codes" description="Ten single-use codes for the day you lose your authenticator or security key.">
      {state.kind === 'rejected' ? <RejectionAlert rejection={state.reason === 'denied' ? { title: 'Codes weren’t created', body: 'You need to verify again first, or the session ended. Verify and try again.' } : commonRejection(state.reason)} active /> : null}
      {state.kind === 'none' || state.kind === 'working' ? (
        <>
          <Alert tone="warning" role="none" title="No recovery codes yet">
            Without them, losing your only second factor means the host operator has to reset your account.
          </Alert>
          <Button icon="list" busy={state.kind === 'working'} busyLabel="Creating codes…" onClick={onIssue}>
            Create recovery codes
          </Button>
        </>
      ) : null}
      {state.kind === 'issued' || state.kind === 'rejected' ? (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p>
            <span className="font-semibold tabular-nums">{state.kind === 'issued' ? state.remaining : '—'}</span> of 10 codes unused.
          </p>
          <Button variant="secondary" onClick={onAskRegenerate}>
            Replace all codes
          </Button>
        </div>
      ) : null}
      {state.kind === 'confirming_regenerate' ? (
        <div role="group" aria-label="Confirm replacing recovery codes" className="rounded-control border border-danger bg-danger-soft p-3.5">
          <p className="font-medium text-danger">Replace all recovery codes?</p>
          <p className="mt-1 text-sm">The {state.remaining} unused codes stop working immediately. You’ll get ten new ones, shown once.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="danger" onClick={onConfirmRegenerate}>
              Replace codes
            </Button>
            <Button variant="secondary" onClick={onCancelRegenerate}>
              Keep current codes
            </Button>
          </div>
        </div>
      ) : null}
    </Panel>
  );
}

// ───────────────────────── restricted recovery (saved code) ─────────────────────────

export function RestrictedRecovery({ state, onSubmit, onBeginTotp, onConfirmTotp, onRegisterKey, onReplacementHidden, signInHref }: RestrictedRecoveryProps) {
  const busy = state.kind === 'submitting';
  const form = useRequiredForm(
    [
      ['username', 'your username'],
      ['password', 'your password'],
      ['code', 'one of your recovery codes'],
    ],
    (data) => onSubmit({ username: String(data.get('username')).trim(), password: String(data.get('password')), code: String(data.get('code')).trim() }),
    { rejected: state.kind === 'rejected', clearOnReject: ['password', 'code'], untrimmed: ['password'] },
  );

  if (state.kind === 'completed') {
    return (
      <Panel title="Recovery complete">
        <Alert tone="success" role="status" title="Your new authenticator is active">
          The old second factors were removed and your other notification addresses were told. Sign in with your password and the new authenticator.
        </Alert>
        <a href={signInHref} className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-4 font-medium text-accent-fg hover:bg-accent-hover">
          Go to sign in
        </a>
      </Panel>
    );
  }
  if (state.kind === 'capability') {
    const methods = state.methods ?? ['totp'];
    return (
      <div className="space-y-5">
        <Alert tone="info" role="status" title={`Recovery code accepted · ${state.minutesLeft} ${state.minutesLeft === 1 ? 'minute' : 'minutes'} left`}>
          Add a new {methods.includes('totp') ? 'authenticator app' : 'security key'} to finish. This does not sign you in; you’ll sign in normally afterwards.
        </Alert>
        {state.replacementCode !== undefined ? (
          <SecretReveal
            heading="Your replacement recovery code"
            items={[state.replacementCode]}
            intro="The code you just used is gone. This one replaces it. Keep it offline, apart from your devices. It works once and is shown only now."
            acknowledge={{ confirmLabel: 'I have stored this code somewhere safe.', doneLabel: 'Hide the code', onDone: onReplacementHidden ?? (() => undefined) }}
          />
        ) : null}
        {methods.includes('totp') ? <TotpEnrollment state={state.totp} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={onBeginTotp} onConfirm={onConfirmTotp} /> : null}
        {methods.includes('webauthn') && onRegisterKey ? <WebAuthnRegister state={state.key ?? { kind: 'idle' }} onSubmit={onRegisterKey} /> : null}
      </div>
    );
  }
  return (
    <Panel title="Recover with a saved code" description="For when you can’t use your authenticator app or security key. You need your password and one unused recovery code.">
      <form {...form.formProps} aria-label="Recover access" className="space-y-4">
        {state.kind === 'rejected' ? <RejectionAlert rejection={state.reason === 'denied' ? { title: 'Recovery failed', body: 'The username, password or code is incorrect, or the code was already used. Check them and try again.' } : commonRejection(state.reason)} active /> : null}
        <TextField name="username" label="Username" autoComplete="username" autoCapitalize="none" autoCorrect="off" spellCheck={false} required error={form.errorFor('username')} readOnly={busy} />
        <PasswordField name="password" label="Password" autoComplete="current-password" required error={form.errorFor('password')} readOnly={busy} />
        <CodeField kind="saved-code" name="code" label="Recovery code" required error={form.errorFor('code')} readOnly={busy} />
        <Button type="submit" busy={busy} busyLabel="Checking…" className="w-full">
          Continue
        </Button>
      </form>
    </Panel>
  );
}

/** Static instructions when every factor and every code is gone. No form: this path is host-local by design. */
export function HostRecoveryHelp() {
  return (
    <Panel title="Lost every second factor and every code?" description="No email or web link can restore access. That is deliberate.">
      <p className="flex gap-2.5 text-sm">
        <Icon name="lock" className="mt-0.5 size-5 text-muted" />
        <span>
          Someone with access to the Mandatary host can start an emergency reset. It ends this account’s sessions, retires its old second factors and issues a 30-minute setup token. On the host run{' '}
          <Command>mandatary recovery reset-mfa --user NAME --acknowledge-all-factors-lost-risk</Command>, then <Command>mandatary recovery reveal --user NAME</Command>.
        </span>
      </p>
    </Panel>
  );
}
