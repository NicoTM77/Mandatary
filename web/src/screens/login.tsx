import { Alert, Button, CodeField, Icon, Panel, PasswordField, TextField } from '../ui';
import type { LoginFactorProps, LoginMethod, LoginPasswordProps, StepUpMethod, StepUpPanelProps, TotpChoiceRow } from './contract';
import { Command, RejectionAlert, commonRejection, useRequiredForm, type Rejection } from './shared';

// ───────────────────────── password step ─────────────────────────

function loginRejection(reason: 'denied' | 'recovery_required' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  switch (reason) {
    case 'denied':
      // One message for unknown user, wrong password, an exhausted factor and an account-level wait: the
      // UI must never reveal which (password contract: generic 401 parity, no account-existence signal).
      return { title: 'Sign-in failed', body: 'The username or password is incorrect, or sign-in is paused after too many attempts. Check them and try again, or wait a minute.' };
    case 'recovery_required':
      return { title: 'This account can’t sign in with a password alone right now', body: 'Use one of your saved recovery codes to get back in, or ask the administrator for help.' };
    default:
      return commonRejection(reason);
  }
}

export function LoginPassword({ state, onSubmit, recoveryHref }: LoginPasswordProps) {
  const busy = state.kind === 'submitting';
  const rejected = state.kind === 'rejected';
  const form = useRequiredForm(
    [
      ['username', 'your username'],
      ['password', 'your password'],
    ],
    (data) => onSubmit({ username: String(data.get('username')).trim(), password: String(data.get('password')) }),
    { rejected, clearOnReject: ['password'], untrimmed: ['password'] },
  );
  return (
    <Panel title="Sign in" description="Use your Mandatary username and password.">
      <form {...form.formProps} aria-label="Sign in" className="space-y-4">
        {state.kind === 'rejected' ? <RejectionAlert rejection={loginRejection(state.reason)} active /> : null}
        <TextField name="username" label="Username" autoComplete="username" autoCapitalize="none" autoCorrect="off" spellCheck={false} required error={form.errorFor('username')} readOnly={busy} />
        <PasswordField name="password" label="Password" autoComplete="current-password" required error={form.errorFor('password')} readOnly={busy} />
        <Button type="submit" busy={busy} busyLabel="Signing in…" className="w-full">
          Sign in
        </Button>
      </form>
      {recoveryHref ? (
        <p className="text-center text-sm text-muted">
          Lost your authenticator or security key?{' '}
          <a href={recoveryHref} className="font-medium text-accent-text underline underline-offset-2">
            Use a recovery code
          </a>
        </p>
      ) : null}
    </Panel>
  );
}

// ───────────────────────── second factor ─────────────────────────

function factorRejection(reason: 'denied' | 'password_only_refused' | 'webauthn_cancelled' | 'webauthn_unsupported' | 'rate_limited' | 'unavailable' | 'invalid_request', method: LoginMethod): Rejection {
  switch (reason) {
    case 'denied':
      return method === 'totp'
        ? { title: 'That code wasn’t accepted', body: 'Enter the current code from your authenticator app. Each code works once, so wait for the next one if you just used it.' }
        : { title: 'That security key wasn’t accepted', body: 'Try again, or use another sign-in method if your account has one.' };
    case 'password_only_refused':
      // The page offered it because the server listed it, but the server re-checks policy on the call itself.
      return { title: 'Password-only sign-in isn’t available', body: 'This account must verify with a second factor. Use your authenticator code, or start again.' };
    case 'webauthn_cancelled':
      return { title: 'The security key request ended', body: 'It was cancelled or timed out. Try again and follow your browser’s prompt.' };
    case 'webauthn_unsupported':
      return { title: 'This browser can’t use security keys here', body: 'Security keys need a secure (HTTPS) connection and a supported browser. Use another method or another browser.' };
    default:
      return commonRejection(reason);
  }
}

function MethodChoice({ methods, method, disabled, onChoose }: { methods: readonly LoginMethod[]; method: LoginMethod; disabled: boolean; onChoose: (method: LoginMethod) => void }) {
  if (methods.length < 2) return null;
  return (
    <fieldset className="grid grid-cols-2 gap-2" disabled={disabled}>
      <legend className="mb-1.5 text-sm font-medium">Verification method</legend>
      {methods.map((candidate) => (
        <label
          key={candidate}
          className={`flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-control border px-3 text-sm font-medium has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-focus ${method === candidate ? 'border-accent bg-accent-soft text-accent-text' : 'border-line-strong bg-surface text-fg hover:bg-sunken'}`}
        >
          <input type="radio" name="method" value={candidate} checked={method === candidate} onChange={() => onChoose(candidate)} className="sr-only" />
          <Icon name={candidate === 'totp' ? 'phone' : 'usb'} className="size-4" />
          {candidate === 'totp' ? 'Authenticator app' : 'Security key'}
        </label>
      ))}
    </fieldset>
  );
}

/**
 * Several authenticator apps: the person names which one the code is from (the server never guesses).
 * Native radios inside the form; the first is preselected. Nothing here is a secret.
 */
export function AuthenticatorChoice({ factors }: { factors: readonly TotpChoiceRow[] }) {
  if (factors.length < 2) return null;
  return (
    <fieldset className="space-y-1">
      <legend className="mb-1 text-sm font-medium">Which authenticator app is the code from?</legend>
      {factors.map((factor, index) => (
        <label key={factor.id} className="flex min-h-11 cursor-pointer items-center gap-2.5 rounded-control border border-line-strong bg-surface px-3 text-sm has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-focus">
          <input type="radio" name="authenticator" value={factor.id} defaultChecked={index === 0} className="size-4 accent-accent" />
          {factor.label}
        </label>
      ))}
    </fieldset>
  );
}

function chosenAuthenticator(data: FormData, factors: readonly TotpChoiceRow[]): { authenticatorId?: string } {
  if (factors.length < 2) return {};
  const id = String(data.get('authenticator') ?? '');
  return factors.some((factor) => factor.id === id) ? { authenticatorId: id } : {};
}

export function LoginFactor({ next, method, state, totpFactors = [], onChooseMethod, onSubmitTotp, onStartWebAuthn, onContinuePasswordOnly, onRestart }: LoginFactorProps) {
  const methods = next.filter((step): step is LoginMethod => step === 'totp' || step === 'webauthn');
  const passwordOnly = next.includes('no-mfa') && onContinuePasswordOnly;
  const busy = state.kind === 'submitting';
  const form = useRequiredForm([['code', 'the code from your app']], (data) => onSubmitTotp({ code: String(data.get('code')).replace(/[\s-]/g, ''), ...chosenAuthenticator(data, totpFactors) }), {
    rejected: state.kind === 'rejected',
    clearOnReject: ['code'],
  });

  if (state.kind === 'expired') {
    return (
      <Panel title="Verify your identity">
        <Alert tone="warning" role="alert" title="Your sign-in timed out" actions={<Button onClick={onRestart}>Start again</Button>}>
          You have 5 minutes to finish verifying after entering your password. Nothing was changed.
        </Alert>
      </Panel>
    );
  }
  return (
    <Panel title="Verify it’s you" description="Your password was accepted. One more step to finish signing in.">
      <div className="space-y-4">
        {state.kind === 'rejected' ? <RejectionAlert rejection={factorRejection(state.reason, method)} active /> : null}
        <MethodChoice methods={methods} method={method} disabled={busy || state.kind === 'webauthn_waiting'} onChoose={onChooseMethod} />
        {method === 'totp' ? (
          <form {...form.formProps} aria-label="Enter authenticator code" className="space-y-4">
            <AuthenticatorChoice factors={totpFactors} />
            <CodeField kind="totp" name="code" label="6-digit code" hint="From your authenticator app." error={form.errorFor('code')} required readOnly={busy} />
            <Button type="submit" busy={busy} busyLabel="Verifying…" className="w-full">
              Verify
            </Button>
          </form>
        ) : (
          <div className="space-y-4">
            {state.kind === 'webauthn_waiting' ? (
              <Alert tone="info" role="status" title="Waiting for your security key…">
                Follow your browser’s prompt: insert or tap the key, then confirm with your PIN or fingerprint.
              </Alert>
            ) : (
              <p className="text-sm text-muted">Use a security key or a built-in passkey that asks for your PIN, fingerprint or face.</p>
            )}
            <Button icon="usb" busy={state.kind === 'webauthn_waiting'} busyLabel="Waiting for key…" onClick={onStartWebAuthn} className="w-full">
              Use security key
            </Button>
          </div>
        )}
        {passwordOnly ? (
          <div className="border-t border-line pt-4">
            <Button variant="quiet" onClick={onContinuePasswordOnly} className="w-full">
              Continue with password only
            </Button>
            <p className="mt-1.5 text-center text-sm text-muted">Password-only sessions can’t change security settings or administer Mandatary.</p>
          </div>
        ) : null}
        <p className="text-center text-sm">
          <button type="button" onClick={onRestart} className="rounded text-muted underline underline-offset-2 hover:text-fg">
            Use a different account
          </button>
        </p>
      </div>
    </Panel>
  );
}

// ───────────────────────── step-up ─────────────────────────

function stepUpRejection(reason: 'denied' | 'webauthn_cancelled' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  switch (reason) {
    case 'denied':
      return { title: 'Verification failed', body: 'Check your password and code and try again. Nothing was changed.' };
    case 'webauthn_cancelled':
      return { title: 'The security key request ended', body: 'It was cancelled or timed out. Try again.' };
    default:
      return commonRejection(reason);
  }
}

/**
 * Inline interstitial shown when a sensitive action returns step_up_required. Step-up is a fresh
 * sign-in: it issues a NEW session, so the container must (1) discard any ceremony begun under the
 * old session, (2) take the rotated CSRF token from the new session, and (3) NOT replay the blocked
 * request — the person repeats it once the "verified" state shows.
 */
function stepUpMethodLabel(method: StepUpMethod): string {
  switch (method) {
    case 'password':
      return 'Use my password';
    case 'totp':
      return 'Use my password and authenticator app';
    case 'webauthn':
      return 'Use a security key';
  }
}

export function StepUpPanel({ method, actionLabel, state, username, totpFactors = [], methods = [], onChooseMethod, onSubmitPassword, onSubmitTotp, onStartWebAuthn, onDismiss }: StepUpPanelProps) {
  const busy = state.kind === 'submitting';
  const needsCode = method === 'totp';
  const form = useRequiredForm(
    needsCode
      ? [
          ['password', 'your password'],
          ['code', 'the code from your app'],
        ]
      : [['password', 'your password']],
    (data) =>
      needsCode
        ? onSubmitTotp({ password: String(data.get('password')), code: String(data.get('code')).replace(/[\s-]/g, ''), ...chosenAuthenticator(data, totpFactors) })
        : onSubmitPassword({ password: String(data.get('password')) }),
    { rejected: state.kind === 'rejected', clearOnReject: ['password', 'code'], untrimmed: ['password'] },
  );
  const others = onChooseMethod ? methods.filter((candidate) => candidate !== method) : [];

  if (state.kind === 'verified') {
    return (
      <Panel title="You’re verified">
        <Alert tone="success" role="status" title={`Verified for ${state.validMinutes} minutes`}>
          Your earlier request was not sent. Repeat <strong>{actionLabel.toLowerCase()}</strong> now.
        </Alert>
        <Button onClick={onDismiss}>Continue</Button>
      </Panel>
    );
  }
  if (state.kind === 'unavailable') {
    return (
      <Panel title="This account can’t be verified right now">
        <Alert tone="danger" role="alert" title="No usable verification method">
          {actionLabel} needs a recent multi-factor verification, and none of this account’s factors can be used at the moment. Use a saved recovery code to restore a factor, or ask the host operator to run{' '}
          <Command>mandatary recovery reset-mfa</Command>.
        </Alert>
        <Button variant="secondary" onClick={onDismiss}>
          Close
        </Button>
      </Panel>
    );
  }
  return (
    <Panel title={`Confirm it’s you to ${actionLabel.toLowerCase()}`} description="This needs a recent verification, within the last 15 minutes. Verifying again signs you in fresh.">
      <div className="space-y-4">
        {state.kind === 'rejected' ? <RejectionAlert rejection={stepUpRejection(state.reason)} active /> : null}
        {method === 'webauthn' ? (
          <>
            {state.kind === 'webauthn_waiting' ? (
              <Alert tone="info" role="status" title="Waiting for your security key…">
                Follow your browser’s prompt.
              </Alert>
            ) : null}
            <Button icon="usb" busy={state.kind === 'webauthn_waiting'} busyLabel="Waiting for key…" onClick={onStartWebAuthn}>
              Use security key
            </Button>
          </>
        ) : (
          <form {...form.formProps} aria-label="Verify again" className="space-y-4">
            {/* Lets password managers file the password under the right account. Not a control for people. */}
            <input type="text" name="username" autoComplete="username" defaultValue={username} readOnly tabIndex={-1} aria-hidden="true" className="sr-only" />
            <PasswordField name="password" label="Password" autoComplete="current-password" required error={form.errorFor('password')} readOnly={busy} />
            {needsCode ? <AuthenticatorChoice factors={totpFactors} /> : null}
            {needsCode ? <CodeField kind="totp" name="code" label="6-digit code" error={form.errorFor('code')} required readOnly={busy} /> : null}
            <Button type="submit" busy={busy} busyLabel="Verifying…">
              Verify
            </Button>
          </form>
        )}
        {others.length > 0 ? (
          <div className="flex flex-wrap gap-2" role="group" aria-label="Other ways to verify">
            {others.map((candidate) => (
              <Button key={candidate} variant="secondary" onClick={() => onChooseMethod?.(candidate)} disabled={busy || state.kind === 'webauthn_waiting'}>
                {stepUpMethodLabel(candidate)}
              </Button>
            ))}
          </div>
        ) : null}
        <Button variant="quiet" onClick={onDismiss}>
          Cancel
        </Button>
      </div>
    </Panel>
  );
}
