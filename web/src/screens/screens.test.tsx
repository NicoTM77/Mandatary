import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { AgentCredentials } from './agents';
import { HostRecoveryHelp, RecoveryCodes, RestrictedRecovery, SignInMethods, WebAuthnRegister } from './factors';
import { LoginFactor, LoginPassword, StepUpPanel } from './login';
import { AddressManagement, NoticeHealth } from './notices';
import { SetupAccount, SetupAddresses, SetupClockNotice, SetupComplete, SetupExchange, TotpEnrollment } from './setup';
import { ThemeProvider } from '../theme';

afterEach(cleanup);

const noop = () => undefined;

function mount(ui: ReactElement) {
  return render(<ThemeProvider>{ui}</ThemeProvider>);
}

function type(label: string | RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

// ───────────────────────── shared form discipline ─────────────────────────

test('every form is method=post, never navigates, and an empty required field is reported inline without calling the container', () => {
  const onSubmit = vi.fn();
  mount(<SetupExchange state={{ kind: 'idle' }} onSubmit={onSubmit} />);
  const form = screen.getByRole('form', { name: 'Enter setup token' });
  expect(form.getAttribute('method')).toBe('post');
  expect(form.hasAttribute('action')).toBe(false);
  // fireEvent returns false when a handler called preventDefault: a native submit (a GET carrying
  // the value in the URL, or a POST the CSP would block) can never happen.
  expect(fireEvent.submit(form)).toBe(false);
  expect(onSubmit).not.toHaveBeenCalled();
  const input = screen.getByLabelText('Setup token');
  expect(input.getAttribute('aria-invalid')).toBe('true');
  expect(document.getElementById(input.getAttribute('aria-describedby')?.split(' ').at(-1) ?? '')?.textContent).toBe('Enter the setup token.');
  expect(document.activeElement).toBe(input);
});

test('the setup token is trimmed, sent once, and cleared from the field when the exchange is rejected', () => {
  const onSubmit = vi.fn();
  const { rerender } = mount(<SetupExchange state={{ kind: 'idle' }} onSubmit={onSubmit} />);
  type('Setup token', '  SYNTHETIC-TOKEN-0000  ');
  fireEvent.submit(screen.getByRole('form', { name: 'Enter setup token' }));
  expect(onSubmit).toHaveBeenCalledExactlyOnceWith({ token: 'SYNTHETIC-TOKEN-0000' });
  rerender(
    <ThemeProvider>
      <SetupExchange state={{ kind: 'rejected', reason: 'invalid_token' }} onSubmit={onSubmit} />
    </ThemeProvider>,
  );
  expect((screen.getByLabelText('Setup token') as HTMLInputElement).value).toBe('');
});

test('the setup token field opts out of password managers and paste is left alone', () => {
  mount(<SetupExchange state={{ kind: 'idle' }} onSubmit={noop} />);
  const input = screen.getByLabelText('Setup token');
  expect(input.getAttribute('autocomplete')).toBe('off');
  expect(input.getAttribute('data-1p-ignore')).toBe('true');
  const paste = new Event('paste', { bubbles: true, cancelable: true });
  input.dispatchEvent(paste);
  expect(paste.defaultPrevented).toBe(false);
});

test('a rejected token gives one message for wrong, expired and replayed tokens and names the host remedy', () => {
  mount(<SetupExchange state={{ kind: 'rejected', reason: 'invalid_token' }} onSubmit={noop} />);
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('That token wasn’t accepted');
  expect(alert.textContent).toContain('mandatary setup rotate');
  expect(alert.textContent).not.toMatch(/expired token|already-used token/i);
});

test('a closed setup surface reveals nothing beyond "not open" and offers no form', () => {
  mount(<SetupExchange state={{ kind: 'closed' }} onSubmit={noop} />);
  expect(screen.queryByRole('form')).toBeNull();
  expect(screen.queryByLabelText('Setup token')).toBeNull();
  expect(screen.getByText('Setup isn’t open')).toBeTruthy();
});

test('the submitting state is read-only (not disabled) so focus is kept, and the button announces progress', () => {
  mount(<SetupExchange state={{ kind: 'submitting' }} onSubmit={noop} />);
  const input = screen.getByLabelText('Setup token') as HTMLInputElement;
  expect(input.readOnly).toBe(true);
  expect(input.disabled).toBe(false);
  expect(screen.getByRole('button', { name: 'Checking token…' }).getAttribute('aria-busy')).toBe('true');
});

// ───────────────────────── setup · account ─────────────────────────

test('the account form classifies the password as NEW for managers, allows paste, and has no confirm-password box', () => {
  mount(<SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'idle' }} onSubmit={noop} />);
  expect(screen.getByLabelText('Password').getAttribute('autocomplete')).toBe('new-password');
  expect(screen.getByLabelText('Username').getAttribute('autocomplete')).toBe('username');
  expect(screen.getByLabelText(/Email address 1/).getAttribute('autocomplete')).toBe('email');
  expect(screen.queryByLabelText(/confirm password|repeat/i)).toBeNull();
  expect(screen.getByText(/Password managers and pasting are welcome/)).toBeTruthy();
  expect(screen.getByText(/accents and emoji can be typed differently/)).toBeTruthy();
});

test('the account form sends one record, keeps the password verbatim (no trimming) and only non-empty addresses', () => {
  const onSubmit = vi.fn();
  mount(<SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'idle' }} onSubmit={onSubmit} />);
  type('Username', ' sample-admin ');
  type('Password', '  synthetic pass phrase  ');
  type(/Email address 1/, 'a@example.invalid');
  fireEvent.click(screen.getByRole('button', { name: 'Add another address' }));
  fireEvent.submit(screen.getByRole('form', { name: 'Create administrator' }));
  expect(onSubmit).toHaveBeenCalledExactlyOnceWith({ username: 'sample-admin', password: '  synthetic pass phrase  ', addresses: ['a@example.invalid'] });
});

test('addresses can be added only up to the maximum and the limit is explained', () => {
  mount(<SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={2} state={{ kind: 'idle' }} onSubmit={noop} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add another address' }));
  expect(screen.getByLabelText(/Email address 2 \(optional\)/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Add another address' })).toBeNull();
  expect(screen.getByText('You’ve added the maximum of 2 addresses.')).toBeTruthy();
});

test('server password guidance is rendered as text on the password field, and the password is cleared', () => {
  const guidance = 'This password appears in a list. <b>Choose another.</b>';
  const { rerender, container } = mount(<SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'idle' }} onSubmit={noop} />);
  type('Password', 'synthetic pass phrase');
  rerender(
    <ThemeProvider>
      <SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'rejected', reason: 'password_rejected', guidance }} onSubmit={noop} />
    </ThemeProvider>,
  );
  const password = screen.getByLabelText('Password') as HTMLInputElement;
  expect(password.value).toBe('');
  expect(password.getAttribute('aria-invalid')).toBe('true');
  expect(container.textContent).toContain(guidance);
  expect(container.querySelector('b')).toBeNull();
});

test('without a mail relay the account step blocks with an operator explanation instead of a doomed form', () => {
  mount(<SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured={false} maxAddresses={4} state={{ kind: 'idle' }} onSubmit={noop} />);
  expect(screen.queryByRole('form')).toBeNull();
  expect(screen.getByText('Setup can’t be completed yet')).toBeTruthy();
});

test('an emergency reset shows the bound administrator read-only and asks only for a new password', () => {
  mount(<SetupAccount purpose="mfa_reset" targetUser="sample-admin" replacePassword mailConfigured maxAddresses={4} state={{ kind: 'idle' }} onSubmit={noop} />);
  const username = screen.getByLabelText('Username') as HTMLInputElement;
  expect(username.readOnly).toBe(true);
  expect(username.value).toBe('sample-admin');
  expect(screen.queryByLabelText(/Email address/)).toBeNull();
});

test('a reset that keeps the password renders nothing for the password step', () => {
  const { container } = mount(<SetupAccount purpose="mfa_reset" targetUser="x" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'idle' }} onSubmit={noop} />);
  expect(container.querySelector('form')).toBeNull();
});

// ───────────────────────── setup · addresses, clock, totp, finish ─────────────────────────

test('address confirmation strips spaces and hyphens from the mailed code and offers a new code', () => {
  const onConfirm = vi.fn();
  const onSendProof = vi.fn();
  mount(
    <SetupAddresses
      addresses={[
        { id: 'a1', address: 'one@example.invalid', confirmed: true, proof: { kind: 'idle' } },
        { id: 'a2', address: 'two@example.invalid', confirmed: false, proof: { kind: 'sent' } },
      ]}
      mailConfigured
      onSendProof={onSendProof}
      onConfirm={onConfirm}
    />,
  );
  const form = screen.getByRole('form', { name: 'Confirm two@example.invalid' });
  fireEvent.change(within(form).getByLabelText('Code from the email'), { target: { value: '123 456-789' } });
  fireEvent.submit(form);
  expect(onConfirm).toHaveBeenCalledExactlyOnceWith('a2', '123456789');
  fireEvent.click(screen.getByRole('button', { name: 'Send a new code' }));
  expect(onSendProof).toHaveBeenCalledWith('a2');
  expect(screen.getByText('1 of 2 addresses confirmed. You can continue.')).toBeTruthy();
  expect(screen.getAllByText('Confirmed')).toHaveLength(1);
});

test('with no confirmed address the screen says continuing is not possible, and an unsendable relay is called out', () => {
  mount(<SetupAddresses addresses={[{ id: 'a1', address: 'one@example.invalid', confirmed: false, proof: { kind: 'idle' } }]} mailConfigured={false} onSendProof={noop} onConfirm={noop} />);
  expect(screen.getByText('Confirm at least one address to continue.')).toBeTruthy();
  expect(screen.getByText('Confirmation emails can’t be sent')).toBeTruthy();
});

test('the setup clock distinguishes active, expiring and expired and tells the operator how to restart', () => {
  const { rerender } = mount(<SetupClockNotice clock={{ kind: 'active', minutesLeft: 24 }} />);
  expect(screen.getByText('Setup session ends in 24 minutes.')).toBeTruthy();
  rerender(
    <ThemeProvider>
      <SetupClockNotice clock={{ kind: 'expiring', minutesLeft: 1 }} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('status').textContent).toContain('1 minute');
  rerender(
    <ThemeProvider>
      <SetupClockNotice clock={{ kind: 'expired' }} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('alert').textContent).toContain('mandatary setup rotate');
});

test('the authenticator key exists in the DOM only while enrolment is in progress, never after it is proven or lost', () => {
  const seed = 'SYNTHETIC-SEED-0000';
  const { container, rerender } = mount(<TotpEnrollment state={{ kind: 'seed_shown', seed }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} />);
  expect(container.textContent?.replaceAll(' ', '')).toContain(seed);
  for (const state of [{ kind: 'proven' }, { kind: 'seed_lost' }, { kind: 'not_started' }] as const) {
    rerender(
      <ThemeProvider>
        <TotpEnrollment state={state} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} />
      </ThemeProvider>,
    );
    expect(document.body.textContent?.replaceAll(' ', '')).not.toContain(seed);
  }
});

test('the TOTP code is sent without spaces, with one-time-code autofill and no restart offered unless supported', () => {
  const onConfirm = vi.fn();
  mount(<TotpEnrollment state={{ kind: 'seed_shown', seed: 'SYNTHETIC' }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={onConfirm} />);
  const input = screen.getByLabelText('6-digit code');
  expect(input.getAttribute('autocomplete')).toBe('one-time-code');
  fireEvent.change(input, { target: { value: '123 456' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Confirm authenticator code' }));
  expect(onConfirm).toHaveBeenCalledExactlyOnceWith('123456');
  cleanup();
  mount(<TotpEnrollment state={{ kind: 'seed_lost' }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} />);
  expect(screen.queryByRole('button', { name: /start over/i })).toBeNull();
});

test('finish is blocked until every requirement is met and a completed setup states that no session was issued', () => {
  const onComplete = vi.fn();
  const { rerender } = mount(<SetupComplete accountStaged confirmedAddressCount={0} totpProven={false} state={{ kind: 'idle' }} onComplete={onComplete} signInHref="/login" />);
  const button = screen.getByRole('button', { name: 'Finish setup' }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  expect(screen.getAllByText(/still needed/)).toHaveLength(2);
  rerender(
    <ThemeProvider>
      <SetupComplete accountStaged confirmedAddressCount={1} totpProven state={{ kind: 'idle' }} onComplete={onComplete} signInHref="/login" />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Finish setup' }));
  expect(onComplete).toHaveBeenCalledTimes(1);
  rerender(
    <ThemeProvider>
      <SetupComplete accountStaged confirmedAddressCount={1} totpProven state={{ kind: 'done', username: 'sample-admin' }} onComplete={onComplete} signInHref="/login" />
    </ThemeProvider>,
  );
  expect(screen.getByText(/does not sign you in/)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Go to sign in' }).getAttribute('href')).toBe('/login');
});

// ───────────────────────── login ─────────────────────────

test('the sign-in form uses the standard username / current-password attributes managers recognise', () => {
  const onSubmit = vi.fn();
  mount(<LoginPassword state={{ kind: 'idle' }} onSubmit={onSubmit} />);
  expect(screen.getByLabelText('Username').getAttribute('autocomplete')).toBe('username');
  const password = screen.getByLabelText('Password');
  expect(password.getAttribute('autocomplete')).toBe('current-password');
  expect(password.getAttribute('name')).toBe('password');
  type('Username', 'sample-admin');
  type('Password', 'synthetic');
  fireEvent.submit(screen.getByRole('form', { name: 'Sign in' }));
  expect(onSubmit).toHaveBeenCalledExactlyOnceWith({ username: 'sample-admin', password: 'synthetic' });
});

test('a failed sign-in never says which part was wrong and clears only the password', () => {
  const { rerender } = mount(<LoginPassword state={{ kind: 'idle' }} onSubmit={noop} />);
  type('Username', 'sample-admin');
  type('Password', 'synthetic');
  rerender(
    <ThemeProvider>
      <LoginPassword state={{ kind: 'rejected', reason: 'denied' }} onSubmit={noop} />
    </ThemeProvider>,
  );
  expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
  expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('sample-admin');
  const text = screen.getByRole('alert').textContent ?? '';
  expect(text).toContain('The username or password is incorrect');
  expect(text).not.toMatch(/locked|disabled|no such|doesn’t exist|not found|mfa|second factor/i);
});

test('rate limiting and storage trouble are distinct from a wrong password', () => {
  const { rerender } = mount(<LoginPassword state={{ kind: 'rejected', reason: 'rate_limited' }} onSubmit={noop} />);
  expect(screen.getByRole('alert').textContent).toContain('Too many attempts');
  rerender(
    <ThemeProvider>
      <LoginPassword state={{ kind: 'rejected', reason: 'unavailable' }} onSubmit={noop} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('alert').textContent).toContain('Nothing was changed');
});

test('password-only continuation is offered only when the server permitted it and explains the lower assurance', () => {
  const onContinue = vi.fn();
  const { rerender } = mount(<LoginFactor next={['totp']} method="totp" state={{ kind: 'idle' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onContinuePasswordOnly={onContinue} onRestart={noop} />);
  expect(screen.queryByRole('button', { name: 'Continue with password only' })).toBeNull();
  rerender(
    <ThemeProvider>
      <LoginFactor next={['totp', 'no-mfa']} method="totp" state={{ kind: 'idle' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onContinuePasswordOnly={onContinue} onRestart={noop} />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Continue with password only' }));
  expect(onContinue).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/can’t change security settings or administer/)).toBeTruthy();
});

test('the method chooser lists only server-permitted methods and reports the choice', () => {
  const onChoose = vi.fn();
  mount(<LoginFactor next={['totp', 'webauthn']} method="totp" state={{ kind: 'idle' }} onChooseMethod={onChoose} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} />);
  const group = screen.getByRole('group', { name: 'Verification method' });
  expect(within(group).getAllByRole('radio')).toHaveLength(2);
  fireEvent.click(within(group).getByLabelText('Security key'));
  expect(onChoose).toHaveBeenCalledWith('webauthn');
  cleanup();
  mount(<LoginFactor next={['totp']} method="totp" state={{ kind: 'idle' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} />);
  expect(screen.queryByRole('group', { name: 'Verification method' })).toBeNull();
});

test('waiting for a security key is announced and locks the choice; an expired preauth restarts from the password', () => {
  const onRestart = vi.fn();
  const { rerender } = mount(<LoginFactor next={['totp', 'webauthn']} method="webauthn" state={{ kind: 'webauthn_waiting' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={onRestart} />);
  expect(screen.getByRole('status').textContent).toContain('Waiting for your security key');
  expect((screen.getByRole('group', { name: 'Verification method' }) as HTMLFieldSetElement).disabled).toBe(true);
  rerender(
    <ThemeProvider>
      <LoginFactor next={['totp']} method="totp" state={{ kind: 'expired' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={onRestart} />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Start again' }));
  expect(onRestart).toHaveBeenCalledTimes(1);
});

// ───────────────────────── step-up ─────────────────────────

test('step-up asks for the password and code, gives managers the account name, and strips the code', () => {
  const onSubmitTotp = vi.fn();
  const { container } = mount(<StepUpPanel method="totp" actionLabel="Add a security key" username="sample-admin" state={{ kind: 'idle' }} onSubmitPassword={noop} onSubmitTotp={onSubmitTotp} onStartWebAuthn={noop} onDismiss={noop} />);
  const hidden = container.querySelector<HTMLInputElement>('input[name="username"]');
  expect(hidden?.value).toBe('sample-admin');
  expect(hidden?.getAttribute('autocomplete')).toBe('username');
  type('Password', 'synthetic');
  type('6-digit code', '123 456');
  fireEvent.submit(screen.getByRole('form', { name: 'Verify again' }));
  expect(onSubmitTotp).toHaveBeenCalledExactlyOnceWith({ password: 'synthetic', code: '123456' });
});

test('after step-up the blocked request is NOT replayed: the person is told to repeat it', () => {
  mount(<StepUpPanel method="totp" actionLabel="Add a security key" username="u" state={{ kind: 'verified', validMinutes: 15 }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} />);
  expect(screen.getByText(/Your earlier request was not sent/)).toBeTruthy();
  expect(screen.getByText('Verified for 15 minutes')).toBeTruthy();
});

test('when no factor can meet the required assurance, step-up says so and points to recovery instead of retrying', () => {
  mount(<StepUpPanel method="totp" actionLabel="Add a security key" username="u" state={{ kind: 'unavailable' }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} />);
  expect(screen.getByRole('alert').textContent).toContain('No usable verification method');
  expect(screen.getByRole('alert').textContent).toContain('mandatary recovery reset-mfa');
  expect(screen.queryByLabelText('Password')).toBeNull();
});

// ───────────────────────── factors ─────────────────────────

test('removing a sign-in method needs an explicit confirmation naming the method; add is capped at the key limit', () => {
  const onAskRemove = vi.fn();
  const { rerender } = mount(
    <SignInMethods
      totp={[{ id: 't1', label: 'Authenticator app', addedOn: '3 Nov 2026', status: 'active' }]}
      keys={[{ id: 'k1', name: 'Desk key', addedOn: '9 Nov 2026' }]}
      maxKeys={1}
      onAddTotp={noop}
      onAddKey={noop}
      onAskRemove={onAskRemove}
      onCancelRemove={noop}
      onConfirmRemove={noop}
    />,
  );
  expect((screen.getByRole('button', { name: 'Add security key' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Remove Desk key' }));
  expect(onAskRemove).toHaveBeenCalledWith('webauthn', 'k1');
  rerender(
    <ThemeProvider>
      <SignInMethods
        totp={[{ id: 't1', label: 'Authenticator app', addedOn: '3 Nov 2026', status: 'disabled' }]}
        keys={[{ id: 'k1', name: 'Desk key', addedOn: '9 Nov 2026' }]}
        maxKeys={16}
        confirmingRemoval={{ kind: 'webauthn', id: 'k1' }}
        onAddTotp={noop}
        onAddKey={noop}
        onAskRemove={noop}
        onCancelRemove={noop}
        onConfirmRemove={noop}
      />
    </ThemeProvider>,
  );
  expect(screen.getByRole('group', { name: 'Confirm removing Desk key' })).toBeTruthy();
  expect(screen.getByText('Disabled after too many failed codes')).toBeTruthy();
});

test('security key registration explains cancellation, insecure context and the key limit separately', () => {
  const titles = new Map<string, string>();
  for (const reason of ['webauthn_cancelled', 'insecure_context', 'limit_reached', 'webauthn_unsupported'] as const) {
    const { unmount } = mount(<WebAuthnRegister state={{ kind: 'rejected', reason }} onSubmit={noop} />);
    titles.set(reason, screen.getByRole('alert').textContent ?? '');
    unmount();
  }
  expect(new Set(titles.values()).size).toBe(4);
  expect(titles.get('insecure_context')).toContain('HTTPS');
});

test('recovery codes appear once, are removed after acknowledgement, and replacement is a confirmed step', () => {
  const onHidden = vi.fn();
  const codes = ['SYNTH-AAAA-1', 'SYNTH-BBBB-2'];
  const { container, rerender } = mount(<RecoveryCodes state={{ kind: 'reveal', codes }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={onHidden} />);
  expect(container.textContent).toContain('SYNTH-AAAA-1');
  fireEvent.click(screen.getByLabelText('I have stored these codes somewhere safe.'));
  fireEvent.click(screen.getByRole('button', { name: 'Hide the codes' }));
  expect(onHidden).toHaveBeenCalledTimes(1);
  expect(document.body.textContent).not.toContain('SYNTH-AAAA-1');
  rerender(
    <ThemeProvider>
      <RecoveryCodes state={{ kind: 'confirming_regenerate', remaining: 7 }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={noop} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('group', { name: 'Confirm replacing recovery codes' }).textContent).toContain('7 unused codes stop working immediately');
});

test('restricted recovery takes a saved code that is never offered to password managers, then proves a replacement factor', () => {
  mount(<RestrictedRecovery state={{ kind: 'idle' }} onSubmit={noop} onBeginTotp={noop} onConfirmTotp={noop} signInHref="/login" />);
  const code = screen.getByLabelText('Recovery code');
  expect(code.getAttribute('autocomplete')).toBe('off');
  expect(code.getAttribute('data-1p-ignore')).toBe('true');
  expect(screen.getByLabelText('Password').getAttribute('autocomplete')).toBe('current-password');
  cleanup();
  mount(<RestrictedRecovery state={{ kind: 'capability', minutesLeft: 8, totp: { kind: 'not_started' } }} onSubmit={noop} onBeginTotp={noop} onConfirmTotp={noop} signInHref="/login" />);
  expect(screen.getByRole('status').textContent).toContain('does not sign you in');
});

test('host-local recovery is instructions only: no form or input', () => {
  const { container } = mount(<HostRecoveryHelp />);
  expect(container.querySelector('form, input')).toBeNull();
  expect(container.textContent).toContain('mandatary recovery reset-mfa');
});

// ───────────────────────── notification addresses & notices ─────────────────────────

const ADDRESSES = [
  { id: 'm1', address: 'one@example.invalid', status: 'confirmed' as const },
  { id: 'm2', address: 'two@example.invalid', status: 'confirmed' as const },
];

function addressProps(overrides: Partial<Parameters<typeof AddressManagement>[0]> = {}) {
  return { addresses: ADDRESSES, maxAddresses: 4, state: { kind: 'idle' as const }, mailConfigured: true, onStartAdd: noop, onSubmitAddress: noop, onSubmitProof: noop, onCancelAdd: noop, onAskRemove: noop, onCancelRemove: noop, onConfirmRemove: noop, ...overrides };
}

test('the last confirmed address cannot be removed and the reason is shown', () => {
  mount(<AddressManagement {...addressProps({ addresses: [ADDRESSES[0] as (typeof ADDRESSES)[number]] })} />);
  expect((screen.getByRole('button', { name: 'Remove one@example.invalid' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/only confirmed address, so it can’t be removed/)).toBeTruthy();
  expect(screen.getByText('You have one confirmed address')).toBeTruthy();
});

test('with two confirmed addresses either can be removed after a named confirmation', () => {
  const onAskRemove = vi.fn();
  const { rerender } = mount(<AddressManagement {...addressProps({ onAskRemove })} />);
  fireEvent.click(screen.getByRole('button', { name: 'Remove two@example.invalid' }));
  expect(onAskRemove).toHaveBeenCalledWith('m2');
  rerender(
    <ThemeProvider>
      <AddressManagement {...addressProps({ state: { kind: 'confirming_removal', id: 'm2' } })} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('group', { name: 'Confirm removing two@example.invalid' }).textContent).toContain('email your remaining addresses');
});

test('adding is capped at the maximum, and impossible without a mail relay', () => {
  const four = ['a', 'b', 'c', 'd'].map((id) => ({ id, address: `${id}@example.invalid`, status: 'confirmed' as const }));
  const { rerender } = mount(<AddressManagement {...addressProps({ addresses: four })} />);
  expect((screen.getByRole('button', { name: 'Add address' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText('You’ve reached the maximum of 4 addresses.')).toBeTruthy();
  rerender(
    <ThemeProvider>
      <AddressManagement {...addressProps({ mailConfigured: false })} />
    </ThemeProvider>,
  );
  expect((screen.getByRole('button', { name: 'Add address' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText('Email isn’t configured')).toBeTruthy();
});

test('adding an address is two steps: enter it, then prove it with the mailed code', () => {
  const onSubmitAddress = vi.fn();
  const onSubmitProof = vi.fn();
  const { rerender } = mount(<AddressManagement {...addressProps({ state: { kind: 'adding', step: 'enter' }, onSubmitAddress, onSubmitProof })} />);
  type('Email address', 'new@example.invalid');
  fireEvent.submit(screen.getByRole('form', { name: 'Add notification address' }));
  expect(onSubmitAddress).toHaveBeenCalledExactlyOnceWith({ address: 'new@example.invalid' });
  rerender(
    <ThemeProvider>
      <AddressManagement {...addressProps({ state: { kind: 'adding', step: 'proof', pendingAddress: 'new@example.invalid' }, onSubmitAddress, onSubmitProof })} />
    </ThemeProvider>,
  );
  expect(screen.getByText(/isn’t used until you confirm it/)).toBeTruthy();
  type('Code from the email', '654 321');
  fireEvent.submit(screen.getByRole('form', { name: 'Confirm notification address' }));
  expect(onSubmitProof).toHaveBeenCalledExactlyOnceWith({ code: '654321' });
});

test('notice health never reports an unreadable status as healthy and never shows recipients', () => {
  const { container, rerender } = mount(<NoticeHealth health={{ pending: 0, failed: 0, bounced: 0, quarantined: 0, protective: 0, unknown: true }} />);
  expect(screen.getByRole('status').textContent).toContain('status is unknown');
  expect(container.textContent).not.toContain('Security notices are being delivered');
  rerender(
    <ThemeProvider>
      <NoticeHealth health={{ pending: 0, failed: 2, bounced: 1, quarantined: 0, protective: 0 }} onRetry={noop} />
    </ThemeProvider>,
  );
  expect(container.textContent).not.toMatch(/@|smtp:/i);
});

test('a security change without a recorded notice is the most severe notice state and offers no retry', () => {
  mount(<NoticeHealth health={{ pending: 0, failed: 3, bounced: 0, quarantined: 0, protective: 1 }} onRetry={noop} />);
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('1 security change has no recorded notice');
  expect(screen.queryByRole('button', { name: 'Retry failed notices' })).toBeNull();
});

test('retry is offered only for failed notices and only to a viewer who may repair them', () => {
  const onRetry = vi.fn();
  const { rerender } = mount(<NoticeHealth health={{ pending: 0, failed: 2, bounced: 0, quarantined: 0, protective: 0 }} onRetry={onRetry} />);
  fireEvent.click(screen.getByRole('button', { name: 'Retry failed notices' }));
  expect(onRetry).toHaveBeenCalledTimes(1);
  rerender(
    <ThemeProvider>
      <NoticeHealth health={{ pending: 0, failed: 2, bounced: 0, quarantined: 0, protective: 0 }} />
    </ThemeProvider>,
  );
  expect(screen.queryByRole('button', { name: 'Retry failed notices' })).toBeNull();
  rerender(
    <ThemeProvider>
      <NoticeHealth health={{ pending: 0, failed: 0, bounced: 4, quarantined: 0, protective: 0 }} onRetry={onRetry} />
    </ThemeProvider>,
  );
  expect(screen.queryByRole('button', { name: 'Retry failed notices' })).toBeNull();
});

// ───────────────────────── agent token ─────────────────────────

const TOKEN = 'mdt_SYNTHETIC_NOT_A_REAL_TOKEN_0000';
const CREDS = [{ id: 'c1', displayId: 'mdt_a1b2…', status: 'active' as const, expiresOn: '11 Feb 2027' }];

function agentProps(overrides: Partial<Parameters<typeof AgentCredentials>[0]> = {}) {
  return { agentName: 'ci-runner', credentials: CREDS, state: { kind: 'idle' as const }, onIssue: noop, onRotate: noop, onAskRevoke: noop, onCancelRevoke: noop, onConfirmRevoke: noop, onHidden: noop, ...overrides };
}

test('the agent token is shown once, only inside the reveal panel, and is gone from the DOM after hiding', () => {
  const onHidden = vi.fn();
  const { container } = mount(<AgentCredentials {...agentProps({ state: { kind: 'reveal', token: TOKEN, expiresOn: '11 Feb 2027' }, onHidden })} />);
  const region = screen.getByRole('region', { name: 'New token for ci-runner' });
  expect(region.textContent).toContain(TOKEN);
  const list = screen.getByRole('list');
  expect(list.textContent).not.toContain(TOKEN);
  fireEvent.click(screen.getByLabelText('I have copied this token to where the agent will read it.'));
  fireEvent.click(screen.getByRole('button', { name: 'Hide the token' }));
  expect(onHidden).toHaveBeenCalledTimes(1);
  expect(container.textContent).not.toContain(TOKEN);
});

test('issue is offered when nothing is live and rotate when something is; an overlap is described in plain words', () => {
  const { rerender } = mount(<AgentCredentials {...agentProps({ credentials: [] })} />);
  expect(screen.getByRole('button', { name: 'Issue token' })).toBeTruthy();
  rerender(
    <ThemeProvider>
      <AgentCredentials {...agentProps()} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('button', { name: 'Rotate token' })).toBeTruthy();
  rerender(
    <ThemeProvider>
      <AgentCredentials {...agentProps({ state: { kind: 'reveal', token: TOKEN, expiresOn: null, rotatedOutDisplayId: 'mdt_old…' } })} />
    </ThemeProvider>,
  );
  expect(screen.getByText(/previous token \(mdt_old…\) keeps working only until the overlap window/)).toBeTruthy();
  expect(screen.getByText(/does not expire/)).toBeTruthy();
});

test('revoking needs a named confirmation and a missing recent verification is explained without a retry loop', () => {
  const { rerender } = mount(<AgentCredentials {...agentProps({ state: { kind: 'confirming_revoke', id: 'c1' } })} />);
  expect(screen.getByRole('group', { name: 'Confirm revoking mdt_a1b2…' }).textContent).toContain('cut off immediately');
  rerender(
    <ThemeProvider>
      <AgentCredentials {...agentProps({ state: { kind: 'rejected', reason: 'step_up_required' } })} />
    </ThemeProvider>,
  );
  expect(screen.getByRole('alert').textContent).toContain('Nothing was created or changed');
});
