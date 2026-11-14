import { cleanup, render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, describe, expect, test } from 'vitest';
import { ThemeProvider } from '../theme';
import type { SecurityKeyRow, SignInMethodsProps, TotpFactorRow } from './contract';
import { SignInMethods } from './factors';
import { removalConsequence, removalWarning } from './removal';

/**
 * P1.18.4 AUTH-08-L4: removing the last WORKING second factor says so BEFORE confirmation, including that a sibling disabled after failed codes does not
 * count and that only a saved recovery code gets the person back in. The conservative server rule is untouched; this is the missing warning.
 */

afterEach(cleanup);
const noop = () => undefined;
const app = (id: string, status: TotpFactorRow['status'] = 'active'): TotpFactorRow => ({ id, label: `Authenticator app ${id}`, addedOn: '3 Nov 2026', status });
const key = (id: string): SecurityKeyRow => ({ id, name: `Key ${id}`, addedOn: '9 Nov 2026' });

function mount(ui: ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

const props = (patch: Partial<SignInMethodsProps>): SignInMethodsProps => ({ totp: [], keys: [], maxKeys: 16, onAddTotp: noop, onAddKey: noop, onAskRemove: noop, onCancelRemove: noop, onConfirmRemove: noop, ...patch });

describe('the consequence, as a pure function of the account’s own rows', () => {
  test('a genuine last working factor, with and without a disabled sibling', () => {
    expect(removalConsequence([app('a')], [], { kind: 'totp', id: 'a' })).toEqual({ lastWorking: true, targetWorks: true, disabledApps: 0, otherWorking: 0 });
    expect(removalConsequence([app('a'), app('b', 'disabled')], [], { kind: 'totp', id: 'a' })).toEqual({ lastWorking: true, targetWorks: true, disabledApps: 1, otherWorking: 0 });
    expect(removalConsequence([app('b', 'disabled')], [key('k')], { kind: 'webauthn', id: 'k' })).toEqual({ lastWorking: true, targetWorks: true, disabledApps: 1, otherWorking: 0 });
  });
  test('a remaining working method (app or key) means it is not the last', () => {
    expect(removalConsequence([app('a'), app('b')], [], { kind: 'totp', id: 'a' }).lastWorking).toBe(false);
    expect(removalConsequence([app('a')], [key('k')], { kind: 'totp', id: 'a' }).lastWorking).toBe(false);
    expect(removalConsequence([app('a')], [key('k')], { kind: 'webauthn', id: 'k' }).lastWorking).toBe(false);
    expect(removalConsequence([app('a'), app('b', 'disabled')], [key('k')], { kind: 'totp', id: 'a' }).otherWorking).toBe(1);
  });
  test('removing a method that is itself disabled gives nothing up and warns of nothing', () => {
    const consequence = removalConsequence([app('b', 'disabled')], [], { kind: 'totp', id: 'b' });
    expect(consequence.targetWorks).toBe(false);
    expect(removalWarning(consequence, 5)).toBeNull();
  });
  test('the warning states the count of saved codes, the lock-out when there are none, and never invents a sibling', () => {
    const last = removalConsequence([app('a')], [], { kind: 'totp', id: 'a' });
    expect(removalWarning(last, 5)?.body).toBe('After this you can get back in only with a saved recovery code. You have 5 unused codes. Everyone signed in as you is signed out when it is removed.');
    expect(removalWarning(last, 1)?.body).toContain('You have 1 unused code.');
    expect(removalWarning(last, 0)?.body).toContain('you have none left, so you would be locked out until whoever runs this server does the host recovery');
    expect(removalWarning(last, 5)?.body).not.toContain('disabled');
    const protective = removalConsequence([app('a'), app('b', 'disabled'), app('c', 'disabled')], [], { kind: 'totp', id: 'a' });
    expect(removalWarning(protective, 3)?.body).toContain('Your other authenticator apps are disabled after too many failed codes, so they don’t count, and removing this one doesn’t bring them back.');
    expect(removalWarning(removalConsequence([app('a'), app('b', 'disabled')], [], { kind: 'totp', id: 'a' }), 3)?.body).toContain('Your other authenticator app is disabled after too many failed codes, so it doesn’t count');
    expect(removalWarning(removalConsequence([app('a'), app('b')], [], { kind: 'totp', id: 'a' }), 3)).toBeNull();
  });
});

describe.each(['light', 'dark'] as const)('the confirmation (%s theme)', (theme) => {
  test('the last working factor with a protectively disabled sibling shows the consequence before anything is confirmed', () => {
    mount(<SignInMethods {...props({ totp: [app('a'), app('b', 'disabled')], confirmingRemoval: { kind: 'totp', id: 'a' }, recoveryRemaining: 4 })} />, theme);
    const group = screen.getByRole('group', { name: 'Confirm removing Authenticator app a' });
    expect(group.textContent).toContain('This is your last working second factor.');
    expect(group.textContent).toContain('Your other authenticator app is disabled after too many failed codes');
    expect(group.textContent).toContain('You have 4 unused codes');
    expect(group.textContent).toContain('signed out');
    // The warning is in the confirmation itself, before the destructive button.
    const text = group.textContent ?? '';
    expect(text.indexOf('last working second factor')).toBeLessThan(text.indexOf('Keep it'));
    expect(within(group).getByRole('button', { name: 'Remove Authenticator app a' })).toBeTruthy();
  });

  test('with another working method left, only the ordinary confirmation shows (no false alarm)', () => {
    mount(<SignInMethods {...props({ totp: [app('a'), app('b')], keys: [key('k')], confirmingRemoval: { kind: 'totp', id: 'a' }, recoveryRemaining: 4 })} />, theme);
    const group = screen.getByRole('group', { name: 'Confirm removing Authenticator app a' });
    expect(group.textContent).not.toContain('last working second factor');
    expect(group.textContent).toContain('You won’t be able to use it to sign in.');
  });

  test('a security key that is the last working method warns the same way', () => {
    mount(<SignInMethods {...props({ totp: [app('b', 'disabled')], keys: [key('k')], confirmingRemoval: { kind: 'webauthn', id: 'k' }, recoveryRemaining: 0 })} />, theme);
    const group = screen.getByRole('group', { name: 'Confirm removing Key k' });
    expect(group.textContent).toContain('This is your last working second factor.');
    expect(group.textContent).toContain('you have none left');
  });

  test('while the inventory is being re-read the confirmation cannot be used, and says why', () => {
    mount(<SignInMethods {...props({ totp: [app('a')], confirmingRemoval: { kind: 'totp', id: 'a' }, removalCheck: 'checking' })} />, theme);
    const group = screen.getByRole('group', { name: 'Confirm removing Authenticator app a' });
    expect(group.getAttribute('aria-busy')).toBe('true');
    expect(within(group).getByRole('status').textContent).toContain('Checking which other sign-in methods you have');
    expect((within(group).getByRole('button', { name: 'Remove Authenticator app a' }) as HTMLButtonElement).disabled).toBe(true);
    expect(group.textContent).not.toContain('last working second factor');
  });

  test('when the re-read failed the page assumes the worst instead of staying silent', () => {
    mount(<SignInMethods {...props({ totp: [app('a'), app('b')], confirmingRemoval: { kind: 'totp', id: 'a' }, removalCheck: 'failed' })} />, theme);
    const group = screen.getByRole('group', { name: 'Confirm removing Authenticator app a' });
    expect(group.textContent).toContain('couldn’t re-check your other sign-in methods just now');
    expect(group.textContent).toContain('Treat this as your last working second factor');
    expect((within(group).getByRole('button', { name: 'Remove Authenticator app a' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
