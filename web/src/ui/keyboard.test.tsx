import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { LoginFactor } from '../screens/login';
import type { LoginFactorProps } from '../screens/contract';
import { Button, PasswordField, TextField } from '.';

/**
 * Keyboard contract (UX §9 "Keyboard"): every control is a native element, tab order equals
 * DOM order, and no custom widget handles keys itself.
 *
 * Scope note: jsdom does not synthesise browser key→activation (Enter/Space clicking a button,
 * arrow keys moving between radios). These tests therefore assert the native-element
 * preconditions that make those browser behaviours apply, plus the handlers React wires.
 * Real key behaviour is exercised in the Chromium checks, not here.
 */

afterEach(cleanup);

test('controls are native and in visual order, with no positive tabindex to reorder them', () => {
  const { container } = render(
    <form>
      <TextField name="name" label="Name" />
      <PasswordField name="password" label="Password" autoComplete="new-password" />
      <Button type="submit">Save</Button>
    </form>,
  );
  const tabbables = Array.from(container.querySelectorAll<HTMLElement>('input, button, a[href], select, textarea'));
  expect(tabbables.map((element) => element.tagName)).toEqual(['INPUT', 'INPUT', 'BUTTON', 'BUTTON']);
  for (const element of tabbables) {
    expect(Number(element.getAttribute('tabindex') ?? 0)).toBeLessThanOrEqual(0);
  }
  expect(container.querySelector('[role="button"], [onclick]')).toBeNull();
});

test('the show/hide password toggle keeps keyboard focus when it is activated', () => {
  render(
    <form>
      <PasswordField name="password" label="Password" autoComplete="new-password" />
    </form>,
  );
  const toggle = screen.getByRole('button', { name: 'Show password' });
  toggle.focus();
  expect(document.activeElement).toBe(toggle);
  fireEvent.click(toggle);
  expect(document.activeElement).toBe(toggle);
  expect(toggle.getAttribute('aria-pressed')).toBe('true');
  expect((screen.getByLabelText('Password') as HTMLInputElement).type).toBe('text');
});

test('a busy button stays focusable and swallows repeat Enter-driven activation', () => {
  const onClick = vi.fn();
  render(
    <Button busy busyLabel="Saving…" onClick={onClick}>
      Save
    </Button>,
  );
  const button = screen.getByRole('button', { name: 'Saving…' });
  button.focus();
  expect(document.activeElement).toBe(button);
  expect((button as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(button);
  expect(onClick).not.toHaveBeenCalled();
});

test('the verification-method radios are native inputs grouped by a named fieldset', () => {
  const props: LoginFactorProps = {
    next: ['totp', 'webauthn'],
    method: 'totp',
    state: { kind: 'idle' },
    onChooseMethod: vi.fn(),
    onSubmitTotp: vi.fn(),
    onStartWebAuthn: vi.fn(),
    onRestart: vi.fn(),
  };
  const { container } = render(<LoginFactor {...props} />);
  const group = screen.getByRole('group', { name: 'Verification method' });
  const radios = Array.from(group.querySelectorAll<HTMLInputElement>('input[type="radio"]'));
  expect(radios).toHaveLength(2);
  expect(radios.map((radio) => radio.name)).toEqual(['method', 'method']);
  expect(radios.find((radio) => radio.checked)?.value).toBe('totp');
  for (const radio of radios) {
    expect(radio.tabIndex).toBeGreaterThanOrEqual(0);
  }
  expect(container.querySelector('[role="radio"]')).toBeNull();
});

test('choosing a radio reports the chosen method once and does not submit a form', () => {
  const onChooseMethod = vi.fn();
  const onSubmitTotp = vi.fn();
  render(
    <LoginFactor
      next={['totp', 'webauthn']}
      method="totp"
      state={{ kind: 'idle' }}
      onChooseMethod={onChooseMethod}
      onSubmitTotp={onSubmitTotp}
      onStartWebAuthn={vi.fn()}
      onRestart={vi.fn()}
    />,
  );
  fireEvent.click(screen.getByRole('radio', { name: 'Security key' }));
  expect(onChooseMethod).toHaveBeenCalledWith('webauthn');
  expect(onChooseMethod).toHaveBeenCalledTimes(1);
  expect(onSubmitTotp).not.toHaveBeenCalled();
});

test('while a request is in flight the method fieldset is disabled, so focus is not moved to a live choice', () => {
  render(
    <LoginFactor
      next={['totp', 'webauthn']}
      method="totp"
      state={{ kind: 'submitting' }}
      onChooseMethod={vi.fn()}
      onSubmitTotp={vi.fn()}
      onStartWebAuthn={vi.fn()}
      onRestart={vi.fn()}
    />,
  );
  const group = screen.getByRole('group', { name: 'Verification method' });
  expect((group as HTMLFieldSetElement).disabled).toBe(true);
});
