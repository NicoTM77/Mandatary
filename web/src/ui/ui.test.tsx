import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { ThemeProvider, useTheme } from '../theme';
import { AdminShell, Alert, Button, CodeField, PasswordField, SecretReveal, Steps, TextField, ThemeToggle } from '.';

afterEach(() => {
  cleanup();
  document.documentElement.removeAttribute('data-theme');
});

// ───────────────────────── Button ─────────────────────────

test('a busy button keeps focus, announces busy and swallows repeat activation (no double submit)', () => {
  const onClick = vi.fn();
  const onSubmit = vi.fn((event: { preventDefault: () => void }) => event.preventDefault());
  render(
    <form onSubmit={onSubmit}>
      <Button type="submit" busy busyLabel="Signing in…" onClick={onClick}>
        Sign in
      </Button>
    </form>,
  );
  const button = screen.getByRole('button', { name: 'Signing in…' });
  button.focus();
  expect(document.activeElement).toBe(button);
  expect(button.getAttribute('aria-busy')).toBe('true');
  expect(button.getAttribute('aria-disabled')).toBe('true');
  expect((button as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(button);
  expect(onClick).not.toHaveBeenCalled();
  expect(onSubmit).not.toHaveBeenCalled();
});

test('an idle button runs its handler and defaults to type=button so it never submits a form by accident', () => {
  const onClick = vi.fn();
  render(<Button onClick={onClick}>Save</Button>);
  const button = screen.getByRole('button', { name: 'Save' });
  expect(button.getAttribute('type')).toBe('button');
  fireEvent.click(button);
  expect(onClick).toHaveBeenCalledTimes(1);
});

// ───────────────────────── fields ─────────────────────────

test('a field is labelled, and its hint and error are linked with aria-describedby / aria-invalid', () => {
  render(<TextField name="username" label="Username" hint="Letters and digits." error="Enter a username." />);
  const input = screen.getByLabelText('Username');
  expect(input.getAttribute('aria-invalid')).toBe('true');
  const described = (input.getAttribute('aria-describedby') ?? '').split(' ');
  expect(described).toHaveLength(2);
  const text = described.map((id) => document.getElementById(id)?.textContent);
  expect(text).toEqual(['Letters and digits.', 'Enter a username.']);
});

test('a valid field carries no aria-invalid', () => {
  render(<TextField name="username" label="Username" />);
  expect(screen.getByLabelText('Username').hasAttribute('aria-invalid')).toBe(false);
});

test('password fields never block paste or managers, classify the form, and mask again on submit', () => {
  const onPaste = vi.fn();
  render(
    <form>
      <PasswordField name="password" label="Password" autoComplete="new-password" onPaste={onPaste} />
    </form>,
  );
  const input = screen.getByLabelText('Password') as HTMLInputElement;
  expect(input.type).toBe('password');
  expect(input.autocomplete).toBe('new-password');
  const paste = new Event('paste', { bubbles: true, cancelable: true });
  input.dispatchEvent(paste);
  expect(onPaste).toHaveBeenCalled();
  expect(paste.defaultPrevented).toBe(false);

  const toggle = screen.getByRole('button', { name: 'Show password' });
  expect(toggle.getAttribute('aria-pressed')).toBe('false');
  fireEvent.click(toggle);
  expect(input.type).toBe('text');
  expect(toggle.getAttribute('aria-pressed')).toBe('true');
  fireEvent.submit(input.form as HTMLFormElement);
  expect(input.type).toBe('password');
});

test('password fields expose the autofill attributes managers rely on for sign-in', () => {
  render(<PasswordField name="password" label="Password" autoComplete="current-password" />);
  const input = screen.getByLabelText('Password') as HTMLInputElement;
  expect(input.getAttribute('autocomplete')).toBe('current-password');
  expect(input.getAttribute('name')).toBe('password');
  expect(input.getAttribute('spellcheck')).toBe('false');
});

test.each([
  ['totp', { inputmode: 'numeric', autocomplete: 'one-time-code' }],
  ['mailed-proof', { inputmode: 'text', autocomplete: 'one-time-code' }],
  ['saved-code', { inputmode: 'text', autocomplete: 'off' }],
  ['setup-token', { inputmode: 'text', autocomplete: 'off' }],
] as const)('code field "%s" sets the right keyboard and autofill hints, and no length cap that would break paste', (kind, expected) => {
  render(<CodeField kind={kind} name="code" label="Code" />);
  const input = screen.getByLabelText('Code');
  expect(input.getAttribute('inputmode')).toBe(expected.inputmode);
  expect(input.getAttribute('autocomplete')).toBe(expected.autocomplete);
  expect(input.hasAttribute('maxlength')).toBe(false);
  expect(input.hasAttribute('pattern')).toBe(false);
  expect(input.getAttribute('spellcheck')).toBe('false');
});

test('offline codes and setup tokens opt out of password managers', () => {
  render(<CodeField kind="saved-code" name="code" label="Code" />);
  const input = screen.getByLabelText('Code');
  expect(input.getAttribute('data-1p-ignore')).toBe('true');
  expect(input.getAttribute('data-lpignore')).toBe('true');
});

// ───────────────────────── alert ─────────────────────────

test('danger alerts are assertive, others polite, and "none" is silent on load', () => {
  const { rerender } = render(<Alert tone="danger" title="Failed" />);
  expect(screen.getByRole('alert').textContent).toContain('Failed');
  rerender(<Alert tone="info" title="FYI" />);
  expect(screen.getByRole('status').textContent).toContain('FYI');
  rerender(<Alert tone="info" role="none" title="Static" />);
  expect(screen.queryByRole('status')).toBeNull();
  expect(screen.queryByRole('alert')).toBeNull();
});

// ───────────────────────── reveal-once ─────────────────────────

const SECRET = 'SYNTHETIC-REVEAL-VALUE-0000';

function installClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(globalThis.navigator, 'clipboard', { value: { writeText }, configurable: true });
}

beforeEach(() => {
  Object.defineProperty(globalThis.navigator, 'clipboard', { value: undefined, configurable: true });
});

test('the secret is text content only: no attribute, id, title or storage ever holds it', () => {
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const { container } = render(<SecretReveal heading="Your token" value={SECRET} acknowledge={{ confirmLabel: 'Stored.', doneLabel: 'Hide', onDone: vi.fn() }} />);
  expect(container.textContent).toContain(SECRET);
  for (const element of container.querySelectorAll('*')) {
    for (const attribute of Array.from(element.attributes)) {
      expect(`${attribute.name}=${attribute.value}`).not.toContain(SECRET);
    }
  }
  expect(document.title).not.toContain(SECRET);
  expect(globalThis.location.href).not.toContain(SECRET);
  expect(setItem).not.toHaveBeenCalled();
  expect(localStorage.length + sessionStorage.length).toBe(0);
});

test('the reveal panel takes focus so a screen-reader user lands on the warning first', () => {
  render(<SecretReveal heading="Your token" value={SECRET} />);
  const region = screen.getByRole('region', { name: 'Your token' });
  expect(document.activeElement).toBe(region);
  expect(region.textContent).toContain('only time it will be shown');
});

test('copy reports success in a live region that never contains the secret', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  installClipboard(writeText);
  render(<SecretReveal heading="Your token" value={SECRET} />);
  fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
  await waitFor(() => expect(screen.getByRole('status').textContent).toBe('Copied to clipboard.'));
  expect(writeText).toHaveBeenCalledWith(SECRET);
  expect(screen.getByRole('status').textContent).not.toContain(SECRET);
});

test('a failed or unavailable clipboard tells the person to copy manually and still never echoes the secret', async () => {
  render(<SecretReveal heading="Your token" value={SECRET} />);
  fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
  await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/copy it yourself/));
  expect(screen.getByRole('status').textContent).not.toContain(SECRET);
});

test('hiding requires acknowledgement first, then REMOVES the secret from the DOM and calls onDone once', () => {
  const onDone = vi.fn();
  const { container } = render(<SecretReveal heading="Your token" value={SECRET} acknowledge={{ confirmLabel: 'I stored it.', doneLabel: 'Hide token', onDone }} />);
  const hide = screen.getByRole('button', { name: 'Hide token' }) as HTMLButtonElement;
  expect(hide.disabled).toBe(true);
  fireEvent.click(hide);
  expect(onDone).not.toHaveBeenCalled();
  expect(container.textContent).toContain(SECRET);

  fireEvent.click(screen.getByLabelText('I stored it.'));
  expect(hide.disabled).toBe(false);
  fireEvent.click(hide);
  expect(onDone).toHaveBeenCalledTimes(1);
  expect(container.textContent).not.toContain(SECRET);
  expect(document.body.innerHTML).not.toContain(SECRET);
  expect(screen.getByRole('status').textContent).toContain('can’t be shown again');
});

test('several secrets (recovery codes) render as one ordered list and copy together', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  installClipboard(writeText);
  render(<SecretReveal heading="Codes" items={['AAA-1', 'BBB-2']} />);
  expect(screen.getAllByRole('listitem').map((item) => item.textContent)).toEqual(['AAA-1', 'BBB-2']);
  fireEvent.click(screen.getByRole('button', { name: 'Copy all codes' }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith('AAA-1\nBBB-2'));
});

test('a single value can be shown in groups while copying the raw value', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  installClipboard(writeText);
  render(<SecretReveal heading="Key" value="ABCDEFGH" groupEvery={4} />);
  expect(screen.getByText('ABCD EFGH')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith('ABCDEFGH'));
});

// ───────────────────────── steps ─────────────────────────

test('steps announce position as text and mark the current step', () => {
  render(
    <Steps
      steps={[
        { id: 'a', label: 'First' },
        { id: 'b', label: 'Second' },
        { id: 'c', label: 'Third' },
      ]}
      currentId="b"
    />,
  );
  expect(screen.getByText('Step 2 of 3')).toBeTruthy();
  const current = screen.getAllByRole('listitem').find((item) => item.getAttribute('aria-current') === 'step');
  expect(current?.textContent).toContain('Second');
  expect(screen.getByText('(done)')).toBeTruthy();
});

// ───────────────────────── shell ─────────────────────────

const NAV = [
  { id: 'a', label: 'Account security', href: '#a', group: 'Account' },
  { id: 'b', label: 'Sign-in methods', href: '#b', group: 'Account' },
] as const;

function Shell({ assurance = 'aal2' as const }) {
  return (
    <ThemeProvider>
      <AdminShell nav={NAV} currentId="b" account={{ username: 'sample-admin', assurance, freshnessNote: 'Verified 4 minutes ago' }} onSignOut={vi.fn()}>
        <h1>Page</h1>
      </AdminShell>
    </ThemeProvider>
  );
}

test('the shell exposes a skip link, labelled navigation, one main landmark and aria-current', () => {
  render(<Shell />);
  const skip = screen.getByRole('link', { name: 'Skip to main content' });
  expect(skip.getAttribute('href')).toBe('#main-content');
  expect(document.getElementById('main-content')?.tagName).toBe('MAIN');
  const nav = screen.getByRole('navigation', { name: 'Primary' });
  expect(nav.querySelector('[aria-current="page"]')?.textContent).toBe('Sign-in methods');
  expect(screen.getAllByRole('main')).toHaveLength(1);
});

test('the skip link is the first focusable element', () => {
  render(<Shell />);
  const focusable = Array.from(document.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled])'));
  expect(focusable[0]?.textContent).toBe('Skip to main content');
});

test('the assurance label is server-derived text, never colour alone', () => {
  const { rerender } = render(<Shell />);
  expect(screen.getByText('Multi-factor verified')).toBeTruthy();
  rerender(<Shell assurance={'password-only' as unknown as 'aal2'} />);
  expect(screen.getByText('Password only')).toBeTruthy();
  expect(screen.getByText('Verified 4 minutes ago')).toBeTruthy();
});

test('the menu button exposes expanded state and Escape closes it and returns focus', () => {
  render(<Shell />);
  const menu = screen.getByRole('button', { name: 'Menu' });
  expect(menu.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(menu);
  expect(menu.getAttribute('aria-expanded')).toBe('true');
  expect(menu.getAttribute('aria-controls')).toBe(screen.getByRole('navigation', { name: 'Primary' }).id);
  const link = screen.getByRole('link', { name: 'Account security' });
  link.focus();
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(menu.getAttribute('aria-expanded')).toBe('false');
  expect(document.activeElement).toBe(menu);
});

test('sign out is only offered with a session and a handler', () => {
  render(
    <ThemeProvider>
      <AdminShell nav={NAV} currentId="a">
        <p>content</p>
      </AdminShell>
    </ThemeProvider>,
  );
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull();
  expect(screen.getByText('Not signed in')).toBeTruthy();
});

// ───────────────────────── theme ─────────────────────────

function Probe() {
  const { theme } = useTheme();
  return <p data-testid="theme">{theme}</p>;
}

function stubMatchMedia(dark: boolean) {
  const listeners = new Set<(event: MediaQueryListEvent) => void>();
  const query = {
    matches: dark,
    addEventListener: (_: string, listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
  };
  Object.defineProperty(globalThis, 'matchMedia', { value: () => query, configurable: true, writable: true });
  return (next: boolean) => {
    for (const listener of listeners) listener({ matches: next } as MediaQueryListEvent);
  };
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, 'matchMedia');
});

test('the first paint follows the operating system theme and updates when it changes', () => {
  const change = stubMatchMedia(true);
  render(
    <ThemeProvider>
      <Probe />
    </ThemeProvider>,
  );
  expect(screen.getByTestId('theme').textContent).toBe('dark');
  expect(document.documentElement.dataset.theme).toBe('dark');
  act(() => change(false));
  expect(screen.getByTestId('theme').textContent).toBe('light');
  expect(document.documentElement.dataset.theme).toBe('light');
});

test('an explicit choice overrides the system theme, is in-memory only, and is removed on unmount', () => {
  stubMatchMedia(true);
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const { unmount } = render(
    <ThemeProvider>
      <Probe />
      <ThemeToggle />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Use light theme' }));
  expect(document.documentElement.dataset.theme).toBe('light');
  expect(screen.getByRole('button', { name: 'Use dark theme' })).toBeTruthy();
  expect(setItem).not.toHaveBeenCalled();
  expect(document.cookie).toBe('');
  unmount();
  expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
});
