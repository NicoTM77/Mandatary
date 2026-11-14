import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AccountApi } from '../api/account';
import { SetupApi } from '../api/setup';
import { ThemeProvider, type Theme } from '../theme';
import { FakeServer, SESSION_CSRF, SETUP_CSRF, empty, json, requireCsrf, setupView } from './fakeServer';
import { LoginContainer } from './LoginContainer';
import { SessionHome } from './SessionHome';
import { SetupContainer } from './SetupContainer';

// Synthetic canaries. None is shaped like a real credential, and none may appear anywhere below.
const PASSWORD = 'synthetic-container-password-canary';
const SEED = 'SYNTHETIC-SEED-CANARY-0001';
const TOKEN = 'SYNTHETIC-SETUP-TOKEN-CANARY';
const COOKIE = 'synthetic-cookie-canary';

const themes: Theme[] = ['light', 'dark'];

let consoleCalls: unknown[][] = [];

beforeEach(() => {
  consoleCalls = [];
  for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      consoleCalls.push(args);
    });
  }
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  localStorage.clear();
  sessionStorage.clear();
});

function mount(ui: ReactElement, theme: Theme = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

function type(label: string | RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function submit(name: string) {
  fireEvent.submit(screen.getByRole('form', { name }));
}

function click(name: string | RegExp) {
  fireEvent.click(screen.getByRole('button', { name }));
}

/** Equality on synthetic canaries only (the lint rule cannot tell a fixture from a credential check). */
function sameValue(actual: string, expected: string): boolean {
  return Object.is(actual, expected);
}

function shownText(): string {
  return (document.body.textContent ?? '').replace(/\s/g, '');
}

/** No canary in the DOM (text and attributes), the URL, the title, storage or the console. */
function expectNoLeak(...secrets: string[]) {
  const dom = document.documentElement.outerHTML;
  const fields = Array.from(document.querySelectorAll('input')).map((input) => input.value);
  const text = document.body.textContent ?? '';
  const surfaces = [dom, text, text.replace(/\s/g, ''), ...fields, location.href, document.title, JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage }), JSON.stringify(consoleCalls)];
  for (const secret of secrets) for (const surface of surfaces) expect(surface).not.toContain(secret);
}

// ───────────────────────── setup ─────────────────────────

interface SetupWorld {
  server: FakeServer;
  state: { staged: boolean; confirmed: boolean; begun: boolean; proven: boolean; expiresAt: number };
}

function setupWorld(overrides: { purpose?: string; replacePassword?: boolean; session?: 'none' | 'live' | 'closed'; begun?: boolean } = {}): SetupWorld {
  const state = { staged: false, confirmed: false, begun: overrides.begun ?? false, proven: false, expiresAt: Math.floor(Date.now() / 1000) + 30 * 60 };
  const purpose = overrides.purpose ?? 'initial_setup';
  const view = () =>
    setupView({
      purpose,
      expires_at: state.expiresAt,
      replace_password: overrides.replacePassword ?? false,
      target_user: purpose === 'mfa_reset' ? 'existing-admin' : '',
      account_staged: state.staged,
      totp_begun: state.begun,
      totp_proven: state.proven,
      addresses: state.staged && purpose !== 'mfa_reset' ? [{ id: 'addr-1', address: 'admin@example.invalid', confirmed: state.confirmed }] : null,
    });
  let live = overrides.session === 'live';
  const server = new FakeServer()
    .route('POST', '/api/v1/setup/exchange', (request) => {
      if (!sameValue((request.body as { token: string }).token, TOKEN)) return json(401, { error: 'invalid_token' });
      live = true;
      return json(200, view());
    })
    .route('GET', '/api/v1/setup/session', () => (overrides.session === 'closed' ? json(404, { error: 'not_found' }) : live ? json(200, view()) : json(401, { error: 'unauthenticated' })))
    .route('POST', '/api/v1/setup/account', (request) =>
      requireCsrf(request, SETUP_CSRF, () => {
        const body = request.body as { password: string };
        if (body.password === 'short') return json(422, { error: 'password_rejected', guidance: 'Use at least 8 characters.' });
        state.staged = true;
        return json(200, { addresses: [] });
      }),
    )
    .route('POST', '/api/v1/setup/addresses/proof', (request) => requireCsrf(request, SETUP_CSRF, () => empty()))
    .route('POST', '/api/v1/setup/addresses/confirm', (request) =>
      requireCsrf(request, SETUP_CSRF, () => {
        if ((request.body as { proof: string }).proof !== '123456') return json(403, { error: 'denied' });
        state.confirmed = true;
        return empty();
      }),
    )
    .route('POST', '/api/v1/setup/totp', (request) =>
      requireCsrf(request, SETUP_CSRF, () => {
        if (state.begun) return json(403, { error: 'denied' });
        state.begun = true;
        return json(200, { authenticator_id: 'auth-1', secret: SEED, algorithm: 'SHA256', digits: 6, period: 30 });
      }),
    )
    .route('POST', '/api/v1/setup/totp/confirm', (request) =>
      requireCsrf(request, SETUP_CSRF, () => {
        if ((request.body as { code: string }).code !== '654321') return json(403, { error: 'denied' });
        state.proven = true;
        return empty();
      }),
    )
    .route('POST', '/api/v1/setup/complete', (request) => requireCsrf(request, SETUP_CSRF, () => json(200, { purpose, username: 'first-admin', login_required: true })));
  return { server, state };
}

function mountSetup(world: SetupWorld, theme: Theme = 'light') {
  return mount(<SetupContainer api={new SetupApi(world.server.fetcher)} />, theme);
}

describe.each(themes)('setup against the adapter contract (%s theme)', (theme) => {
  test('the whole flow: token → account → address → authenticator → finish, with no secret surviving its step', async () => {
    const world = setupWorld();
    mountSetup(world, theme);
    expect(document.documentElement.dataset.theme).toBe(theme);

    fireEvent.change(await screen.findByLabelText('Setup token'), { target: { value: TOKEN } });
    submit('Enter setup token');
    await screen.findByRole('form', { name: 'Create administrator' });
    expectNoLeak(TOKEN);

    type('Username', 'first-admin');
    type('Password', PASSWORD);
    type('Email address 1', 'admin@example.invalid');
    submit('Create administrator');
    await screen.findByText('Confirm a notification address');
    expectNoLeak(PASSWORD);

    click('Send confirmation code');
    await screen.findByRole('form', { name: 'Confirm admin@example.invalid' });
    type('Code from the email', '123456');
    submit('Confirm admin@example.invalid');
    await screen.findByText('1 of 1 addresses confirmed. You can continue.');
    click('Continue');

    click('Create authenticator key');
    await screen.findByText('Your authenticator key');
    expect(shownText()).toContain(SEED); // visible exactly while it must be shown (grouped by spaces on screen)
    type('6-digit code', '000000');
    submit('Confirm authenticator code');
    await screen.findByText('That code didn’t match');
    expect(shownText()).toContain(SEED); // still shown so a retry is possible
    type('6-digit code', '654321');
    submit('Confirm authenticator code');
    await screen.findByText('Authenticator confirmed');
    expectNoLeak(SEED); // dropped the moment the code is proven
    click('Continue');

    click('Finish setup');
    await screen.findByText('first-admin is ready');
    const signIn = screen.getByRole('link', { name: 'Go to sign in' });
    expect(signIn.getAttribute('href')).toBe('/login');

    // CSRF: every unsafe request after the exchange carries the server token, in a header only.
    const unsafe = world.server.requests.filter((request) => request.method === 'POST' && request.path !== '/api/v1/setup/exchange');
    expect(unsafe.length).toBeGreaterThanOrEqual(7);
    for (const request of unsafe) {
      expect(request.headers['x-csrf-token']).toBe(SETUP_CSRF);
      expect(request.path).not.toContain('?');
    }
    // The CSRF token is not echoed into the page, and nothing else leaked anywhere.
    expectNoLeak(SETUP_CSRF, TOKEN, PASSWORD, SEED);
    expect(consoleCalls).toEqual([]);
  });

  test('a wrong, expired or replayed token is one message and the field is emptied', async () => {
    const world = setupWorld();
    mountSetup(world, theme);
    for (const attempt of ['WRONG-TOKEN-CANARY', 'EXPIRED-TOKEN-CANARY']) {
      fireEvent.change(await screen.findByLabelText('Setup token'), { target: { value: attempt } });
      submit('Enter setup token');
      await screen.findByText('That token wasn’t accepted');
      expect((screen.getByLabelText('Setup token') as HTMLInputElement).value).toBe('');
      expectNoLeak(attempt);
    }
    expect(screen.queryByText(/expired/i, { selector: 'h1,h2,p.font-semibold' })).toBeNull();
  });

  test('a closed setup surface reveals nothing else', async () => {
    mountSetup(setupWorld({ session: 'closed' }), theme);
    expect(await screen.findByText('Setup isn’t open')).toBeTruthy();
    expect(screen.queryByLabelText('Setup token')).toBeNull();
  });

  test('server password guidance is rendered as text on the field, and the password is cleared', async () => {
    const world = setupWorld({ session: 'live' });
    mountSetup(world, theme);
    await screen.findByRole('form', { name: 'Create administrator' });
    type('Username', 'first-admin');
    type('Password', 'short');
    type('Email address 1', 'admin@example.invalid');
    submit('Create administrator');
    expect(await screen.findByText('Use at least 8 characters.')).toBeTruthy();
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('first-admin');
  });

  test('the rejected password is already blanked in the commit that first shows the guidance', async () => {
    const world = setupWorld({ session: 'live' });
    mountSetup(world, theme);
    await screen.findByRole('form', { name: 'Create administrator' });
    type('Username', 'first-admin');
    type('Password', 'short');
    type('Email address 1', 'admin@example.invalid');
    // Observe the DOM at the moment the guidance first appears: a password still sitting in the field then
    // (cleared only by a later passive effect) is what made the neighbouring test timing-dependent.
    const seen: string[] = [];
    const observer = new MutationObserver(() => {
      if (seen.length === 0 && document.body.textContent?.includes('Use at least 8 characters.')) {
        seen.push((document.querySelector('input[name="password"]') as HTMLInputElement).value);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    submit('Create administrator');
    expect(await screen.findByText('Use at least 8 characters.')).toBeTruthy();
    observer.disconnect();
    expect(seen).toEqual(['']);
  });

  test('a session ended by the server (401) shows the expired state and drops a shown seed', async () => {
    const world = setupWorld({ session: 'live' });
    world.state.staged = true;
    world.state.confirmed = true;
    mountSetup(world, theme);
    await screen.findByText('Add an authenticator app');
    click('Create authenticator key');
    await screen.findByText('Your authenticator key');
    world.server.route('POST', '/api/v1/setup/totp/confirm', () => json(401, { error: 'unauthenticated' }));
    type('6-digit code', '654321');
    submit('Confirm authenticator code');
    await screen.findByText('This setup session has expired');
    expectNoLeak(SEED);
    expect(screen.queryByLabelText('6-digit code')).toBeNull();
  });

  test('the fixed deadline blocks the flow when it passes, with the seed gone', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const world = setupWorld({ session: 'live' });
    world.state.staged = true;
    world.state.confirmed = true;
    mountSetup(world, theme);
    await screen.findByText('Add an authenticator app');
    click('Create authenticator key');
    await screen.findByText('Your authenticator key');
    act(() => {
      vi.setSystemTime(Date.now() + 31 * 60 * 1000);
      vi.advanceTimersByTime(16_000);
    });
    await screen.findByText('This setup session has expired');
    expectNoLeak(SEED);
    expect(screen.getByText(/mandatary setup rotate/)).toBeTruthy();
  });

  test('a reload after the key was created never shows the key again', async () => {
    const world = setupWorld({ session: 'live', begun: true });
    world.state.staged = true;
    world.state.confirmed = true;
    mountSetup(world, theme);
    expect(await screen.findByText('The key can’t be shown again')).toBeTruthy();
    expect(screen.queryByText('Your authenticator key')).toBeNull();
    // Starting over is not offered: a lost seed needs the host to rotate the setup session.
    expect(screen.queryByRole('button', { name: /start over/i })).toBeNull();
  });

  test('a repeated begin is refused by the server and presented as a lost key, not a second seed', async () => {
    const world = setupWorld({ session: 'live' });
    world.state.staged = true;
    world.state.confirmed = true;
    mountSetup(world, theme);
    await screen.findByText('Add an authenticator app');
    world.state.begun = true; // another tab already began
    click('Create authenticator key');
    expect(await screen.findByText('The key can’t be shown again')).toBeTruthy();
  });

  test('an emergency MFA reset sends only the new password: no username, no addresses, no address step', async () => {
    const world = setupWorld({ session: 'live', purpose: 'mfa_reset', replacePassword: true });
    mountSetup(world, theme);
    await screen.findByRole('form', { name: 'Replace password' });
    expect((screen.getByLabelText('Username') as HTMLInputElement).readOnly).toBe(true);
    type('Password', PASSWORD);
    submit('Replace password');
    await screen.findByText('Add an authenticator app');
    expect(world.server.calls('POST', '/api/v1/setup/account')[0]?.body).toEqual({ password: PASSWORD });
    expect(screen.queryByText('Confirm a notification address')).toBeNull();
    expectNoLeak(PASSWORD);
  });

  test('a window of an unknown purpose is not driven by this screen', async () => {
    mountSetup(setupWorld({ session: 'live', purpose: 'something_else' }), theme);
    expect(await screen.findByText('This setup window can’t be used here')).toBeTruthy();
    expect(screen.queryByRole('form')).toBeNull();
  });

  // RESTORE-08: the host-authorized recovery of a RESTORED installation enrolls a NEW administrator (fresh password, a
  // confirmed address and a fresh authenticator). It is presented as that, never as "first setup", and it never offers a way to
  // reuse an account, factor or session that the backup carried.
  test('a restore-recovery window enrolls a new recovery administrator and says what it does not do', async () => {
    const world = setupWorld({ purpose: 'restore_recovery' });
    mountSetup(world, theme);
    fireEvent.change(await screen.findByLabelText('Setup token'), { target: { value: TOKEN } });
    submit('Enter setup token');
    await screen.findByRole('form', { name: 'Create recovery administrator' });
    expect(screen.getByText(/restored from a backup/i)).toBeTruthy();
    expect(screen.getByText(/stay switched off/i)).toBeTruthy();
    expect(screen.queryByRole('form', { name: 'Create administrator' })).toBeNull();
    expectNoLeak(TOKEN);

    type('Username', 'recovery-admin');
    type('Password', PASSWORD);
    type('Email address 1', 'admin@example.invalid');
    submit('Create recovery administrator');
    await screen.findByText('Confirm a notification address');
    expect(world.server.calls('POST', '/api/v1/setup/account')[0]?.body).toEqual({ username: 'recovery-admin', password: PASSWORD, addresses: ['admin@example.invalid'] });
    click('Send confirmation code');
    await screen.findByRole('form', { name: 'Confirm admin@example.invalid' });
    type('Code from the email', '123456');
    submit('Confirm admin@example.invalid');
    await screen.findByText('1 of 1 addresses confirmed. You can continue.');
    click('Continue');
    click('Create authenticator key');
    await screen.findByText('Your authenticator key');
    type('6-digit code', '654321');
    submit('Confirm authenticator code');
    await screen.findByText('Authenticator confirmed');
    expectNoLeak(SEED);
    click('Continue');

    expect(screen.getByText('Recovery administrator account saved')).toBeTruthy();
    click('Finish recovery');
    await screen.findByText('first-admin is ready');
    expect(screen.getByText(/nothing from the backup was switched on/i)).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Go to sign in' }).getAttribute('href')).toBe('/login');
    const unsafe = world.server.requests.filter((request) => request.method === 'POST' && request.path !== '/api/v1/setup/exchange');
    for (const request of unsafe) expect(request.headers['x-csrf-token']).toBe(SETUP_CSRF);
    expectNoLeak(SETUP_CSRF, TOKEN, PASSWORD, SEED);
    expect(consoleCalls).toEqual([]);
  });

  test('an expired restore-recovery window names the restore commands, not the first-setup ones', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const world = setupWorld({ session: 'live', purpose: 'restore_recovery' });
    mountSetup(world, theme);
    await screen.findByRole('form', { name: 'Create recovery administrator' });
    act(() => {
      vi.setSystemTime(Date.now() + 31 * 60 * 1000);
      vi.advanceTimersByTime(16_000);
    });
    await screen.findByText('This setup session has expired');
    expect(screen.getByText(/mandatary recovery restore-admin/)).toBeTruthy();
    expect(screen.queryByText(/mandatary setup rotate/)).toBeNull();
  });

  test('without a configured mail relay a restore recovery explains the restore command', async () => {
    const world = setupWorld({ session: 'live', purpose: 'restore_recovery' });
    world.server.route('GET', '/api/v1/setup/session', () => json(200, setupView({ purpose: 'restore_recovery', mail_configured: false })));
    mountSetup(world, theme);
    expect(await screen.findByText('Setup can’t be completed yet')).toBeTruthy();
    expect(screen.getByText(/mandatary recovery restore-admin/)).toBeTruthy();
    expect(screen.queryByLabelText('Password')).toBeNull();
  });

  test('without a configured mail relay the account form is replaced by an operator explanation', async () => {
    const world = setupWorld({ session: 'live' });
    world.server.route('GET', '/api/v1/setup/session', () => json(200, setupView({ mail_configured: false })));
    mountSetup(world, theme);
    expect(await screen.findByText('Setup can’t be completed yet')).toBeTruthy();
    expect(screen.queryByLabelText('Password')).toBeNull();
  });
});

// ───────────────────────── login ─────────────────────────

interface LoginWorld {
  server: FakeServer;
  navigate: ReturnType<typeof vi.fn<(path: string) => void>>;
}

function loginWorld(next: string[] = ['totp', 'no-mfa'], extra?: (server: FakeServer) => void): LoginWorld {
  const server = new FakeServer()
    .route('POST', '/api/v1/login', (request) => {
      const body = request.body as { username: string; password: string };
      if (!sameValue(body.password, PASSWORD)) return json(401, { error: 'unauthenticated' });
      return next.length === 0 ? json(200, { step: 'session' }) : json(200, { step: 'factor', next, csrf_token: SESSION_CSRF });
    })
    .route('POST', '/api/v1/login/totp', (request) =>
      requireCsrf(request, SESSION_CSRF, () => ((request.body as { code: string }).code === '123456' ? json(200, { step: 'session' }) : json(403, { error: 'denied' }))),
    )
    .route('POST', '/api/v1/login/no-mfa', (request) => requireCsrf(request, SESSION_CSRF, () => json(200, { step: 'session' })));
  extra?.(server);
  return { server, navigate: vi.fn<(path: string) => void>() };
}

function mountLogin(world: LoginWorld, theme: Theme = 'light') {
  return mount(<LoginContainer api={new AccountApi(world.server.fetcher)} navigate={world.navigate} />, theme);
}

function signIn(password = PASSWORD) {
  type('Username', 'someone');
  type('Password', password);
  submit('Sign in');
}

describe.each(themes)('login against the adapter contract (%s theme)', (theme) => {
  test('password then authenticator code, then a full navigation home; nothing secret is kept', async () => {
    const world = loginWorld();
    mountLogin(world, theme);
    expect(document.documentElement.dataset.theme).toBe(theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    expectNoLeak(PASSWORD);
    type('6-digit code', '123 456'); // pasted with a space: the container strips it
    submit('Enter authenticator code');
    await waitFor(() => expect(world.navigate).toHaveBeenCalledExactlyOnceWith('/'));
    expect(world.server.calls('POST', '/api/v1/login/totp')[0]?.body).toEqual({ code: '123456' });
    expect(world.server.calls('POST', '/api/v1/login/totp')[0]?.headers['x-csrf-token']).toBe(SESSION_CSRF);
    expectNoLeak(PASSWORD, SESSION_CSRF, '123456');
    expect(consoleCalls).toEqual([]);
  });

  test('unknown user, wrong password and a paused account are one message, and the password field is emptied', async () => {
    const world = loginWorld();
    mountLogin(world, theme);
    signIn('wrong-password-canary');
    const alert = await screen.findByText('Sign-in failed');
    expect(alert).toBeTruthy();
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('someone');
    expectNoLeak('wrong-password-canary');
    expect(world.navigate).not.toHaveBeenCalled();
  });

  test('a refused code is one message and the code field is emptied', async () => {
    const world = loginWorld();
    mountLogin(world, theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    type('6-digit code', '000000');
    submit('Enter authenticator code');
    await screen.findByText('That code wasn’t accepted');
    expect((screen.getByLabelText('6-digit code') as HTMLInputElement).value).toBe('');
    expect(world.navigate).not.toHaveBeenCalled();
  });

  test('"Continue with password only" appears only when the server listed it, with the lower-assurance explanation', async () => {
    const mfaOnly = loginWorld(['totp']);
    const { unmount } = mountLogin(mfaOnly, theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    expect(screen.queryByRole('button', { name: 'Continue with password only' })).toBeNull();
    unmount();

    const optional = loginWorld(['totp', 'no-mfa']);
    mountLogin(optional, theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    expect(screen.getByText('Password-only sessions can’t change security settings or administer Mandatary.')).toBeTruthy();
    click('Continue with password only');
    await waitFor(() => expect(optional.navigate).toHaveBeenCalledExactlyOnceWith('/'));
  });

  test('a direct password-only attempt the server refuses (mandatory MFA) is shown as refused and signs nobody in', async () => {
    const world = loginWorld(['totp', 'no-mfa'], (server) => server.route('POST', '/api/v1/login/no-mfa', () => json(403, { error: 'denied' })));
    mountLogin(world, theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    click('Continue with password only');
    await screen.findByText('Password-only sign-in isn’t available');
    expect(world.navigate).not.toHaveBeenCalled();
  });

  test('an ended capability (401) shows the timeout and "Start again" returns to an empty password step', async () => {
    const world = loginWorld(['totp'], (server) => server.route('POST', '/api/v1/login/totp', () => json(401, { error: 'unauthenticated' })));
    mountLogin(world, theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    type('6-digit code', '123456');
    submit('Enter authenticator code');
    await screen.findByText('Your sign-in timed out');
    click('Start again');
    expect((await screen.findByLabelText('Password') as HTMLInputElement).value).toBe('');
    expect(world.navigate).not.toHaveBeenCalled();
  });

  test('the five-minute preauth window also ends on this page, as a display only', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const world = loginWorld(['totp']);
    mountLogin(world, theme);
    signIn();
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    act(() => {
      vi.advanceTimersByTime(5 * 60 * 1000 + 1000);
    });
    expect(await screen.findByText('Your sign-in timed out')).toBeTruthy();
  });

  test('an optional-MFA account with no second factor goes straight home as a labelled lower-assurance session', async () => {
    const world = loginWorld([]);
    mountLogin(world, theme);
    signIn();
    await waitFor(() => expect(world.navigate).toHaveBeenCalledExactlyOnceWith('/'));
  });

  test('connection-level refusals and faults get their own copy; a response with nothing usable never signs in', async () => {
    for (const [status, title] of [
      [429, 'Too many attempts'],
      [503, 'Mandatary couldn’t finish that'],
      [400, 'That request couldn’t be read'],
    ] as const) {
      const world = loginWorld(['totp'], (server) => server.route('POST', '/api/v1/login', () => json(status, { error: 'x' })));
      const { unmount } = mountLogin(world, theme);
      signIn();
      expect(await screen.findByText(title)).toBeTruthy();
      unmount();
    }
    const nothing = loginWorld(['telepathy']);
    mountLogin(nothing, theme);
    signIn();
    expect(await screen.findByText('Mandatary couldn’t finish that')).toBeTruthy();
    expect(nothing.navigate).not.toHaveBeenCalled();
  });

  test('a security-key-only account is told this build cannot use keys; it is never silently skipped', async () => {
    const world = loginWorld(['webauthn']);
    mountLogin(world, theme);
    signIn();
    fireEvent.click(await screen.findByRole('button', { name: 'Use security key' }));
    expect(await screen.findByText('This browser can’t use security keys here')).toBeTruthy();
    expect(world.server.calls('POST', '/api/v1/login/totp')).toHaveLength(0);
    expect(world.navigate).not.toHaveBeenCalled();
  });
});

// ───────────────────────── signed-in home ─────────────────────────

function sessionJson(overrides: Record<string, unknown> = {}) {
  return {
    username: 'someone',
    assurance: 'aal2',
    methods: ['password', 'totp'],
    phishing_resistant: false,
    required_assurance: 2,
    usable_assurance: 2,
    authenticated_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    csrf_token: SESSION_CSRF,
    step_up_required: false,
    ...overrides,
  };
}

function homeWorld(view = sessionJson(), extra?: (server: FakeServer) => void) {
  const server = new FakeServer()
    .route('GET', '/api/v1/session', () => json(200, view))
    .route('POST', '/api/v1/logout', (request) => requireCsrf(request, SESSION_CSRF, () => empty()));
  extra?.(server);
  return { server, navigate: vi.fn<(path: string) => void>() };
}

function mountHome(world: { server: FakeServer; navigate: (path: string) => void }, theme: Theme = 'light') {
  return mount(<SessionHome api={new AccountApi(world.server.fetcher)} navigate={world.navigate} />, theme);
}

describe.each(themes)('signed-in home (%s theme)', (theme) => {
  test('shows only the server-derived labels for a multi-factor session', async () => {
    mountHome(homeWorld(), theme);
    expect(await screen.findByText('Multi-factor verified', { selector: '.inline-flex, span' })).toBeTruthy();
    expect(screen.getByText('Password + Authenticator app')).toBeTruthy();
    expect(screen.queryByText('This is a password-only session')).toBeNull();
    expectNoLeak(SESSION_CSRF);
  });

  test('a password-only session is labelled lower assurance and says what it cannot do', async () => {
    mountHome(homeWorld(sessionJson({ assurance: 'password-only', methods: ['password'] })), theme);
    expect(await screen.findByText('This is a password-only session')).toBeTruthy();
    expect(screen.getAllByText('Password only').length).toBeGreaterThan(0);
  });

  test('an assurance label the page does not know is refused, not displayed as something else', async () => {
    mountHome(homeWorld(sessionJson({ assurance: 'aal3' })), theme);
    expect(await screen.findByText('Couldn’t load your session')).toBeTruthy();
    expect(screen.queryByText('Multi-factor verified')).toBeNull();
  });

  test('no session (401) goes to sign-in without showing any content', async () => {
    const world = homeWorld(sessionJson(), (server) => server.route('GET', '/api/v1/session', () => json(401, { error: 'unauthenticated' })));
    mountHome(world, theme);
    await waitFor(() => expect(world.navigate).toHaveBeenCalledExactlyOnceWith('/login'));
    expect(screen.queryByRole('heading', { name: 'Overview' })).toBeNull();
  });

  test('sign out sends the CSRF header and navigates only after the server confirmed', async () => {
    const world = homeWorld();
    mountHome(world, theme);
    await screen.findByRole('heading', { name: 'Overview', level: 1 });
    click('Sign out');
    await waitFor(() => expect(world.navigate).toHaveBeenCalledExactlyOnceWith('/login'));
    expect(world.server.calls('POST', '/api/v1/logout')[0]?.headers['x-csrf-token']).toBe(SESSION_CSRF);
  });

  test('a sign-out the server could not complete is reported and the session stays visible', async () => {
    const world = homeWorld(sessionJson(), (server) => server.route('POST', '/api/v1/logout', () => json(503, { error: 'unavailable' })));
    mountHome(world, theme);
    await screen.findByRole('heading', { name: 'Overview', level: 1 });
    click('Sign out');
    expect(await screen.findByText('Sign-out wasn’t completed')).toBeTruthy();
    expect(screen.getByText('You are still signed in. Try again; if it keeps failing, close this browser window and check the server log.')).toBeTruthy();
    expect(world.navigate).not.toHaveBeenCalled();
  });

  test('a session that ended while the page was open is shown as ended once its deadline passes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mountHome(homeWorld(sessionJson({ expires_at: Math.floor(Date.now() / 1000) + 60 })), theme);
    await screen.findByRole('heading', { name: 'Overview', level: 1 });
    act(() => {
      vi.setSystemTime(Date.now() + 5 * 60 * 1000);
      vi.advanceTimersByTime(31_000);
    });
    expect(await screen.findByText('Your session ended')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Sign in again' })).toBeTruthy();
  });

  test('a load failure offers a retry instead of an empty page', async () => {
    let attempts = 0;
    const world = homeWorld(sessionJson(), (server) => server.route('GET', '/api/v1/session', () => (attempts++ === 0 ? json(503, { error: 'unavailable' }) : json(200, sessionJson()))));
    mountHome(world, theme);
    click(await screen.findByRole('button', { name: 'Try again' }).then((button) => button.textContent ?? 'Try again'));
    expect(await screen.findByRole('heading', { name: 'Overview', level: 1 })).toBeTruthy();
  });
});

test('cookies are never read or written by the page', () => {
  const cookie = vi.spyOn(document, 'cookie', 'get');
  const set = vi.spyOn(document, 'cookie', 'set');
  mountLogin(loginWorld());
  signIn();
  expect(cookie).not.toHaveBeenCalled();
  expect(set).not.toHaveBeenCalled();
  expectNoLeak(COOKIE);
});
