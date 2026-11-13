import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AccountApi } from '../api/account';
import { RecoveryApi } from '../api/security';
import { ThemeProvider, type Theme } from '../theme';
import { AgentsContainer } from './AgentsContainer';
import { FakeServer, SESSION_CSRF, empty, json, requireCsrf } from './fakeServer';
import { LoginContainer } from './LoginContainer';
import { RecoveryContainer } from './RecoveryContainer';
import { SecurityContainer } from './SecurityContainer';

// P1.16.4 containers against the adapter contract (internal/auth/security_http.go, recovery_http.go,
// agents_http.go). The FakeServer reproduces paths, statuses and JSON shapes; the REAL services are
// exercised by the browser tests (web/tests/security-ui-browser.mjs). Every value is synthetic.

const PASSWORD = 'synthetic-security-password-canary';
const SEED = 'SYNTHETICSEEDCANARYABCDEFGH';
const CODES = Array.from({ length: 10 }, (_, index) => `SYNTH-CODE-CANARY-${String(index).padStart(2, '0')}`);
const REPLACEMENT = 'SYNTH-REPLACEMENT-CANARY-77';
const TOKEN = 'SYNTHETIC-AGENT-TOKEN-CANARY-xyz0123456789';
const NEW_CSRF = 'synthetic-successor-csrf-0002';
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

const type = (label: string | RegExp, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const submit = (name: string) => fireEvent.submit(screen.getByRole('form', { name }));
const click = (name: string | RegExp) => fireEvent.click(screen.getByRole('button', { name }));

function expectNoLeak(...secrets: string[]) {
  const dom = document.documentElement.outerHTML;
  const fields = Array.from(document.querySelectorAll('input')).map((input) => input.value);
  const text = document.body.textContent ?? '';
  const surfaces = [dom, text, text.replace(/\s/g, ''), ...fields, location.href, document.title, JSON.stringify({ ...localStorage }), JSON.stringify({ ...sessionStorage }), JSON.stringify(consoleCalls)];
  for (const secret of secrets) for (const surface of surfaces) expect(surface).not.toContain(secret);
}

// ───────────────────────── fixtures ─────────────────────────

function sessionJson(overrides: Record<string, unknown> = {}) {
  return {
    username: 'someone',
    administrator: true,
    assurance: 'aal2',
    methods: ['password', 'totp'],
    phishing_resistant: false,
    required_assurance: 2,
    usable_assurance: 2,
    authenticated_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    csrf_token: SESSION_CSRF,
    step_up_required: false,
    step_up_methods: ['totp'],
    totp_factors: [{ id: 'totp-1', added_at: 1_700_000_000 }],
    ...overrides,
  };
}

function inventoryJson(overrides: Record<string, unknown> = {}) {
  return {
    totp: [{ id: 'totp-1', added_at: 1_700_000_000, status: 'active' }],
    keys: [],
    max_keys: 16,
    webauthn_available: true,
    recovery_codes: { remaining: 0 },
    addresses: [
      { id: 'addr-1', address: 'first@example.invalid', confirmed: true },
      { id: 'addr-2', address: 'second@example.invalid', confirmed: true },
    ],
    max_addresses: 10,
    notices: { pending: 0, failed: 0, bounced: 0, quarantined: 0, protective: 0, unknown: false },
    ...overrides,
  };
}

interface World {
  server: FakeServer;
  navigate: ReturnType<typeof vi.fn<(path: string) => void>>;
  api: AccountApi;
}

function world(extra?: (server: FakeServer) => void, view = sessionJson()): World {
  const server = new FakeServer()
    .route('GET', '/api/v1/session', () => json(200, view))
    .route('GET', '/api/v1/account/security', () => json(200, inventoryJson()))
    .route('POST', '/api/v1/logout', (request) => requireCsrf(request, SESSION_CSRF, () => empty()));
  extra?.(server);
  return { server, navigate: vi.fn<(path: string) => void>(), api: new AccountApi(server.fetcher) };
}

const mountSecurity = (w: World, theme: Theme = 'light') => mount(<SecurityContainer api={w.api} navigate={w.navigate} />, theme);
const mountAgents = (w: World, theme: Theme = 'light') => mount(<AgentsContainer api={w.api} navigate={w.navigate} />, theme);

function stepUpRequired() {
  return json(403, { error: 'step_up_required' });
}

// ───────────────────────── account-security page ─────────────────────────

describe.each(themes)('account security page (%s theme)', (theme) => {
  test('shows the server’s inventory and only that; nothing secret is in the page', async () => {
    const w = world();
    mountSecurity(w, theme);
    expect(await screen.findByText('Authenticator app 1')).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(screen.getByText('first@example.invalid')).toBeTruthy();
    expect(screen.getByText('Security notices are being delivered')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Agents' })).toBeTruthy();
    expect(w.server.requests.every((request) => !request.path.includes('?'))).toBe(true);
    expectNoLeak(PASSWORD, SESSION_CSRF);
    expect(consoleCalls).toEqual([]);
  });

  test('a blocked change opens the step-up panel and is NOT replayed; the successor session is adopted', async () => {
    let fresh = false;
    const w = world((server) => {
      server
        .route('POST', '/api/v1/account/totp', (request) =>
          requireCsrf(request, fresh ? NEW_CSRF : SESSION_CSRF, () => (fresh ? json(201, { authenticator_id: 'totp-2', secret: SEED, algorithm: 'SHA256', digits: 6, period: 30 }) : stepUpRequired())),
        )
        .route('POST', '/api/v1/stepup/totp', (request) =>
          requireCsrf(request, SESSION_CSRF, () => {
            fresh = true;
            return empty();
          }),
        )
        .route('GET', '/api/v1/session', () => json(200, sessionJson({ csrf_token: fresh ? NEW_CSRF : SESSION_CSRF })));
    });
    mountSecurity(w, theme);
    await screen.findByText('Authenticator app 1');
    click('Add authenticator app');
    await screen.findByText('Confirm it’s you to add an authenticator app');
    expect(w.server.calls('POST', '/api/v1/account/totp')).toHaveLength(1);
    expect(screen.queryByText('Your authenticator key')).toBeNull();
    type('Password', PASSWORD);
    type('6-digit code', '123 456');
    fireEvent.submit(screen.getByLabelText('Password').closest('form') as HTMLFormElement);
    await screen.findByText('You’re verified');
    expect(w.server.calls('POST', '/api/v1/stepup/totp')[0]?.body).toEqual({ password: PASSWORD, code: '123456' });
    // The blocked request was not sent again behind the person's back.
    expect(w.server.calls('POST', '/api/v1/account/totp')).toHaveLength(1);
    // The person repeats the action, now with the successor session's CSRF token.
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    click('Add authenticator app');
    expect(await screen.findByText('Your authenticator key')).toBeTruthy();
    expect(w.server.calls('POST', '/api/v1/account/totp')[1]?.headers['x-csrf-token']).toBe(NEW_CSRF);
    expectNoLeak(PASSWORD);
  });

  test('an authenticator seed is shown once, proven with a code, and then gone from the page', async () => {
    const w = world((server) => {
      server
        .route('POST', '/api/v1/account/totp', (request) => requireCsrf(request, SESSION_CSRF, () => json(201, { authenticator_id: 'totp-2', secret: SEED, algorithm: 'SHA256', digits: 6, period: 30 })))
        .route('POST', '/api/v1/account/totp/confirm', (request) => requireCsrf(request, SESSION_CSRF, () => empty()));
    });
    mountSecurity(w, theme);
    await screen.findByText('Authenticator app 1');
    click('Add authenticator app');
    await screen.findByText('Your authenticator key');
    expect(shown()).toContain(SEED);
    type('6-digit code', '654321');
    submit('Confirm authenticator code');
    await screen.findByText('Authenticator confirmed');
    expect(w.server.calls('POST', '/api/v1/account/totp/confirm')[0]?.body).toEqual({ authenticator_id: 'totp-2', code: '654321' });
    expectNoLeak(SEED);
  });

  test('recovery codes are revealed once and leave the page when hidden', async () => {
    const w = world((server) => server.route('POST', '/api/v1/account/recovery-codes', (request) => requireCsrf(request, SESSION_CSRF, () => json(200, { codes: CODES }))));
    mountSecurity(w, theme);
    await screen.findByText('Authenticator app 1');
    click('Create recovery codes');
    await screen.findByText('Your recovery codes');
    for (const code of CODES) expect(shown()).toContain(code);
    expect((screen.getByRole('button', { name: 'Hide the codes' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByLabelText('I have stored these codes somewhere safe.'));
    fireEvent.click(screen.getByRole('button', { name: 'Hide the codes' }));
    await screen.findByText('Recovery codes');
    expectNoLeak(...CODES);
  });

  test('removing an authenticator ends every session: the page says so and keeps no state', async () => {
    const w = world((server) => server.route('POST', '/api/v1/account/totp/remove', (request) => requireCsrf(request, SESSION_CSRF, () => empty())));
    mountSecurity(w, theme);
    await screen.findByText('Authenticator app 1');
    click('Remove Authenticator app 1');
    const group = screen.getByRole('group', { name: 'Confirm removing Authenticator app 1' });
    fireEvent.click(within(group).getByRole('button', { name: 'Remove Authenticator app 1' }));
    await screen.findByText('Sign-in method removed');
    expect(screen.queryByText('Authenticator app 1')).toBeNull();
    expect(w.server.calls('POST', '/api/v1/account/totp/remove')[0]?.body).toEqual({ authenticator_id: 'totp-1' });
    click('Sign in');
    expect(w.navigate).toHaveBeenCalledWith('/login');
  });
});

describe('account security page outcomes', () => {
  test('a password-only session gets an explanation and a path to verify, never an empty or healthy-looking page', async () => {
    const w = world((server) => server.route('GET', '/api/v1/account/security', () => json(403, { error: 'denied' })), sessionJson({ assurance: 'password-only', methods: ['password'], administrator: false }));
    mountSecurity(w);
    await screen.findByText('This session can’t show your security settings');
    expect(screen.queryByText('Security notices are being delivered')).toBeNull();
    expect(screen.getByRole('button', { name: 'Verify to continue' })).toBeTruthy();
    expect(w.navigate).not.toHaveBeenCalled();
  });

  test('an ended session (401) goes to sign-in and an unreadable inventory is a retryable fault', async () => {
    const ended = world((server) => server.route('GET', '/api/v1/account/security', () => json(401, { error: 'unauthenticated' })));
    const { unmount } = mountSecurity(ended);
    await waitFor(() => expect(ended.navigate).toHaveBeenCalledWith('/login'));
    unmount();
    const broken = world((server) => server.route('GET', '/api/v1/account/security', () => json(503, { error: 'unavailable' })));
    mountSecurity(broken);
    await screen.findByText('Couldn’t load your security settings');
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  });

  test('a response with a shape the page does not understand is a fault, not an inventory', async () => {
    const w = world((server) => server.route('GET', '/api/v1/account/security', () => json(200, { totp: 'nope' })));
    mountSecurity(w);
    await screen.findByText('Couldn’t load your security settings');
  });

  test('delivery failures are shown from the aggregate counts', async () => {
    const w = world((server) => server.route('GET', '/api/v1/account/security', () => json(200, inventoryJson({ notices: { pending: 0, failed: 2, bounced: 0, quarantined: 0, protective: 0, unknown: false } }))));
    mountSecurity(w);
    await screen.findByText('Some security notices weren’t delivered');
  });

  test('no assurance, method, role or time is ever sent by the page', async () => {
    const w = world((server) => server.route('POST', '/api/v1/account/recovery-codes', () => json(200, { codes: CODES })));
    mountSecurity(w);
    await screen.findByText('Authenticator app 1');
    click('Create recovery codes');
    await screen.findByText('Your recovery codes');
    for (const request of w.server.requests) {
      expect(request.path).not.toContain('?');
      expect(JSON.stringify(request.body ?? {})).not.toMatch(/assurance|aal2|"role"|"method"|"now"/);
    }
  });
});

function shown(): string {
  return (document.body.textContent ?? '').replace(/\s/g, '');
}

// ───────────────────────── agent credentials ─────────────────────────

function agentList(credentials: unknown[] | null = []) {
  return json(200, { agents: [{ id: 'agent-1', name: 'synthetic-agent', state: 'active', credentials }] });
}

describe.each(themes)('agent credentials (%s theme)', (theme) => {
  test('the token is revealed once, is never in the list, and leaves the page when hidden', async () => {
    const w = world((server) =>
      server
        .route('GET', '/api/v1/admin/agents', () => agentList(null))
        .route('POST', '/api/v1/admin/agents/agent-1/credentials', (request) =>
          requireCsrf(request, SESSION_CSRF, () => json(201, { token: TOKEN, credential: { id: 'cred-1', display_id: 'mnd_abcd', status: 'active', issued_at: 1, expires_at: null, non_expiring: true, overlap_until: null } })),
        ),
    );
    mountAgents(w, theme);
    await screen.findByText('Credentials for synthetic-agent');
    click('Issue token');
    await screen.findByText('New token for synthetic-agent');
    expect(shown()).toContain(TOKEN);
    fireEvent.click(screen.getByLabelText('I have copied this token to where the agent will read it.'));
    fireEvent.click(screen.getByRole('button', { name: 'Hide the token' }));
    await waitFor(() => expect(screen.queryByText('New token for synthetic-agent')).toBeNull());
    expectNoLeak(TOKEN);
  });

  test('a refused issue (step-up needed) shows no token and opens the verify panel', async () => {
    const w = world((server) => server.route('GET', '/api/v1/admin/agents', () => agentList()).route('POST', '/api/v1/admin/agents/agent-1/credentials', () => stepUpRequired()));
    mountAgents(w, theme);
    await screen.findByText('Credentials for synthetic-agent');
    click('Issue token');
    await screen.findByText('Confirm it’s you to issue an agent token');
    expect(screen.queryByText('New token for synthetic-agent')).toBeNull();
    expectNoLeak(TOKEN);
  });

  test('a session that may not administer agents sees a refusal and no agent data', async () => {
    const w = world((server) => server.route('GET', '/api/v1/admin/agents', () => json(403, { error: 'forbidden' })));
    mountAgents(w, theme);
    await screen.findByText('Agent administration isn’t available to this session');
    expect(screen.queryByText('Credentials for synthetic-agent')).toBeNull();
  });
});

// ───────────────────────── restricted recovery ─────────────────────────

function recoveryWorld(extra?: (server: FakeServer) => void) {
  const server = new FakeServer().route('GET', '/api/v1/recovery/state', () => json(401, { error: 'unauthenticated' }));
  extra?.(server);
  return server;
}

const mountRecovery = (server: FakeServer, theme: Theme = 'light') => mount(<RecoveryContainer api={new RecoveryApi(server.fetcher)} />, theme);

function recover() {
  type('Username', 'someone');
  type('Password', PASSWORD);
  type('Recovery code', 'AAAA-BBBB-CCCC-DDDD');
  submit('Recover access');
}

describe.each(themes)('restricted recovery (%s theme)', (theme) => {
  test('every refusal is one outcome and the form is cleared', async () => {
    const server = recoveryWorld((s) => s.route('POST', '/api/v1/recovery', () => json(403, { error: 'denied' })));
    mountRecovery(server, theme);
    await screen.findByRole('form', { name: 'Recover access' });
    recover();
    await waitFor(() => expect(server.calls('POST', '/api/v1/recovery')).toHaveLength(1));
    await waitFor(() => expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe(''));
    expect(server.calls('POST', '/api/v1/recovery')[0]?.headers['x-csrf-token']).toBeUndefined();
    expectNoLeak(PASSWORD);
  });

  test('the replacement code is shown once; completing recovery issues no session and says to sign in', async () => {
    const server = recoveryWorld((s) =>
      s
        .route('POST', '/api/v1/recovery', () => json(200, { step: 'capability', csrf_token: 'synthetic-capability-csrf', expires_at: Math.floor(Date.now() / 1000) + 600, methods: ['totp'], replacement_code: REPLACEMENT }))
        .route('POST', '/api/v1/recovery/totp', (request) => requireCsrf(request, 'synthetic-capability-csrf', () => json(201, { authenticator_id: 'totp-9', secret: SEED, algorithm: 'SHA256', digits: 6, period: 30 })))
        .route('POST', '/api/v1/recovery/totp/confirm', (request) => requireCsrf(request, 'synthetic-capability-csrf', () => empty())),
    );
    mountRecovery(server, theme);
    await screen.findByRole('form', { name: 'Recover access' });
    recover();
    await screen.findByText('Your replacement recovery code');
    expect(shown()).toContain(REPLACEMENT);
    fireEvent.click(screen.getByLabelText('I have stored this code somewhere safe.'));
    fireEvent.click(screen.getByRole('button', { name: 'Hide the code' }));
    await waitFor(() => expect(shown()).not.toContain(REPLACEMENT));
    click('Create authenticator key');
    await screen.findByText('Your authenticator key');
    type('6-digit code', '654321');
    submit('Confirm authenticator code');
    await screen.findByText('Recovery complete');
    expect(screen.getByRole('link', { name: 'Go to sign in' }).getAttribute('href')).toBe('/login');
    expect(server.requests.some((request) => request.path === '/api/v1/session' || request.path === '/api/v1/login')).toBe(false);
    expectNoLeak(SEED, REPLACEMENT, PASSWORD, 'synthetic-capability-csrf');
  });

  test('a capability the server ended (401) returns to the form and creates no seed', async () => {
    const server = recoveryWorld((s) =>
      s
        .route('POST', '/api/v1/recovery', () => json(200, { step: 'capability', csrf_token: 'synthetic-capability-csrf', expires_at: Math.floor(Date.now() / 1000) + 600, methods: ['totp'] }))
        .route('POST', '/api/v1/recovery/totp', () => json(401, { error: 'unauthenticated' })),
    );
    mountRecovery(server, theme);
    await screen.findByRole('form', { name: 'Recover access' });
    recover();
    await screen.findByText(/Recovery code accepted/);
    click('Create authenticator key');
    await screen.findByRole('form', { name: 'Recover access' });
    expect(screen.queryByText('Your authenticator key')).toBeNull();
  });

  test('the ten-minute deadline ends the capability on this page as a display only', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const server = recoveryWorld((s) =>
      s.route('POST', '/api/v1/recovery', () => json(200, { step: 'capability', csrf_token: 'synthetic-capability-csrf', expires_at: Math.floor(Date.now() / 1000) + 600, methods: ['totp'], replacement_code: REPLACEMENT })),
    );
    mountRecovery(server, theme);
    await screen.findByRole('form', { name: 'Recover access' });
    recover();
    await screen.findByText('Your replacement recovery code');
    const { act } = await import('@testing-library/react');
    act(() => {
      vi.advanceTimersByTime(11 * 60 * 1000);
    });
    await screen.findByRole('form', { name: 'Recover access' });
    expectNoLeak(REPLACEMENT);
  });
});

// ───────────────────────── sign-in with several authenticator apps ─────────────────────────

describe('sign-in names the authenticator app when there are several', () => {
  test('the chosen app’s identifier is sent with the code; one app sends none', async () => {
    const two = [
      { id: 'totp-a', added_at: 1 },
      { id: 'totp-b', added_at: 2 },
    ];
    const server = new FakeServer()
      .route('POST', '/api/v1/login', () => json(200, { step: 'factor', next: ['totp'], csrf_token: SESSION_CSRF, totp_factors: two }))
      .route('POST', '/api/v1/login/totp', (request) => requireCsrf(request, SESSION_CSRF, () => json(200, { step: 'session' })));
    const navigate = vi.fn<(path: string) => void>();
    mount(<LoginContainer api={new AccountApi(server.fetcher)} navigate={navigate} />);
    type('Username', 'someone');
    type('Password', PASSWORD);
    submit('Sign in');
    await screen.findByRole('form', { name: 'Enter authenticator code' });
    const group = screen.getByRole('group', { name: 'Which authenticator app is the code from?' });
    fireEvent.click(within(group).getByLabelText('Authenticator app 2'));
    type('6-digit code', '123456');
    submit('Enter authenticator code');
    await waitFor(() => expect(navigate).toHaveBeenCalledExactlyOnceWith('/'));
    expect(server.calls('POST', '/api/v1/login/totp')[0]?.body).toEqual({ code: '123456', authenticator_id: 'totp-b' });
  });
});
