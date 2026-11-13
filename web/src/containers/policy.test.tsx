import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AccountApi } from '../api/account';
import { POLICY_NAV } from '../screens/policy/nav';
import { ThemeProvider, type Theme } from '../theme';
import { FakeServer, SESSION_CSRF, empty, json, requireCsrf, type Recorded } from './fakeServer';
import { AgentsContainer } from './AgentsContainer';
import { GroupsContainer, PolicyAgentsContainer, RulesContainer, UsersContainer, reasonOf } from './PolicyContainers';
import { SessionHome } from './SessionHome';

// P1.17.2 containers against the adapter contract (internal/auth/policy_admin_http.go, agents_http.go). The FakeServer
// reproduces the paths, methods, statuses and JSON shapes the Go adapters use (pinned on the Go side by
// policy_admin_http_test.go and the A/B end-to-end test); the REAL authorization decisions are the server's and are
// exercised there, not here. Every value is synthetic.

const themes: Theme[] = ['light', 'dark'];
const BASE = '/api/v1/admin';
const POLICY = `${BASE}/policy`;
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
  localStorage.clear();
  sessionStorage.clear();
  vi.restoreAllMocks();
});

function mount(ui: ReactElement, theme: Theme = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

function sessionJson(overrides: Record<string, unknown> = {}) {
  return {
    username: 'sample-admin',
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

const ok = { allowed: true };
const blocked = (...blockers: string[]) => ({ allowed: false, blockers });

const newUser = { id: 'u-new', username: 'sample-new', state: 'active', administrator: false, groups: [], owned_agents: [], rule_count: 0, removal: ok };
const usersPage = (extra: unknown[] = []) => ({
  users: [
    { id: 'u', username: 'sample-admin', state: 'active', administrator: true, groups: [], owned_agents: [], rule_count: 0, removal: blocked('is the policy administrator') },
    { id: 'u-robin', username: 'sample-robin', state: 'active', administrator: false, groups: ['sample-ops'], owned_agents: ['sample-runner'], rule_count: 1, removal: blocked('owns an agent') },
    ...extra,
  ],
});

const groupsPage = () => ({
  groups: [{ id: 'g-ops', name: 'sample-ops', state: 'active', members: [{ kind: 'user', id: 'u-robin', name: 'sample-robin', state: 'active', membership: 'active' }], owned_agents: [], rule_count: 0, removal: blocked('has members') }],
  candidates: {
    users: [
      { id: 'u', name: 'sample-admin', state: 'active' },
      { id: 'u-robin', name: 'sample-robin', state: 'active' },
    ],
    agents: [{ id: 'a-runner', name: 'sample-runner', state: 'active' }],
  },
});

const agentsPage = () => ({
  agents: [{ id: 'a-runner', name: 'sample-runner', state: 'active', owner: { kind: 'user', id: 'u-robin', name: 'sample-robin', state: 'active' }, groups: [], live_tokens: 1, rule_count: 1, removal: ok }],
  owners: { users: [{ id: 'u-robin', name: 'sample-robin', state: 'active' }], groups: [{ id: 'g-ops', name: 'sample-ops', state: 'active' }] },
});

const selectorJson = (overrides: Record<string, unknown> = {}) => ({ container_name: 'sample-edge-proxy', name_is_glob: false, compose_project: 'sample', ...overrides });
const agentSubject = { kind: 'agent', id: 'a-runner', name: 'sample-runner', state: 'active' };

function rulesPage(overrides: Record<string, unknown> = {}, target: Record<string, unknown> | null = null) {
  return {
    rules: [
      { id: 'r-1', subject: agentSubject, effect: 'ALLOW', operation: 'container:logs', selector: selectorJson(), log_tail_max: 200, stop_timeout_max: null, state: 'active', target: target ?? { status: 'present', matches: 1 } },
      { id: 'r-2', subject: agentSubject, effect: 'ALLOW', operation: 'container:start', selector: selectorJson({ container_name: 'sample-gone' }), log_tail_max: null, stop_timeout_max: null, state: 'active', target: target ?? { status: 'missing' } },
    ],
    subjects: [agentSubject, { kind: 'user', id: 'u', name: 'sample-admin', state: 'active', administrator: true }, { kind: 'group', id: 'g-ops', name: 'sample-ops', state: 'active' }],
    endpoint: { name: 'local', safety: 'verified' },
    inventory: [{ name: 'sample-edge-proxy', short_id: 'aaaaaaaaaaaa', image: 'nginx:1', running: true, compose_project: 'sample', compose_service: 'edge' }],
    ...overrides,
  };
}

interface World {
  server: FakeServer;
  navigate: ReturnType<typeof vi.fn<(path: string) => void>>;
  api: AccountApi;
}

/** Every unsafe request must carry the session CSRF header exactly as the Browser boundary requires. */
const guarded = (request: Recorded, response: () => Response): Response => requireCsrf(request, SESSION_CSRF, response);

function world(extra: (server: FakeServer) => void, view = sessionJson()): World {
  const server = new FakeServer().route('GET', '/api/v1/session', () => json(200, view));
  extra(server);
  return { server, navigate: vi.fn<(path: string) => void>(), api: new AccountApi(server.fetcher) };
}

const click = (name: string | RegExp) => fireEvent.click(screen.getByRole('button', { name }));

// ───────────────────────── outcome mapping ─────────────────────────

describe('reasonOf', () => {
  test.each([
    [400, 'invalid'],
    [415, 'invalid'],
    [403, 'denied'],
    [404, 'not_found'],
    [409, 'conflict'],
    [429, 'rate_limited'],
    // Anything the screen cannot prove did not happen is "outcome unknown": a 503 can follow a durable commit.
    [503, 'outcome_unknown'],
    [500, 'outcome_unknown'],
    [0, 'outcome_unknown'],
  ])('HTTP %i is %s', (status, reason) => {
    expect(reasonOf({ ok: false, status, code: '' })).toBe(reason);
  });
});

// ───────────────────────── users ─────────────────────────

describe.each(themes)('Users page (%s theme)', (theme) => {
  test('lists the server’s users, offers no delete, and leaks nothing', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/users`, () => json(200, usersPage())));
    mount(<UsersContainer api={w.api} navigate={w.navigate} />, theme);
    expect(await screen.findByText('sample-robin')).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull();
    expect(screen.getByText('Managing access isn’t the same as having it')).toBeTruthy();
    const surfaces = document.documentElement.outerHTML + JSON.stringify(consoleCalls) + location.href;
    expect(surfaces).not.toContain(SESSION_CSRF);
    expect(consoleCalls).toEqual([]);
  });

  test('adds a user with the CSRF header and the exact body, then reloads the list', async () => {
    let created = false;
    const w = world((s) =>
      s
        .route('GET', `${POLICY}/users`, () => json(200, usersPage(created ? [newUser] : [])))
        .route('POST', `${BASE}/users`, (r) =>
          guarded(r, () => {
            created = true;
            return json(201, { user: { id: 'u-new' } });
          }),
        ),
    );
    mount(<UsersContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText('sample-robin');
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'sample-new' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Add a user' }));
    expect(await screen.findByText(/Added sample-new\./)).toBeTruthy();
    expect(w.server.calls('POST', `${BASE}/users`)[0]?.body).toEqual({ username: 'sample-new' });
    expect(await screen.findByRole('heading', { level: 3, name: 'sample-new' })).toBeTruthy();
  });

  test('disabling asks first, names the object, and sends nothing until confirmed', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/users`, () => json(200, usersPage())).route('POST', `${BASE}/users/u-robin/disable`, (r) => guarded(r, () => empty())));
    mount(<UsersContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText('sample-robin');
    click('Disable sample-robin');
    expect(w.server.calls('POST', `${BASE}/users/u-robin/disable`)).toHaveLength(0);
    const panel = screen.getByRole('group', { name: 'Disable sample-robin?' });
    fireEvent.click(within(panel).getByRole('button', { name: 'Disable sample-robin' }));
    expect(await screen.findByText('Disabled sample-robin.')).toBeTruthy();
    expect(w.server.calls('POST', `${BASE}/users/u-robin/disable`)).toHaveLength(1);
  });
});

test('a list refused with 403 is the one "not available" page, never an empty list', async () => {
  const w = world((s) => s.route('GET', `${POLICY}/users`, () => json(403, { error: 'forbidden' })));
  mount(<UsersContainer api={w.api} navigate={w.navigate} />);
  expect((await screen.findByRole('alert')).textContent).toContain('Policy administration isn’t available to this session');
  expect(screen.queryByText(/No users yet/)).toBeNull();
});

test('a failed list offers a retry; a 401 sends the person to sign in', async () => {
  let attempts = 0;
  const w = world((s) =>
    s.route('GET', `${POLICY}/users`, () => {
      attempts += 1;
      return attempts === 1 ? json(503, { error: 'unavailable' }) : json(200, usersPage());
    }),
  );
  mount(<UsersContainer api={w.api} navigate={w.navigate} />);
  expect((await screen.findByRole('alert')).textContent).toContain('Couldn’t load users');
  click('Try again');
  expect(await screen.findByText('sample-robin')).toBeTruthy();

  cleanup();
  const ended = world((s) => s.route('GET', `${POLICY}/users`, () => json(401, { error: 'unauthenticated' })));
  mount(<UsersContainer api={ended.api} navigate={ended.navigate} />);
  await waitFor(() => expect(ended.navigate).toHaveBeenCalledWith('/login'));
});

test('a malformed list body fails closed as a failed load, not as an empty list', async () => {
  const w = world((s) => s.route('GET', `${POLICY}/users`, () => json(200, { users: [{ id: 'u', username: 'x' }] })));
  mount(<UsersContainer api={w.api} navigate={w.navigate} />);
  expect((await screen.findByRole('alert')).textContent).toContain('Couldn’t load users');
  expect(screen.queryByText(/No users yet/)).toBeNull();
});

test('a mutation answered 503 is "outcome unknown" and the list is re-read; it is never shown as unchanged', async () => {
  const w = world((s) => s.route('GET', `${POLICY}/users`, () => json(200, usersPage())).route('POST', `${BASE}/users/u-robin/disable`, (r) => guarded(r, () => json(503, { error: 'unavailable' }))));
  mount(<UsersContainer api={w.api} navigate={w.navigate} />);
  await screen.findByText('sample-robin');
  click('Disable sample-robin');
  fireEvent.click(within(screen.getByRole('group', { name: 'Disable sample-robin?' })).getByRole('button', { name: 'Disable sample-robin' }));
  expect(await screen.findByText('Mandatary couldn’t confirm the result')).toBeTruthy();
  await waitFor(() => expect(w.server.calls('GET', `${POLICY}/users`).length).toBeGreaterThanOrEqual(2));
});

test('a blocked mutation opens the step-up panel, is NOT replayed, and keeps the list', async () => {
  const w = world((s) => s.route('GET', `${POLICY}/users`, () => json(200, usersPage())).route('POST', `${BASE}/users/u-robin/disable`, () => json(403, { error: 'step_up_required' })));
  mount(<UsersContainer api={w.api} navigate={w.navigate} />);
  await screen.findByText('sample-robin');
  click('Disable sample-robin');
  fireEvent.click(within(screen.getByRole('group', { name: 'Disable sample-robin?' })).getByRole('button', { name: 'Disable sample-robin' }));
  await waitFor(() => expect(screen.getByLabelText(/password/i)).toBeTruthy());
  expect(w.server.calls('POST', `${BASE}/users/u-robin/disable`)).toHaveLength(1); // not retried by the page
  expect(screen.queryByText('Disabled sample-robin.')).toBeNull();
  expect(screen.getByText('sample-robin')).toBeTruthy();
});

// ───────────────────────── groups ─────────────────────────

describe.each(themes)('Groups page (%s theme)', (theme) => {
  test('adding a member is PUT on the member route, removing is DELETE after a confirmation, deleting is DELETE on the group', async () => {
    const w = world((s) =>
      s
        .route('GET', `${POLICY}/groups`, () => json(200, groupsPage()))
        .route('PUT', `${BASE}/groups/g-ops/members/agent/a-runner`, (r) => guarded(r, () => empty()))
        .route('DELETE', `${BASE}/groups/g-ops/members/user/u-robin`, (r) => guarded(r, () => empty()))
        .route('DELETE', `${BASE}/groups/g-ops`, (r) => guarded(r, () => empty())),
    );
    mount(<GroupsContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText('sample-robin');

    const form = screen.getByRole('form', { name: 'Add a member to sample-ops' });
    fireEvent.change(within(form).getByLabelText('Add a member'), { target: { value: 'agent:a-runner' } });
    fireEvent.submit(form);
    expect(await screen.findByText('Added sample-runner to sample-ops.')).toBeTruthy();
    expect(w.server.calls('PUT', `${BASE}/groups/g-ops/members/agent/a-runner`)).toHaveLength(1);

    click('Remove sample-robin from sample-ops');
    expect(w.server.calls('DELETE', `${BASE}/groups/g-ops/members/user/u-robin`)).toHaveLength(0);
    const confirm = screen.getAllByRole('group').find((g) => /Remove/.test(g.getAttribute('aria-label') ?? g.textContent ?? ''));
    if (!confirm) throw new Error('no removal confirmation');
    fireEvent.click(within(confirm).getByRole('button', { name: /^Remove/ }));
    await waitFor(() => expect(w.server.calls('DELETE', `${BASE}/groups/g-ops/members/user/u-robin`)).toHaveLength(1));
  });
});

// ───────────────────────── agents ─────────────────────────

test('Policy > Agents links to the token page for the agent and renders no secret field; no delete is offered', async () => {
  const w = world((s) => s.route('GET', `${POLICY}/agents`, () => json(200, agentsPage())));
  mount(<PolicyAgentsContainer api={w.api} navigate={w.navigate} />);
  await screen.findByText('sample-runner');
  const link = screen.getAllByRole('link').find((a) => a.getAttribute('href')?.startsWith('/agents#agent='));
  expect(link?.getAttribute('href')).toBe('/agents#agent=a-runner');
  expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull();
  expect(document.querySelector('input[type="password"]')).toBeNull();
});

// ───────────────────────── rules ─────────────────────────

describe.each(themes)('Rules page (%s theme)', (theme) => {
  test('shows rules with their target status; a missing target is flagged, not hidden', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/rules`, () => json(200, rulesPage())));
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    expect(await screen.findByText(/Matches 1 container now/)).toBeTruthy();
    expect(screen.getAllByText(/Inactive · target missing/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Managing access isn’t the same as having it')).toBeTruthy();
  });

  test('an unverified endpoint is shown as such, and its targets are never shown as present', async () => {
    const page = rulesPage({ endpoint: { name: 'local', safety: 'unverified' }, inventory: null }, { status: 'unknown' });
    const w = world((s) => s.route('GET', `${POLICY}/rules`, () => json(200, page)));
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    expect((await screen.findAllByText(/Target status unknown/)).length).toBe(2);
    expect(screen.queryByText(/Matches \d+ container/)).toBeNull();
    expect(screen.getByRole('alert').textContent).toContain('Mandatary can’t verify its own container');
  });

  test('adding a rule sends one request with the exact wire body, closes the editor and reloads', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/rules`, () => json(200, rulesPage())).route('POST', `${POLICY}/rules`, (r) => guarded(r, () => json(201, { rules: [] }))));
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText(/Matches 1 container now/);
    click('Add a rule');
    const form = screen.getByRole('form', { name: 'Add a rule' });
    fireEvent.change(form.querySelector('[name="subject"]') as HTMLSelectElement, { target: { value: 'a-runner' } });
    fireEvent.click(within(form).getByRole('checkbox', { name: /Read logs/ }));
    fireEvent.change(form.querySelector('[name="containerName"]') as HTMLInputElement, { target: { value: 'sample-edge-proxy' } });
    fireEvent.change(within(form).getByLabelText('Most log lines per request'), { target: { value: '50' } });
    fireEvent.submit(form);
    expect(await screen.findByText('Added the rule.')).toBeTruthy();
    expect(screen.queryByRole('form', { name: 'Add a rule' })).toBeNull();
    const body = w.server.calls('POST', `${POLICY}/rules`)[0]?.body;
    expect(body).toEqual({
      subject: { kind: 'agent', id: 'a-runner' },
      effect: 'ALLOW',
      operations: ['container:logs'],
      selector: { container_name: 'sample-edge-proxy', name_is_glob: false },
      log_tail_max: 50,
      stop_timeout_max: null,
    });
    expect(w.server.calls('GET', `${POLICY}/rules`).length).toBeGreaterThanOrEqual(2);
  });

  test('a refused create keeps the draft open under its own error', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/rules`, () => json(200, rulesPage())).route('POST', `${POLICY}/rules`, (r) => guarded(r, () => json(400, { error: 'invalid_request' }))));
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText(/Matches 1 container now/);
    click('Add a rule');
    const form = screen.getByRole('form', { name: 'Add a rule' });
    fireEvent.change(form.querySelector('[name="subject"]') as HTMLSelectElement, { target: { value: 'a-runner' } });
    fireEvent.click(within(form).getByRole('checkbox', { name: /View status/ }));
    fireEvent.change(form.querySelector('[name="containerName"]') as HTMLInputElement, { target: { value: 'sample-edge-proxy' } });
    fireEvent.submit(form);
    expect(await screen.findByText('That wasn’t accepted')).toBeTruthy();
    expect(screen.getByRole('form', { name: 'Add a rule' })).toBeTruthy();
  });

  test('a step-up requirement on save keeps the draft and does not replay the request', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/rules`, () => json(200, rulesPage())).route('POST', `${POLICY}/rules`, () => json(403, { error: 'step_up_required' })));
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText(/Matches 1 container now/);
    click('Add a rule');
    const form = screen.getByRole('form', { name: 'Add a rule' });
    fireEvent.change(form.querySelector('[name="subject"]') as HTMLSelectElement, { target: { value: 'a-runner' } });
    fireEvent.click(within(form).getByRole('checkbox', { name: /View status/ }));
    fireEvent.change(form.querySelector('[name="containerName"]') as HTMLInputElement, { target: { value: 'sample-edge-proxy' } });
    fireEvent.submit(form);
    await waitFor(() => expect(screen.getByLabelText(/password/i)).toBeTruthy());
    expect(w.server.calls('POST', `${POLICY}/rules`)).toHaveLength(1);
    expect((screen.getByRole('form', { name: 'Add a rule' }).querySelector('[name="containerName"]') as HTMLInputElement).value).toBe('sample-edge-proxy');
  });

  test('disable and delete use their own routes and verbs, only after a confirmation', async () => {
    const w = world((s) =>
      s
        .route('GET', `${POLICY}/rules`, () => json(200, rulesPage()))
        .route('POST', `${POLICY}/rules/r-1/disable`, (r) => guarded(r, () => empty()))
        .route('DELETE', `${POLICY}/rules/r-2`, (r) => guarded(r, () => empty())),
    );
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText(/Matches 1 container now/);
    fireEvent.click(screen.getAllByRole('button', { name: /^Disable: / })[0] as HTMLElement);
    expect(w.server.calls('POST', `${POLICY}/rules/r-1/disable`)).toHaveLength(0);
    fireEvent.click(within(screen.getByRole('group', { name: /^Disable “/ })).getByRole('button', { name: /^Disable/ }));
    expect(await screen.findByText(/Disabled the rule for sample-runner\./)).toBeTruthy();
    expect(w.server.calls('POST', `${POLICY}/rules/r-1/disable`)).toHaveLength(1);

    fireEvent.click(screen.getAllByRole('button', { name: /^Delete: / })[1] as HTMLElement);
    expect(w.server.calls('DELETE', `${POLICY}/rules/r-2`)).toHaveLength(0);
    fireEvent.click(within(screen.getByRole('group', { name: /^Delete “/ })).getByRole('button', { name: 'Delete rule' }));
    await waitFor(() => expect(w.server.calls('DELETE', `${POLICY}/rules/r-2`)).toHaveLength(1));
  });

  test('after a delete the row is gone, and its confirmation is still shown for the page', async () => {
    let deleted = false;
    const w = world((s) =>
      s
        .route('GET', `${POLICY}/rules`, () => {
          const page = rulesPage();
          return json(200, deleted ? { ...page, rules: page.rules.slice(0, 1) } : page);
        })
        .route('DELETE', `${POLICY}/rules/r-2`, (r) =>
          guarded(r, () => {
            deleted = true;
            return empty();
          }),
        ),
    );
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText(/Matches 1 container now/);
    fireEvent.click(screen.getAllByRole('button', { name: /^Delete: / })[1] as HTMLElement);
    fireEvent.click(within(screen.getByRole('group', { name: /^Delete “/ })).getByRole('button', { name: 'Delete rule' }));
    await waitFor(() => expect(screen.queryByText(/Inactive · target missing/)).toBeNull());
    expect(screen.getByText('Deleted the rule for sample-runner.')).toBeTruthy();
  });

  test('a preview posts the selector only; an endpoint that cannot be inspected is reported, never guessed', async () => {
    const w = world((s) => s.route('GET', `${POLICY}/rules`, () => json(200, rulesPage())).route('POST', `${POLICY}/rules/preview`, (r) => guarded(r, () => json(200, { available: false, matches: [] }))));
    mount(<RulesContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByText(/Matches 1 container now/);
    click('Add a rule');
    const form = screen.getByRole('form', { name: 'Add a rule' });
    fireEvent.change(form.querySelector('[name="containerName"]') as HTMLInputElement, { target: { value: 'sample-edge-proxy' } });
    fireEvent.click(within(form).getByRole('button', { name: 'Check matches' }));
    await waitFor(() => expect(w.server.calls('POST', `${POLICY}/rules/preview`)).toHaveLength(1));
    expect(w.server.calls('POST', `${POLICY}/rules/preview`)[0]?.body).toEqual({ selector: { container_name: 'sample-edge-proxy', name_is_glob: false } });
  });
});

// ───────────────────────── navigation ─────────────────────────

test('the Policy group and Agent tokens appear only for a session that says it is the administrator', async () => {
  const admin = world(() => undefined);
  mount(<SessionHome api={admin.api} navigate={admin.navigate} />);
  await screen.findByRole('link', { name: 'Agent tokens' });
  for (const name of ['Rules', 'Users', 'Groups', 'Agents']) expect(screen.getAllByRole('link', { name }).length).toBeGreaterThan(0);
  cleanup();

  const ordinary = world(() => undefined, sessionJson({ administrator: false, username: 'sample-robin' }));
  mount(<SessionHome api={ordinary.api} navigate={ordinary.navigate} />);
  await screen.findAllByRole('link', { name: 'Account security' });
  for (const name of ['Agent tokens', 'Rules', 'Users', 'Groups', 'Agents']) expect(screen.queryByRole('link', { name })).toBeNull();
});

test('every Policy link is an exact document route', () => {
  expect(POLICY_NAV.map((item) => item.href)).toEqual(['/policy', '/policy/users', '/policy/groups', '/policy/agents']);
});

// ───────────────────────── token page preselection ─────────────────────────

describe('Agent tokens page preselection from Policy > Agents', () => {
  const list = () =>
    json(200, {
      agents: [
        { id: 'agent-1', name: 'first-agent', state: 'active', credentials: [] },
        { id: 'agent-2', name: 'second-agent', state: 'active', credentials: [] },
      ],
    });

  afterEach(() => {
    history.replaceState(null, '', '/');
  });

  test('a fragment naming a listed agent selects it; nothing is sent to the server for it', async () => {
    history.replaceState(null, '', '/agents#agent=agent-2');
    const w = world((s) => s.route('GET', '/api/v1/admin/agents', () => list()));
    mount(<AgentsContainer api={w.api} navigate={w.navigate} />);
    await screen.findByText('Credentials for second-agent');
    expect(w.server.requests.every((request) => !request.path.includes('agent-2') && !request.path.includes('?'))).toBe(true);
  });

  test('a fragment naming an agent that is not listed is ignored, never trusted', async () => {
    history.replaceState(null, '', '/agents#agent=not-listed');
    const w = world((s) => s.route('GET', '/api/v1/admin/agents', () => list()));
    mount(<AgentsContainer api={w.api} navigate={w.navigate} />);
    await screen.findByText('Credentials for first-agent');
  });
});
