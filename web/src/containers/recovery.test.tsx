import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { AccountApi, type SessionView } from '../api/account';
import type { ExportedFile } from '../api/recovery';
import { App, routeFor } from '../App';
import { RECOVERY_NAV } from '../screens/recovery/nav';
import { ThemeProvider, type Theme } from '../theme';
import { FakeServer, SESSION_CSRF, json, requireCsrf, type Recorded } from './fakeServer';
import { ExportContainer, RestoreContainer, ReviewContainer } from './RecoveryContainers';
import { navFor } from './SignedIn';

// P1.18.3 containers against the P1.18.1 adapter contract (internal/auth/backup_http.go). The FakeServer reproduces the paths, methods,
// statuses and JSON shapes; the REAL service decisions, the real step-up gate and a real browser are exercised on the Go side and in
// web/tests/recovery-ui-browser.mjs. Every value is synthetic.

const themes: Theme[] = ['light', 'dark'];
const EXPORT = '/api/v1/admin/backup/export';
const RESTORE = '/api/v1/admin/restore';
const MANIFEST = '/api/v1/admin/restore/manifest';
const APPROVALS = '/api/v1/admin/restore/approvals';
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

interface World {
  server: FakeServer;
  navigate: ReturnType<typeof vi.fn<(path: string) => void>>;
  api: AccountApi;
}

const guarded = (request: Recorded, response: () => Response): Response => requireCsrf(request, SESSION_CSRF, response);

function world(extra: (server: FakeServer) => void, view = sessionJson()): World {
  const server = new FakeServer().route('GET', '/api/v1/session', () => json(200, view));
  extra(server);
  return { server, navigate: vi.fn<(path: string) => void>(), api: new AccountApi(server.fetcher) };
}

const click = (name: string | RegExp) => fireEvent.click(screen.getByRole('button', { name }));

const archiveResponse = (mode = 'clean') =>
  new Response('{"format":"mandatary-logical-backup","synthetic":true}', {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="mandatary-backup-bk-0001-${mode}.json"`, 'X-Backup-Id': 'bk-0001', 'X-Backup-Mode': mode },
  });

const REPORT = {
  backup_id: 'bk-0001',
  mode: 'full',
  provenance: 'authenticated',
  initiator: 'admin',
  restore_generation: 3,
  state: 'restore_quarantine',
  next_step: 'host_recovery_required',
  imported: { user: 2, group: 1 },
  retained_local: { user: 1 },
  inactive_credentials: { authenticators: 2, agent_credentials: 1 },
  credentials_stripped: false,
  excluded: ['sessions', 'usage_statistics'],
};
const restored = () => json(200, { report: REPORT, authorizer_notified: true, session_ended: true });

// ───────────────────────── routes and navigation ─────────────────────────

test('the three recovery documents are routes, and only an administrator is shown the Recovery group', () => {
  expect(routeFor('/backup')).toBe('backup-export');
  expect(routeFor('/restore')).toBe('backup-restore');
  expect(routeFor('/restore/review')).toBe('backup-review');
  for (const closed of ['/backup/', '/restore/', '/restore/x', '/Backup', '/restore%2freview']) expect(routeFor(closed), closed).toBe('unknown');
  const view = (administrator: boolean): SessionView => ({ username: 'a', administrator, assurance: 'aal2', methods: [], phishingResistant: false, authenticatedAt: 1, expiresAt: 2, stepUpRequired: false, stepUpMethods: [], totpFactors: [] });
  const adminIds = navFor(view(true)).map((item) => item.id);
  for (const item of RECOVERY_NAV) expect(adminIds).toContain(item.id);
  const ordinary = navFor(view(false)).map((item) => item.id);
  for (const item of RECOVERY_NAV) expect(ordinary).not.toContain(item.id);
  expect(navFor(null).map((item) => item.id)).not.toContain('backup-export');
});

test('the application mounts each recovery view on its own path', async () => {
  // Real fetch is unavailable in jsdom; a rejected call lands on the page's own failure state, which is enough to prove the view is mounted.
  vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')));
  for (const [path, heading] of [
    ['/backup', 'Mandatary'],
    ['/restore', 'Mandatary'],
    ['/restore/review', 'Mandatary'],
  ] as const) {
    const view = render(<App path={path} />);
    expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeTruthy();
    view.unmount();
  }
  vi.unstubAllGlobals();
});

// ───────────────────────── export ─────────────────────────

describe.each(themes)('Export page (%s theme)', (theme) => {
  test('exports with the CSRF header and the exact body, saves what the server sent, and reports it', async () => {
    const save = vi.fn<(file: ExportedFile) => void>();
    const w = world((s) => s.route('POST', EXPORT, (r) => guarded(r, () => archiveResponse('clean'))));
    mount(<ExportContainer api={w.api} navigate={w.navigate} save={save} />, theme);
    expect(await screen.findByRole('heading', { level: 1, name: 'Export a backup' })).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe(theme);
    click('Export clean backup');
    expect(await screen.findByText(/mandatary-backup-bk-0001-clean\.json/)).toBeTruthy();
    expect(w.server.calls('POST', EXPORT)).toHaveLength(1);
    expect(w.server.calls('POST', EXPORT)[0]?.body).toEqual({ mode: 'clean' });
    expect(save).toHaveBeenCalledTimes(1);
    const file = save.mock.calls[0]?.[0];
    expect(file).toMatchObject({ backupId: 'bk-0001', mode: 'clean', fileName: 'mandatary-backup-bk-0001-clean.json' });
    // The bytes go to the download and nowhere else: not the DOM, not the console, not the URL.
    const surfaces = document.documentElement.outerHTML + JSON.stringify(consoleCalls) + location.href;
    expect(surfaces).not.toContain('mandatary-logical-backup');
    expect(surfaces).not.toContain(SESSION_CSRF);
    expect(consoleCalls).toEqual([]);
  });

  test('a full export asks for the full mode', async () => {
    const save = vi.fn();
    const w = world((s) => s.route('POST', EXPORT, (r) => guarded(r, () => archiveResponse('full'))));
    mount(<ExportContainer api={w.api} navigate={w.navigate} save={save} />, theme);
    await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
    fireEvent.click(screen.getByRole('radio', { name: /Full backup/ }));
    click('Export full backup');
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(w.server.calls('POST', EXPORT)[0]?.body).toEqual({ mode: 'full' });
  });
});

test('a stale verification opens the step-up panel, saves nothing and does NOT replay the export', async () => {
  const save = vi.fn();
  const w = world((s) => s.route('POST', EXPORT, () => json(403, { error: 'step_up_required' })));
  mount(<ExportContainer api={w.api} navigate={w.navigate} save={save} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup');
  expect(await screen.findByRole('heading', { name: 'Confirm it’s you to export a backup' })).toBeTruthy();
  expect(save).not.toHaveBeenCalled();
  expect(w.server.calls('POST', EXPORT)).toHaveLength(1);
});

test('no usable second factor is the step-up panel in its unavailable state, not a save', async () => {
  const save = vi.fn();
  const w = world((s) => s.route('POST', EXPORT, () => json(403, { error: 'assurance_unavailable' })));
  mount(<ExportContainer api={w.api} navigate={w.navigate} save={save} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup');
  expect(await screen.findByText('No usable verification method')).toBeTruthy();
  expect(document.body.textContent).toContain('Export a backup needs a recent multi-factor verification');
  expect(save).not.toHaveBeenCalled();
});

test.each([
  [403, { error: 'forbidden' }, /Nothing was exported/],
  [429, { error: 'rate_limited' }, /Nothing was exported/],
  [400, { error: 'invalid_request' }, /Nothing was exported/],
  [503, { error: 'unavailable' }, /Nothing was exported/],
])('an export refused with HTTP %i says nothing was exported and saves nothing', async (status, body, text) => {
  const save = vi.fn();
  const w = world((s) => s.route('POST', EXPORT, () => json(status, body)));
  mount(<ExportContainer api={w.api} navigate={w.navigate} save={save} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup');
  expect((await screen.findByRole('alert')).textContent).toMatch(text);
  expect(save).not.toHaveBeenCalled();
  expect(w.navigate).not.toHaveBeenCalled();
});

test('an export whose headers do not match the request is treated as failed and never saved', async () => {
  const save = vi.fn();
  const w = world((s) => s.route('POST', EXPORT, () => archiveResponse('full')));
  mount(<ExportContainer api={w.api} navigate={w.navigate} save={save} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup'); // asked for clean, the "server" sent full
  expect((await screen.findByRole('alert')).textContent).toMatch(/Nothing was exported/);
  expect(save).not.toHaveBeenCalled();
});

test('a lost connection during an export is a retryable failure, never a success', async () => {
  const save = vi.fn();
  const server = new FakeServer().route('GET', '/api/v1/session', () => json(200, sessionJson()));
  const failing = (input: string, init: RequestInit) => (input === EXPORT ? Promise.reject(new Error('reset')) : server.fetcher(input, init));
  mount(<ExportContainer api={new AccountApi(failing)} navigate={vi.fn()} save={save} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup');
  expect((await screen.findByRole('alert')).textContent).toMatch(/Nothing was exported/);
  expect(save).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Export clean backup' })).toBeTruthy();
});

test('an ended session on export sends the person to sign in', async () => {
  const w = world((s) => s.route('POST', EXPORT, () => json(401, { error: 'unauthenticated' })));
  mount(<ExportContainer api={w.api} navigate={w.navigate} save={vi.fn()} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup');
  await waitFor(() => expect(w.navigate).toHaveBeenCalledWith('/login'));
});

test('a second press while an export runs sends nothing more', async () => {
  let release: (response: Response) => void = () => undefined;
  const w = world((s) => s.route('POST', EXPORT, () => new Promise<Response>((resolve) => (release = resolve)) as unknown as Response));
  mount(<ExportContainer api={w.api} navigate={w.navigate} save={vi.fn()} />);
  await screen.findByRole('heading', { level: 1, name: 'Export a backup' });
  click('Export clean backup');
  const busy = await screen.findByRole('button', { name: 'Creating the backup…' });
  fireEvent.click(busy);
  fireEvent.submit(screen.getByRole('form', { name: 'Export a backup' }));
  expect(w.server.calls('POST', EXPORT)).toHaveLength(1);
  release(archiveResponse('clean'));
  await screen.findByText(/mandatary-backup-bk-0001-clean\.json/);
});

// ───────────────────────── restore ─────────────────────────

const archiveFile = (text = '{"format":"mandatary-logical-backup","synthetic":true}', name = 'sample-backup-0001-full.json') => new File([text], name, { type: 'application/json' });

async function startRestore(w: World, file = archiveFile(), theme: Theme = 'light', props: { reload?: () => void } = {}) {
  mount(<RestoreContainer api={w.api} navigate={w.navigate} {...props} />, theme);
  await screen.findByRole('heading', { level: 1, name: 'Restore from a backup' });
  fireEvent.change(screen.getByLabelText('Backup file'), { target: { files: [file] } });
  click('Restore from this file…');
  fireEvent.change(screen.getByLabelText('Type RESTORE to confirm'), { target: { value: 'RESTORE' } });
}
const confirm = () => click('Restore this backup');

describe.each(themes)('Restore page (%s theme)', (theme) => {
  test('a committed restore replaces the whole page with the terminal result: no shell, no session read, no retry', async () => {
    const w = world((s) => s.route('POST', RESTORE, (r) => guarded(r, restored)));
    await startRestore(w, archiveFile(), theme);
    confirm();
    expect(await screen.findByRole('heading', { level: 1, name: 'Restore complete' })).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(w.server.calls('POST', RESTORE)[0]?.body).toEqual({ archive: { format: 'mandatary-logical-backup', synthetic: true }, confirm: 'RESTORE', acknowledge_unauthenticated_provenance: false });
    // The signed-in shell (navigation, account strip, sign-out) is gone: the session it showed no longer exists.
    expect(screen.queryByRole('navigation', { name: 'Primary' })).toBeNull();
    expect(screen.queryByRole('button', { name: /sign out/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /restore|retry|try again/i })).toBeNull();
    expect(w.server.calls('GET', '/api/v1/session')).toHaveLength(1); // read once at load; never again
    expect(w.navigate).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain('2 users');
    const surfaces = document.documentElement.outerHTML + JSON.stringify(consoleCalls) + location.href;
    expect(surfaces).not.toContain('mandatary-logical-backup');
    expect(surfaces).not.toContain(SESSION_CSRF);
    expect(consoleCalls).toEqual([]);
  });
});

test('a notice failure after a committed restore is a calm note, not a failure', async () => {
  const w = world((s) => s.route('POST', RESTORE, () => json(200, { report: REPORT, authorizer_notified: false, session_ended: true })));
  await startRestore(w);
  confirm();
  expect(await screen.findByText('Access decisions may take a moment to catch up')).toBeTruthy();
  expect(screen.getByRole('heading', { level: 1, name: 'Restore complete' })).toBeTruthy();
});

test('an unverifiable origin asks for the acknowledgement, then sends the same file with it', async () => {
  let attempts = 0;
  const w = world((s) =>
    s.route('POST', RESTORE, (r) =>
      guarded(r, () => {
        attempts++;
        return (r.body as { acknowledge_unauthenticated_provenance: boolean }).acknowledge_unauthenticated_provenance ? restored() : json(409, { error: 'provenance_unverified' });
      }),
    ),
  );
  await startRestore(w, archiveFile('{"format":"mandatary-logical-backup","mode":"clean"}', 'sample-other-key-clean.json'));
  confirm();
  const box = (await screen.findByRole('checkbox', { name: /origin can’t be verified/ })) as HTMLInputElement;
  expect(box.checked).toBe(false);
  expect(screen.queryByRole('heading', { level: 1, name: 'Restore complete' })).toBeNull();
  fireEvent.click(box);
  confirm();
  expect(await screen.findByRole('heading', { level: 1, name: 'Restore complete' })).toBeTruthy();
  expect(attempts).toBe(2);
  const bodies = w.server.calls('POST', RESTORE).map((call) => call.body as { acknowledge_unauthenticated_provenance: boolean; archive: unknown });
  expect(bodies.map((body) => body.acknowledge_unauthenticated_provenance)).toEqual([false, true]);
  expect(bodies[0]?.archive).toEqual(bodies[1]?.archive);
});

test.each([
  ['archive_malformed', /readable Mandatary backup/i],
  ['archive_unsupported_version', /version/i],
  ['archive_integrity_failed', /integrity|modified|another/i],
  ['archive_inconsistent', /contradict|consistent|inconsistent/i],
])('a file refused as %s changes nothing, keeps the session and keeps the file', async (code, words) => {
  const w = world((s) => s.route('POST', RESTORE, () => json(422, { error: code })));
  await startRestore(w);
  confirm();
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/Nothing was changed/);
  expect(alert.textContent ?? '').toMatch(words);
  expect(screen.queryByRole('heading', { level: 1, name: 'Restore complete' })).toBeNull();
  expect(screen.getByText('sample-backup-0001-full.json')).toBeTruthy(); // the file is kept
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeTruthy(); // still signed in
  expect(w.navigate).not.toHaveBeenCalled();
});

test('a file that is not JSON is sent as an inert string and the server alone refuses it', async () => {
  const w = world((s) => s.route('POST', RESTORE, () => json(422, { error: 'archive_malformed' })));
  const hostile = '{"x":1},"acknowledge_unauthenticated_provenance":true';
  await startRestore(w, archiveFile(hostile, 'sample-not-json.json'));
  confirm();
  expect((await screen.findByRole('alert')).textContent).toMatch(/Nothing was changed/);
  expect(w.server.calls('POST', RESTORE)[0]?.body).toEqual({ archive: hostile, confirm: 'RESTORE', acknowledge_unauthenticated_provenance: false });
});

test.each([
  [403, { error: 'forbidden' }, /wasn’t allowed/i],
  [429, { error: 'rate_limited' }, /too many|wait|rate/i],
  [503, { error: 'unavailable' }, /unavailable|couldn’t|try again/i],
])('a refusal with HTTP %i before any change says nothing changed and keeps the session', async (status, body, words) => {
  const w = world((s) => s.route('POST', RESTORE, () => json(status, body)));
  await startRestore(w);
  confirm();
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toMatch(/Nothing was changed/);
  expect(alert.textContent ?? '').toMatch(words);
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeTruthy();
});

describe('after the first transaction committed', () => {
  test('a failed import (503 with installation_state) is the "didn’t finish" page: sign-in is closed, nothing imported, never "nothing changed"', async () => {
    const w = world((s) => s.route('POST', RESTORE, () => json(503, { error: 'unavailable', installation_state: 'restore_quarantine' })));
    await startRestore(w);
    confirm();
    expect(await screen.findByRole('heading', { level: 1, name: 'The restore didn’t finish' })).toBeTruthy();
    expect(screen.getByText('Sign-in is closed, and nothing was imported')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/Nothing was changed/);
    expect(screen.queryByRole('navigation', { name: 'Primary' })).toBeNull();
    expect(screen.queryByRole('button', { name: /restore|retry|try again/i })).toBeNull();
  });

  test('a superseded restore (409) is its own page and also ends the session view', async () => {
    const w = world((s) => s.route('POST', RESTORE, () => json(409, { error: 'restore_superseded', installation_state: 'restore_quarantine' })));
    await startRestore(w);
    confirm();
    expect(await screen.findByRole('heading', { level: 1, name: 'The restore didn’t finish' })).toBeTruthy();
    expect(document.body.textContent).toContain('Another restore ran at the same moment');
  });

  test('even a plain 409 conflict carrying the quarantine state is not read as a refusal', async () => {
    const w = world((s) => s.route('POST', RESTORE, () => json(409, { error: 'conflict', installation_state: 'restore_quarantine' })));
    await startRestore(w);
    confirm();
    expect(await screen.findByRole('heading', { level: 1, name: 'The restore didn’t finish' })).toBeTruthy();
  });
});

describe('when no usable answer arrived', () => {
  test.each([
    ['a lost connection', () => Promise.reject(new Error('reset'))],
    ['a proxy 502', () => Promise.resolve(new Response('<html>bad gateway</html>', { status: 502 }))],
    ['a bare 500', () => Promise.resolve(json(500, {}))],
    ['a 200 that is not the documented report', () => Promise.resolve(json(200, { report: { nope: true } }))],
    ['a 200 that is not JSON', () => Promise.resolve(new Response('ok', { status: 200 }))],
  ])('%s is "couldn’t confirm", never a failure and never a success', async (_name, answer) => {
    const server = new FakeServer().route('GET', '/api/v1/session', () => json(200, sessionJson()));
    const fetcher = (input: string, init: RequestInit) => (input === RESTORE ? answer() : server.fetcher(input, init));
    const reload = vi.fn();
    mount(<RestoreContainer api={new AccountApi(fetcher)} navigate={vi.fn()} reload={reload} />);
    await screen.findByRole('heading', { level: 1, name: 'Restore from a backup' });
    fireEvent.change(screen.getByLabelText('Backup file'), { target: { files: [archiveFile()] } });
    click('Restore from this file…');
    fireEvent.change(screen.getByLabelText('Type RESTORE to confirm'), { target: { value: 'RESTORE' } });
    confirm();
    expect(await screen.findByRole('heading', { level: 1, name: 'Mandatary couldn’t confirm what happened' })).toBeTruthy();
    expect(screen.getByText('Don’t start another restore yet')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/Restore complete/);
    expect(screen.queryByRole('button', { name: /restore this|try again/i })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Reload this page' }));
    expect(reload).toHaveBeenCalledTimes(1);
  });
});

test('a stale verification opens the step-up panel and does not replay the restore; the form and file stay', async () => {
  const w = world((s) => s.route('POST', RESTORE, () => json(403, { error: 'step_up_required' })));
  await startRestore(w);
  confirm();
  expect(await screen.findByRole('heading', { name: 'Confirm it’s you to restore a backup' })).toBeTruthy();
  expect(w.server.calls('POST', RESTORE)).toHaveLength(1);
  expect(screen.getByText('sample-backup-0001-full.json')).toBeTruthy();
  expect(screen.queryByRole('heading', { level: 1, name: 'Restore complete' })).toBeNull();
});

test('an ended session before the restore starts sends the person to sign in', async () => {
  const w = world((s) => s.route('POST', RESTORE, () => json(401, { error: 'unauthenticated' })));
  await startRestore(w);
  confirm();
  await waitFor(() => expect(w.navigate).toHaveBeenCalledWith('/login'));
  expect(screen.queryByRole('heading', { level: 1, name: 'Restore complete' })).toBeNull();
});

test('pressing the confirm button twice sends one restore', async () => {
  let release: (response: Response) => void = () => undefined;
  const w = world((s) => s.route('POST', RESTORE, () => new Promise<Response>((resolve) => (release = resolve)) as unknown as Response));
  await startRestore(w);
  confirm();
  const busy = await screen.findByRole('button', { name: 'Restoring…' });
  fireEvent.click(busy);
  fireEvent.click(busy);
  expect(w.server.calls('POST', RESTORE)).toHaveLength(1);
  release(restored());
  await screen.findByRole('heading', { level: 1, name: 'Restore complete' });
  expect(w.server.calls('POST', RESTORE)).toHaveLength(1);
});

test('a wrong confirmation phrase never reaches the network', async () => {
  const w = world((s) => s.route('POST', RESTORE, () => restored()));
  mount(<RestoreContainer api={w.api} navigate={w.navigate} />);
  await screen.findByRole('heading', { level: 1, name: 'Restore from a backup' });
  fireEvent.change(screen.getByLabelText('Backup file'), { target: { files: [archiveFile()] } });
  click('Restore from this file…');
  fireEvent.change(screen.getByLabelText('Type RESTORE to confirm'), { target: { value: 'restore' } });
  confirm();
  expect(w.server.calls('POST', RESTORE)).toHaveLength(0);
});

test('a file that cannot be read sends nothing and says so', async () => {
  const w = world((s) => s.route('POST', RESTORE, () => restored()));
  const broken = archiveFile();
  Object.defineProperty(broken, 'text', { value: () => Promise.reject(new Error('read failed')) });
  await startRestore(w, broken);
  confirm();
  expect((await screen.findByRole('alert')).textContent).toMatch(/Nothing was changed/);
  expect(w.server.calls('POST', RESTORE)).toHaveLength(0);
});

// ───────────────────────── review ─────────────────────────

const rowOf = (over: Record<string, unknown>) => ({ kind: 'group', id: 'g-1', label: 'sample-ops', origin: 'imported', source_state: 'active', imported: {}, effective: {}, decision: 'pending', approvable: true, needs: 'approval', ...over });
function manifestJson(items: unknown[] = defaultItems()) {
  return {
    backup_id: 'bk-0001',
    mode: 'full',
    provenance: 'authenticated',
    initiator: 'admin',
    restore_generation: 3,
    restored_at: 1_700_000_000,
    summary: { imported: { group: 1, user: 1 }, retained_local: {}, inactive_credentials: {}, credentials_stripped: false, excluded: ['sessions'] },
    items,
    pending: items.length,
    approved: 0,
    inactive_credentials: { authenticators: 2, agent_credentials: 1 },
  };
}
function defaultItems() {
  return [
    rowOf({ kind: 'user', id: 'u-1', label: 'sample-restored', imported: { mfa_requirement: 'optional', compromised: false }, effective: { mfa_requirement: 'required', credentials: 'none' }, needs: 'credential_enrollment' }),
    rowOf({ kind: 'group', id: 'g-1', label: 'sample-ops' }),
    rowOf({ kind: 'agent', id: 'a-1', label: 'sample-runner', needs: 'token_reissue' }),
    rowOf({ kind: 'role', id: 'adm', label: 'administrator role of sample-admin', approvable: false, blocked_reason: 'single_administrator', needs: 'none_in_phase_1' }),
  ];
}
const box = (name: string) => screen.getByRole('checkbox', { name }) as HTMLInputElement;

describe.each(themes)('Review page (%s theme)', (theme) => {
  test('lists the restored records from the manifest with the imported-versus-effective comparison, and nothing is selected', async () => {
    const w = world((s) => s.route('GET', MANIFEST, () => json(200, manifestJson())));
    mount(<ReviewContainer api={w.api} navigate={w.navigate} />, theme);
    expect(await screen.findByRole('heading', { level: 1, name: 'Review restored access' })).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(await screen.findByRole('checkbox', { name: 'User sample-restored' })).toBeTruthy();
    expect((screen.getAllByRole('checkbox') as HTMLInputElement[]).every((b) => !b.checked)).toBe(true);
    expect(document.body.textContent).toContain('Approving applies the setting on the right, not the one in the file');
    expect(screen.queryByRole('button', { name: /approve all|select all/i })).toBeNull();
    expect(screen.getByRole('navigation', { name: 'Primary' })).toBeTruthy();
  });

  test('approves exactly the named records with the CSRF header, then re-reads the manifest', async () => {
    let approved = false;
    const w = world((s) =>
      s
        .route('GET', MANIFEST, () => json(200, manifestJson(approved ? defaultItems().map((item) => (item.id === 'g-1' ? { ...item, decision: 'approved', approvable: false } : item)) : defaultItems())))
        .route('POST', APPROVALS, (r) =>
          guarded(r, () => {
            approved = true;
            return json(200, { approved: [{ kind: 'user', id: 'u-1', result: 'approved' }, { kind: 'group', id: 'g-1', result: 'approved' }] });
          }),
        ),
    );
    mount(<ReviewContainer api={w.api} navigate={w.navigate} />, theme);
    await screen.findByRole('checkbox', { name: 'User sample-restored' });
    fireEvent.click(box('User sample-restored'));
    fireEvent.click(box('Group sample-ops'));
    click('Approve 2 selected…');
    expect(w.server.calls('POST', APPROVALS)).toHaveLength(0); // naming and confirming first
    fireEvent.click(within(screen.getByRole('group', { name: /^Approve 2 records\?/ })).getByRole('button', { name: 'Approve 2 records' }));
    expect(await screen.findByText('Approved 2 records')).toBeTruthy();
    expect(w.server.calls('POST', APPROVALS)[0]?.body).toEqual({ items: [{ kind: 'user', id: 'u-1' }, { kind: 'group', id: 'g-1' }] });
    await waitFor(() => expect(w.server.calls('GET', MANIFEST).length).toBeGreaterThanOrEqual(2));
    expect(consoleCalls).toEqual([]);
  });
});

test('no restore is an explanation, not an error', async () => {
  const w = world((s) => s.route('GET', MANIFEST, () => json(404, { error: 'no_restore' })));
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  expect(await screen.findByRole('heading', { name: 'No restore to review' })).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
});

test('a manifest refused with 403 is the one refusal, never an empty list', async () => {
  const w = world((s) => s.route('GET', MANIFEST, () => json(403, { error: 'forbidden' })));
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  expect((await screen.findByRole('alert')).textContent).toContain('Policy administration isn’t available to this session');
  expect(screen.queryByText(/Nothing is waiting for approval/)).toBeNull();
});

test('a failed or unreadable manifest offers a retry and never an empty list', async () => {
  let attempts = 0;
  const w = world((s) =>
    s.route('GET', MANIFEST, () => {
      attempts++;
      return attempts === 1 ? json(200, { items: 'nope' }) : json(200, manifestJson());
    }),
  );
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  expect((await screen.findByRole('alert')).textContent).toContain('Couldn’t load the restored records');
  expect(screen.queryByText('Nothing is waiting for approval')).toBeNull();
  click('Try again');
  expect(await screen.findByRole('checkbox', { name: 'User sample-restored' })).toBeTruthy();
});

test('an ended session while loading the manifest sends the person to sign in', async () => {
  const w = world((s) => s.route('GET', MANIFEST, () => json(401, { error: 'unauthenticated' })));
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  await waitFor(() => expect(w.navigate).toHaveBeenCalledWith('/login'));
});

test('a refused approval names each refused record, approves nothing and keeps the selection', async () => {
  const w = world((s) =>
    s
      .route('GET', MANIFEST, () => json(200, manifestJson()))
      .route('POST', APPROVALS, () => json(409, { error: 'conflict', items: [{ kind: 'user', id: 'u-1', reason: 'compromised' }, { kind: 'agent', id: 'a-1', reason: 'owner_not_active' }] })),
  );
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  await screen.findByRole('checkbox', { name: 'User sample-restored' });
  fireEvent.click(box('User sample-restored'));
  fireEvent.click(box('Agent sample-runner'));
  click('Approve 2 selected…');
  fireEvent.click(within(screen.getByRole('group', { name: /^Approve 2 records\?/ })).getByRole('button', { name: 'Approve 2 records' }));
  expect(await screen.findByText('Nothing was approved')).toBeTruthy();
  expect(box('User sample-restored').checked).toBe(true);
  expect(box('Agent sample-runner').checked).toBe(true);
});

test.each([
  [403, { error: 'forbidden' }, /wasn’t allowed/i],
  [429, { error: 'rate_limited' }, /too many|wait/i],
  [409, { error: 'restore_quarantine' }, /quarantine/i],
  [400, { error: 'invalid_request' }, /couldn’t|invalid|selection/i],
])('an approval refused with HTTP %i is shown as such and changes nothing', async (status, body, words) => {
  const w = world((s) => s.route('GET', MANIFEST, () => json(200, manifestJson())).route('POST', APPROVALS, () => json(status, body)));
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  await screen.findByRole('checkbox', { name: 'Group sample-ops' });
  fireEvent.click(box('Group sample-ops'));
  click('Approve 1 selected…');
  fireEvent.click(within(screen.getByRole('group', { name: /^Approve 1 record\?/ })).getByRole('button', { name: 'Approve 1 record' }));
  const alert = await screen.findByRole('alert');
  expect(alert.textContent ?? '').toMatch(words);
});

test.each([
  ['a 503', () => Promise.resolve(json(503, { error: 'unavailable' }))],
  ['a lost connection', () => Promise.reject(new Error('reset'))],
])('%s during an approval is "couldn’t confirm", never "nothing approved", and the list is re-read', async (_name, answer) => {
  const server = new FakeServer().route('GET', '/api/v1/session', () => json(200, sessionJson())).route('GET', MANIFEST, () => json(200, manifestJson()));
  const fetcher = (input: string, init: RequestInit) => (input === APPROVALS ? answer() : server.fetcher(input, init));
  mount(<ReviewContainer api={new AccountApi(fetcher)} navigate={vi.fn()} />);
  await screen.findByRole('checkbox', { name: 'Group sample-ops' });
  fireEvent.click(box('Group sample-ops'));
  click('Approve 1 selected…');
  fireEvent.click(within(screen.getByRole('group', { name: /^Approve 1 record\?/ })).getByRole('button', { name: 'Approve 1 record' }));
  expect(await screen.findByText('Mandatary couldn’t confirm the result')).toBeTruthy();
  expect(screen.queryByText('Nothing was approved')).toBeNull();
  await waitFor(() => expect(server.calls('GET', MANIFEST).length).toBeGreaterThanOrEqual(2));
});

test('a stale verification opens the step-up panel for approvals and does not replay them', async () => {
  const w = world((s) => s.route('GET', MANIFEST, () => json(200, manifestJson())).route('POST', APPROVALS, () => json(403, { error: 'step_up_required' })));
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  await screen.findByRole('checkbox', { name: 'Group sample-ops' });
  fireEvent.click(box('Group sample-ops'));
  click('Approve 1 selected…');
  fireEvent.click(within(screen.getByRole('group', { name: /^Approve 1 record\?/ })).getByRole('button', { name: 'Approve 1 record' }));
  expect(await screen.findByRole('heading', { name: 'Confirm it’s you to approve restored records' })).toBeTruthy();
  expect(w.server.calls('POST', APPROVALS)).toHaveLength(1);
  expect(box('Group sample-ops').checked).toBe(true); // the selection survives the verification
});

test('links lead to the management pages and the token page, and a role or address has none', async () => {
  const items = [
    rowOf({ kind: 'user', id: 'u-1', label: 'sample-restored', imported: { mfa_requirement: 'required', compromised: false }, effective: { mfa_requirement: 'required', credentials: 'none' }, needs: 'credential_enrollment' }),
    rowOf({ kind: 'group', id: 'g-1', label: 'sample-ops' }),
    rowOf({ kind: 'agent', id: 'a-1', label: 'sample-runner', decision: 'approved', approvable: false, needs: 'token_reissue' }),
    rowOf({ kind: 'policy', id: 'p-1', label: 'ALLOW container:logs', imported: { effect: 'ALLOW', operation: 'container:logs' }, effective: { effect: 'ALLOW', operation: 'container:logs', scope: 'none until approved' } }),
    rowOf({ kind: 'role', id: 'adm', label: 'administrator role', approvable: false, blocked_reason: 'single_administrator', needs: 'none_in_phase_1' }),
  ];
  const w = world((s) => s.route('GET', MANIFEST, () => json(200, manifestJson(items))));
  mount(<ReviewContainer api={w.api} navigate={w.navigate} />);
  await screen.findByRole('checkbox', { name: 'User sample-restored' });
  const hrefs = screen.getAllByRole('link').map((link) => link.getAttribute('href') ?? '');
  for (const expected of ['/policy/users', '/policy/groups', '/policy', '/agents#agent=a-1']) expect(hrefs, expected).toContain(expected);
  expect(hrefs.filter((href) => href.includes('adm'))).toEqual([]);
});
