import { afterEach, expect, test, vi } from 'vitest';
import { FakeServer, SESSION_CSRF, json, requireCsrf } from '../containers/fakeServer';
import { AccountApi } from './account';
import { EXPORT_TIMEOUT_MS, RESTORE_TIMEOUT_MS, RecoveryApi, downloadName } from './recovery';
import type { Fetcher } from './http';

// P1.18.3: the browser client of the four P1.18.1 routes (internal/auth/backup_http.go). The FakeServer reproduces the documented
// paths, statuses and JSON shapes; the real service decisions are exercised on the Go side and in the real-browser scenario.
// Every value is synthetic.

const EXPORT = '/api/v1/admin/backup/export';
const RESTORE = '/api/v1/admin/restore';
const MANIFEST = '/api/v1/admin/restore/manifest';
const APPROVALS = '/api/v1/admin/restore/approvals';

afterEach(() => {
  vi.useRealTimers();
});

async function signedIn(server: FakeServer): Promise<RecoveryApi> {
  server.route('GET', '/api/v1/session', () =>
    json(200, { username: 'sample-admin', administrator: true, assurance: 'aal2', methods: ['password', 'totp'], phishing_resistant: false, authenticated_at: 1, expires_at: 2, step_up_required: false, csrf_token: SESSION_CSRF }),
  );
  const account = new AccountApi(server.fetcher);
  await account.session();
  return new RecoveryApi(account);
}

const archiveResponse = (mode = 'clean', id = 'bk-0001') =>
  new Response('{"format":"mandatary-logical-backup"}', { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="mandatary-backup-${id}-${mode}.json"`, 'X-Backup-Id': id, 'X-Backup-Mode': mode } });

// ───────────────────────── export ─────────────────────────

test('export posts only the mode with the CSRF header and returns the file with its server-named identity', async () => {
  const server = new FakeServer().route('POST', EXPORT, (request) => requireCsrf(request, SESSION_CSRF, () => archiveResponse('full', 'bk-0007')));
  const api = await signedIn(server);
  const result = await api.exportBackup('full');
  expect(server.calls('POST', EXPORT)[0]?.body).toEqual({ mode: 'full' });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.data).toMatchObject({ backupId: 'bk-0007', mode: 'full', fileName: 'mandatary-backup-bk-0007-full.json' });
  expect(await result.data.blob.text()).toBe('{"format":"mandatary-logical-backup"}');
});

test('the download name comes from the server only when it has exactly the documented shape', () => {
  expect(downloadName('attachment; filename="mandatary-backup-bk-1-clean.json"', 'bk-1', 'clean')).toBe('mandatary-backup-bk-1-clean.json');
  for (const hostile of ['attachment; filename="../../evil.sh"', 'attachment; filename="mandatary-backup-bk-1-clean.json\\evil"', 'attachment; filename="mandatary-backup-bk-1-full.json"', 'inline', '', null, 'attachment; filename="mandatary-backup-<x>-clean.json"']) {
    expect(downloadName(hostile, 'bk-1', 'clean'), String(hostile)).toBe('mandatary-backup-bk-1-clean.json');
  }
});

test('an export whose headers disagree with the request or are malformed is refused, never saved', async () => {
  const cases: Array<[string, () => Response]> = [
    ['mode mismatch', () => archiveResponse('full')],
    ['no id', () => new Response('{}', { status: 200, headers: { 'X-Backup-Mode': 'clean' } })],
    ['bad id', () => new Response('{}', { status: 200, headers: { 'X-Backup-Mode': 'clean', 'X-Backup-Id': '<script>' } })],
  ];
  for (const [name, respond] of cases) {
    const server = new FakeServer().route('POST', EXPORT, respond);
    const result = await (await signedIn(server)).exportBackup('clean');
    expect(result, name).toEqual({ ok: false, status: 200, code: 'invalid_response' });
  }
});

test('an export failure is passed through as the transport reported it', async () => {
  const server = new FakeServer().route('POST', EXPORT, () => json(403, { error: 'step_up_required' }));
  expect(await (await signedIn(server)).exportBackup('clean')).toEqual({ ok: false, status: 403, code: 'step_up_required' });
});

// ───────────────────────── restore ─────────────────────────

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

test('restore sends the parsed archive as one VALUE with the confirmation phrase and the acknowledgement exactly as given', async () => {
  const server = new FakeServer().route('POST', RESTORE, (request) => requireCsrf(request, SESSION_CSRF, () => json(200, { report: REPORT, authorizer_notified: true, session_ended: true })));
  const api = await signedIn(server);
  const result = await api.restore('{"format":"mandatary-logical-backup","scope":{}}', false);
  expect(server.calls('POST', RESTORE)[0]?.body).toEqual({ archive: { format: 'mandatary-logical-backup', scope: {} }, confirm: 'RESTORE', acknowledge_unauthenticated_provenance: false });
  expect(result.ok && result.data.report.imported).toEqual({ user: 2, group: 1 });
  expect(result.ok && result.data.authorizerNotified).toBe(true);
  await api.restore('{"format":"x"}', true);
  expect(server.calls('POST', RESTORE)[1]?.body).toMatchObject({ acknowledge_unauthenticated_provenance: true });
});

test('a file that is not JSON is wrapped as a string value, so it cannot add or override a request field (the server decides it is malformed)', async () => {
  const server = new FakeServer().route('POST', RESTORE, () => json(422, { error: 'archive_malformed' }));
  const api = await signedIn(server);
  // Spliced into the body this would have set the acknowledgement for the person. As a string it is one inert value.
  const hostile = '{"format":"x"},"acknowledge_unauthenticated_provenance":true,"confirm":"RESTORE","y":{}';
  expect(await api.restore(hostile, false)).toEqual({ ok: false, status: 422, code: 'archive_malformed' });
  expect(server.calls('POST', RESTORE)[0]?.body).toEqual({ archive: hostile, confirm: 'RESTORE', acknowledge_unauthenticated_provenance: false });
  // Keys inside an archive that look like request fields stay inside the archive.
  await api.restore('{"confirm":"nope","acknowledge_unauthenticated_provenance":true}', false);
  expect(server.calls('POST', RESTORE)[1]?.body).toEqual({ archive: { confirm: 'nope', acknowledge_unauthenticated_provenance: true }, confirm: 'RESTORE', acknowledge_unauthenticated_provenance: false });
});

test('a restore success whose body is not exactly the documented report fails closed', async () => {
  for (const [name, body] of Object.entries({
    'no report': { authorizer_notified: true, session_ended: true },
    'wrong mode': { report: { ...REPORT, mode: 'partial' }, authorizer_notified: true, session_ended: true },
    'negative count': { report: { ...REPORT, imported: { user: -1 } }, authorizer_notified: true, session_ended: true },
    'free-text exclusion': { report: { ...REPORT, excluded: [{ x: 1 }] }, authorizer_notified: true, session_ended: true },
    'no notified flag': { report: REPORT, session_ended: true },
    'session not ended': { report: REPORT, authorizer_notified: true, session_ended: false },
  })) {
    const server = new FakeServer().route('POST', RESTORE, () => json(200, body));
    expect(await (await signedIn(server)).restore('{}', false), name).toEqual({ ok: false, status: 200, code: 'invalid_response' });
  }
});

test('a restore is allowed far longer than an ordinary call, and giving up is a status-0 outcome', async () => {
  expect(RESTORE_TIMEOUT_MS).toBeGreaterThan(20_000);
  expect(EXPORT_TIMEOUT_MS).toBeGreaterThan(20_000);
  const server = new FakeServer().route('GET', '/api/v1/session', () => json(200, { username: 'a', administrator: true, assurance: 'aal2', methods: ['password'], phishing_resistant: false, authenticated_at: 1, expires_at: 2, step_up_required: false, csrf_token: SESSION_CSRF }));
  const account = new AccountApi(server.fetcher);
  await account.session();
  vi.useFakeTimers();
  const hang: Fetcher = (input, init) => (input === '/api/v1/session' ? server.fetcher(input, init) : new Promise((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(new Error('aborted')))));
  const api = new RecoveryApi(new AccountApi(hang));
  const settled = vi.fn();
  const pending = api.restore('{}', false).then(settled);
  await vi.advanceTimersByTimeAsync(RESTORE_TIMEOUT_MS - 1000);
  expect(settled).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(2000);
  await pending;
  expect(settled).toHaveBeenCalledWith({ ok: false, status: 0, code: 'network' });
});

test('a post-transition failure keeps installation_state so the screen cannot say nothing changed', async () => {
  const server = new FakeServer().route('POST', RESTORE, () => json(503, { error: 'unavailable', installation_state: 'restore_quarantine' }));
  expect(await (await signedIn(server)).restore('{}', false)).toEqual({ ok: false, status: 503, code: 'unavailable', installationState: 'restore_quarantine' });
});

// ───────────────────────── manifest ─────────────────────────

const DIGEST = 'a1'.repeat(32);
const item = (over: Record<string, unknown>) => ({ kind: 'group', id: 'g-1', label: 'sample-ops', origin: 'imported', source_state: 'active', imported: {}, effective: {}, decision: 'pending', approvable: true, needs: 'approval', digest: DIGEST, ...over });
const manifest = (items: unknown[], over: Record<string, unknown> = {}) => ({
  backup_id: 'bk-0001',
  mode: 'full',
  provenance: 'authenticated',
  initiator: 'admin',
  restore_generation: 3,
  restored_at: 1_700_000_000,
  summary: { imported: { group: 1 }, retained_local: {}, inactive_credentials: {}, credentials_stripped: false, excluded: ['sessions'] },
  items,
  pending: items.length,
  approved: 0,
  inactive_credentials: { authenticators: 2, agent_credentials: 1 },
  ...over,
});

test('the manifest is decoded into the contract: counts, summary flags and the two comparisons only where the service exposes both', async () => {
  const body = manifest([
    item({ kind: 'user', id: 'u-1', label: 'sample-robin', imported: { mfa_requirement: 'optional', compromised: true }, effective: { mfa_requirement: 'required', credentials: 'none' }, needs: 'credential_enrollment' }),
    item({ kind: 'policy', id: 'p-1', label: 'ALLOW container:logs', imported: { effect: 'ALLOW', operation: 'container:logs' }, effective: { effect: 'DENY', note: 'a local DENY with this id was kept' } }),
    item({ kind: 'policy', id: 'p-2', label: 'ALLOW container:logs', imported: { effect: 'ALLOW', operation: 'container:logs' }, effective: { effect: 'ALLOW', operation: 'container:logs', scope: 'none until approved' } }),
    item({ kind: 'group', id: 'g-1' }),
    item({ kind: 'role', id: 'adm', label: 'administrator', approvable: false, blocked_reason: 'single_administrator', needs: 'none_in_phase_1' }),
    item({ kind: 'address', id: 'ad-1', label: 'sample address', approvable: false, blocked_reason: 'needs_reverification', needs: 'reverification' }),
    item({ kind: 'user', id: 'u-2', label: 'sample-local', origin: 'local_retained', source_state: null, imported: {}, effective: {}, needs: 'credential_enrollment' }),
    item({ kind: 'user', id: 'u-3', label: 'sample-done', decision: 'approved', approvable: false, imported: { mfa_requirement: 'optional', compromised: false }, effective: { state: 'active', needs: 'credential_enrollment' }, needs: 'credential_enrollment' }),
  ]);
  const server = new FakeServer().route('GET', MANIFEST, () => json(200, body));
  const result = await (await signedIn(server)).manifest();
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const rows = Object.fromEntries(result.data.items.map((row) => [row.id, row]));
  expect(rows['u-1']?.comparison).toEqual({ kind: 'mfa', imported: 'optional', effective: 'required', compromised: true });
  expect(rows['p-1']?.comparison).toEqual({ kind: 'rule', imported: 'allow', effective: 'deny', localDenyKept: true });
  expect(rows['p-2']?.comparison).toEqual({ kind: 'rule', imported: 'allow', effective: 'allow', localDenyKept: false });
  for (const row of result.data.items.filter((candidate) => ['g-1', 'adm', 'ad-1', 'u-2', 'u-3'].includes(candidate.id))) expect(row.comparison, row.id).toEqual({ kind: 'none' });
  expect(rows['adm']).toMatchObject({ approvable: false, blockedReason: 'single_administrator', needs: 'none_in_phase_1' });
  expect(rows['u-2']).toMatchObject({ origin: 'local_retained', sourceState: null });
  expect(rows['u-3']).toMatchObject({ decision: 'approved', approvable: false });
  expect(result.data).toMatchObject({ backupId: 'bk-0001', mode: 'full', provenance: 'authenticated', initiator: 'admin', restoredAt: 1_700_000_000, credentialsStripped: false, inactiveCredentials: { authenticators: 2, agentCredentials: 1 } });
});

test('a clean backup reports credentials stripped', async () => {
  const body = manifest([item({})], { mode: 'clean', summary: { imported: {}, retained_local: {}, inactive_credentials: {}, credentials_stripped: true, excluded: [] }, inactive_credentials: { authenticators: 0, agent_credentials: 0 } });
  const result = await (await signedIn(new FakeServer().route('GET', MANIFEST, () => json(200, body)))).manifest();
  expect(result.ok && result.data.credentialsStripped).toBe(true);
});

test('a manifest that is not exactly the documented shape fails closed', async () => {
  const bad: Record<string, unknown> = {
    'unknown kind': manifest([item({ kind: 'credential' })]),
    'unknown mode': manifest([item({})], { mode: 'partial' }),
    'approvable not boolean': manifest([item({ approvable: 'yes' })]),
    'unknown blocked reason': manifest([item({ approvable: false, blocked_reason: 'because' })]),
    'unknown needs': manifest([item({ needs: 'magic' })]),
    'decision unknown': manifest([item({ decision: 'maybe' })]),
    'user without imported comparison': manifest([item({ kind: 'user', imported: { mfa_requirement: 'sometimes', compromised: false }, effective: { mfa_requirement: 'required' } })]),
    'user whose imported settings are not an object': manifest([item({ kind: 'user', imported: null, effective: { mfa_requirement: 'required' } })]),
    'policy whose effective settings are not an object': manifest([item({ kind: 'policy', imported: { effect: 'ALLOW' }, effective: 'DENY' })]),
    'user imported but no effective': manifest([item({ kind: 'user', imported: { mfa_requirement: 'optional', compromised: false }, effective: {} })]),
    'policy effect unknown': manifest([item({ kind: 'policy', imported: { effect: 'MAYBE' }, effective: { effect: 'DENY' } })]),
    'no summary': { ...manifest([item({})]), summary: undefined },
    'label too long': manifest([item({ label: 'x'.repeat(301) })]),
    'restored_at not a number': manifest([item({})], { restored_at: 'yesterday' }),
    'not an object': [],
  };
  for (const [name, body] of Object.entries(bad)) {
    const result = await (await signedIn(new FakeServer().route('GET', MANIFEST, () => json(200, body)))).manifest();
    expect(result, name).toEqual({ ok: false, status: 200, code: 'invalid_response' });
  }
});

test('no restore is a 404 the caller can tell apart; a quarantined installation is a 401/403 the caller maps', async () => {
  const none = new FakeServer().route('GET', MANIFEST, () => json(404, { error: 'no_restore' }));
  expect(await (await signedIn(none)).manifest()).toEqual({ ok: false, status: 404, code: 'no_restore' });
});

// ───────────────────────── approvals ─────────────────────────

test('approval sends exactly the named kind and id pairs and nothing else', async () => {
  const server = new FakeServer().route('POST', APPROVALS, (request) =>
    requireCsrf(request, SESSION_CSRF, () => json(200, { approved: [{ kind: 'user', id: 'u-1', result: 'approved' }, { kind: 'group', id: 'g-1', result: 'approved' }] })),
  );
  const api = await signedIn(server);
  const result = await api.approve([
    { kind: 'user', id: 'u-1' },
    { kind: 'group', id: 'g-1', extra: 'state=active' } as unknown as { kind: 'group'; id: string },
  ]);
  expect(server.calls('POST', APPROVALS)[0]?.body).toEqual({ items: [{ kind: 'user', id: 'u-1' }, { kind: 'group', id: 'g-1' }] });
  expect(result).toEqual({ ok: true, status: 200, data: 2 });
});

test('approval refuses an empty, oversized or duplicated selection before any request', async () => {
  const server = new FakeServer().route('POST', APPROVALS, () => json(200, { approved: [] }));
  const api = await signedIn(server);
  const many = Array.from({ length: 501 }, (_, i) => ({ kind: 'user' as const, id: `u-${i}` }));
  for (const items of [[], many, [{ kind: 'user' as const, id: 'u-1' }, { kind: 'user' as const, id: 'u-1' }]]) {
    expect(await api.approve(items)).toEqual({ ok: false, status: 400, code: 'invalid_request' });
  }
  expect(server.calls('POST', APPROVALS)).toHaveLength(0);
});

test('an approval conflict keeps the refused records; an unreadable success is not a count', async () => {
  const items = [{ kind: 'role', id: 'adm', reason: 'single_administrator' }];
  const conflict = new FakeServer().route('POST', APPROVALS, () => json(409, { error: 'conflict', items }));
  expect(await (await signedIn(conflict)).approve([{ kind: 'role', id: 'adm' }])).toEqual({ ok: false, status: 409, code: 'conflict', items });
  const odd = new FakeServer().route('POST', APPROVALS, () => json(200, { approved: 'all' }));
  expect(await (await signedIn(odd)).approve([{ kind: 'user', id: 'u-1' }])).toEqual({ ok: false, status: 200, code: 'invalid_response' });
});

// ───────────────────────── P1.18.4 FC4-1: identifying detail and digest ─────────────────────────

const named = (
  kind: string,
  id: string,
  name: string,
  extra: Record<string, unknown> = {},
) => ({ kind, id, name, ...extra });
const ruleDetail = (over: Record<string, unknown> = {}) => ({
  effect: "ALLOW",
  operation: "container:logs",
  subject: named("agent", "a-1", "sample-bot"),
  endpoint: named("endpoint", "ep-1", "local"),
  selector: {
    id: "sel-1",
    name_type: "glob",
    container_name: "web-*",
    compose_project: "sample-platform",
    image_pattern: "registry.invalid/web:*",
  },
  log_tail_max: 500,
  ...over,
});

async function decoded(items: unknown[]) {
  return await (
    await signedIn(
      new FakeServer().route("GET", MANIFEST, () => json(200, manifest(items))),
    )
  ).manifest();
}

test("a rule and a membership carry their exact detail and digest, decoded by id and never guessed", async () => {
  const result = await decoded([
    item({
      kind: "policy",
      id: "p-1",
      label: "ALLOW container:logs",
      imported: { effect: "ALLOW" },
      effective: { effect: "ALLOW" },
      detail: ruleDetail(),
    }),
    item({
      kind: "agent_membership",
      id: "a-1:g-1",
      label: "x in y",
      detail: {
        member: named("agent", "a-1", "sample-bot"),
        group: named("group", "g-1", "sample-ops", { missing: true }),
      },
    }),
    item({
      kind: "user",
      id: "u-1",
      label: "sample-robin",
      imported: { mfa_requirement: "optional", compromised: true },
      effective: { mfa_requirement: "required" },
      approvable: false,
      blocked_reason: "compromised",
      needs: "credential_enrollment",
      detail: { compromised: true },
    }),
    item({ kind: "group", id: "g-2" }),
  ]);
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const rows = Object.fromEntries(
    result.data.items.map((row) => [row.id, row]),
  );
  expect(rows["p-1"]?.detail).toEqual({
    kind: "rule",
    effect: "allow",
    operation: "container:logs",
    subject: { kind: "agent", id: "a-1", name: "sample-bot", missing: false },
    endpoint: { kind: "endpoint", id: "ep-1", name: "local", missing: false },
    selector: {
      id: "sel-1",
      nameType: "glob",
      containerName: "web-*",
      composeProject: "sample-platform",
      composeService: "",
      imagePattern: "registry.invalid/web:*",
      pinnedContainerId: "",
      pinnedImageDigest: "",
    },
    logTailMax: 500,
    stopTimeoutMax: null,
  });
  expect(rows["a-1:g-1"]?.detail).toEqual({
    kind: "membership",
    member: { kind: "agent", id: "a-1", name: "sample-bot", missing: false },
    group: { kind: "group", id: "g-1", name: "sample-ops", missing: true },
  });
  expect(rows["u-1"]).toMatchObject({
    approvable: false,
    blockedReason: "compromised",
    detail: null,
  });
  expect(rows["g-2"]?.detail).toBeNull();
  expect(rows["p-1"]?.digest).toBe(DIGEST);
});

test("a rule or membership the service sent no detail for has a null detail: the screen then offers no checkbox", async () => {
  const result = await decoded([
    item({
      kind: "policy",
      id: "p-1",
      imported: { effect: "ALLOW" },
      effective: { effect: "ALLOW" },
    }),
    item({ kind: "user_membership", id: "u-1:g-1" }),
  ]);
  expect(result.ok && result.data.items.map((row) => row.detail)).toEqual([
    null,
    null,
  ]);
});

test("a half-understood detail or a digest that is not a digest fails the whole manifest closed", async () => {
  const policy = (detail: unknown) =>
    item({
      kind: "policy",
      id: "p-1",
      imported: { effect: "ALLOW" },
      effective: { effect: "ALLOW" },
      detail,
    });
  const bad: Record<string, unknown[]> = {
    "detail not an object": [policy("ALLOW everything")],
    "unknown effect": [policy(ruleDetail({ effect: "MAYBE" }))],
    "unknown operation": [policy(ruleDetail({ operation: "container:exec" }))],
    "subject of an unknown kind": [
      policy(ruleDetail({ subject: named("credential", "c-1", "x") })),
    ],
    "subject without an id": [
      policy(ruleDetail({ subject: named("agent", "", "x") })),
    ],
    "endpoint of the wrong kind": [
      policy(ruleDetail({ endpoint: named("group", "g-1", "x") })),
    ],
    "selector without a name type": [
      policy(ruleDetail({ selector: { id: "s", container_name: "web" } })),
    ],
    "selector constraint of the wrong type": [
      policy(
        ruleDetail({
          selector: {
            id: "s",
            name_type: "exact",
            container_name: "web",
            compose_project: 7,
          },
        }),
      ),
    ],
    "limit that is not a positive integer": [
      policy(ruleDetail({ log_tail_max: -1 })),
    ],
    "membership with a group of the wrong kind": [
      item({
        kind: "agent_membership",
        id: "a:g",
        detail: {
          member: named("agent", "a", "x"),
          group: named("user", "g", "x"),
        },
      }),
    ],
    "membership whose user member is an agent": [
      item({
        kind: "user_membership",
        id: "u:g",
        detail: {
          member: named("agent", "u", "x"),
          group: named("group", "g", "x"),
        },
      }),
    ],
    "missing digest": [{ ...item({}), digest: undefined }],
    "short digest": [item({ digest: "abc" })],
    "upper-case digest": [item({ digest: "A1".repeat(32) })],
    "name too long": [
      policy(ruleDetail({ subject: named("agent", "a", "x".repeat(301)) })),
    ],
  };
  for (const [name, items] of Object.entries(bad))
    expect(await decoded(items), name).toMatchObject({ ok: false });
});

test("an approval sends each record's kind, id and the digest the person reviewed, and nothing else", async () => {
  const server = new FakeServer().route("POST", APPROVALS, () =>
    json(200, {
      approved: [
        { kind: "policy", id: "p-1", result: "approved" },
        { kind: "user", id: "u-1", result: "approved" },
      ],
    }),
  );
  const api = await signedIn(server);
  expect(
    await api.approve([
      { kind: "policy", id: "p-1", digest: DIGEST },
      { kind: "user", id: "u-1" },
    ]),
  ).toMatchObject({ ok: true, data: 2 });
  expect(server.calls("POST", APPROVALS)[0]?.body).toEqual({
    items: [
      { kind: "policy", id: "p-1", digest: DIGEST },
      { kind: "user", id: "u-1" },
    ],
  });
});
