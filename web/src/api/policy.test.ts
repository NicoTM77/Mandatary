import { describe, expect, test } from 'vitest';
import { FakeServer, SESSION_CSRF, empty, json } from '../containers/fakeServer';
import { EMPTY_SELECTOR } from '../screens/policy/selector';
import { AccountApi } from './account';
import { PolicyApi } from './policy';

// The policy client decodes server data strictly and never builds a path from anything but a validated identifier.
// All values are synthetic.

const BASE = '/api/v1/admin';
const POLICY = `${BASE}/policy`;
const subject = { kind: 'agent', id: 'a-1', name: 'sample-agent', state: 'active' };
const selector = { container_name: 'sample-web', name_is_glob: false };
const rule = (overrides: Record<string, unknown> = {}) => ({ id: 'r-1', subject, effect: 'ALLOW', operation: 'container:logs', selector, log_tail_max: null, stop_timeout_max: null, state: 'active', target: { status: 'present', matches: 1 }, ...overrides });
const page = (rules: unknown[]) => ({ rules, subjects: [subject], endpoint: { name: 'local', safety: 'verified' }, inventory: [] });

async function client(server: FakeServer): Promise<PolicyApi> {
  server.route('GET', '/api/v1/session', () =>
    json(200, { username: 'sample-admin', administrator: true, assurance: 'aal2', methods: ['password'], phishing_resistant: false, authenticated_at: 1, expires_at: 2, csrf_token: SESSION_CSRF, step_up_required: false }),
  );
  const account = new AccountApi(server.fetcher);
  await account.session(); // adopts the CSRF token exactly as the signed-in frame does
  return new PolicyApi(account);
}

describe('rules decoding fails closed', () => {
  test('a well-formed page decodes', async () => {
    const server = new FakeServer().route('GET', `${POLICY}/rules`, () => json(200, page([rule()])));
    const result = await (await client(server)).rules();
    expect(result.ok && result.data.rules[0]?.effect).toBe('allow');
  });

  test.each([
    ['an unknown effect', rule({ effect: 'MAYBE' })],
    ['a lower-case effect', rule({ effect: 'allow' })],
    ['an operation outside the six', rule({ operation: 'container:exec' })],
    ['a wildcard operation', rule({ operation: 'container:*' })],
    ['an unknown target status', rule({ target: { status: 'probably' } })],
    ['a present target with no count', rule({ target: { status: 'present' } })],
    ['a negative cap', rule({ log_tail_max: -1 })],
    ['a string cap', rule({ log_tail_max: '10' })],
    ['an unknown rule state', rule({ state: 'pending' })],
  ])('%s is a failed load, not a rule the page might trust', async (_name, bad) => {
    const server = new FakeServer().route('GET', `${POLICY}/rules`, () => json(200, page([rule(), bad])));
    const result = await (await client(server)).rules();
    expect(result).toMatchObject({ ok: false, code: 'invalid_response' });
  });

  test('an inventory that is null is "cannot be listed", and an unknown safety value is refused', async () => {
    const nullInventory = new FakeServer().route('GET', `${POLICY}/rules`, () => json(200, { ...page([]), inventory: null }));
    const loaded = await (await client(nullInventory)).rules();
    expect(loaded.ok && loaded.data.inventory).toBeNull();
    const odd = new FakeServer().route('GET', `${POLICY}/rules`, () => json(200, { ...page([]), endpoint: { name: 'local', safety: 'trusted' } }));
    expect(await (await client(odd)).rules()).toMatchObject({ ok: false, code: 'invalid_response' });
  });
});

describe('requests', () => {
  test('identifiers that are not a safe path segment are never sent', async () => {
    const server = new FakeServer();
    const api = await client(server);
    for (const id of ['../x', 'a/b', '', 'a b', '%2e%2e', '..', '.']) {
      expect(await api.userLifecycle(id, 'disable')).toMatchObject({ ok: false, code: 'invalid_request' });
      expect(await api.deleteRule(id)).toMatchObject({ ok: false, code: 'invalid_request' });
      expect(await api.addMember('g', 'user', id)).toMatchObject({ ok: false, code: 'invalid_request' });
      expect(await api.transferAgent(id, { kind: 'user', id: 'u' })).toMatchObject({ ok: false, code: 'invalid_request' });
    }
    expect(server.requests.filter((request) => request.path !== '/api/v1/session')).toEqual([]);
  });

  test('verbs, paths and bodies match the server routes, and every one carries the CSRF header', async () => {
    const server = new FakeServer();
    for (const [method, path] of [
      ['POST', `${BASE}/users`],
      ['POST', `${BASE}/users/u-1/enable`],
      ['POST', `${BASE}/groups`],
      ['DELETE', `${BASE}/groups/g-1`],
      ['PUT', `${BASE}/groups/g-1/members/agent/a-1`],
      ['DELETE', `${BASE}/groups/g-1/members/user/u-1`],
      ['POST', `${BASE}/agents`],
      ['PUT', `${BASE}/agents/a-1/owner`],
      ['POST', `${BASE}/agents/a-1/disable`],
      ['PUT', `${POLICY}/rules/r-1`],
      ['POST', `${POLICY}/rules/r-1/enable`],
      ['DELETE', `${POLICY}/rules/r-1`],
    ] as const) {
      server.route(method, path, () => empty());
    }
    const api = await client(server);
    const draft = { subject: { kind: 'agent' as const, id: 'a-1' }, effect: 'deny' as const, operations: ['container:stop' as const], selector: { ...EMPTY_SELECTOR, containerName: 'sample-web' }, caps: { logTailMax: null, stopTimeoutMax: null }, acknowledgedBroad: false };
    await api.createUser('sample-new');
    await api.userLifecycle('u-1', 'enable');
    await api.createGroup('sample-ops');
    await api.deleteGroup('g-1');
    await api.addMember('g-1', 'agent', 'a-1');
    await api.removeMember('g-1', 'user', 'u-1');
    await api.createAgent('sample-bot', { kind: 'group', id: 'g-1' });
    await api.transferAgent('a-1', { kind: 'user', id: 'u-1' });
    await api.agentLifecycle('a-1', 'disable');
    await api.updateRule('r-1', draft);
    await api.ruleLifecycle('r-1', 'enable');
    await api.deleteRule('r-1');

    const sent = server.requests.filter((request) => request.path !== '/api/v1/session');
    expect(sent).toHaveLength(12);
    for (const request of sent) {
      expect(request.headers['x-csrf-token']).toBe(SESSION_CSRF);
      expect(request.path).not.toContain('?');
    }
    expect(server.calls('POST', `${BASE}/agents`)[0]?.body).toEqual({ name: 'sample-bot', owner_group_id: 'g-1' });
    expect(server.calls('PUT', `${BASE}/agents/a-1/owner`)[0]?.body).toEqual({ owner_user_id: 'u-1' });
    // An edit never carries a subject or an operation: those are fixed once a rule exists.
    expect(server.calls('PUT', `${POLICY}/rules/r-1`)[0]?.body).toEqual({ effect: 'DENY', selector: { container_name: 'sample-web', name_is_glob: false }, log_tail_max: null, stop_timeout_max: null });
  });
});
