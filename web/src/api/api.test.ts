import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';
import { FakeServer, SESSION_CSRF, SETUP_CSRF, empty, json, requireCsrf, setupView } from '../containers/fakeServer';
import { AccountApi } from './account';
import { send } from './http';
import { SetupApi } from './setup';

// ───────────────────────── transport ─────────────────────────

test('every request is same-origin, uncached, redirect-refusing and sends no referrer', async () => {
  const server = new FakeServer().route('POST', '/api/v1/x', () => empty());
  await send(server.fetcher, 'POST', '/api/v1/x', { csrf: 'token-1', body: { a: 1 } });
  const { init, headers } = server.requests[0] ?? { init: {}, headers: {} };
  expect(init).toMatchObject({ credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', method: 'POST' });
  expect(headers['x-csrf-token']).toBe('token-1');
  expect(headers['content-type']).toBe('application/json');
  expect(Object.keys(headers)).not.toContain('authorization');
  expect(init.body).toBe('{"a":1}');
});

test('no CSRF header is sent when none is held, and a GET has no body or content type', async () => {
  const server = new FakeServer().route('GET', '/api/v1/y', () => json(200, {}));
  await send(server.fetcher, 'GET', '/api/v1/y', {});
  const { headers, init } = server.requests[0] ?? { init: {}, headers: {} };
  expect(headers['x-csrf-token']).toBeUndefined();
  expect(headers['content-type']).toBeUndefined();
  expect(init.body).toBeUndefined();
});

test('a failure exposes only a snake_case code and the fixed guidance string, never free text', async () => {
  const hostile = new FakeServer()
    .route('POST', '/a', () => json(401, { error: 'invalid_token' }))
    .route('POST', '/b', () => json(500, { error: '<img src=x onerror=alert(1)>', detail: 'secret stack trace' }))
    .route('POST', '/c', () => json(422, { error: 'password_rejected', guidance: 'Use at least 8 characters.' }))
    .route('POST', '/d', () => json(422, { error: 'password_rejected', guidance: 'x'.repeat(5000) }))
    .route('POST', '/e', () => new Response('<html>nope</html>', { status: 502 }));
  expect(await send(hostile.fetcher, 'POST', '/a')).toEqual({ ok: false, status: 401, code: 'invalid_token' });
  expect(await send(hostile.fetcher, 'POST', '/b')).toEqual({ ok: false, status: 500, code: '' });
  expect(await send(hostile.fetcher, 'POST', '/c')).toEqual({ ok: false, status: 422, code: 'password_rejected', guidance: 'Use at least 8 characters.' });
  expect(await send(hostile.fetcher, 'POST', '/d')).toEqual({ ok: false, status: 422, code: 'password_rejected' });
  expect(await send(hostile.fetcher, 'POST', '/e')).toEqual({ ok: false, status: 502, code: '' });
});

test('a malformed success body fails closed and a network error carries no message', async () => {
  const server = new FakeServer().route('GET', '/ok', () => json(200, { nope: true })).route('GET', '/text', () => new Response('not json', { status: 200 }));
  expect(await send(server.fetcher, 'GET', '/ok', { decode: () => null })).toEqual({ ok: false, status: 200, code: 'invalid_response' });
  expect(await send(server.fetcher, 'GET', '/text', { decode: () => ({}) })).toEqual({ ok: false, status: 200, code: 'invalid_response' });
  const throwing = () => Promise.reject(new Error('connect ECONNREFUSED with a secret in the message'));
  expect(await send(throwing, 'GET', '/x')).toEqual({ ok: false, status: 0, code: 'network' });
});

// ───────────────────────── setup client ─────────────────────────

function setupServer(extra?: (server: FakeServer) => void): FakeServer {
  const server = new FakeServer()
    .route('POST', '/api/v1/setup/exchange', (request) => ((request.body as { token?: string }).token === 'GOOD-TOKEN' ? json(200, setupView()) : json(401, { error: 'invalid_token' })))
    .route('GET', '/api/v1/setup/session', () => json(200, setupView()));
  extra?.(server);
  return server;
}

test('the setup client holds the CSRF token privately and sends it on every unsafe call after the exchange', async () => {
  const server = setupServer((s) => s.route('POST', '/api/v1/setup/account', (request) => requireCsrf(request, SETUP_CSRF, () => json(200, { addresses: [] }))));
  const api = new SetupApi(server.fetcher);
  expect((await api.account({ password: 'p' })).ok).toBe(false); // no token yet → server says 403
  const exchanged = await api.exchange('GOOD-TOKEN');
  expect(exchanged.ok).toBe(true);
  if (exchanged.ok) expect(JSON.stringify(exchanged.data)).not.toContain(SETUP_CSRF); // the view never carries it
  expect((await api.account({ password: 'p' })).ok).toBe(true);
  api.forget();
  expect((await api.account({ password: 'p' })).ok).toBe(false);
  expect(Object.keys(api)).toEqual([]); // private fields are not enumerable properties
});

test('the pasted token is only ever a request body field: never a URL, header or the client state', async () => {
  const server = setupServer();
  const api = new SetupApi(server.fetcher);
  await api.exchange('GOOD-TOKEN');
  const [call] = server.requests;
  expect(call?.path).toBe('/api/v1/setup/exchange');
  expect(JSON.stringify(call?.headers)).not.toContain('GOOD-TOKEN');
  expect(call?.body).toEqual({ token: 'GOOD-TOKEN' });
});

test('wrong, expired and replayed tokens are one indistinguishable outcome', async () => {
  const server = setupServer();
  const api = new SetupApi(server.fetcher);
  const outcomes = await Promise.all(['WRONG', 'EXPIRED', 'USED'].map((token) => api.exchange(token)));
  expect(new Set(outcomes.map((o) => JSON.stringify(o))).size).toBe(1);
  expect(outcomes[0]).toEqual({ ok: false, status: 401, code: 'invalid_token' });
});

test('a null address list from the server decodes to an empty list, and a malformed view fails closed', async () => {
  const server = setupServer((s) => s.route('GET', '/api/v1/setup/session', () => json(200, setupView({ addresses: null }))));
  const api = new SetupApi(server.fetcher);
  const viewed = await api.session();
  expect(viewed.ok && viewed.data.addresses).toEqual([]);
  const broken = new SetupApi(new FakeServer().route('GET', '/api/v1/setup/session', () => json(200, { ...setupView(), csrf_token: '' })).fetcher);
  expect(await broken.session()).toEqual({ ok: false, status: 200, code: 'invalid_response' });
});

test('TOTP begin sends exactly the algorithm the server accepts; mfa_reset sends only a password', async () => {
  const server = setupServer(
    (s) =>
      s
        .route('POST', '/api/v1/setup/totp', () => json(200, { authenticator_id: 'a', secret: 'SYNTHETICSEEDNOTREAL', algorithm: 'SHA256', digits: 6, period: 30 }))
        .route('POST', '/api/v1/setup/account', () => json(200, { addresses: [] })),
  );
  const api = new SetupApi(server.fetcher);
  await api.exchange('GOOD-TOKEN');
  await api.beginTotp();
  await api.account({ password: 'only-the-password' });
  expect(server.calls('POST', '/api/v1/setup/totp')[0]?.body).toEqual({ algorithm: 'SHA256' });
  expect(server.calls('POST', '/api/v1/setup/account')[0]?.body).toEqual({ password: 'only-the-password' });
});

// ───────────────────────── account client ─────────────────────────

test('the account client drops factor steps it does not understand and keeps the CSRF token private', async () => {
  const server = new FakeServer()
    .route('POST', '/api/v1/login', () => json(200, { step: 'factor', next: ['webauthn', 'telepathy', 'totp', 'no-mfa'], csrf_token: SESSION_CSRF }))
    .route('POST', '/api/v1/login/totp', (request) => requireCsrf(request, SESSION_CSRF, () => json(200, { step: 'session' })));
  const api = new AccountApi(server.fetcher);
  const result = await api.login('someone', 'a password');
  expect(result).toEqual({ ok: true, status: 200, data: { step: 'factor', next: ['totp', 'webauthn', 'no-mfa'], totpFactors: [] } });
  expect(JSON.stringify(result)).not.toContain(SESSION_CSRF);
  expect((await api.loginTotp('123456')).ok).toBe(true);
  expect(server.calls('POST', '/api/v1/login/totp')[0]?.body).toEqual({ code: '123456' });
});

test('a session view is accepted only with a server assurance label this page understands', async () => {
  const good = { username: 'someone', assurance: 'aal2', methods: ['password', 'totp'], phishing_resistant: false, authenticated_at: 1, expires_at: 2, step_up_required: false, csrf_token: SESSION_CSRF };
  const serve = (body: unknown) => new AccountApi(new FakeServer().route('GET', '/api/v1/session', () => json(200, body)).fetcher).session();
  expect((await serve(good)).ok).toBe(true);
  for (const assurance of ['preauth', 'aal3', '', 2, null]) {
    expect(await serve({ ...good, assurance })).toEqual({ ok: false, status: 200, code: 'invalid_response' });
  }
});

// ───────────────────────── source hygiene ─────────────────────────

test('the API layer and containers never touch storage, cookies, history, the console or a URL query', () => {
  const sources = [
    readFileSync('src/api/http.ts', 'utf8'),
    readFileSync('src/api/setup.ts', 'utf8'),
    readFileSync('src/api/account.ts', 'utf8'),
    readFileSync('src/containers/SetupContainer.tsx', 'utf8'),
    readFileSync('src/containers/LoginContainer.tsx', 'utf8'),
    readFileSync('src/containers/SessionHome.tsx', 'utf8'),
  ]
    .join('\n')
    .replace(/\/\*[\s\S]*?\*\//g, '') // comments may name what the code must not use
    .replace(/^\s*\/\/.*$/gm, '');
  for (const forbidden of ['console', 'localStorage', 'sessionStorage', 'document.cookie', 'indexedDB', 'history.', 'pushState', 'replaceState', 'location.search', 'location.hash', 'URLSearchParams', 'dangerouslySetInnerHTML', 'innerHTML', 'postMessage', 'sendBeacon', 'XMLHttpRequest', 'WebSocket', 'EventSource']) {
    expect(sources, forbidden).not.toContain(forbidden);
  }
});
