import { afterEach, expect, test, vi } from 'vitest';
import { FakeServer, json } from '../containers/fakeServer';
import { send, type Fetcher } from './http';

// P1.18.3: the transport must carry the two documented extra fields of a failed P1.18 call (installation_state, items),
// strictly validated, or a failure AFTER the quarantine transition is indistinguishable from "nothing changed"
// (docs/ui/p1.18-restore-ux-contract.md §7.1), and it must allow a call's own time bound (a restore is not a 20 s call).

afterEach(() => {
  vi.useRealTimers();
});

test('a failure keeps installation_state only when it is exactly restore_quarantine', async () => {
  const server = new FakeServer()
    .route('POST', '/q', () => json(503, { error: 'unavailable', installation_state: 'restore_quarantine' }))
    .route('POST', '/other', () => json(503, { error: 'unavailable', installation_state: 'something_else' }))
    .route('POST', '/typed', () => json(503, { error: 'unavailable', installation_state: 7 }))
    .route('POST', '/none', () => json(503, { error: 'unavailable' }));
  expect(await send(server.fetcher, 'POST', '/q')).toEqual({ ok: false, status: 503, code: 'unavailable', installationState: 'restore_quarantine' });
  for (const path of ['/other', '/typed', '/none']) {
    const result = await send(server.fetcher, 'POST', path);
    expect(result).toEqual({ ok: false, status: 503, code: 'unavailable' });
    expect(Object.keys(result)).not.toContain('installationState');
  }
});

test('conflict items are kept only as a bounded list of short fixed-shape entries, else dropped whole', async () => {
  const good = [
    { kind: 'user', id: 'u-1', reason: 'compromised' },
    { kind: 'user_membership', id: 'u-1:g-1', reason: 'subject_not_active' },
  ];
  const server = new FakeServer()
    .route('POST', '/ok', () => json(409, { error: 'conflict', items: good }))
    .route('POST', '/free-text', () => json(409, { error: 'conflict', items: [{ kind: 'user', id: 'u-1', reason: '<img src=x onerror=alert(1)>' }] }))
    .route('POST', '/missing', () => json(409, { error: 'conflict', items: [{ kind: 'user', id: 'u-1' }] }))
    .route('POST', '/not-a-list', () => json(409, { error: 'conflict', items: { kind: 'user' } }))
    .route('POST', '/huge', () => json(409, { error: 'conflict', items: Array.from({ length: 501 }, (_, i) => ({ kind: 'user', id: `u-${i}`, reason: 'compromised' })) }))
    .route('POST', '/long-id', () => json(409, { error: 'conflict', items: [{ kind: 'user', id: 'x'.repeat(300), reason: 'compromised' }] }));
  expect(await send(server.fetcher, 'POST', '/ok')).toEqual({ ok: false, status: 409, code: 'conflict', items: good });
  for (const path of ['/free-text', '/missing', '/not-a-list', '/huge', '/long-id']) {
    const result = await send(server.fetcher, 'POST', path);
    expect(result, path).toEqual({ ok: false, status: 409, code: 'conflict' });
    expect(Object.keys(result), path).not.toContain('items');
  }
});

test('a call can name its own time bound; a client abort is the same status-0 outcome as a lost connection', async () => {
  vi.useFakeTimers();
  const hangs: Fetcher = (_input, init) =>
    new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
    });
  const settled = vi.fn();
  const pending = send(hangs, 'POST', '/slow', { timeoutMs: 120_000 }).then(settled);
  await vi.advanceTimersByTimeAsync(60_000); // well past the default 20 s
  expect(settled).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(60_001);
  await pending;
  expect(settled).toHaveBeenCalledWith({ ok: false, status: 0, code: 'network' });
});

test('the default bound is still 20 seconds', async () => {
  vi.useFakeTimers();
  const hangs: Fetcher = (_input, init) =>
    new Promise((_resolve, reject) => {
      init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
    });
  const pending = send(hangs, 'GET', '/slow');
  await vi.advanceTimersByTimeAsync(20_001);
  expect(await pending).toEqual({ ok: false, status: 0, code: 'network' });
});

test('a caller-supplied reader receives the response of a successful call (used for the backup download)', async () => {
  const server = new FakeServer().route('POST', '/file', () => new Response('{"a":1}', { status: 200, headers: { 'X-Backup-Id': 'b-1' } }));
  const ok = await send(server.fetcher, 'POST', '/file', { read: (response) => Promise.resolve(response.headers.get('X-Backup-Id')) });
  expect(ok).toEqual({ ok: true, status: 200, data: 'b-1' });
  const refused = await send(server.fetcher, 'POST', '/file', { read: () => Promise.resolve(null) });
  expect(refused).toEqual({ ok: false, status: 200, code: 'invalid_response' });
});
