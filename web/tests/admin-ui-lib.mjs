import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import https from 'node:https';
import process from 'node:process';
import { URL } from 'node:url';
import { auditAccessibility } from './a11y-audit.mjs';

/* global fetch, document, localStorage, sessionStorage, location */

// Helpers for the admin UI browser tests (P1.16.3). Test-only. Everything here talks to the loopback
// synthetic TLS fixture started by internal/auth/admin_ui_browser_test.go; nothing reaches the network,
// and no helper prints a secret (failures name the surface, never the value).

export function appOrigin(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'example.invalid');
  assert.notEqual(url.port, '');
  assert.equal(url.pathname, '/');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url;
}

export function controlBase(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  return url;
}

const DOCUMENTS = new Set(['/', '/setup', '/login', '/security', '/recovery', '/agents', '/policy', '/policy/users', '/policy/groups', '/policy/agents', '/backup', '/restore', '/restore/review']);
const API_GET = new Set([
  '/api/v1/session',
  '/api/v1/setup/session',
  '/api/v1/account/security',
  '/api/v1/recovery/state',
  '/api/v1/admin/agents',
  // Policy administration (P1.17): the four management pages' lists.
  '/api/v1/admin/policy/users',
  '/api/v1/admin/policy/groups',
  '/api/v1/admin/policy/agents',
  '/api/v1/admin/policy/rules',
  // Recovery (P1.18): the restored-records manifest.
  '/api/v1/admin/restore/manifest',
]);
// Policy administration commands (P1.17), by method. Identifiers are server-issued path segments; nothing else is open.
const ID = '[A-Za-z0-9._-]+';
const POLICY_COMMANDS = new Map([
  [
    'POST',
    [
      /^\/api\/v1\/admin\/(users|groups|agents)$/,
      new RegExp(`^/api/v1/admin/(users|groups|agents)/${ID}/(disable|enable)$`),
      /^\/api\/v1\/admin\/policy\/rules(\/preview)?$/,
      new RegExp(`^/api/v1/admin/policy/rules/${ID}/(enable|disable)$`),
    ],
  ],
  ['PUT', [new RegExp(`^/api/v1/admin/groups/${ID}/members/(user|agent)/${ID}$`), new RegExp(`^/api/v1/admin/agents/${ID}/owner$`), new RegExp(`^/api/v1/admin/policy/rules/${ID}$`)]],
  ['DELETE', [new RegExp(`^/api/v1/admin/groups/${ID}$`), new RegExp(`^/api/v1/admin/groups/${ID}/members/(user|agent)/${ID}$`), new RegExp(`^/api/v1/admin/policy/rules/${ID}$`)]],
]);
function allowsPolicyCommand(method, pathname) {
  return (POLICY_COMMANDS.get(method) ?? []).some((pattern) => pattern.test(pathname));
}
// Account-security, step-up, recovery and agent-credential routes (P1.16.4).
const API_POST_SECURITY = new Set([
  '/api/v1/stepup/password',
  '/api/v1/stepup/totp',
  '/api/v1/stepup/webauthn/begin',
  '/api/v1/stepup/webauthn/finish',
  '/api/v1/login/webauthn/begin',
  '/api/v1/login/webauthn/finish',
  '/api/v1/account/totp',
  '/api/v1/account/totp/confirm',
  '/api/v1/account/totp/remove',
  '/api/v1/account/recovery-codes',
  '/api/v1/account/webauthn/register/begin',
  '/api/v1/account/webauthn/register/finish',
  '/api/v1/account/webauthn/remove',
  '/api/v1/account/addresses',
  '/api/v1/account/addresses/proof',
  '/api/v1/account/addresses/confirm',
  '/api/v1/account/addresses/remove',
  '/api/v1/recovery',
  '/api/v1/recovery/totp',
  '/api/v1/recovery/totp/confirm',
  '/api/v1/recovery/webauthn/begin',
  '/api/v1/recovery/webauthn/finish',
]);
// Agent credentials: issue, rotate and revoke on a server-issued agent (and credential) identifier.
const SEGMENT = /^[A-Za-z0-9._-]+$/;
function allowsAgentPost(pathname) {
  const parts = pathname.split('/'); // '', api, v1, admin, agents, {agent}, credentials, ...rest
  if (parts.length < 7 || parts.slice(0, 5).join('/') !== '/api/v1/admin/agents') return false;
  const [agent, kind, ...rest] = parts.slice(5);
  if (!SEGMENT.test(agent) || kind !== 'credentials') return false;
  if (rest.length === 0) return true;
  if (rest.length === 1) return rest[0] === 'rotate';
  return rest.length === 2 && SEGMENT.test(rest[0]) && rest[1] === 'revoke';
}
const API_POST = new Set([
  '/api/v1/setup/exchange',
  '/api/v1/setup/account',
  '/api/v1/setup/addresses/proof',
  '/api/v1/setup/addresses/confirm',
  '/api/v1/setup/totp',
  '/api/v1/setup/totp/confirm',
  '/api/v1/setup/complete',
  '/api/v1/login',
  '/api/v1/login/totp',
  '/api/v1/login/no-mfa',
  '/api/v1/logout',
  // Recovery (P1.18): export, restore and the named, per-record approvals.
  '/api/v1/admin/backup/export',
  '/api/v1/admin/restore',
  '/api/v1/admin/restore/approvals',
]);

/** The only browser egress: the exact fixture origin, known documents/assets and the known API paths, no query string. */
export function allowsAppRequest(origin, value, method) {
  const url = new URL(value);
  if (url.origin !== origin.origin || url.username || url.password || url.search || url.hash) return false;
  if (method === 'GET') return DOCUMENTS.has(url.pathname) || API_GET.has(url.pathname) || /^\/assets\/[A-Za-z0-9._-]+$/.test(url.pathname);
  return (method === 'POST' && (API_POST.has(url.pathname) || API_POST_SECURITY.has(url.pathname) || allowsAgentPost(url.pathname))) || allowsPolicyCommand(method, url.pathname);
}

// ───────────────────────── control channel (fixture host actions) ─────────────────────────

export function control(base) {
  const call = async (method, path, body) => {
    const response = await fetch(new URL(path, base), { method, body: body === undefined ? undefined : JSON.stringify(body), headers: body === undefined ? {} : { 'Content-Type': 'application/json' } });
    assert.equal(response.status, 200, `control ${method} ${path}`);
    return response.json();
  };
  return {
    /** Host terminal: `mandatary setup reveal`. */
    revealToken: async () => (await call('POST', '/reveal')).token,
    /** The newest address proof delivered to the loopback SMTP receiver. */
    lastProof: async () => (await call('GET', '/proof')).proof,
    /** Moves the SERVER clock forward (the browser's own clock is untouched). */
    advance: (seconds) => call('POST', '/advance', { seconds }),
    /** The server's periodic cleanup tick (cmd/mandatary runs it every 30 s). */
    maintain: () => call('POST', '/maintain'),
    now: async () => (await call('GET', '/now')).unix,
    seed: async () => (await call('GET', '/seed')).seed,
    policy: (mfa) => call('POST', '/policy', { mfa }),
    /** Whether any of these values appears in the server log. */
    leaked: async (canaries) => (await call('POST', '/check-logs', { canaries })).leaked,
    /** Whether any of these values rests in the raw database/WAL/shm bytes. */
    storeLeaked: async (canaries) => (await call('POST', '/check-store', { canaries })).leaked,
    /** The newest address proof mailed to one recipient. */
    proofTo: async (to) => (await call('POST', '/proof', { to })).proof,
    /** Delivers the durable security-notice outbox to the loopback receiver; resolves with the count sent. */
    dispatch: async () => (await call('POST', '/dispatch')).dispatched,
    /** Messages held by the loopback receiver and their recipients. */
    mailbox: () => call('GET', '/mailbox'),
    /** The administrator role is switched off (the account becomes an ordinary person). */
    demote: () => call('POST', '/demote'),
    /** The mail relay disappears: later notices cannot be delivered. */
    breakMail: () => call('POST', '/break-mail'),
    /** An agent presents this token to the shared verifier: accepted now? */
    agentAccepts: async (token) => (await call('POST', '/agent-accepts', { token })).accepted,
    /** P1.18 fixture host actions (internal/auth/recovery_ui_browser_test.go): a seeded world, a change made after a backup, the modeled host recovery, the installation's state, a real database fault, an ordinary signed-in person. */
    world: () => call('POST', '/world'),
    localChange: () => call('POST', '/local-change'),
    state: () => call('GET', '/state'),
    /** Runs the REAL host recovery; returns the NEW administrator's synthetic credentials { username, password, seed }. */
    ceremony: () => call('POST', '/ceremony'),
    fault: (on) => call('POST', '/fault', { on }),
    ordinary: async () => (await call('POST', '/ordinary')).cookie,
  };
}

// ───────────────────────── TOTP (RFC 6238, SHA-256, 6 digits, 30 s) ─────────────────────────

function base32Decode(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of text.replace(/[\s=]/g, '').toUpperCase()) {
    const index = alphabet.indexOf(char);
    assert.notEqual(index, -1, 'seed is not base32');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let at = 0; at + 8 <= bits.length; at += 8) bytes.push(Number.parseInt(bits.slice(at, at + 8), 2));
  return Buffer.from(bytes);
}

export function totpCode(seed, unixSeconds) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const digest = createHmac('sha256', base32Decode(seed)).update(counter).digest();
  const offset = digest.at(-1) & 0x0f;
  const value = ((digest.at(offset) & 0x7f) << 24) | (digest.at(offset + 1) << 16) | (digest.at(offset + 2) << 8) | digest.at(offset + 3);
  return String(value % 1_000_000).padStart(6, '0');
}

// ───────────────────────── direct HTTP (a hostile client: any headers, any cookie) ─────────────────────────

// The raw client verifies the fixture server's TLS certificate: it trusts exactly the fixture's own public
// certificate (handed over by the Go test) and checks it against the name that certificate carries. The Host
// header and Origin still name the synthetic origin; certificate validation is never switched off.
const FIXTURE_CERT_NAME = 'example.com'; // a SAN of net/http/httptest's built-in certificate
function fixtureCA() {
  const pem = process.env.MANDATARY_FIXTURE_CA_PEM;
  assert.ok(pem && pem.includes('BEGIN CERTIFICATE'), 'MANDATARY_FIXTURE_CA_PEM (the fixture certificate) is required');
  return pem;
}

/**
 * Raw request to the fixture with full control over headers. Defaults mimic a same-origin browser fetch;
 * pass `headers` to break exactly one thing. Returns status, lower-cased headers and the parsed body.
 */
export function rawRequest(origin, { method, path, body, headers = {}, cookie, csrf, contentType = 'application/json', omit = [] }) {
  const send = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  const merged = new Map([
    ['host', origin.host],
    ['origin', origin.origin],
    ['accept', 'application/json'],
  ]);
  if (method !== 'GET') merged.set('content-type', contentType);
  if (cookie) merged.set('cookie', cookie);
  if (csrf) merged.set('x-csrf-token', csrf);
  for (const [name, value] of Object.entries(headers)) merged.set(name.toLowerCase(), value);
  for (const name of omit) merged.delete(name.toLowerCase());
  if (send !== undefined) merged.set('content-length', String(Buffer.byteLength(send)));
  return new Promise((resolve, reject) => {
    const request = https.request(
      { host: '127.0.0.1', port: Number(origin.port), method, path, headers: Object.fromEntries(merged), ca: fixtureCA(), servername: FIXTURE_CERT_NAME },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            // plain-text 404/405
          }
          resolve({ status: response.statusCode, headers: response.headers, json, setCookie: response.headers['set-cookie'] ?? [] });
        });
      },
    );
    request.on('error', reject);
    request.setTimeout(15_000, () => request.destroy(new Error('request timed out')));
    if (send !== undefined) request.write(send);
    request.end();
  });
}

export function cookieHeader(cookies, name) {
  const found = cookies.find((cookie) => cookie.name === name);
  assert.ok(found, `cookie ${name} present`);
  return { header: `${name}=${found.value}`, value: found.value };
}

// ───────────────────────── leakage scanning ─────────────────────────

/** Surfaces where a secret must never appear: the DOM (text and attributes, also with whitespace removed), URL, title, storage. */
export async function scanSurfaces(page, secrets, label) {
  const surfaces = await page.evaluate(() => {
    const text = document.body.textContent ?? '';
    return {
      html: document.documentElement.outerHTML,
      compact: text.replace(/\s/g, ''),
      fields: Array.from(document.querySelectorAll('input')).map((input) => input.value),
      url: location.href,
      title: document.title,
      local: JSON.stringify({ ...localStorage }),
      session: JSON.stringify({ ...sessionStorage }),
      cookie: document.cookie,
    };
  });
  const flat = [surfaces.html, surfaces.compact, surfaces.url, surfaces.title, surfaces.local, surfaces.session, surfaces.cookie, ...surfaces.fields];
  for (const secret of secrets) {
    assert.ok(secret && secret.length >= 8, 'canary must be long enough to be meaningful');
    for (const [index, surface] of flat.entries()) assert.ok(!surface.includes(secret), `${label}: a secret reached surface #${index}`);
  }
  assert.equal(surfaces.local, '{}', `${label}: localStorage written`);
  assert.equal(surfaces.session, '{}', `${label}: sessionStorage written`);
  assert.equal(surfaces.cookie, '', `${label}: a script-readable cookie exists`);
  // Every scanned page state is also audited for the serious/critical structural accessibility rules.
  await auditAccessibility(page, label);
}
