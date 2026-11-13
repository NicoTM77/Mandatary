import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import https from 'node:https';
import { URL } from 'node:url';

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

const DOCUMENTS = new Set(['/', '/setup', '/login']);
const API_GET = new Set(['/api/v1/session', '/api/v1/setup/session']);
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
]);

/** The only browser egress: the exact fixture origin, known documents/assets and the known API paths, no query string. */
export function allowsAppRequest(origin, value, method) {
  const url = new URL(value);
  if (url.origin !== origin.origin || url.username || url.password || url.search || url.hash) return false;
  if (method === 'GET') return DOCUMENTS.has(url.pathname) || API_GET.has(url.pathname) || /^\/assets\/[A-Za-z0-9._-]+$/.test(url.pathname);
  return method === 'POST' && API_POST.has(url.pathname);
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
      { host: '127.0.0.1', port: Number(origin.port), method, path, headers: Object.fromEntries(merged), rejectUnauthorized: false, servername: 'example.invalid' },
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
}
