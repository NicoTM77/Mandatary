import assert from 'node:assert/strict';
import { URL } from 'node:url';

// The only browser content admitted by this test harness is our local synthetic
// TLS fixture. Host resolution to 127.0.0.1 is fixed at launch, not caller input.
export function fixtureOrigin(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'example.invalid');
  assert.notEqual(url.port, '');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.pathname, '/');
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
  return url;
}

export function allowsFixtureRequest(origin, value, method) {
  const url = new URL(value);
  if (url.origin !== origin.origin || url.username || url.password) return false;
  if (method === 'GET') return url.pathname === '/' && !url.search;
  return method === 'POST' && ['/begin-registration', '/finish-registration', '/begin-assertion', '/finish-assertion'].includes(url.pathname);
}
