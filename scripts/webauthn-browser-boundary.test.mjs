import assert from 'node:assert/strict';
import test from 'node:test';
import { fixtureOrigin, allowsFixtureRequest } from '../web/tests/webauthn-boundary.mjs';

test('browser fixture accepts only its explicit synthetic HTTPS loopback mapping', () => {
  assert.equal(fixtureOrigin('https://example.invalid:43123').origin, 'https://example.invalid:43123');
  for (const value of ['https://example.com:43123', 'http://example.invalid:43123', 'https://example.invalid', 'https://user@example.invalid:43123', 'https://example.invalid:43123/other', 'https://example.invalid:43123/?x=1', 'https://example.invalid:43123/#fragment']) {
    assert.throws(() => fixtureOrigin(value));
  }
});

test('browser egress permits only exact fixture origin and known routes/methods', () => {
  const origin = fixtureOrigin('https://example.invalid:43123');
  const allowed = (url, method = 'GET') => allowsFixtureRequest(origin, url, method);
  assert.equal(allowed(origin.href), true);
  for (const path of ['/begin-registration?resident=true', '/finish-registration?id=synthetic', '/begin-assertion', '/finish-assertion?id=synthetic']) {
    assert.equal(allowed(new URL(path, origin).href, 'POST'), true);
    assert.equal(allowed(new URL(path, origin).href), false);
  }
  for (const url of ['https://example.com/', 'https://example.invalid:43124/', 'http://example.invalid:43123/', 'https://sub.example.invalid:43123/', 'https://example.invalid:43123/external', 'https://example.invalid:43123/redirect', 'file:///etc/passwd', 'data:text/html,external']) {
    assert.equal(allowed(url), false);
  }
  assert.equal(allowed(origin.href, 'POST'), false);
});
