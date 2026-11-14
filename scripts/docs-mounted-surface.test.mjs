import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// P1.18.4 round 3: docs/sessions-browser-security.md went stale when P1.16 mounted the step-up/factor/recovery routes and was independently
// reviewed. This guard ties the document to what cmd/mandatary/main.go actually mounts, so the next change that mounts or unmounts a route
// group cannot leave the prose claiming the opposite, and the "notice relay required" condition cannot silently disappear from either side.

const main = readFileSync('cmd/mandatary/main.go', 'utf8');
const doc = readFileSync('docs/sessions-browser-security.md', 'utf8');
const header = doc.slice(0, doc.indexOf('## Components'));

test('every route group main.go mounts on the browser boundary is named by the document', () => {
  for (const group of ['auth.AccountPaths()', 'auth.SecurityPaths()', 'auth.AdminPathPrefix']) {
    assert.ok(main.includes(group), `main.go no longer mounts ${group}; update this guard and the document together`);
    assert.ok(header.includes(group.replace('auth.', '').replace('()', '')), `the document does not describe ${group}`);
  }
});

test('the document does not claim the step-up, factor or recovery routes are unmounted or the contribution unreviewed', () => {
  assert.equal(/are not mounted/.test(header), false, 'stale: the security routes are mounted');
  assert.equal(/not independently reviewed/.test(header), false, 'stale: P1.16 was independently reviewed');
  assert.equal(/remain slice 2/.test(header), false, 'stale: slice 2 (P1.16.4) is delivered');
});

test('the relay condition is stated on both sides: the code builds the Lifecycle only with a relay and the document says sign-in then does not exist', () => {
  assert.match(main, /if c\.NoticeRelay != ""/, 'main.go no longer gates Lifecycle (and the account routes) on the notice relay');
  assert.match(main, /if lifecycle != nil/, 'main.go no longer gates the account routes on the Lifecycle');
  assert.match(header, /notice relay is configured/);
  assert.match(header, /cannot sign in/);
  for (const name of ['MANDATARY_SMTP_RELAY', 'MANDATARY_SMTP_TLS', 'MANDATARY_SMTP_SENDER', 'MANDATARY_NOTICE_CONTACT', 'MANDATARY_PUBLIC_ORIGIN']) {
    assert.ok(header.includes(name), `the recovery instruction does not name ${name}`);
  }
});
