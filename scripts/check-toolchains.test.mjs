import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('accepts the installed approved Go/Node/npm tuple', () => {
  const result = spawnSync('bash', ['scripts/check-toolchains.sh'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('checks the actual PATH toolchain instead of ambient auto-download selection', () => {
  const result = spawnSync('bash', ['scripts/check-toolchains.sh'], {
    encoding: 'utf8', env: { ...process.env, GOTOOLCHAIN: 'invalid' },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('refuses an unapproved requested Go version before building', () => {
  const result = spawnSync('bash', ['scripts/check-toolchains.sh'], {
    encoding: 'utf8', env: { ...process.env, MANDATARY_GO_VERSION: '1.0.0' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /UNAPPROVED_GO_VERSION/);
});
