import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('bootstrap rejects unapproved toolchain before any download or write', () => {
  const result = spawnSync('bash', ['scripts/bootstrap.sh'], {
    encoding: 'utf8', env: { ...process.env, MANDATARY_GO_VERSION: '1.0.0' },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /UNAPPROVED_GO_VERSION/);
});
