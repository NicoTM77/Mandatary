import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isolateNodeModules } from './isolate-node-modules.mjs';

test('creates an idempotent Go module boundary around npm dependencies', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mandatary-isolation-'));
  try {
    await isolateNodeModules(dir);
    assert.equal(await readFile(join(dir, 'go.mod'), 'utf8'), 'module mandatary.invalid/npm-dependencies\n');
    await isolateNodeModules(dir);
    assert.equal(await readFile(join(dir, 'go.mod'), 'utf8'), 'module mandatary.invalid/npm-dependencies\n');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
