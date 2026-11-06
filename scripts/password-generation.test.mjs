import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, cpSync, chmodSync, appendFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

test('frozen password generator rejects stale output, source and corpus without repair', () => {
  const cache = spawnSync('go', ['env', 'GOMODCACHE'], { encoding: 'utf8' });
  assert.equal(cache.status, 0, cache.stderr);
  const dir = mkdtempSync(join(tmpdir(), 'mandatary-nfc-generation-'));
  try {
    const root = join(dir, 'repo');
    mkdirSync(join(root, 'scripts'), { recursive: true });
    mkdirSync(join(root, 'internal/auth'), { recursive: true });
    cpSync(resolve('scripts/regenerate-password-nfc.py'), join(root, 'scripts/regenerate-password-nfc.py'));
    cpSync(resolve('internal/auth/nfc17'), join(root, 'internal/auth/nfc17'), { recursive: true });
    const module = join(cache.stdout.trim(), 'golang.org/x/text@v0.43.0');
    const source = join(dir, 'upstream/unicode/norm');
    mkdirSync(source, { recursive: true });
    for (const name of Object.keys(JSON.parse(readFileSync('internal/auth/nfc17/upstream-sha256.json', 'utf8')))) {
      cpSync(join(module, 'unicode/norm', name), join(source, name));
    }
    cpSync(join(module, 'LICENSE'), join(dir, 'upstream/LICENSE'));
    const gate = () => spawnSync('python3', ['scripts/regenerate-password-nfc.py', '--check', '--upstream', source], { cwd: root, encoding: 'utf8' });
    let result = gate();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const output = join(root, 'internal/auth/nfc17/repertoire_data.go');
    appendFileSync(output, '\n// stale negative fixture\n');
    result = gate();
    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /generated output differs/);
    assert.match(readFileSync(output, 'utf8'), /stale negative fixture/, 'check must not repair');
    cpSync(resolve('internal/auth/nfc17/repertoire_data.go'), output);
    chmodSync(join(source, 'composition.go'), 0o600);
    appendFileSync(join(source, 'composition.go'), '\n// changed source\n');
    result = gate();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /upstream input checksum/);
    cpSync(join(module, 'unicode/norm/composition.go'), join(source, 'composition.go'));
    appendFileSync(join(root, 'internal/auth/nfc17/LICENSE-UNICODE'), 'changed');
    result = gate();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unicode input checksum/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
