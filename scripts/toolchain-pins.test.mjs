import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// GO-2026-6859 (net/http) is fixed in Go 1.27.4 and 1.26.11. These tests keep
// every pin surface coherent and refuse the vulnerable patch releases, so a
// stale pin cannot silently return.
const PRIMARY = '1.27.4';
const COMPAT = '1.26.11';
const VULNERABLE = ['1.27.3', '1.26.10'];
const read = (path) => readFileSync(path, 'utf8');

for (const version of VULNERABLE) {
  for (const script of ['scripts/check-toolchains.sh', 'scripts/bootstrap.sh']) {
    test(`${script} refuses vulnerable Go ${version} before any download or write`, () => {
      const result = spawnSync('bash', [script], {
        encoding: 'utf8', env: { ...process.env, MANDATARY_GO_VERSION: version },
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /UNAPPROVED_GO_VERSION/);
    });
  }
}

test('the default requested Go version is the patched primary', () => {
  for (const script of ['scripts/check-toolchains.sh', 'scripts/bootstrap.sh']) {
    assert.match(read(script), new RegExp(`:-${PRIMARY.replaceAll('.', '\\.')}\\}`), script);
  }
});

test('go.mod files pin the patched primary toolchain and keep the 1.26.0 language floor', () => {
  for (const file of ['go.mod', 'tools/sqlc/go.mod']) {
    const text = read(file);
    assert.match(text, new RegExp(`^toolchain go${PRIMARY.replaceAll('.', '\\.')}$`, 'm'), file);
    assert.match(text, /^go 1\.26\.0$/m, file);
  }
});

test('official checksums exist for every patched archive and none for vulnerable Go', () => {
  const sums = read('scripts/toolchains.sha256').split('\n').filter((l) => /^[0-9a-f]{64} /.test(l));
  const names = sums.map((l) => l.split(/\s+/)[1]);
  for (const version of [PRIMARY, COMPAT]) {
    for (const platform of ['linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64']) {
      assert.ok(names.includes(`go${version}.${platform}.tar.gz`), `missing go${version}.${platform}`);
    }
  }
  for (const version of VULNERABLE) {
    assert.equal(names.filter((n) => n.startsWith(`go${version}.`)).length, 0, `vulnerable go${version} still pinned`);
  }
  assert.equal(new Set(names).size, names.length, 'duplicate checksum entries');
});

test('CI pins only patched Go versions and has no vulnerable label', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, new RegExp(`go: \\['${PRIMARY.replaceAll('.', '\\.')}', '${COMPAT.replaceAll('.', '\\.')}'\\]`));
  assert.equal([...ci.matchAll(new RegExp(`go-version: '${PRIMARY.replaceAll('.', '\\.')}'`, 'g'))].length, 2);
  for (const version of VULNERABLE) assert.ok(!ci.includes(version), `CI still references ${version}`);
});

test('current development documentation names the patched releases and vulnerable ones only beside the advisory', () => {
  for (const file of ['development.md', 'docs/sqlc-dependencies.md', 'support-and-deployment-matrix.md', 'technical-decisions.md']) {
    const text = read(file);
    assert.ok(text.includes(PRIMARY) && text.includes(COMPAT), `${file} must name ${PRIMARY} and ${COMPAT}`);
    for (const line of text.split('\n')) {
      for (const version of VULNERABLE) {
        if (new RegExp(`(?<![0-9.])${version.replaceAll('.', '\\.')}(?![0-9])`).test(line)) {
          assert.ok(line.includes('GO-2026-6859'), `${file}: ${version} outside advisory context: ${line.slice(0, 80)}`);
        }
      }
    }
  }
});
