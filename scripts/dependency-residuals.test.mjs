import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// P1.18.4 dependency residuals. These pin the narrow remediation of the advisories that earlier cards carried as "disclosed, deadline 2026-11-29":
//   * GHSA-g3hv-75wg-m249 (minimatch 7.0.0 - 11.0.0, a dev-only ESLint dependency): eslint 10.14.0 -> 10.15.0, the same pinned 10.x family, which depends
//     on minimatch ^11.0.5 (resolved 11.0.8). No override, no `audit fix --force`, no other direct tool moved.
//   * GO-2026-6866 and GO-2026-6860 (golang.org/x/net/html, fixed in v0.62.0), GO-2026-5932 (golang.org/x/crypto/openpgp, fixed after v0.58.0): the app
//     imports only x/net/publicsuffix and x/crypto/argon2, so none was ever reachable, but the modules were required at affected versions. They move to
//     the fixed releases (x/net v0.62.0, x/crypto v0.59.0, and x/sys v0.50.0 that x/crypto requires).
//   * GO-2026-6094 (github.com/google/cel-go, an indirect module of the pinned sqlc generator, fixed in v0.30.0): resolved in the generator's own module
//     with `go mod tidy` and no other change; sqlc v1.31.1 is unchanged and `sqlc diff` shows no generated-output change.
// The test refuses a lockfile or module file that falls back below those versions. It does not claim "zero vulnerabilities": the scanners still run
// in `make security`/CI and the Moderate-or-higher npm gate is `npm audit --audit-level=high` plus this explicit range check.

const read = (path) => readFileSync(path, 'utf8');
const parse = (version) => version.replace(/^v/, '').split('-')[0].split('.').map(Number);
const compare = (a, b) => {
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i += 1) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
};
const goRequires = (file, module) => new RegExp(`^\\s*${module.replaceAll('.', '\\.')} (v[0-9][^\\s]*)`, 'm').exec(read(file))?.[1];

test('ESLint is exactly the patched 10.x release and no locked minimatch is inside the advisory range', () => {
  const pkg = JSON.parse(read('web/package.json'));
  assert.equal(pkg.devDependencies.eslint, '10.15.0');
  assert.equal(pkg.overrides, undefined, 'no override hides the advisory');
  const lock = JSON.parse(read('web/package-lock.json'));
  assert.equal(lock.packages['node_modules/eslint'].version, '10.15.0');
  const versions = Object.entries(lock.packages).filter(([key]) => key.endsWith('node_modules/minimatch')).map(([, value]) => value.version);
  assert.ok(versions.length > 0, 'minimatch is locked');
  for (const version of versions) {
    const vulnerable = compare(version, '7.0.0') >= 0 && compare(version, '11.0.0') <= 0;
    assert.equal(vulnerable, false, `locked minimatch ${version} is inside the GHSA-g3hv-75wg-m249 range 7.0.0 - 11.0.0`);
  }
});

test('the application module requires the fixed x/net, x/crypto and x/sys', () => {
  assert.ok(compare(goRequires('go.mod', 'golang.org/x/net'), 'v0.62.0') >= 0, 'x/net >= v0.62.0 (GO-2026-6866, GO-2026-6860)');
  assert.ok(compare(goRequires('go.mod', 'golang.org/x/crypto'), 'v0.59.0') >= 0, 'x/crypto >= v0.59.0 (GO-2026-5932)');
  assert.ok(compare(goRequires('go.mod', 'golang.org/x/sys'), 'v0.50.0') >= 0, 'x/sys >= v0.50.0 (required by x/crypto v0.59.0)');
});

test('the pinned sqlc generator module resolves the fixed cel-go and keeps the pinned sqlc and Go family', () => {
  assert.ok(compare(goRequires('tools/sqlc/go.mod', 'github.com/google/cel-go'), 'v0.30.0') >= 0, 'cel-go >= v0.30.0 (GO-2026-6094)');
  assert.match(read('tools/sqlc/go.mod'), /^toolchain go1\.27\.4$/m);
  assert.match(read('tools/sqlc/go.mod'), /^go 1\.26\.0$/m);
  assert.match(read('go.mod'), /^toolchain go1\.27\.4$/m);
});

test('no tracked Go file imports the packages the advisories are in (x/net/html, x/crypto/openpgp)', () => {
  // Reachability stays an explicit, checkable fact rather than an assumption: if either package is ever imported, the advisory must be reviewed first.
  const listed = spawnSync('git', ['ls-files', '*.go'], { encoding: 'utf8' });
  assert.equal(listed.status, 0);
  const files = listed.stdout.split('\n').filter(Boolean);
  assert.ok(files.length > 100, 'the repository Go files were listed');
  const banned = /"golang\.org\/x\/(net\/html(\/[a-z]+)?|crypto\/openpgp(\/[a-z]+)?)"/;
  const offenders = files.filter((file) => file !== 'scripts/dependency-residuals.test.mjs' && banned.test(read(file)));
  assert.deepEqual(offenders, []);
});
