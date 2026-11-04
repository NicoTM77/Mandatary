import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { resolveResources } from './resource-profile.mjs';

const local = { GOMAXPROCS: '2', GOFLAGS: '-mod=readonly -p=1', GOMEMLIMIT: '768MiB', GOGC: '25', GOTOOLCHAIN: 'local' };
const allocation = { cpus: 8, memoryBytes: 16 * 1024 ** 3 };

test('default and incidental CI=true stay conservative, standard Go overrides cannot widen', () => {
  for (const env of [{}, { CI: 'true', GITHUB_ACTIONS: 'true' }, { GOMAXPROCS: '64', GOFLAGS: '-mod=mod -p=64', GOGC: 'off', GOMEMLIMIT: 'off', GOTOOLCHAIN: 'auto' }]) {
    assert.deepEqual(values(probe(env)), local);
  }
});

test('CI envelope follows available CPUs and lowers for small memory allocations', () => {
  const ci = { MANDATARY_BUILD_PROFILE: 'github-ci' };
  assert.deepEqual(resolveResources(ci, allocation), { ...local, GOMAXPROCS: '4', GOFLAGS: '-mod=readonly -p=2', GOMEMLIMIT: '2048MiB', GOGC: '100' });
  assert.deepEqual(resolveResources(ci, { ...allocation, cpus: 1 }), { ...local, GOMAXPROCS: '1', GOMEMLIMIT: '2048MiB', GOGC: '100' });
  assert.deepEqual(resolveResources(ci, { ...allocation, memoryBytes: 5 * 1024 ** 3 }), local);
});

test('unknown profiles and invalid or above-ceiling numeric settings fail closed before recipe', () => {
  for (const env of [
    { MANDATARY_BUILD_PROFILE: 'typo' },
    ...['0', '-1', '1.5', 'NaN', '1; echo unsafe', '999999999999999999999'].map(v => ({ MANDATARY_GO_PROCS: v })),
    { MANDATARY_GO_PROCS: '3' }, { MANDATARY_GO_PACKAGES: '2' },
    { MANDATARY_GO_MEMORY_MIB: '769' }, { MANDATARY_GO_GC: '26' },
    { MANDATARY_BUILD_PROFILE: 'github-ci', MANDATARY_GO_PROCS: '5' },
    { MANDATARY_BUILD_PROFILE: 'github-ci', MANDATARY_GO_PACKAGES: '3' },
    { MANDATARY_BUILD_PROFILE: 'github-ci', MANDATARY_GO_MEMORY_MIB: '2049' },
    { MANDATARY_BUILD_PROFILE: 'github-ci', MANDATARY_GO_GC: '101' },
  ]) {
    const result = probe(env);
    assert.notEqual(result.status, 0, JSON.stringify(env));
    assert.match(result.stderr, /BUILD_RESOURCE_ERROR/);
    assert.equal(result.stdout, '');
  }
});

test('explicit lower settings respect command-line over environment and recursive inheritance', () => {
  const env = { MANDATARY_GO_PROCS: '2', MANDATARY_GO_MEMORY_MIB: '700' };
  const args = ['MANDATARY_GO_PROCS=1', 'MANDATARY_GO_MEMORY_MIB=512', 'GOMAXPROCS=64', 'GOFLAGS=-mod=mod -p=99', 'GOTOOLCHAIN=auto'];
  assert.deepEqual(values(probe(env, args, true)), { ...local, GOMAXPROCS: '1', GOMEMLIMIT: '512MiB' });
});

const makefile = resolve('Makefile');
const keys = ['GOMAXPROCS', 'GOFLAGS', 'GOMEMLIMIT', 'GOGC', 'GOTOOLCHAIN'];
function probe(env = {}, args = [], recursive = false) {
  const dir = mkdtempSync(join(tmpdir(), 'mandatary-resources-'));
  const cleanEnv = { ...process.env };
  for (const key of ['MANDATARY_BUILD_PROFILE', 'MANDATARY_GO_PROCS', 'MANDATARY_GO_PACKAGES', 'MANDATARY_GO_MEMORY_MIB', 'MANDATARY_GO_GC', 'MAKEFLAGS', 'MAKELEVEL', 'MFLAGS']) delete cleanEnv[key];
  try {
    writeFileSync(join(dir, 'probe.mjs'), `console.log(JSON.stringify(Object.fromEntries(${JSON.stringify(keys)}.map(k => [k, process.env[k]]))));`);
    writeFileSync(join(dir, 'Makefile'), `include ${makefile}\n.PHONY: probe child\nprobe:\n\t${recursive ? '$(MAKE) --no-print-directory child' : 'node probe.mjs'}\nchild:\n\tnode probe.mjs\n`);
    return spawnSync('make', ['--no-print-directory', '-s', 'probe', ...args], {
      cwd: dir, encoding: 'utf8', env: { ...cleanEnv, ...env },
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
function values(result) {
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return JSON.parse(result.stdout.trim());
}

test('fresh-checkout recipes work without relying on untracked executable filesystem bits', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mandatary-resource-checkout-'));
  try {
    mkdirSync(join(dir, 'scripts'));
    for (const name of ['resource-shell.mjs', 'resource-profile.mjs']) writeFileSync(join(dir, 'scripts', name), readFileSync(join('scripts', name)), { mode: 0o644 });
    writeFileSync(join(dir, 'Makefile'), readFileSync('Makefile'));
    const result = spawnSync('make', ['--no-print-directory', '-s', 'resources'], { cwd: dir, encoding: 'utf8', env: process.env });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(JSON.parse(result.stdout).resolved.GOTOOLCHAIN, 'local');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('workflow opts in explicitly, separates jobs and caches every locked module', () => {
  const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');
  assert.match(workflow, /MANDATARY_BUILD_PROFILE: github-ci/);
  assert.match(workflow, /max-parallel: 2/);
  assert.doesNotMatch(workflow, /needs: baseline|cache: false/);
  for (const path of ['go.mod', 'go.sum', 'tools/go.mod', 'tools/go.sum', 'tools/sqlc/go.mod', 'tools/sqlc/go.sum']) {
    assert.ok(workflow.includes(`            ${path}\n`), `cache must include ${path}`);
  }
  assert.match(workflow, /make resources/);
  assert.match(workflow, /make install check negative-control/);
  assert.match(workflow, /make install build tools security/);
});

test('every scanner/generator build and nested scan inherits the same resolved resources', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mandatary-resource-recipes-'));
  try {
    for (const path of ['probes', 'bin/tools', 'tools/sqlc']) mkdirSync(join(dir, path), { recursive: true });
    const log = join(dir, 'commands.jsonl');
    const script = `#!/usr/bin/env node\nimport { appendFileSync } from 'node:fs';\nappendFileSync(${JSON.stringify(log)}, JSON.stringify({ command: process.argv[1].split('/').at(-1), args: process.argv.slice(2), cwd: process.cwd(), env: Object.fromEntries(${JSON.stringify(keys)}.map(k => [k, process.env[k]])) }) + '\\n');\n`;
    // Instrument only the command boundary; no compilation or verdict is simulated as acceptance.
    for (const path of ['probes/go', 'probes/npm', 'bin/tools/sqlc', 'bin/tools/govulncheck', 'bin/tools/gosec', 'bin/tools/golangci-lint']) writeFileSync(join(dir, path), script, { mode: 0o755 });
    const result = spawnSync('make', ['--no-print-directory', '-s', '-f', makefile, 'tools', 'generate', 'generate-check', 'security', 'MANDATARY_BUILD_PROFILE=github-ci', 'MANDATARY_GO_PROCS=1', 'MANDATARY_GO_PACKAGES=1', 'MANDATARY_GO_MEMORY_MIB=512', 'MANDATARY_GO_GC=20'], {
      cwd: dir, encoding: 'utf8', env: { ...process.env, MAKEFLAGS: '', PATH: `${join(dir, 'probes')}:${process.env.PATH}` },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const commands = readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(commands.length, 17, JSON.stringify(commands));
    for (const command of commands) {
      assert.deepEqual(command.env, { ...local, GOMAXPROCS: '1', GOMEMLIMIT: '512MiB', GOGC: '20' }, JSON.stringify(command));
      assert.ok(!command.args.some(arg => arg.startsWith('-p=')), 'recipe must not override shared package parallelism');
    }
    const builds = commands.filter(c => c.command === 'go' && c.args.includes('build'));
    assert.deepEqual(builds.map(c => c.args.at(-1)), ['golang.org/x/vuln/cmd/govulncheck', 'github.com/securego/gosec/v2/cmd/gosec', 'github.com/golangci/golangci-lint/v2/cmd/golangci-lint', 'github.com/sqlc-dev/sqlc/cmd/sqlc']);
    assert.ok(commands.some(c => c.command === 'govulncheck' && c.cwd === join(dir, 'tools/sqlc')));
    assert.ok(commands.some(c => c.command === 'sqlc' && c.args.includes('--no-remote')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('explicit CI profile reaches real make recipe processes and recursive make', () => {
  const env = { MANDATARY_BUILD_PROFILE: 'github-ci', MANDATARY_GO_PROCS: '1', MANDATARY_GO_PACKAGES: '1', MANDATARY_GO_MEMORY_MIB: '512', MANDATARY_GO_GC: '20' };
  for (const recursive of [false, true]) {
    const actual = values(probe(env, [], recursive));
    assert.equal(actual.GOGC, '20');
    assert.equal(actual.GOMAXPROCS, '1');
    assert.equal(actual.GOMEMLIMIT, '512MiB');
    assert.ok(Number(actual.GOMAXPROCS) >= 1 && Number(actual.GOMAXPROCS) <= 4);
    assert.match(actual.GOFLAGS, /^-mod=readonly -p=[12]$/);
    assert.equal(actual.GOTOOLCHAIN, 'local');
  }
});
