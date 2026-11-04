import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, appendFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const makefile = resolve('Makefile');
const sqlc = resolve('bin/tools/sqlc');

test('generation gate rejects stale, missing and invalid outputs without rewriting files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mandatary-generation-'));
  try {
    writeFileSync(join(dir, 'sqlc.yaml'), `version: "2"
sql:
  - engine: sqlite
    schema: schema.sql
    queries: query.sql
    gen:
      go:
        package: fixture
        out: generated
`);
    writeFileSync(join(dir, 'schema.sql'), 'CREATE TABLE items(id TEXT NOT NULL PRIMARY KEY);\n');
    writeFileSync(join(dir, 'query.sql'), '-- name: GetItem :one\nSELECT * FROM items WHERE id=?;\n');
    const run = (command, args) => spawnSync(command, args, { cwd: dir, encoding: 'utf8' });
    const gate = () => run('make', ['--no-print-directory', '-f', makefile, 'generate-check', `SQLC=${sqlc}`]);
    const generated = run(sqlc, ['generate', '--no-remote']);
    assert.equal(generated.status, 0, generated.stdout + generated.stderr);
    let result = gate();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const model = join(dir, 'generated/models.go');
    appendFileSync(model, '\n// deliberately stale negative fixture\n');
    result = gate();
    assert.notEqual(result.status, 0, 'stale generated model must fail');
    assert.match(result.stdout + result.stderr, /stale negative fixture/);
    assert.match(readFileSync(model, 'utf8'), /stale negative fixture/, 'check must not repair stale input');
    rmSync(model);
    result = gate();
    assert.notEqual(result.status, 0, 'missing generated model must fail');
    assert.equal(run(sqlc, ['generate', '--no-remote']).status, 0);
    writeFileSync(join(dir, 'query.sql'), '-- name: Invalid :one\nSELECT missing FROM items;\n');
    result = gate();
    assert.notEqual(result.status, 0, 'invalid query must fail closed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
