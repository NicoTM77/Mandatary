import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// P1.18.4 AUTH-CI-BUDGET (P1.09 #190 L8, P1.10 #192): the two matrix Baseline jobs run the complete race suite and then the browser suites in ONE job
// per pinned Go version, so their wall-clock budget has to cover both with headroom. The budget was raised from 30 to 45 minutes for those two jobs
// only (Baseline Go 1.27.4 and 1.26.11). Everything else is deliberately unchanged and pinned here, so a later edit cannot quietly loosen it:
// the other jobs' budgets, the check names, the matrix versions, the parallelism/memory limits, the immutable action pins and the security
// aggregation that requires every Baseline and negative-control job. Go's own per-test timeout is NOT touched, and no test is skipped or split.
// This asserts the workflow text; it does not start CI.

const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');

/** The text of one top-level job: from `  <id>:` up to the next top-level job or comment block that precedes it. */
function job(id) {
  const lines = workflow.split('\n');
  const start = lines.findIndex((line) => line === `  ${id}:`);
  assert.notEqual(start, -1, `job ${id} exists`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {2}[a-z][a-z0-9-]*:$/.test(lines[i]) || /^ {2}#/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

const minutes = (text) => Number(/^ {4}timeout-minutes: (\d+)$/m.exec(text)?.[1]);

test('the two Baseline matrix jobs have a 45 minute wall-clock budget', () => {
  const baseline = job('baseline');
  assert.equal(minutes(baseline), 45);
  assert.match(baseline, /name: Baseline \(Go \$\{\{ matrix\.go \}\}\)/);
  assert.match(baseline, /go: \['1\.27\.4', '1\.26\.11'\]/, 'both pinned Go versions are in the matrix this budget covers');
});

test('no other job budget was widened: negative control and security stay at 30, arm64 storage at 45', () => {
  assert.equal(minutes(job('negative-control')), 30);
  assert.equal(minutes(job('security')), 30);
  assert.equal(minutes(job('storage-arm64')), 45);
});

test('the budget increase did not touch parallelism, memory, check names, action pins or the Go per-test timeout', () => {
  const baseline = job('baseline');
  assert.match(baseline, /max-parallel: 2/);
  assert.match(baseline, /GOMAXPROCS: '4'/);
  assert.match(baseline, /GOMEMLIMIT: 12GiB/);
  assert.match(baseline, /GOFLAGS: '-mod=readonly -p=4'/);
  assert.match(baseline, /make install check GOFLAGS="-mod=readonly -p=4" GOMAXPROCS=4 GOMEMLIMIT=12GiB GOGC=100/);
  assert.match(baseline, /make browser-test /);
  for (const [, ref] of workflow.matchAll(/uses: (\S+@\S+)/g)) {
    assert.match(ref, /@[0-9a-f]{40}$/, `${ref} is an immutable commit pin`);
  }
  assert.match(workflow, /name: Negative control \(Go \$\{\{ matrix\.go \}\}\)/);
  assert.match(workflow, /name: Storage \(linux\/arm64\)/);
  assert.match(workflow, /name: Security\b/);
  assert.match(workflow, /go test -race -timeout=30m -count=1 -v \.\/\.\.\./, 'the arm64 per-test timeout is unchanged');
});

test('the security job still requires every Baseline and negative-control job to have passed', () => {
  const security = workflow.slice(workflow.indexOf('  security:'));
  assert.match(security, /needs:/);
  assert.match(security, /Require every Baseline and negative-control job to have passed/);
});
