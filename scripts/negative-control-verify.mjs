#!/usr/bin/env node
// Verifier for scripts/negative-control.sh (P1.13 owner observation O1).
//
// The negative control runs the ORDINARY full race gate (`go test -race ./...`)
// with an intentionally wrong security expectation injected, and the gate is
// healthy only if it fails for exactly that reason. This verifier consumes the
// structured `go test -json` evidence and accepts the run only when ALL of these
// hold; every other outcome is rejected, so an unrelated regression can never hide
// behind the intended failure (the old check only rejected build/setup/race text):
//
//   1. the process exited with status exactly 1 (not 0, not a signal, not a
//      usage/abnormal status);
//   2. the intended assertion was observed: the injected subtest failed in the
//      security package with the exact SECURITY_ROUTE_EXPOSURE message;
//   3. the set of failed tests, and the set of failed packages, equal exactly the
//      intended ones (an unrelated failure in ANY package, including inside the
//      security package or inside the same test, is rejected);
//   4. no build or setup failure, no race report, no panic/fatal error/timeout,
//      no test or package that started without a terminal result (abnormal
//      termination), and no unparseable stdout line.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const SECURITY_PACKAGE = 'github.com/NicoTM77/Mandatary/tests/security';
export const INTENDED_PARENT = 'TestUnavailableProductRoutes';
// t.Run("/", ...) inside TestUnavailableProductRoutes: Go joins parent and subtest
// name with "/", and the subtest name is the path "/" itself.
export const INTENDED_SUBTEST = 'TestUnavailableProductRoutes//';
export const INTENDED_MESSAGE = 'SECURITY_ROUTE_EXPOSURE: unavailable route returned 200';

const RACE = /WARNING: DATA RACE|race detected during execution of test/;
const ABNORMAL = /^(?:panic:|fatal error:|SIGQUIT:|signal: |unexpected fault address|runtime: |test timed out after)|panic: test timed out/m;
const BUILD_OR_SETUP = /\[build failed\]|\[setup failed\]|build failed|setup failed/;
const TERMINAL = new Set(['pass', 'fail', 'skip']);

function key(pkg, test) { return `${pkg}\u0000${test}`; }
function show(k) { return k.replace('\u0000', ' :: '); }

// evaluate returns {ok, reasons, summary}. stdout is the raw `go test -json` stdout,
// stderr the raw stderr, exitStatus the numeric process status.
export function evaluate({ stdout, stderr = '', exitStatus }) {
  const reasons = [];
  const summary = { packages: 0, tests: 0, failedPackages: [], failedTests: [], exitStatus };
  const reject = (why) => { if (reasons.length < 40 && !reasons.includes(why)) reasons.push(why); };

  if (exitStatus !== 1) {
    reject(`go test exited with status ${exitStatus}, expected exactly 1 (0 = nothing failed; other = abnormal termination or usage error)`);
  }
  if (RACE.test(stderr)) reject('race report on stderr');
  if (BUILD_OR_SETUP.test(stderr)) reject('build/setup failure text on stderr');
  if (ABNORMAL.test(stderr)) reject('panic/fatal error/signal/timeout text on stderr');

  const pkgStarted = new Set();
  const pkgResult = new Map();
  const testStarted = new Set();
  const testResult = new Map();
  const testOutput = new Map();
  const lines = stdout.split('\n');
  let events = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === '') continue;
    let ev;
    try { ev = JSON.parse(line); } catch { ev = null; }
    if (ev === null || typeof ev !== 'object' || Array.isArray(ev) || typeof ev.Action !== 'string') {
      reject(`stdout line ${i + 1} is not a go test -json event (abnormal output)`);
      continue;
    }
    events++;
    const pkg = ev.Package ?? ev.ImportPath ?? '';
    const out = typeof ev.Output === 'string' ? ev.Output : '';
    if (ev.Action === 'build-output' || ev.Action === 'build-fail') {
      reject(`build failure event (${ev.Action}) for ${pkg || '(unknown)'}`);
      continue;
    }
    if (out !== '') {
      if (RACE.test(out)) reject(`race report in ${pkg}${ev.Test ? ' :: ' + ev.Test : ''}`);
      if (ABNORMAL.test(out)) reject(`panic/fatal error/signal/timeout output in ${pkg}${ev.Test ? ' :: ' + ev.Test : ''}`);
      if (!ev.Test && BUILD_OR_SETUP.test(out)) reject(`build/setup failure reported for ${pkg}`);
    }
    if (pkg === '') continue;
    if (ev.Action === 'start' && !ev.Test) { pkgStarted.add(pkg); continue; }
    if (ev.Test) {
      const k = key(pkg, ev.Test);
      if (ev.Action === 'run') testStarted.add(k);
      if (ev.Action === 'output') testOutput.set(k, (testOutput.get(k) ?? '') + out);
      if (TERMINAL.has(ev.Action)) testResult.set(k, ev.Action);
    } else if (TERMINAL.has(ev.Action)) {
      pkgResult.set(pkg, ev.Action);
    }
  }
  if (events === 0) reject('no go test -json events were produced');

  summary.packages = new Set([...pkgStarted, ...pkgResult.keys()]).size;
  summary.tests = testStarted.size;

  for (const k of testStarted) {
    if (!testResult.has(k)) reject(`test ${show(k)} started but never finished (abnormal termination)`);
  }
  for (const pkg of pkgStarted) {
    if (!pkgResult.has(pkg)) reject(`package ${pkg} started but never finished (abnormal termination)`);
  }

  const failedPackages = [...pkgResult].filter(([, r]) => r === 'fail').map(([p]) => p).sort();
  const failedTests = [...testResult].filter(([, r]) => r === 'fail').map(([k]) => k).sort();
  summary.failedPackages = failedPackages;
  summary.failedTests = failedTests.map(show);

  const intendedTests = [key(SECURITY_PACKAGE, INTENDED_PARENT), key(SECURITY_PACKAGE, INTENDED_SUBTEST)].sort();
  for (const p of failedPackages) {
    if (p !== SECURITY_PACKAGE) reject(`unrelated package failure: ${p}`);
  }
  for (const k of failedTests) {
    if (!intendedTests.includes(k)) reject(`unrelated test failure: ${show(k)}`);
  }
  const subtestKey = key(SECURITY_PACKAGE, INTENDED_SUBTEST);
  if (testResult.get(subtestKey) !== 'fail') {
    reject(`intended failure missing: ${INTENDED_SUBTEST} in ${SECURITY_PACKAGE} did not fail`);
  } else if (!(testOutput.get(subtestKey) ?? '').includes(INTENDED_MESSAGE)) {
    reject(`intended failure lacks the assertion message "${INTENDED_MESSAGE}"`);
  }
  if (testResult.get(key(SECURITY_PACKAGE, INTENDED_PARENT)) !== 'fail') {
    reject(`intended failure missing: ${INTENDED_PARENT} did not fail`);
  }
  if (pkgResult.get(SECURITY_PACKAGE) !== 'fail') {
    reject(`intended failure missing: package ${SECURITY_PACKAGE} did not fail`);
  }

  // Failing output of every non-passing test, for the CI log.
  summary.failureOutput = failedTests.map((k) => `--- ${show(k)}\n${(testOutput.get(k) ?? '').trimEnd()}`);
  return { ok: reasons.length === 0, reasons, summary };
}

function main(argv) {
  if (argv.length !== 3 || !/^\d+$/.test(argv[2])) {
    process.stderr.write('usage: negative-control-verify.mjs <go-test-json-stdout> <stderr> <exit-status>\n');
    return 2;
  }
  const [stdoutPath, stderrPath, status] = argv;
  let result;
  try {
    result = evaluate({ stdout: readFileSync(stdoutPath, 'utf8'), stderr: readFileSync(stderrPath, 'utf8'), exitStatus: Number(status) });
  } catch (err) {
    process.stderr.write(`Negative control evidence could not be read: ${err.code ?? 'error'}\n`);
    return 1;
  }
  const { summary } = result;
  process.stdout.write(`negative control: ${summary.packages} packages, ${summary.tests} tests observed; go test exit status ${summary.exitStatus}\n`);
  process.stdout.write(`failed packages: ${summary.failedPackages.join(', ') || '(none)'}\n`);
  process.stdout.write(`failed tests: ${summary.failedTests.join(', ') || '(none)'}\n`);
  for (const text of summary.failureOutput ?? []) process.stdout.write(`${text}\n`);
  if (!result.ok) {
    process.stderr.write('Negative control REJECTED:\n');
    for (const r of result.reasons) process.stderr.write(`  - ${r}\n`);
    return 1;
  }
  process.stdout.write('Negative control observed: ordinary race gate rejected exactly the exposed-route fixture (exit 1); no unrelated failure, build/setup failure, race report or abnormal termination.\n');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
