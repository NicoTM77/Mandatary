// Regression coverage for scripts/negative-control.sh and its verifier (P1.13
// owner observation O1). Two layers:
//
//  * end-to-end: the real shell script runs the real `go test -race -json` against
//    a small Go module that reproduces the gate's structure (a security package
//    carrying the intended exposed-route assertion plus other packages), with one
//    injected condition per scenario;
//  * unit: the verifier is fed synthetic go test -json streams for conditions that
//    cannot be produced quickly or portably (timeouts, odd exit statuses, stream
//    corruption).
//
// The gate must accept ONLY the intended failure, alone.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  evaluate, INTENDED_MESSAGE, INTENDED_PARENT, INTENDED_SUBTEST, SECURITY_PACKAGE,
} from './negative-control-verify.mjs';

const here = dirname(fileURLToPath(import.meta.url));
// NEGATIVE_CONTROL_SCRIPT lets the RED run point the same scenarios at the retired
// script; it is a test-only selector and is never read by the gate itself.
const script = resolve(process.env.NEGATIVE_CONTROL_SCRIPT ?? join(here, 'negative-control.sh'));

const MODULE = 'github.com/NicoTM77/Mandatary';

const securityTest = `package security_test

import (
	"os"
	"syscall"
	"testing"
)

func scenario() string { return os.Getenv("NC_SCENARIO") }

// Mirrors tests/security/surface_test.go: the injected fixture adds the public
// index "/" to the routes that must be absent, so the subtest "/" fails.
func TestUnavailableProductRoutes(t *testing.T) {
	paths := []string{"/api/v1/containers", "/mcp"}
	if os.Getenv("MANDATARY_NEGATIVE_FIXTURE") == "exposed-route" && scenario() != "clean" {
		paths = append(paths, "/")
	}
	if scenario() == "security-subtest" {
		paths = append(paths, "/leaky") // an unrelated failure INSIDE the intended test
	}
	if scenario() == "intended-wrong-message" {
		t.Run("/", func(t *testing.T) { t.Fatal("some other assertion") })
		return
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			code := 404
			if p == "/" || p == "/leaky" {
				code = 200
			}
			if code != 404 {
				t.Fatalf("SECURITY_ROUTE_EXPOSURE: unavailable route returned %d", code)
			}
		})
	}
}

func TestSecurityOther(t *testing.T) {
	switch scenario() {
	case "security-unrelated":
		t.Fatal("unrelated failure in the security package")
	case "security-kill":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	case "security-panic":
		panic("boom in the security package")
	}
}
`;

const otherTest = `package other

import (
	"os"
	"syscall"
	"testing"
)

func TestOther(t *testing.T) {
	switch os.Getenv("NC_SCENARIO") {
	case "other-unrelated":
		t.Fatal("unrelated failure in another package")
	case "other-exit":
		os.Exit(3)
	case "other-kill":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	case "other-panic":
		panic("boom in another package")
	case "other-race":
		x := 0
		done := make(chan bool)
		go func() { x++; done <- true }()
		x++
		<-done
	}
}
`;

function makeFixtureModule(scenario) {
  const root = mkdtempSync(join(process.env.TMPDIR || tmpdir(), 'negctl-'));
  const put = (rel, body) => {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  };
  put('go.mod', `module ${MODULE}\n\ngo 1.26.0\n`);
  put('tests/security/surface_test.go', securityTest);
  put('other/other_test.go', otherTest);
  if (scenario === 'build-failure') {
    put('broken/broken.go', 'package broken\n\nvar X int = "not an int"\n');
    put('broken/broken_test.go', 'package broken\n\nimport "testing"\n\nfunc TestBroken(t *testing.T) {}\n');
  }
  if (scenario === 'setup-failure') {
    put('setup/setup_test.go', `package setup\n\nimport (\n\t"testing"\n\n\t_ "${MODULE}/doesnotexist"\n)\n\nfunc TestSetup(t *testing.T) {}\n`);
  }
  return root;
}

function runScript(scenario) {
  const root = makeFixtureModule(scenario);
  try {
    const env = { ...process.env, NC_SCENARIO: scenario };
    delete env.MANDATARY_NEGATIVE_FIXTURE; // the script, not the caller, injects it
    const r = spawnSync('bash', [script], { cwd: root, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    return { status: r.status, signal: r.signal, out: r.stdout ?? '', err: r.stderr ?? '' };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const E2E_TIMEOUT = 600_000;

test('e2e: the intended exposed-route failure alone is accepted', { timeout: E2E_TIMEOUT }, () => {
  const r = runScript('intended-only');
  assert.equal(r.status, 0, `${r.out}\n${r.err}`);
  assert.match(r.out, /Negative control observed/);
  if (process.env.NEGATIVE_CONTROL_SCRIPT === undefined) {
    assert.ok(r.out.includes(`failed tests: ${SECURITY_PACKAGE} :: ${INTENDED_PARENT}`), r.out);
    assert.ok(r.out.includes(`${SECURITY_PACKAGE} :: ${INTENDED_SUBTEST}`), r.out);
  }
});

for (const [name, scenario, expected] of [
  ['an unrelated failure in the security package (alone with the intended one)', 'security-unrelated', /unrelated test failure: .*TestSecurityOther/],
  ['an unrelated failure inside the intended test itself', 'security-subtest', /unrelated test failure: .*leaky/],
  ['an unrelated failure in another package', 'other-unrelated', /unrelated (test|package) failure: .*other/],
  ['a clean run without the intended failure', 'clean', /intended failure missing/],
  ['a different assertion failing at the intended subtest', 'intended-wrong-message', /lacks the assertion message/],
  ['a build failure', 'build-failure', /build|unrelated package failure: .*broken/],
  ['a setup failure', 'setup-failure', /setup|unrelated package failure: .*setup/],
  ['a data race report', 'other-race', /race report|unrelated/],
  ['abnormal termination by os.Exit in another package', 'other-exit', /never finished|unrelated package failure: .*other/],
  ['abnormal termination by SIGKILL in another package', 'other-kill', /never finished|unrelated package failure: .*other/],
  ['a panic in another package', 'other-panic', /panic|unrelated/],
  ['abnormal termination by SIGKILL in the security package after the intended failure', 'security-kill', /never finished|unrelated/],
  ['a panic in the security package after the intended failure', 'security-panic', /panic|unrelated/],
]) {
  test(`e2e: ${name} is rejected`, { timeout: E2E_TIMEOUT }, () => {
    const r = runScript(scenario);
    assert.notEqual(r.status, 0, `scenario ${scenario} was accepted\n${r.out}\n${r.err}`);
    assert.doesNotMatch(r.out, /Negative control observed/);
    assert.match(r.err, /REJECTED|failed for an unrelated reason|must fail|exit/, r.err);
    if (process.env.NEGATIVE_CONTROL_SCRIPT === undefined) assert.match(r.err, expected, r.err);
  });
}

// ---- unit layer: synthetic go test -json streams -------------------------------------

const ev = (e) => JSON.stringify({ Time: '2026-11-12T00:00:00Z', ...e });
const OTHER = `${MODULE}/internal/other`;
function stream(...events) { return `${events.map(ev).join('\n')}\n`; }
const run = (pkg, test) => ev({ Action: 'run', Package: pkg, Test: test });
const out = (pkg, test, text) => (test ? ev({ Action: 'output', Package: pkg, Test: test, Output: text }) : ev({ Action: 'output', Package: pkg, Output: text }));
const end = (action, pkg, test) => (test ? ev({ Action: action, Package: pkg, Test: test }) : ev({ Action: action, Package: pkg }));
const start = (pkg) => ev({ Action: 'start', Package: pkg });

// intended(): the exact events of the intended failure, alone.
function intended() {
  return [
    start(SECURITY_PACKAGE),
    run(SECURITY_PACKAGE, INTENDED_PARENT),
    run(SECURITY_PACKAGE, INTENDED_SUBTEST),
    out(SECURITY_PACKAGE, INTENDED_SUBTEST, `    surface_test.go:25: ${INTENDED_MESSAGE}\n`),
    end('fail', SECURITY_PACKAGE, INTENDED_SUBTEST),
    end('fail', SECURITY_PACKAGE, INTENDED_PARENT),
    out(SECURITY_PACKAGE, '', `FAIL\t${SECURITY_PACKAGE}\t0.1s\n`),
    end('fail', SECURITY_PACKAGE),
    start(OTHER),
    run(OTHER, 'TestFine'),
    end('pass', OTHER, 'TestFine'),
    end('pass', OTHER),
  ];
}
const join_ = (events) => `${events.join('\n')}\n`;
const verdict = (events, exitStatus = 1, stderr = '') => evaluate({ stdout: join_(events), stderr, exitStatus });

test('unit: the intended failure alone is accepted, with its evidence summarized', () => {
  const r = verdict(intended());
  assert.deepEqual(r.reasons, []);
  assert.equal(r.ok, true);
  assert.deepEqual(r.summary.failedPackages, [SECURITY_PACKAGE]);
});

test('unit: unrelated failures are rejected alone and together with the intended one', () => {
  const unrelatedTest = [run(OTHER, 'TestBad'), out(OTHER, 'TestBad', 'x\n'), end('fail', OTHER, 'TestBad'), end('fail', OTHER)];
  const unrelatedInSecurity = [run(SECURITY_PACKAGE, 'TestOtherSecurity'), end('fail', SECURITY_PACKAGE, 'TestOtherSecurity')];
  // alone: no intended failure at all
  const alone = [start(OTHER), ...unrelatedTest];
  assert.equal(verdict(alone).ok, false);
  // together, in another package
  assert.equal(verdict([...intended(), ...unrelatedTest]).ok, false);
  // together, inside the security package
  assert.equal(verdict([...intended(), ...unrelatedInSecurity]).ok, false);
  // a sibling subtest of the intended test failing too
  assert.equal(verdict([...intended(), run(SECURITY_PACKAGE, `${INTENDED_PARENT}//mcp`), end('fail', SECURITY_PACKAGE, `${INTENDED_PARENT}//mcp`)]).ok, false);
  // the same test name failing in a different package is not the intended failure
  const sameNameElsewhere = [start(OTHER), run(OTHER, INTENDED_SUBTEST), out(OTHER, INTENDED_SUBTEST, `${INTENDED_MESSAGE}\n`), end('fail', OTHER, INTENDED_SUBTEST), end('fail', OTHER)];
  const r = verdict(sameNameElsewhere);
  assert.equal(r.ok, false);
  assert.ok(r.reasons.some((x) => x.includes('intended failure missing')));
});

test('unit: a clean run without the intended failure is rejected (exit 0 and exit 1 variants)', () => {
  const clean = [start(SECURITY_PACKAGE), run(SECURITY_PACKAGE, INTENDED_PARENT), end('pass', SECURITY_PACKAGE, INTENDED_PARENT), end('pass', SECURITY_PACKAGE)];
  assert.equal(verdict(clean, 0).ok, false);
  assert.equal(verdict(clean, 1).ok, false);
  assert.equal(verdict([], 1).ok, false);
  assert.equal(verdict([], 0).ok, false);
});

test('unit: exit statuses other than exactly 1 are rejected even with perfect evidence', () => {
  for (const status of [0, 2, 3, 124, 130, 137, 143]) {
    const r = verdict(intended(), status);
    assert.equal(r.ok, false, `status ${status}`);
    assert.ok(r.reasons.some((x) => x.includes('expected exactly 1')));
  }
});

test('unit: build, setup, race, panic, timeout and fatal conditions are rejected', () => {
  const cases = {
    'build-fail event': [ev({ Action: 'build-fail', ImportPath: `${OTHER} [${OTHER}.test]` })],
    'build-output event': [ev({ Action: 'build-output', ImportPath: OTHER, Output: 'x.go:1:1: syntax error\n' })],
    'package build failed': [out(OTHER, '', `FAIL\t${OTHER} [build failed]\n`)],
    'package setup failed': [out(OTHER, '', `FAIL\t${OTHER} [setup failed]\n`)],
    'data race': [run(OTHER, 'TestRace'), out(OTHER, 'TestRace', '==================\nWARNING: DATA RACE\n'), end('pass', OTHER, 'TestRace')],
    'race detected': [run(OTHER, 'TestRace'), out(OTHER, 'TestRace', '    testing.go:1: race detected during execution of test\n'), end('pass', OTHER, 'TestRace')],
    panic: [run(OTHER, 'TestPanic'), out(OTHER, 'TestPanic', 'panic: boom\n'), end('pass', OTHER, 'TestPanic')],
    'test timeout': [out(OTHER, 'TestSlow', 'panic: test timed out after 20m0s\n')],
    'fatal error': [out(OTHER, '', 'fatal error: all goroutines are asleep - deadlock!\n')],
    'killed by a signal': [out(OTHER, 'TestKilled', 'signal: killed\n')],
  };
  for (const [name, extra] of Object.entries(cases)) {
    const r = verdict([...intended(), ...extra]);
    assert.equal(r.ok, false, name);
  }
  for (const stderr of ['# pkg\nsetup failed\n', 'go: build failed\n', 'WARNING: DATA RACE\n', 'panic: oops\n', 'signal: killed\n']) {
    assert.equal(verdict(intended(), 1, stderr).ok, false, stderr);
  }
});

test('unit: abnormal termination (started without a terminal result) and corrupt streams are rejected', () => {
  assert.equal(verdict([...intended(), start(`${MODULE}/internal/gone`)]).ok, false); // package never finished
  assert.equal(verdict([...intended(), run(OTHER, 'TestHung')]).ok, false); // test never finished
  assert.equal(verdict([...intended().slice(0, 4)]).ok, false); // truncated stream
  assert.equal(verdict(['not json at all', ...intended()]).ok, false);
  assert.equal(verdict([...intended(), '{"no":"action"}']).ok, false);
  assert.equal(verdict([...intended(), '[1,2,3]']).ok, false);
});

test('unit: the intended failure must carry the exact assertion message', () => {
  const wrong = intended().map((line) => line.replace(INTENDED_MESSAGE, 'SOMETHING_ELSE'));
  const r = verdict(wrong);
  assert.equal(r.ok, false);
  assert.ok(r.reasons.some((x) => x.includes('lacks the assertion message')));
});
