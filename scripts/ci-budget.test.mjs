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

test('the security job still requires every Baseline, negative-control and image job to have passed', () => {
  const security = workflow.slice(workflow.indexOf('  security:'));
  assert.match(security, /needs: \[baseline, negative-control, image\]/);
  assert.match(security, /Require every Baseline, negative-control and image job to have passed/);
  assert.match(security, /"\$BASELINE_RESULT" == success && "\$NEGATIVE_CONTROL_RESULT" == success && "\$IMAGE_RESULT" == success/);
});

// P1.19: the production image is built AND run on both supported CPUs (never cross-compile only), the scanner is pinned by digest and
// is never handed the Docker socket, and a HIGH/CRITICAL finding fails the job.
test('the image job covers both CPUs natively and gates on a digest-pinned Trivy HIGH/CRITICAL scan', () => {
  const image = job('image');
  assert.equal(minutes(image), 75);
  assert.match(image, /name: Image \(\$\{\{ matrix\.platform \}\}\)/);
  assert.match(image, /platform: linux\/amd64\n\s+runner: ubuntu-24\.04\n/);
  assert.match(image, /platform: linux\/arm64\n\s+runner: ubuntu-24\.04-arm\n/);
  assert.match(image, /TRIVY_IMAGE: ghcr\.io\/aquasecurity\/trivy@sha256:[0-9a-f]{64}/);
  assert.match(image, /--severity HIGH,CRITICAL --exit-code 1/);
  assert.match(image, /tests\/image\/acceptance\.py/);
  // The scanner step is isolated: it never sees the Docker socket. (The acceptance step must name its fixture daemon
  // explicitly, S1.4, so the socket path legitimately appears elsewhere in the job as an --docker-host argument; it must
  // never be bind-mounted into a container by the workflow itself.)
  const scanner = image.slice(image.indexOf('- name: SBOM and Trivy'), image.indexOf('- uses: actions/upload-artifact'));
  assert.match(scanner, /trivy image --input/, 'the scanner step was not found');
  assert.doesNotMatch(scanner, /docker\.sock/, 'the scanner step is never given the Docker socket');
  assert.doesNotMatch(image, /-v\s+\S*docker\.sock/, 'the workflow never bind-mounts the Docker socket');
  assert.doesNotMatch(image, /--privileged/);
  // S1.4: the acceptance run names its fixture daemon and its identity; there is no ambient fallback.
  assert.match(image, /acceptance\.py[^\n]*\\\n[^\n]*--docker-host "\$FIXTURE_DOCKER_HOST" --expect-daemon-id "\$FIXTURE_DAEMON_ID"/);
  assert.match(image, /python3 tests\/image\/test_isolation\.py/);
  assert.match(image, /NOT-THE-DECLARED-FIXTURE-DAEMON/);
});

// P1.20: the release acceptance runs in the same job on both CPUs against the same explicit fixture daemon, never an ambient one, and its
// hermetic tests run first. The real MCP client and the migration tool are test tools built from the locked module.
test('the image job runs the P1.20 release acceptance on the declared fixture daemon, on both CPUs', () => {
  const image = job('image');
  assert.match(image, /python3 tests\/release\/test_release\.py/);
  assert.match(image, /python3 tests\/release\/test_evidence\.py/);
  // The dev-image publication contract (scripts/publish_dev_image.py, the publish job) is tested hermetically on every pull request.
  assert.match(image, /python3 tests\/publish\/test_publish\.py/);
  assert.match(image, /python3 tests\/publish\/test_workflow\.py/);
  // The report check is the COMPACT verification: it needs no archive and no credential, so a fresh clone and a fork pull request run it
  // as is. The full archive audit (evidence.py stage / report.py --audit-archive) must never become a credentialed pull-request step.
  assert.doesNotMatch(image, /--audit-archive|evidence\.py stage|--from-release/);
  assert.match(image, /python3 tests\/release\/report\.py --evidence docs\/release\/evidence --criteria tests\/release\/criteria\.json --out docs\/release\/phase1-release-acceptance\.md --check/);
  assert.match(image, /release\.py[^\n]*\\\n[^\n]*--docker-host "\$FIXTURE_DOCKER_HOST" --expect-daemon-id "\$FIXTURE_DAEMON_ID"/);
  assert.match(image, /--mcp-client "\$RUNNER_TEMP\/out\/mcpclient" --mig-tool "\$RUNNER_TEMP\/out\/migfixture"/);
  assert.match(image, /go build -trimpath -o "\$RUNNER_TEMP\/out\/mcpclient" \.\/tests\/release\/mcpclient/);
  assert.match(image, /--results "\$RUNNER_TEMP\/evidence\/release-\$\{\{ matrix\.arch \}\}\.json"/);
  // The evidence is uploaded even when the run fails (the upload step is always()), and the scanner still follows the acceptance steps.
  assert.ok(image.indexOf('Release acceptance (Compose A/B') < image.indexOf('- name: SBOM and Trivy'));
  assert.match(image, /uses: actions\/upload-artifact[^\n]*\n\s+if: \$\{\{ always\(\) \}\}/);
});
