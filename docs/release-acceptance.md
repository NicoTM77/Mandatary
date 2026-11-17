# Release acceptance, security and footprint evidence (P1.20)

This page is the **method**. The **result** for a given release is the generated, versioned report
`docs/release/phase1-release-acceptance.md`, built by
`tests/release/report.py` from the **compact evidence** committed in `docs/release/evidence/` (a catalog, an archive manifest and
compact summaries; the bulky raw run output is in a separate evidence archive, see "Evidence layout"). Nothing in the report is typed by
hand: `python3 tests/release/report.py --check ...` fails when the page is stale or edited, and every criterion links the
result of a named check together with the SHA-256 of the **raw** artifact that holds it.

It is acceptance evidence for one release candidate. It is **not** a NIST, FIPS, product-qualification or
runtime-compatibility claim, it does not authorize a merge or a deployment, and a skipped target, an unimplemented check, a
missing browser or a missing architecture is reported as UNVERIFIED, never as a pass.

## What runs where

| Piece | Where | What it proves |
| --- | --- | --- |
| `tests/release/release.py` | Disposable Docker daemon (the isolated VM; the hosted runner's own daemon in CI), reached **only** through an explicitly declared endpoint and daemon identity (the P1.19 guard in `tests/image/isolation.py`) | The complete release acceptance of the packaged image: clean Compose deployment, A/B containers, matrix, lifecycle, usage, footprint, persistence, restore, migration, logging, local workflow, documentation checks |
| `tests/release/mcpclient` | Built from the locked Go module, never shipped in the image | The **real MCP client**: the official go-sdk over Streamable HTTP with verified TLS, one session per scripted run, and a load mode |
| `tests/release/migfixture` | Built from the locked Go module, never shipped | Lowers a **copy** of a populated store to the immediately prior schema with the repository's own goose down-migration, so the release image is proven to upgrade real data |
| `tests/release/collect.py` | Controller | Turns the raw output of the local gates, the browser suites, the Trivy/SBOM files and the hosted jobs document into `results` documents; a gate that exited 0 without producing its evidence is FAIL |
| `tests/release/report.py` | Controller and CI | Links each criterion in `tests/release/criteria.json` to results and artifact digests, renders the report, and `--check`s it (compact verification); `--audit-archive` adds the full raw-archive audit |
| `tests/release/evidence.py` | Controller; CI runs only its compact `verify` through `report.py --check` | Compact summaries of raw results, the deterministic evidence archive (`pack`), resolving it from a local file or the draft-release asset (`stage`), the full audit (`audit`), local regeneration of the summaries (`regenerate`) and `seal` |
| `tests/release/test_release.py`, `tests/release/test_evidence.py` | Anywhere, no Docker, no network, no credential | Hermetic positive/negative tests of everything above that does not need a daemon: the harness pieces, and the evidence design (regeneration, archive resolution and staging, unavailable evidence, digest and provenance mismatches, hostile archives, verdict rules) |

## Clean source, exact commit

The final evidence run uses a `git archive` of the exact release commit (no overlay of uncommitted files): the image is built
from that tree on the VM, the host helper binary is built from the same tree, and `REL-IMG-01` records the commit, the image
digest and the binary digest next to every result. The evidence commit that follows adds documentation only.

## Budgets and how they are measured (technical-decisions.md 10.2)

All budgets use **MB = 10^6 bytes** (the stricter reading of MB/MiB); the report states raw bytes as well. A missing, zero,
negative, boolean or non-numeric measurement is never a pass (`footprint.within`).

* **Image <= 60 MB compressed.** Sum of the manifest, config and every layer blob of the OCI archive that `buildx --output type=oci,compression=gzip` exports for the same source
  (the attestation manifest is not part of the runtime image and is not counted); the diffIDs of that archive must equal the layers of the image under test. Where the daemon's buildx driver cannot export OCI (the hosted runners' `docker` driver), every layer of `docker save` of the image under test is gzip-compressed at level 6 and summed with the config and manifest; the report names that as an **estimate** (on the VM it was within 0.15% of the real export: 12 400 226 against 12 418 702 bytes). Measured per CPU.
* **Idle <= 50 MB resident after stabilization** (technical-decisions.md 10.2, clarified by the owner during the P1.20 review remediation: "measured over the final 60 seconds of a 300-second observation
  window after readiness, with SQLite initialized and 1 local Docker endpoint connected; the start-up memory peak and the time to stabilization are reported separately and the idle limit does not apply to that
  start-up transient"). Method actually applied: `VmRSS` of the service process read from `/proc/<pid>/status` on the host of the disposable daemon (container PID namespaces are read through the host PID),
  sampled every 5 s for 300 s from readiness; the **gated value is the maximum of the samples inside the final 60 s** (twelve samples; the strictest aggregation, the median is in the evidence). It is measured three times:
  right after the first start (before any administrator exists), after configuration and a long run, and after a restart of an installation that holds data, each with its own 300 s window. The whole curve is recorded.
  The **start-up transient** is a real property of the product (about 100 MB for about 2.5 minutes after every start, observed on all three platforms; its in-product cause is not asserted here, it is not optimized and no authentication change was made for it). Its peak
  and the time to stabilization (the first sample after which every later sample is within 50 MB) are reported in the report's footprint table and as their own result (`REL-FOOT-SETTLE-*`, a pass only when both were measured); the idle limit is not applied to it.
  A sign-in or setup burst has its own, larger high-water mark (observed about 180 MB; not asserted to be a particular allocation); it lies outside the approved workload and is reported as evidence, not as a budget failure.
* **Load <= 150 MB resident.** The approved workload: **20 concurrent clients** - 10 REST pollers (status and logs) and 10 real-MCP
  sessions (status and logs) - plus **5 active follow-log streams**, for 40 s of load, against the deployment through its TLS proxy.
  `VmHWM` is reset (`/proc/<pid>/clear_refs`) immediately before the window so the peak covers only the window; the sampled peak
  and the kernel high-water mark are both gated. The cgroup `memory.peak` is recorded for information (it includes page cache).
* **Long stop and restart (`REL-STOP-LONG`).** The matrix records the duration of every REST and MCP call (`matrix.timing` in the
  evidence). The lifecycle stage then stops container A, which ignores SIGTERM, with `timeout_seconds` 12 through REST, starts it, and
  restarts it through the real MCP client: each must answer 200 although the call outlasts the server's 10 s write bound
  (docs/api-mcp.md, "Stop and restart outlive the 10 s server write bound"), A must run again, and both the REST stop and the MCP
  restart must have been **measured** to take longer than the bound (a fast or unmeasured answer is a failure, never a pass).
* **Stability under the workload (SH-2d, `REL-LOAD-STABLE`).** Every attempt of the workload is traced (revision, interface, operation,
  outcome or error reason, duration) and correlated with the service's own `docker safety proof dropped` / `restored` log lines
  (closed `reason`/`step`/`cause` vocabulary, durations and counts only; never an error text, path, ID or payload), a probe of the
  fixture daemon's own latency, and a once-a-second `/proc` sample of the host CPU and of `dockerd`, `containerd`, the proxy and the
  service (`host_cpu` in the record). The harness therefore says, for every refusal, whether a recorded safety transition explains it.
  A client-visible refusal or timeout does not decide what the server accounted: the usage totals of a cell with unobserved attempts
  are held to the documented rule (every observed success accounted, at most the unobserved attempts more), never recomputed from
  client successes; a cell without unobserved attempts stays exact. A criterion may name **sealed adverse runs**
  (`adverse` in `tests/release/criteria.json`): while their state is `open`, a failing one fails the criterion even when the final run is
  clean; only a reviewed change sets a closed state: `dispositioned` (an owner decision, which states what it does not claim) or
  `remediated` (a defect fixed in the product, pinned by a regression test, with fresh passing evidence of the criterion's own checks;
  a technical closure, not an owner decision, which states what it does not establish). A closed group needs its own text, so the closure is
  never silent, and the adverse run itself is never rewritten.
* **Environment.** Docker server/API/Compose versions, kernel, OS, CPU count, memory, storage driver, 4 KiB `fsync` latency of the
  work file system and the daemon ID are recorded in the evidence.

## The matrix

`tests/release/matrix.py` builds one case list (about 90 cases) executed through **both** the REST API and the real MCP client: every
operation on A and on B for agents with a full grant, a read-only grant, no grant, an explicit DENY on B, a group grant and a
wildcard; the unauthenticated, invalid-credential, malformed-input, unsupported-operation (exec, kill, pause, remove, list,
discovery, raw Docker paths, wrong methods, smuggled parameters), Mandatary-itself and labelled-peer cases; and an authorized call
that the daemon itself refuses (container C cannot start). Each case states the exact status, error code and reason expected;
REST and MCP must classify identically (`REL-MATRIX-PARITY`). The daemon's **event stream** is recorded during the matrix and no
`start/stop/kill/die/restart/pause` event may touch B, Mandatary or its peer (`REL-MATRIX-EFFECT`).

## Usage counts

The expected counts are **derived from the executed matrix**, not typed: a verified principal blocked by policy = `denied`; a
backend success = `allowed`; an authorized call the daemon failed = `error`; nothing is counted for 401, invalid input,
unsupported operations, or refusals of Mandatary itself and its labelled peers (decision D2 in `docs/usage-accounting.md`). The totals read from the
store (through a host-local read of the database copy) must equal the expected totals per (agent, owner user, selector, operation)
exactly, after the matrix, after the lifecycle scenarios, after the workload, after a graceful restart, after a SIGKILL and after
restore. `REL-USAGE-RING-*` also checks that the recent-event ring is bounded and carries no payload column.

## Crash and restart

A graceful `stop` must exit 0 within the stop timeout; a `restart` and a **SIGKILL delivered to the service process from the host**
must be followed by the restart policy bringing it back with a fresh verification (`docker kill` is not used for the crash: the
daemon treats an explicit kill as a manual stop and never applies the restart policy to it).

## Local evidence gates (controller)

`gofmt`, `go vet`, `go mod verify`, the pinned `golangci-lint`, `gosec`, `govulncheck` (reachability-based) and the Go test suite;
`tsc`, `eslint --max-warnings 0`, Vitest and `npm audit --audit-level=high`; the three browser suites (Chromium, Firefox,
WebKit; desktop and 390x844; each scenario in light and dark) via `go test -tags=webauthnbrowser`; Trivy (digest-pinned image,
HIGH/CRITICAL exit code) and a CycloneDX SBOM on the VM. Each result is read by `collect.py` from the raw output.

## Running it

On a machine with an **isolated, disposable Docker daemon** (never a production one):

```bash
CGO_ENABLED=0 go build -trimpath -o out/mcpclient ./tests/release/mcpclient
CGO_ENABLED=0 go build -trimpath -o out/migfixture ./tests/release/migfixture
python3 tests/release/release.py --image IMAGE --platform linux/amd64 --repo . \
  --docker-host unix:///var/run/docker.sock --expect-daemon-id DAEMON_ID \
  --work "$HOME/mandatary-release" --host-binary out/mandatary --mcp-client out/mcpclient --mig-tool out/migfixture \
  --sha "$(git rev-parse HEAD)" --results release.json
python3 tests/release/test_release.py          # hermetic, no Docker
```

The harness refuses to start without `--expect-daemon-id` and refuses an ambient or remote endpoint before it creates anything
(`ISO-00`); it removes every resource it created, and `ISO-01` re-checks the daemon identity before cleanup. Every resource carries
the unique `p120...` prefix of its run, never a name from another run.

## Evidence layout and consistency

The raw output of a release run (the full harness JSON of every environment, raw browser, gate and driver logs including empty
snapshots, detailed diagnostics and the A/B raw runs, scan outputs and SBOMs) is large and run-specific, so it is **not** part of the
maintained source tree. It is held in ONE immutable, versioned evidence archive; Git keeps only what is needed to read, regenerate and
check the result (`docs/release/evidence/`, all sealed by `SHA256SUMS`):

| File | Content |
| --- | --- |
| `catalog.json` | The provenance catalog: the tested code commit and the other revisions, the archive identity, size, digest and location, the artifact each summary came from (archive member, SHA-256, revision and how the revision is established), the diagnostics and adverse runs with their dispositions, the owner-approved dispositions, the acceptance gates still open, the publication status, the findings and the known limits |
| `ARCHIVE.sha256` | The complete member manifest of the archive (`sha256sum` format, sorted, one line per member) |
| `summaries/*.json` | A compact, deterministic summary of each raw `results` document: the digest of the raw member it was derived from, its revision, every check result, and the measured values (long traces are cut to their length) |

The archive of this release is `p120-evidence-v3`: `p120-evidence-v3-<12 hex>.tar.gz` plus `p120-evidence-v3.ARCHIVE.sha256`, assets of
an **evidence-only draft pre-release** of this repository (tag name `p120-evidence-v3`; it is not a product release, not a C5 release,
and must never be published). It **supersedes** `p120-evidence-v2` without changing it (and v2 superseded `p120-evidence-v1`): the older
archives stay in their own draft releases, and the v3 manifest contains every one of the v2 members (so every v1 member too) with the
identical SHA-256. The committed `ARCHIVE.p120-evidence-v2.sha256` is the v2 manifest (and `ARCHIVE.p120-evidence-v1.sha256` the v1 manifest),
so `report.py --check` proves that containment from the committed manifests without reading any archive, and the
full audit covers the older members too (they are in the v3 tarball). The roots are `round-1-f306a2a/` and `round-2-fbb8193/` (the
earlier rounds, including the R2 A/B raw runs), `records/` (the R2 root-cause report, the review reports, the interim design, the F5
analysis), `round-3-2ac064f/` (the integrated evidence of the previous code commit, with the first runs of the F2 fix under
`diagnostics/run-41ae8d5/`), `adverse-ci-e5e1856/` (the adverse hosted run of review 519 F1) and `round-4-fd69639/` (the integrated
evidence of the final code commit, and the corrected description of the run at 41ae8d5; an immutable archive is never edited, so a
description found wrong in an older version is corrected by a new member, and the catalog says so). The authoritative
identifiers, size, tarball digest and member count are in `catalog.json` and the generated report. A draft release is visible to
repository writers; it is read with the caller's own `gh` (never a credential of this repository). It is durable while the repository and
the draft exist; an administrator can delete it, which the digests make detectable but cannot prevent. A new evidence round makes a new
archive id (`p120-evidence-v3`, ...): archives are never rewritten.

**Two verification levels, never confused.**

1. **Compact-summary verification** - `python3 tests/release/report.py --check` (the Image job runs it, and `tests/release/test_evidence.py`
   runs it against this repository's own evidence). It needs no archive and no credential. It checks that `SHA256SUMS` matches every
   committed file, that the catalog, `ARCHIVE.sha256` and every summary agree (each summary names its raw member, that member's SHA-256 and
   revision, equal to the manifest and to the catalog; a missing, edited or re-bound summary fails), and that the committed report is what
   they produce. It does **not** open the archive and so does not prove that the raw evidence exists.
2. **Full raw-archive audit** - needs read access to the archive:

   ```bash
   python3 tests/release/evidence.py stage --evidence docs/release/evidence --dest "$WORK/staged" --from-release --gh "gh"   # or --tarball FILE
   python3 tests/release/report.py --evidence docs/release/evidence --criteria tests/release/criteria.json \
     --out docs/release/phase1-release-acceptance.md --check --audit-archive "$WORK/staged"
   ```

   `stage` fetches the asset (or reads the given tarball), refuses a wrong size or tarball digest, refuses any member that is not a regular
   file with a safe name that the manifest lists (path traversal, symlinks, duplicates, unlisted members, oversize are all refused),
   and checks every member digest against `ARCHIVE.sha256`; `--audit-archive` then checks completeness (no member missing or extra)
   and **regenerates every summary from its raw member** and compares it byte for byte. Unavailable evidence, a digest mismatch or a
   provenance mismatch fails; nothing is skipped silently. Pull requests only run level 1.

**Regenerating after a new run.** Collect the raw results (`collect.py`, the harness), add them to a new archive root, then
`evidence.py pack --root PREFIX=DIR ... --out TARBALL --manifest ARCHIVE.sha256` (refuses symlinks, unsafe names and secret-like
patterns; the tarball is deterministic), upload the tarball and the manifest as assets of a new evidence-only draft release, update
`catalog.json` (archive identity and digests, artifacts, revisions, dispositions), read the asset back with `stage --from-release`,
`evidence.py regenerate --staged ...`, `evidence.py seal`, `report.py` (writes the report), then `report.py --check --audit-archive`.

**Honest limit of the move.** The raw evidence files of the first two rounds were committed at `f306a2a` and `fbb8193` of this pull
request. They are removed at the branch tip by ordinary additive commits; the Git objects of those commits stay in the repository's
history (behind `refs/pull/25/head`) and are **not** purged: no history was rewritten. If the pull request is squash-merged they are not
part of the main history; the archive, not Git history, is the durable record.

The VM run is produced from a `git archive` of the code commit; the evidence commits that follow add the compact evidence and the
report only. `catalog.json` records the code commit, the baseline, the image and binary digests and states that the local gates and the
browser suites ran on a clean worktree at exactly that code commit, so no product file differs between what they judged and what the VM
archive built (`GATE-PRODUCT-TREE`; since the UX and R2 changes the product tree is no longer the merged baseline, so the comparison is
against the code commit, not against `main`). The commits after the code commit change no product file (`git diff 1528ef0 HEAD -- cmd
internal web ':(exclude)*_test.go'` is empty; the one test file that differs is the X2 regression test): they add the X2 test, the
evidence hygiene and the CI publication job.

## R2 measurement: bounded continuity freshness (interleaved A/B)

The refusals of SH-2d were traced to a saturated fixture daemon that the service loaded further: one admitted status call issued 12
daemon reads (9 of them continuity checks), a tail-logs call 33, and the open follow streams re-verified continuously
(`docs/docker-backend.md`, "Bounded continuity freshness"). R2 changes the product so that one continuity check (daemon ID, own
container, all-state inventory) covers the other reads and stream deliveries for less than one second; nothing else is cached.
The measurement follows the reviewer protocol and was run on the isolated VM (4 vCPU, Docker 29.9.3), one release-harness run per
point, **interleaved** A/B, each arm built from its own `git archive`, the same harness, the same workload (20 clients + 5 streams,
40 s), no changed limit:

* **Arm A** is the product without the cache but with the request counters (the counters-only commit b93ddae/9984df2 product
  tree); **arm B** is the cache (`d12331c`/`0f7d879`). The counters are the only difference to the pre-R2 product that A carries; they
  only count (`docker daemon requests`, closed kinds, counts only).
* **Clean**: 10 A + 10 B, strictly alternating. **Contended**: 15 A + 30 B in blocks (ABB/BAB/BBA) with two bounded host CPU
  burners (plain shell loops, `timeout`-bounded, killed by PID after each run), i.e. the fixture under CPU pressure.
* The window's own daemon requests are the difference between the counter line before it and the one written at the graceful stop
  after it. Daemon CPU is the 1 Hz `/proc` sample of `dockerd` + `containerd` inside the window. Latency is the client-side latency of
  successful calls.
* Every run is kept (archive member `round-2-fbb8193/docs/release/evidence/diagnostics/r2-ab/` (not in Git, see "Evidence layout"): per-run rows, summaries, raw `release.json` of every run, the driver
  logs, schedules and the analysis script). Two disclosures: (1) the first driver version stopped reading its clean schedule after
  `clean-A01` because `ssh` consumed the rest of standard input, and its chain went on into the contended schedule; the arm-A
  contended run it started (`burn-A00-orphan`) was allowed to finish and is kept and listed, but it is **not** one of the 15 counted A
  runs (it failed `REL-LOAD-STABLE` like the others: 47 timeouts, no drop), and both schedules were then restarted (the clean one from
  `clean-B01`); (2) a harness smoke run (`smoke-B`) preceded the schedules and is kept too.

| Result (median of runs) | clean A | clean B | change |
|---|---|---|---|
| metadata reads (`/info` + list + inspect) per admitted call | 44.5 | 3.22 | **-92.8 %** (target >= 65 %) |
| `/info` calls per admitted call | 13.16 | 0.028 | **-99.8 %** (target >= 90 %) |
| daemon CPU seconds per admitted call | 0.523 | 0.071 | **-86.4 %** (target >= 30 %) |
| metadata reads per second | 261 | 118 | -55 % (calls are served ~5.6 times faster, so this is the raw load on the daemon) |
| daemon CPU in the 40 s window | 140 s | 106 s | -24 % |
| p95 latency, status / logs | 2.13 s / 5.99 s | 0.48 s / 0.49 s | not worse (target) |
| admitted calls in the window | 266 | 1497 | |
| runs with a refusal, proof drop or timeout | 1 of 10 (5 log timeouts) | 0 of 10 | clean B: 0 (target) |
| `REL-LOAD-STABLE` | 9/10 PASS | 10/10 PASS | |

| Result (contended) | A (15 runs) | B (30 runs) |
|---|---|---|
| runs with a proof drop | 2 | 0 |
| `REL-LOAD-STABLE` | 0/15 PASS | 30/30 PASS |
| median timed-out calls per run | 45 | 0 |
| refusals (`safety_unverified` / `default_deny`) | 183 / 8 (2 runs) | 0 / 0 |
| median p95 latency, status / logs | 5.4 s / 13.4 s | 0.94 s / 0.94 s |

**What is and is not established.** All clean-host targets are met (per-call reductions, p95, 0 refusals/drops/timeouts in 10 runs).
The contended arm is far better in the observable failure (0 of 30 B runs against 15 of 15 A runs failing the stability result,
timeouts 669 against 0), but the pre-registered statistic on the **drop rate alone is not met**: 2 of 15 against 0 of 30 gives a
one-sided Fisher exact p = 0.106 (target p < 0.05), because the drop is rare even under contention in arm A. R2 is therefore **not**
claimed as resolved on the stated target; the evidence is that the mechanism is evidenced (daemon saturation amplified by the service's
own continuity reads; the exact cause of the original clean-host failures was not reproduced and is not established) and that
removing most of that amplification removes the observed timeouts and failures in this fixture.

**Owner-approved disposition (SH-2d).** The owner accepted this A/B evidence as the disposition of R2 (option 1 of reviewer run 518):
SH-2d is reported as **PASS WITH DISCLOSURES**. This is an acceptance-policy decision, **not** a claim that the pre-registered
statistic passed, and it waives nothing in security: authorization, identity, invalidation, cancellation and fault classification, leases
and freshness are unchanged. The disclosures stay visible in the report (section 6) and the criteria: 2/15 against 0/30 runs with a
proof drop and p = 0.106 (target not met); contended `REL-LOAD-STABLE` 0/15 A against 30/30 B passes, 669 against 0 timeouts, 191
against 0 refusals; the original clean-host failures (3 of 5 VM runs) were not exactly reproduced although the mechanism is evidenced.
The historical adverse runs (`vm-diag-loop-1`, `vm-diag-loop-2`, `vm-run-1a01db9`) stay FAIL in the archive and in the criterion's
adverse list; the criterion's adverse state is `dispositioned` and carries the disposition text instead of being rewritten as a success.
**Residual risk:** under a saturated daemon the service can still refuse a legitimate call or time out a daemon read; this fails closed
(an availability risk, not an integrity or confidentiality one) and is logged by the safety-transition diagnostics. The report as a whole
is `CRITERIA MET - ACCEPTANCE PENDING` and becomes `ACCEPTED` only when the acceptance gates of the catalog (independent exact-head
review, hosted CI at the final head, the owner's merge, and the post-merge registry read-back) are closed; the report cannot close them.

## Known limits of this evidence

* The footprint figures are for the stated host and workload; they are a gate on the budget, not a capacity claim.
* arm64 is exercised only on the hosted arm64 runner; the Ubuntu 24.04, Debian 13 and Unraid hosts are not exercised.
* The browser suites drive the SPA served directly by the server, not through the Caddy proxy.
* The documentation checks are mechanical (links, named files, required statements); the accuracy of the prose is a reviewer
  judgment, as is the review of the changed attack surface (the reviewer's verdict is on the Kanban card and the pull request).
* The harness leaves its `--work` tree (fixture-only TLS keys, a `stack.env` without secrets) for the caller to remove.
