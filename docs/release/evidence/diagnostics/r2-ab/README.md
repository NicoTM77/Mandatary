# P1.20 R2 — interleaved A/B measurement of the bounded continuity cache (sealed diagnostics)

Not linked to a release criterion's pass/fail; cited by `docs/release-acceptance.md` ("R2 measurement"). Every run that was started is kept.

## Arms (both built from their own `git archive` on the isolated VM, same harness, same image recipe, same workload)

| arm | commit used for the archive | product |
|---|---|---|
| A | `26fbc1a4234bdc65c2d592e141bf49602e1bca24` (a local, unpublished measurement commit: the tree of `9984df2` with `tests/release` of `0f7d879`) | the pre-R2 product (`79abc2f`) plus the request **counters only** (`b93ddae`); no cache |
| B | `0f7d87903fcc09fa99bf6de668c5898391748db4` | the bounded continuity cache (`d12331c`) plus the same counters; the harness change `0f7d879` |

The product code of the PR head differs from B only by documentation and a criteria text (`1528ef0`).

Fixture: the declared VM daemon (Docker 29.9.3, 4 vCPU), daemon ID verified by the harness before the first resource. Workload: the approved one (20 clients: 10 REST + 10 real MCP, 5 follow-log streams, 40 s), `--count-requests`, stages that do not exercise the load (idle, restore, migration, dev flow, docs, log level, logs) skipped (`--skip` is diagnostics-only and is why none of these files is evidence for a criterion).
`contended` = two bounded host CPU burners (`timeout 500 sh -c 'while :; do :; done'`, killed by PID after each run).

## Files

* `clean.sched`, `burn.sched`: the schedules (`<arm> <host> <run-id>`); `driver-*.log`: what the driver did; `ab_driver.sh`: the driver; `ab_analyze.py`: the analysis (every readable run is a row; an unreadable run would be listed as ABORTED).
* `clean-eval.{txt,json}`, `burn-eval.{txt,json}`: per-run rows, per-arm summaries and the target evaluation. `orphan-burn-A00-eval.json`: the row of the additional arm-A contended run described below.
* `raw-runs.tar.gz`: `release.json` and `release.log` of every run (clean-A01..A10 / B01..B10, burn-A01..A15 / B01..B30, `smoke-B`, `orphan-burnA`).
* `mutate.py`, `mutation-results.json`, `mutation-final.log`: the 17 mutants of the cache and which tests killed each (all 17 killed at `1528ef0`). `gates-race-twin-before-commit.log`: the `-race` and twin-replay run made on the tree before it was committed.

## Disclosures

1. The first driver version stopped reading its clean schedule after `clean-A01` (`ssh` read the rest of standard input) and its chain then started the contended schedule. The arm-A contended run it had started (`orphan-burnA`, row `burn-A00-orphan`: `REL-LOAD-STABLE` FAIL, 47 timeouts, no proof drop) finished and is kept, **but is not counted in the 15 A runs** (counting it would give 2/16 drops against 0/30; no conclusion changes). Both schedules were then restarted (clean from `clean-B01`, contended from the start).
2. `smoke-B` is a harness smoke run of arm B made before the schedules (a clean B run: 1491 admitted calls, no refusal).
3. The contended blocks (ABB/BAB/BBA) give B twice the runs of A, as the protocol prescribes.
4. `--count-requests` restarts the service once at the end of the window (a graceful stop makes it log its totals). The window's requests are the difference between the counter line before the window and the stop line after it.
5. Per-call figures divide by the *admitted* calls of the run (successful calls plus opened streams). Arm A serves far fewer calls in the same time (the daemon is the bottleneck), so the raw load on the daemon falls less than the per-call figures: metadata reads per second 261 -> 118 (-55 %), daemon CPU in the window 140 s -> 106 s (-24 %) on the clean host.

## Result against the plan's targets

| target | result |
|---|---|
| >= 65 % fewer metadata reads per call | -92.8 % — met |
| >= 90 % fewer `/info` calls per call | -99.8 % — met |
| >= 30 % less daemon CPU per call | -86.4 % — met |
| p95 latency no worse | status 2.13 s -> 0.48 s, logs 5.99 s -> 0.49 s — met |
| clean runs with 0 refusals, drops or timeouts | B: 10/10 — met (A: 1 of 10 had 5 log timeouts) |
| contended drop rate lower, Fisher p < 0.05 | A 2/15, B 0/30, one-sided p = 0.106 — **NOT met** |

R2 is therefore not claimed as resolved on the stated statistic, although `REL-LOAD-STABLE` failed in 15 of 15 contended A runs and 0 of 30 contended B runs.
