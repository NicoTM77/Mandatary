# Release acceptance, security and footprint evidence (P1.20)

This page is the **method**. The **result** for a given release is the generated, versioned report
`docs/release/phase1-release-acceptance.md`, built by
`tests/release/report.py` from the evidence files committed in `docs/release/evidence/`. Nothing in the report is typed by
hand: `python3 tests/release/report.py --check ...` fails when the page is stale or edited, and every criterion links the
result of a named check together with the SHA-256 of the artifact that holds it.

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
| `tests/release/report.py` | Controller and CI | Links each criterion in `tests/release/criteria.json` to results and artifact digests, renders the report, and `--check`s it |
| `tests/release/test_release.py` | Anywhere, no Docker | Hermetic positive/negative tests of everything above that does not need a daemon |

## Clean source, exact commit

The final evidence run uses a `git archive` of the exact release commit (no overlay of uncommitted files): the image is built
from that tree on the VM, the host helper binary is built from the same tree, and `REL-IMG-01` records the commit, the image
digest and the binary digest next to every result. The evidence commit that follows adds documentation only.

## Budgets and how they are measured (technical-decisions.md 10.2)

All budgets use **MB = 10^6 bytes** (the stricter reading of MB/MiB); the report states raw bytes as well. A missing, zero,
negative, boolean or non-numeric measurement is never a pass (`footprint.within`).

* **Image <= 60 MB compressed.** Sum of the manifest, config and every layer blob of the image in the OCI archive that the daemon
  exports (the attestation manifest is not part of the runtime image and is not counted). Measured per CPU.
* **Idle <= 50 MB resident.** `VmRSS` of the service process read from `/proc/<pid>/status` on the host of the disposable daemon
  (container PID namespaces are read through the host PID), sampled every 5 s over a curve from readiness (300 s after a start, 120 s for the long-running configured installation), with the
  budget applied to the **steady state** (the last 60 s). It is measured three times: right after the first start (before any
  administrator exists), after configuration and a long run, and after a restart of an installation that holds data. The whole curve
  is recorded. Because a start-up transient is a real property of the product, a separate check (`REL-FOOT-SETTLE-*`) requires that
  the process is back under the budget, and stays there, within the window; the time it took is reported.
* **Load <= 150 MB resident.** The approved workload: **20 concurrent clients** - 10 REST pollers (status and logs) and 10 real-MCP
  sessions (status and logs) - plus **5 active follow-log streams**, for 40 s of load, against the deployment through its TLS proxy.
  `VmHWM` is reset (`/proc/<pid>/clear_refs`) immediately before the window so the peak covers only the window; the sampled peak
  and the kernel high-water mark are both gated. The cgroup `memory.peak` is recorded for information (it includes page cache).
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

## Known limits of this evidence

* The footprint figures are for the stated host and workload; they are a gate on the budget, not a capacity claim.
* arm64 is exercised only on the hosted arm64 runner; the Ubuntu 24.04, Debian 13 and Unraid hosts are not exercised.
* The browser suites drive the SPA served directly by the server, not through the Caddy proxy.
* The documentation checks are mechanical (links, named files, required statements); the accuracy of the prose is a reviewer
  judgment, as is the review of the changed attack surface (the reviewer's verdict is on the Kanban card and the pull request).
* The harness leaves its `--work` tree (fixture-only TLS keys, a `stack.env` without secrets) for the caller to remove.
