# Deployment: production image, Compose and host-local setup (P1.19)

> **Status.** Mandatary is in active development and the Phase 1 roadmap is **not complete**. This page is
> the deployment contract for what is implemented today and the procedure that was exercised in an isolated
> test environment (see [Evidence and limits](#10-evidence-and-limits)). It is not a release, not a support
> or compatibility promise, and it has never been used on a production host by the project. Nothing here
> authorizes touching a production Docker host. Planned features (Phase 2 and later) are not available.

## 1. What is shipped

| Artifact | Purpose |
| --- | --- |
| `Dockerfile` | Static Go binary with the compiled admin SPA embedded, on the approved `gcr.io/distroless/static-debian13:nonroot` base. All three base images are pinned by multi-architecture index digest. No shell, no package manager, one process. |
| `docker-compose.yml` | The production Compose example: non-root, read-only root, all capabilities dropped, `no-new-privileges`, one persistent data bind mount, the Docker socket for the local endpoint, **no published port**. |
| `deploy/compose.proxy.yml`, `deploy/Caddyfile` | One example of the TLS reverse-proxy contract of §5 (Caddy). Any proxy meeting the contract is acceptable. |
| `deploy/env.example` | Every variable the Compose files need, with placeholders only. |
| `tests/image/` | The isolated acceptance harness that produced the evidence in §10. |

One image serves both roles: the long-running server (`mandatary`) and the **host-local helper**
(`mandatary setup …`, `mandatary recovery …`), which is the same static binary run on the host (§6).
`mandatary healthcheck [--ready]` is the shell-free container probe.

## 2. Build the image

Build only on a Docker host you are allowed to build on. The build needs the exact source commit, because a
container build has no `.git` and the host helper refuses to reveal a token issued by a different build:

```bash
docker build --build-arg VCS_REF="$(git rev-parse HEAD)" -t mandatary:local .
# a specific CPU, built natively on the build platform without emulation:
docker build --platform linux/arm64 --build-arg VCS_REF="$(git rev-parse HEAD)" -t mandatary:local-arm64 .
# the byte-identical host-helper binary the image runs, without starting a container:
docker build --target host-binary --build-arg VCS_REF="$(git rev-parse HEAD)" --output type=local,dest=./out .
```

* `VCS_REF` must be 40 lowercase hex characters; the build refuses anything else and also refuses a Go toolchain
  other than 1.27.4. It is stamped into the binary and recorded in the image label `org.opencontainers.image.revision`.
* The pinned base digests are the `ARG`s at the top of the `Dockerfile`. Updating one is a reviewed change
  (support matrix §5), never an unpinned `latest`. The distroless index digest covers every CPU architecture
  the base publishes; the runtime only has to run on the two supported CPUs below.
* Deploy by **digest**: push the image to your own registry and reference it as
  `registry.example/mandatary@sha256:<digest>` in `MANDATARY_IMAGE`. The Compose file refuses to render
  without that variable.
* Supported CPU targets: `linux/amd64` and `linux/arm64`. A build that cross-compiles but was never run is
  not evidence; the acceptance harness runs the image it built on the CPU it targets.

## 3. Prepare the host before the first start

Mandatary never creates or repairs permissions. It refuses to start on anything unsafe, so prepare exactly this
(numeric IDs are those of the image's `nonroot` user, `65532:65532`):

```bash
sudo install -d -m 0700 -o 65532 -g 65532 /srv/mandatary/data                # persistent data (bind mount)
sudo install -d -m 0755 -o root  -g root  /srv/mandatary/secrets
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | sudo tee /srv/mandatary/secrets/master.key >/dev/null
sudo chown 65532:65532 /srv/mandatary/secrets/master.key && sudo chmod 0400 /srv/mandatary/secrets/master.key
```

* **Master key**: 32 random bytes as 64 hex (or base64) characters in a regular, single-link file that only the
  service user (or root) owns, mode 0400/0600. Generate it once, back it up separately from the data, never put it
  in the image, a repository, an environment value or a log. Losing it makes the store unreadable; a different
  key on an existing store is refused at startup.
* **Data directory**: owner `65532:65532`, mode `0700`. The process creates its database, WAL, lock file and
  setup material inside it as `0600`. A directory owned by anyone else, or one with group/world access, is refused.
* **Every ancestor directory of the key file and of the data directory must not be group- or world-writable.**
  Keep both under an administrator-owned path such as `/srv/mandatary/` (owner root, mode 0755).
* **Local filesystem only.** SQLite WAL, the shared lock and the host helper require a local filesystem (ext4,
  xfs, btrfs…). Network shares (NFS/SMB) are not supported for the data directory.
* **Use a bind mount, not a Docker-managed named volume**, so the host helper can open the same directory.
* Compose reads the key through a file secret, never an environment variable.

### Docker socket access

The local endpoint talks to the daemon over a unix socket. Mounting it gives the service **root-equivalent power
on that host**: that is the reason Mandatary exists as the intermediary, not a detail to relax.

1. Find the socket's numeric group: `stat -c %g /var/run/docker.sock` → `DOCKER_SOCKET_GID` in your `.env`.
   The Compose file adds exactly that supplementary group (`group_add`) to the non-root user; it does not run as
   root and does not add capabilities.
2. A rootless daemon, a socket proxy or a different socket path: set `MANDATARY_DOCKER_SOCKET_HOST`. The setting
   `MANDATARY_DOCKER_SOCKET` accepts only `unix:///absolute/path`; remote transports are Phase 5 (planned, not implemented).
3. If you give Mandatary **no** socket, no Docker surface exists at all: `/api/v1/endpoints/…` and `/mcp` answer
   `404` and `readyz` is not served. That is the supported "Docker access withheld" posture.
4. An optional read/write-restricted socket proxy in front of the daemon is compatible (point the setting at its
   unix socket) but is not shipped and has not been evaluated by this project.

## 4. Configure and start

```bash
cp deploy/env.example .env      # edit every value; keep it out of version control
docker compose config -q        # refuses to render if a required variable is missing
docker compose -f docker-compose.yml -f deploy/compose.proxy.yml up -d
```

| Variable | Meaning |
| --- | --- |
| `MANDATARY_IMAGE` | The image reference, pinned by digest. |
| `MANDATARY_INSTANCE_UUID` | One lowercase UUID, used as the container label `io.mandatary.self.instance-uuid` **and** as `MANDATARY_SELF_INSTANCE_UUID` (§7). |
| `MANDATARY_PUBLIC_ORIGIN` | The `https://host[:port]` users type, exactly. The only source of the setup URL, Host/Origin checks and the WebAuthn relying party. No request header is ever consulted. |
| `MANDATARY_DATA_HOST_DIR`, `MANDATARY_MASTER_KEY_HOST_FILE` | Host paths from §3. |
| `DOCKER_SOCKET_GID`, `MANDATARY_DOCKER_SOCKET_HOST` | Socket access from §3. |
| `MANDATARY_SMTP_RELAY`, `…_SMTP_TLS`, `…_SMTP_SENDER`, `MANDATARY_NOTICE_CONTACT` | Verified-TLS security-notice relay (all four or none). The first administrator cannot be completed without a verified address, so in practice they are required. Authenticated relays are not configurable yet. |
| `MANDATARY_LOG_LEVEL` | `debug`, `info` (default), `warn`, `error`. Logs are JSON on stdout and carry no secret at any level. |

The listener (`MANDATARY_ADMIN_LISTEN_ADDR`) defaults to `127.0.0.1:8080` in the binary and is `:8080` in the image,
because the proxy reaches it over the private `edge` network. The image publishes no port. `MANDATARY_OPS_UI_ENABLED`
and `MANDATARY_OPS_LISTEN_ADDR` (the Phase 4 operations UI) are **refused at startup**: there is no Phase 4 listener
in this release and no switch that could open one.

## 5. TLS and reverse-proxy contract

Mandatary serves plain HTTP on one port and expects a proxy to terminate TLS (technical-decisions.md §2.2).
Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict` and use the `__Host-` prefix, so the origin users
reach **must** be HTTPS. Whatever proxy you use must:

1. Terminate TLS with a certificate valid for the public name, and reach `mandatary:8080` only over a private network.
   Never publish port 8080 of the Mandatary container.
2. Pass the `Host` header **unchanged** and rewrite no path or query. The origin check compares the browser's
   `Origin` with `MANDATARY_PUBLIC_ORIGIN`; `X-Forwarded-*` headers are never trusted, so peer-IP throttling sees
   the proxy's address unless the proxy is on a per-client network (a known limit, §10).
3. Stream responses unbuffered with no idle cut-off for the log-follow route and `/mcp` (Streamable HTTP).
4. Keep `Authorization`, `Cookie` and `Set-Cookie` values and query strings out of its access logs. A setup token
   is never in a URL, but a bearer token and a session cookie are in headers on every request.
5. Not cache `/api/*`, and not add third-party scripts or assets to any Mandatary page.

`deploy/Caddyfile` is one working example (local CA via `tls internal` for a private name, or ACME for a public
one). It is an example of the contract, not a component of Mandatary.

## 6. First administrator: host-local setup (no shell in the container)

The image has no shell, so the setup token is revealed by the **same binary run on the host** against the same
bind-mounted data directory (security-contracts.md §S3). Extract it once from the image you deploy and keep it in
an administrator-owned, non-group/world-writable directory:

```bash
docker build --target host-binary --build-arg VCS_REF=<the same commit> --output type=local,dest=/usr/local/lib/mandatary ./
sudo chown root:root /usr/local/lib/mandatary/mandatary && sudo chmod 0755 /usr/local/lib/mandatary/mandatary
```

The helper refuses to reveal a token that a build with another revision issued, so a mismatched binary fails
closed. Then:

1. Start the stack and read **only** the logged secret-free URL: `docker compose logs mandatary | grep "initial setup available"`.
2. On the host terminal, as root with the numeric service identity (the helper drops privileges before it opens any
   file, clears supplementary groups and verifies it cannot regain root), **on a real controlling terminal**:

   ```bash
   sudo /usr/local/lib/mandatary/mandatary setup reveal --uid 65532 --gid 65532 \
        --data-dir /srv/mandatary/data --master-key-file /srv/mandatary/secrets/master.key
   ```

   Pipes, redirection, `ssh` without a tty, `cat`, `$(...)` and a container shell are refused or unsupported. The
   token is shown once and never reaches a log. It expires 30 minutes after issuance; a restart does not extend or
   renew it. `mandatary setup status` shows the state without a secret and `mandatary setup rotate` issues a fresh
   generation **only** while no administrator exists.
3. Open the logged URL over HTTPS, paste the token, choose a password, add at least one notification address and
   prove control of it with the emailed code, enrol TOTP with a live code, complete. **No session is issued by
   setup**: sign in normally with password and TOTP afterwards. Setup then closes permanently.
4. Emergency MFA reset and restore-administrator recovery use the same helper (`mandatary recovery …`); see
   [setup-recovery.md](setup-recovery.md) and [backup-restore.md](backup-restore.md). They are application-specific
   trusted-host procedures, not NIST AAL2 recovery.

Trust limit: root, the service UID, Docker administrators who can run commands as it, and the host terminal are
trusted. Do not copy the database, widen modes, repair ownership with a recursive `chmod`, or edit the store by hand
to "fix" setup; fix the cause and rotate.

**Unraid.** The same procedure applies with the actual appdata path mapped to `/data`, the container's configured
(not assumed) service identity, and the helper run from an SSH or local terminal (not the container console).
Exclude the data directory from SMB/NFS sharing and from permission-repair jobs. This project has **not** run the
procedure on Unraid; treat it as unqualified until you have recorded your own host, Engine and API versions.

## 7. Self-protection and readiness

Mandatary refuses to see or operate on itself or on any container carrying the `io.mandatary.self` label, whatever
its name, state or policy. It must **prove which container it is** before any Docker access, afresh at every start:

* The image and the Compose file label the container `io.mandatary.self=true`.
* In a private cgroup namespace (Docker's default on cgroup v2) the container cannot read its own ID, so the
  deployment binds it with one UUID in two places: the label `io.mandatary.self.instance-uuid` and the variable
  `MANDATARY_SELF_INSTANCE_UUID`. Exactly one container with that label must exist; two (a recreation overlap)
  fail closed until one is removed. An optional `MANDATARY_SELF_CONTAINER_ID` (64-hex full ID) is an extra
  assertion that must agree, never a substitute.
* Verification re-runs on every start and after every loss of proof (a daemon restart or error, a lost
  continuity check, a restore, an endpoint reapproval). While unverified, **every** inventory, inspect, log and
  start/stop/restart request is refused and nothing reaches the daemon.

Two probes, deliberately different:

| Probe | Healthy means | Used for |
| --- | --- | --- |
| `mandatary healthcheck` (the image `HEALTHCHECK`) | the process answers | "is the container alive" |
| `mandatary healthcheck --ready`, or `GET /api/v1/readyz` | the Docker self-protection proof is **verified** | "may Docker-backed requests succeed" |

Readiness is `false` (HTTP 503, or 404 when no socket is configured at all) when the socket is missing, the Docker
API is older than 1.44, the identity cannot be proven or conflicts, or the proof was dropped. A deployment that
is alive but not ready is correct and safe; it never serves Docker data. Do not point an orchestrator's restart
policy at `--ready`: restarting does not repair a missing binding.

## 8. Operating notes

* **Stop and restart**: `docker compose stop` sends SIGTERM; in-flight requests finish and storage closes within a
  few seconds (the stop grace is 15 s). Setup state, accounts, credentials and usage counts persist. Readiness
  returns only after a fresh verification.
* **Logs**: `docker compose logs mandatary`. Docker-backend transitions are single lines with a fixed reason
  (`unreachable`, `unsupported_api`, `identity`); no ID, UUID or socket path is logged.
* **Backup and restore**: the administrator exports and restores through the protected API/UI
  ([backup-restore.md](backup-restore.md)). A restore enters quarantine and activates nothing; recovery is the
  host-authorized ceremony. Usage statistics are **not** in a logical backup. Back up the data directory and the
  master key at the host level separately if you need them.
* **Updates**: pull and pin a new digest, `docker compose up -d`. The store migrates forward on start; there is no
  automatic downgrade. Read the release notes for the version, and rebuild the host helper from the same commit.
* **Resource use**: the image is about 26 MB as reported by the Docker image store in the hosted job (a larger
  figure appears under the containerd image store) and about 12 MB as the gzip-compressed layer sum, against the
  60 MB budget; the figures depend on the store, so treat them as an order of magnitude. Idle and load memory were **not** measured by this card; those budgets are P1.20 evidence.

## 9. Not implemented (planned) and not provided

Listed so nothing here is mistaken for a feature: the Phase 4 operations UI and its `:8081` listener; remote Docker
endpoints (mTLS, SSH); OIDC/Authentik and multiple administrators; access requests, temporary grants, discovery
and `exec`; webhooks and general notifications; policy-change audit log and own-session visibility; usage
reports (the counts are stored, there is no reporting UI or endpoint yet); an MCP stdio bridge; a published image
and a release. A socket proxy, high availability and multi-instance operation are untested.

## 10. Evidence and limits

The acceptance harness `tests/image/acceptance.py` never uses an ambient Docker endpoint: it requires an explicit
`--docker-host unix:///absolute/path` and the declared identity of that daemon (`--expect-daemon-id` and/or
`--expect-daemon-name`, from `docker info`), verifies it before it creates anything and again before it cleans up, and
refuses an Unraid host (`ISO-00`, `ISO-01`; hermetic tests: `python3 tests/image/test_isolation.py`). It also refuses,
before creating anything, a `--work` path beneath a group/world-writable directory, which the product's storage rule
would refuse (`WORK-00`; create the parent with `umask 022`). `SELF-13N` runs the binary natively against the real
daemon with a borrowed instance UUID and requires readiness to stay false. It ran on the
project's isolated test VM (Ubuntu 26.04, Docker Engine 29.9.3, API 1.56, Compose 5.7.1, `linux/amd64`). The recorded results, image digests, SBOM and scanner
output are in the pull request and review thread, not restated here as facts. Known limits of that evidence:

* **arm64** cannot run on that VM (no emulation configured). The `linux/arm64` image is built and run natively by
  the hosted arm64 CI job; its result is the evidence for that CPU, and an arm64 result from another source is
  not substituted.
* Ubuntu 24.04, Debian 13 and Unraid hosts were **not** exercised: one OS × one CPU was tested. A matrix claim
  needs those runs.
* The browser was not driven through the proxy by this harness; the HTTPS flow is driven by a scripted client with
  the real TLS proxy, the real SMTP/TLS fixture and the real daemon. Browser behaviour is covered by the repository's
  browser suites, not by this run.
* The mail fixture is a verified-TLS (STARTTLS, fixture CA) receiver on the isolated host; no real relay, no real
  mail, and no authenticated relay was exercised.
* Behind the proxy, per-IP throttling sees the proxy's address (no forwarded header is trusted by design).
* **No native real-socket mode** (SELF-13). With a real socket the process must be provably inside a container: its
  cgroup names the container, or it is the root of a private cgroup namespace (Compose on a cgroup v2 host). A process
  started directly on a host, a masked or absent `/proc/self/cgroup`, and a binding that names someone else's
  container all leave readiness false (`TestSELFNativeEvidenceWithARealSocketNeverVerifies`). A native run is possible
  only with the in-memory mock (`MANDATARY_DEV_MOCK_DOCKER=true`), which has no socket.
* **SQLite temporary files**: the root file system is read-only and the service has no `/tmp`. SQLite writes temporary
  files only for large sorts and similar operations; the acceptance flows did not need one, and behaviour with a very
  large data set is **unverified** (P1.20). Add a small `tmpfs: [/tmp]` to the service if it is ever observed.
* Daemon *event* subscription is not implemented: loss of continuity is detected by the per-request check and a
  periodic inventory heartbeat, and recovery is only a fresh verification. This is the documented fail-closed behaviour.
* No NIST, FIPS, product-qualification or Engine/OS compatibility claim follows from this document or from package
  minima; unresolved external evidence stays unresolved (nist-authentication-mapping.md).

## 11. P1.19 acceptance map (findings-ledger rows owned by this card)

`docs/findings-ledger.json` still lists these rows as `future_gate`. This table states what the P1.19 change adds; the status
change itself is for the reviewer and the orchestrator after the exact-head review, because the evidence is the review's to accept.
Scenario ids are those of `tests/image/acceptance.py` (`ISO`, `IMG`, `HARD`, `SELF`, `PRIV`, `STACK`); Go tests are in `cmd/mandatary`.

| Ledger row | What this change provides | Still open |
| --- | --- | --- |
| `GATE-PRODUCTION-PACKAGING`, `OPS-P119-composition` | `cmd/mandatary/product.go` composes the Docker backend, one shared authorizer, `ops.Service`, REST and MCP; `SetBackup`, `WithSafetyReset`, `WithTargetSource` and the authority-change notifier are wired (`ADMIN-targets`, `BACKUP-01..03`, `STREAM-01..03`; `TestSELF*`, `TestSafetyResetWiredToTheSharedAuthorizer…`). | none known |
| `C3-R473-O4-production-safety-reverify-loop`, `P112-event-reconnect-contract` | A verifier re-runs `VerifySelf` at start, after every loss of proof and on a periodic inventory heartbeat; recovery is only a fresh verification (`TestAnUnreachableSocketNever…`, `SELF-07`, `SELF-11D`, `STACK-09`). | No Docker *event* subscription exists (not built, by design); discontinuity is detected by the heartbeat and by the per-request check. |
| `P113-N1-session-push` | `ops.NotifyAuthorityChange` is passed to the administration service; an open follow stream ends on credential revocation within 5 s through the TLS proxy (`STREAM-02`). | Session-revocation push beyond credential revocation relies on the documented bounded pull interval. |
| `P115-D4` | `store.UsageConfig` (90 days, 1000 recent events, hourly prune) is passed explicitly and the ledger is `ops.Config.Usage`; exact totals verified against the real matrix (`USAGE-01..02`). | none known |
| `P117-note-no-endpoint-enable` | Decision: the first-administrator commit activates the seeded `local` endpoint (same transaction as `UnlockInstallation`; it grants no operation). Without it the endpoint stayed quarantined and could never be a policy target (`TestFirstAdminCommitMakesTheSeededLocalEndpoint…`). | none known |
| `OPS-production-restart-runtime` | Container restart on the same data directory keeps credentials, setup closed and readiness only after a fresh verification (`STACK-09..13`, `HARD-10..11`). | A host reboot, a power-loss crash and a real mail relay were not exercised. |
| `P109-R435-privdrop-success-never-executed` | The helper's successful drop is executed as root with only `CAP_SETUID`/`CAP_SETGID` against `0700`/`0400` files owned by 65532, so a revealed token proves the drop happened before any open; refusals as control (`PRIV-01..06`). | Executed on `linux/amd64`; arm64 only by CI. |
| `P109-R435-SETUP-10-11-12-not-run` | SETUP-10 through the real Compose service, TLS proxy and TLS SMTP fixture with a scripted client; SETUP-11 host-helper runbook on `linux/amd64` (arm64 by CI) (`STACK`, `SETUP-*`). | No real browser in this run; Unraid (SETUP-12) not exercised. |
| `P108-R425-tls-retention` | TLS termination in front of the application is exercised (`STACK-05..07`). | Session-row retention/deletion policy is not decided here; still open for P1.20. |
