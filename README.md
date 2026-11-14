# Mandatary

Mandatary is the working name for a security-first **Docker access intermediary**.
An administrator decides **who may perform which operation on which container**,
and Mandatary enforces that through one REST API and one MCP server, so tools and
AI agents get the access they need instead of the Docker socket. It is not an
unrestricted Docker API proxy: it exposes a fixed catalog of six operations (logs,
status inspection, configuration inspection, start, stop, restart), denies
everything not explicitly allowed, and refuses to see or operate on itself.

> ## In active development — the roadmap is not complete
>
> This repository is **under active development toward a first release** that has
> not happened. The Phase 1 roadmap is **not complete**: the release evidence
> (card P1.20) and the later phases are still to do. There is **no published
> image, no release, and no support or compatibility promise**. Components that
> passed their tests are not a finished, production-ready product, and nothing here
> claims NIST, FIPS, WCAG or product-qualification conformance.
> Mandatary is [primarily developed by AI agents](https://github.com/NicoTM77/Mandatary/wiki/Philosophy#how-mandatary-is-developed)
> under human review by NicoTM77, who alone merges.

## What works today (merged code and this repository's tests)

| Area | Status |
| --- | --- |
| Static Go binary with the embedded admin web app; SQLite store with authenticated encryption (master key required) | Implemented |
| First-administrator setup (host-local token, verified mail address, TOTP), password + TOTP/WebAuthn sign-in, account security, local recovery | Implemented ([setup and recovery](docs/setup-recovery.md)) |
| Policy administration: users, groups, agents, per-container allow/deny rules, agent credentials | Implemented ([policy](docs/policy-administration.md), [credentials](docs/agent-credentials.md)) |
| REST and MCP (Streamable HTTP) for the six container operations, one shared authorizer, revocation ends follow streams | Implemented ([API and MCP](docs/api-mcp.md), [authorization](docs/authorization.md)) |
| Docker backend with self-protection (Mandatary and its labelled peers are never visible or operable) | Implemented ([Docker backend](docs/docker-backend.md)) |
| Usage counters, logical backup and quarantine-first restore | Implemented ([usage](docs/usage-accounting.md), [backup/restore](docs/backup-restore.md)) |
| Production image (distroless, non-root, read-only root), Compose and reverse-proxy examples, readiness probe | Added by the P1.19 change; exercised on `linux/amd64` in an isolated environment, `linux/arm64` only by CI ([deployment](docs/deployment.md)) |

## Not implemented (planned)

Everything below is **planned and not yet implemented**: permission-scoped discovery,
access requests, approvals and temporary grants, controlled `exec`, usage *reporting*
(Phase 2); multiple administrators, Authentik/OIDC sign-in, personal session controls and
policy-change auditing (Phase 3); the separate container-operations web interface
and its listener (Phase 4); remote Docker endpoints, webhooks, an MCP stdio bridge, a
published image and a release. Known limitations and open items are in the
[findings ledger](docs/findings-ledger.md) and [deployment § Evidence and limits](docs/deployment.md#10-evidence-and-limits).

## Prerequisites

* **Develop / test:** Git, Bash, Make, Python 3 (standard library only), curl, tar, SHA-256
  tooling and a C compiler (Go's race detector). Go **1.27.4** (compatibility check on 1.26.11) and
  Node **24.22.1** are checked by the build; `bash scripts/bootstrap.sh` installs them into a
  project-local ignored directory. **No Docker is needed** to develop or run the unit tests.
* **Run the container image:** a Docker Engine with API 1.44 or newer and Compose on
  `linux/amd64` or `linux/arm64`, a TLS reverse proxy, a local (not network) filesystem for the data
  directory, and a verified-TLS SMTP relay for the security-notice mails.
* A **master key** (32 random bytes) provisioned outside the repository and a data directory with
  the permissions listed in [deployment](docs/deployment.md#3-prepare-the-host-before-the-first-start).
  Mandatary refuses to start on a missing, wrong or unsafely stored key.

## Develop

```bash
bash scripts/bootstrap.sh          # exact Go + Node into ./.toolchains (PATH and TMPDIR: see development.md)
make install && make check         # locked install, build, lint, unit and integration tests
make negative-control              # proves the gates fail when they should
make security                      # govulncheck, gosec, linters, npm audit gate
make dev                           # loopback server on 127.0.0.1:8080
```

`make dev` needs a master key and a private data directory ([development.md](development.md) explains both,
and the temporary-directory ownership rules the tests enforce). Without a Docker setting the server serves
the admin app and setup but **no Docker surface at all**. Set `MANDATARY_DEV_MOCK_DOCKER=true` to
get an in-memory mock backend; it never touches a Docker socket. Never point development at a production
Docker socket.

## Run the image (isolated test environment first)

Only after reading [docs/deployment.md](docs/deployment.md):

```bash
docker build --build-arg VCS_REF="$(git rev-parse HEAD)" -t mandatary:local .
cp deploy/env.example .env          # fill in every value; keep it out of Git
docker compose config -q && docker compose up -d
```

The Compose file publishes no port; put a TLS proxy in front (`deploy/compose.proxy.yml` is an example).
Mounting a Docker socket gives Mandatary root-equivalent power on that host. Do not run this on a
production host until the release evidence exists.

## Documentation

* [Wiki](https://github.com/NicoTM77/Mandatary/wiki) — introduction, philosophy, security model and limitations, developer guide.
* [Project notes](project-notes.md) → [Roadmap](roadmap.md) → [Technical decisions](technical-decisions.md) —
  requirements, phased scope and acceptance criteria, recorded architecture.
* [Security contracts](security-contracts.md), [support and deployment matrix](support-and-deployment-matrix.md),
  [Phase 1 plan](phase-1-plan.md) and [NIST authentication mapping](nist-authentication-mapping.md).
* Component references under [docs/](docs/): [storage](docs/storage-schema.md), [configuration and logging](docs/configuration-logging.md),
  [authorization](docs/authorization.md), [API and MCP](docs/api-mcp.md), [operations](docs/operations.md), [findings ledger](docs/findings-ledger.md).

The working name is not a claim of trademark clearance. Report security issues with **Report a vulnerability** on the
repository's [Security Advisories page](https://github.com/NicoTM77/Mandatary/security/advisories); do not open a public issue.
