# Container-free development

## Scope and safety

P1.01 is a **development skeleton**, not a Docker-access product. It embeds a
React 19 / TypeScript / Vite / Tailwind SPA in a static Go binary. The listener
is fixed to `127.0.0.1:8080`; only `/` and compiled `/assets/*` files are served.
There is no SPA fallback, directory listing, API, MCP, login, setup, database,
Docker backend, credential handling or mail delivery. Unknown routes return
404 and non-read methods return 405. Do not expose this skeleton as production.
Do not mount, connect to or test against any production Docker socket.

P1.02 adds domain identifiers and structural SQLite/goose/sqlc models with real
file-backed tests; the server still does not open the database. See the
[schema/coverage contract](docs/storage-schema.md) and
[isolated sqlc dependency disposition](docs/sqlc-dependencies.md).
The approved `internal/{domain,auth,authz,docker,store,api,mcp,backup}` boundaries
remain in force. Runtime repository/encryption, authentication, authorization,
mail and Docker behavior stay in their owning later cards. No fake endpoints.

## Prerequisites and isolated setup

Use Git, Bash, Make, curl, tar, SHA-256 tooling (`sha256sum` or macOS `shasum`),
and a C compiler for Go's race detector. No container build or Docker is needed.
Linux/macOS amd64/arm64 are bootstrap targets; cross-platform runtime qualification
is not implied by the installer or a Linux test. Windows is not first-class.

Approved tuple (checked before install/build/test):

- Go **1.27.3** primary; **1.26.10** compatibility (`GOTOOLCHAIN=local`).
- Node **24.22.1 LTS**, including npm **11.19.1**. Node is build tooling only.

Either put that exact tuple on PATH yourself or install into a project-local,
ignored directory (never system or Hermes tooling):

```bash
bash scripts/bootstrap.sh
export PATH="$PWD/.toolchains/go1.27.3/bin:$PWD/.toolchains/node24.22.1/bin:$PATH"
make install
make check
make negative-control
make tools
make security
```

`MANDATARY_TOOLCHAIN_DIR` can select another private writable installation root.
Bootstrap downloads official archives over HTTPS, checks the reviewed SHA-256
manifest before extraction and validates resulting versions. Existing versioned
installations are reused and version-checked, not blindly overwritten. Run one
bootstrap per installation root at a time. The checksums are pinned from
[Go's complete release metadata](https://go.dev/dl/?mode=json&include=all) and
[Node's v24.22.1 manifest](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt).
Updating either the versions or checksums requires review, not an unlocked latest
install. A missing/unavailable approved version is an error, not a fallback.

For compatibility, bootstrap separately and use the matching PATH/selector:

```bash
MANDATARY_GO_VERSION=1.26.10 bash scripts/bootstrap.sh
export PATH="$PWD/.toolchains/go1.26.10/bin:$PWD/.toolchains/node24.22.1/bin:$PATH"
MANDATARY_GO_VERSION=1.26.10 make install check negative-control
```

## Commands and locks

| Command | Actual work |
| --- | --- |
| `make versions` | Fail closed unless exact approved Go/Node/npm tuple is active; print actual versions. |
| `make install` | `npm --prefix web ci`, validate complete npm tree, download/verify Go modules. |
| `make build` | TypeScript no-emit check + Vite/Tailwind build, then `CGO_ENABLED=0 go build -trimpath` with real embedded assets. |
| `make test` | Node tooling tests, non-watch Vitest/Testing Library tests, `go test -race -count=1 ./...`. Run `make build` first in a fresh checkout. |
| `make check` | Build, formatting, Go vet, strict typecheck, ESLint + security/hooks rules and all tests. |
| `make sqlc` | Verify/download the isolated locked `tools/sqlc` module, build approved sqlc1.31.1 locally. |
| `make generate` | Rebuild sqlc and regenerate models/queries from goose SQL and `sqlc.yaml`. |
| `make generate-check` | Require previously built sqlc; non-mutating generated-output comparison. `make check` builds it and invokes this automatically. |
| `make tool-security` | Require existing pinned govulncheck; build/verify sqlc, then scan BOTH binary and isolated tool source. Automatically required by `make security`. |
| `make tools` | Build pinned govulncheck/gosec/golangci-lint from separate `tools/go.mod` + `tools/go.sum` into ignored `bin/tools`. Requires primary Go. |
| `make security` | Run all three Go scanners and `npm audit --audit-level=high`; tool/advisory errors fail the command. Requires install/build/tools. |
| `make negative-control` | Inject an intentionally invalid route-denial expectation into the ordinary race suite; require exit 1 and exact assertion signature. Build/setup/race-detector failures do not qualify. |
| `make dev` | Build and serve the embedded SPA at `http://127.0.0.1:8080`; Ctrl-C to stop. |
| `make frontend-dev` | Vite loopback-only frontend iteration; no API proxy or Docker access. |

The root Go module now locks the approved SQLite/goose test/model dependencies in
`go.mod`/`go.sum`. Scanner dependencies are isolated in `tools/`; the generator
has its separate `tools/sqlc/` module. Neither is linked into the shipped binary.
Frontend direct versions and all transitive integrities are
locked in `web/package-lock.json`; `.npmrc` enforces engines and exact saves.
Vitest + jsdom + Testing Library exercise rendering/theme behavior without a
browser service; they do **not** establish branded-browser/WebAuthn qualification.
ESLint uses Babel's TypeScript/JSX syntax parser alongside strict `tsc` (including
unused locals/parameters); no parser fallback or disabled security rules.

npm tooling ships some Go source files. The tested postinstall writes a Go module
boundary **only inside generated `web/node_modules`**, keeping `go test ./...`
focused on repository code without excluding an application package. npm audit
still sees the full dependency graph. Do not use `--ignore-scripts` and then
claim this setup succeeded.

Go package compilation defaults to serial (`-p=1`, `GOMAXPROCS=2`) for small
machines. No platform-specific CPU-affinity helper is a product prerequisite.
In the restricted Hermes execution environment, use the separately authorized
local launcher and resource ceiling; positive niceness does not limit memory.
Do not run multiple memory-heavy tool builds concurrently.
Make additionally bounds its child processes with GOMEMLIMIT=768MiB/GOGC25 and
serializes targets; these are local process settings, not runtime configuration.

## Tests and CI

The PR workflow pins actions to immutable commit SHAs, uses read-only contents
permission, disables persisted checkout credentials, and runs both exact Go
versions with locked Node/npm. Baseline and Security checks are required evidence,
not permission to merge; Nico controls merge and independent native review is
required for the exact head.

`tests/security/surface_test.go` rejects unimplemented product/raw-Docker paths.
Its negative control injects `/` (a genuinely public static route) into that
must-be-404 matrix; the unchanged race command must fail. CI invokes the control
and fails if the assertion is no longer detected. These are static-exposure
regressions, **not** implemented authorization or SELF conformance tests.
`tests/security/fixtures` seeds deterministic clocks and independent active,
expired, revoked, quarantined, cross-endpoint and protected-target inputs for
later suites. No fixture contains a real credential or talks to a daemon.

SUP-01 is the install/build/race/toolchain gate here. SELF/RESTORE/SETUP and N63B4
product implementations, physical-provider evidence, browser/device qualification,
Docker integration, image scanning and footprint budgets remain assigned to their
owning later cards. There is no image to scan in P1.01 and no NIST/FIPS, runtime,
release-readiness or production compatibility claim from this skeleton.

## Support and updates

The approved [support matrix](support-and-deployment-matrix.md) remains binding:
weekly advisory review, monthly patch review, quarterly supported-line review;
triage relevant advisories within two business days, immediate active-exploitation
triage, target mitigation of reachable Critical within 24 hours and High within
seven days. An unresolved reachable CVSS >=7 finding blocks release regardless
of target windows. No auto-merge, automatic major upgrade or EOL-support promise.
Support removals normally require 90 days' notice; urgent security withdrawal
requires written impact/migration guidance and Nico's disposition. Every update
needs locked graph/build/security regression evidence and independent exact-head
review. Routine review commitments are not claims that a scheduler was installed.
