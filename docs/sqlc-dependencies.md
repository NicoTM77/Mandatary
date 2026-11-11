# sqlc dependency disposition (P1.02)

## Authorization and graph boundary

Retain approved **sqlc v1.31.1**, Go1.27.4/1.26.11 and Node24.22.1/npm11.19.1.
The owner-approved exception on original P1.02 permits explicitly pinned security
updates only in the **new** `tools/sqlc` module, plus required compatibility
transitives. App, frontend and scanner locks are unchanged by this remediation.
No `go get -u`, replacement/fork, suppression, waiver or scanner upgrade is used.
The generator is local tooling; it is not linked into the static HTTP binary.

The original WIP graph has recorded failing binary/source govulncheck evidence
(nine/eight symbol findings), not an application-runtime exploit demonstration.
A minimal first attempt using grpc1.83.1 still failed binary scanning with
GO-2026-6443: the advisory's patched branch floor is **1.83.2**. The error was
not waived or treated as success. New source/binary scans are mandatory; package
publication and version comparisons do not establish security/compatibility.

## Every selected module/lock change from preserved WIP

| Module | WIP → selected | Reason |
| --- | --- | --- |
| `golang.org/x/net` | 0.49.0 → **0.62.0** | GO-2026-6603/6611/6612/6617 fixed0.60; verbose rescan additionally identified HTML module advisories GO-2026-6860/6866 fixed0.62, so0.60 was not retained |
| `golang.org/x/text` | 0.36.0 → **0.43.0** | GO-2026-5970/6629 need≥0.39/0.41; x/net0.62 **requires0.43** |
| `google.golang.org/grpc` | 1.80.0 → **1.83.2** | GO-2026-6061 (including High GHSA-hrxh-6v49-42gf),6348,6443;1.83.1 binary remained affected by6443, fixed branch1.83.2 |
| `golang.org/x/sys` | 0.43.0 → **0.49.0** | Minimum required by net0.62 (grpc1.83.2 needs0.47) |
| `golang.org/x/sync` | 0.20.0 → **0.24.0** | Minimum required by text0.43 (grpc requires0.22) |
| `cel.dev/expr` | 0.25.1 → **0.25.2** | grpc1.83.2's module requirement |
| `google.golang.org/genproto/googleapis/api` | 20260120221211-b8f7ae30c516 → **20260526163538-3dc84a4a5aaa** (v0.0.0 pseudo-version) | grpc1.83.2's requirement |
| `google.golang.org/genproto/googleapis/rpc` | same old/new pseudo-versions as api | grpc1.83.2's requirement |
| `go.opentelemetry.io/otel`, `/metric`, `/sdk`, `/sdk/metric`, `/trace` | 1.39.0 → **1.44.0** (go.sum only) | grpc1.83.2 requires1.44; dependency test closure retained by tidy, no new direct dependency |

These are the entire changed module/version set in `tools/sqlc/go.mod`/`go.sum`;
all changed checksum pairs follow the same versions. The **full MVS graph** also
contains the following required changes, even where Go's lazy package closure
needs no new local go.sum entry. These are not discretionary extra upgrades;
`go list -m all` was compared against a pristine scratch copy of the WIP module.

| Additional graph-only module | WIP → selected | Required edge |
| --- | --- | --- |
| `cloud.google.com/go/auth` | absent → 0.18.2 | grpc1.83.2 |
| `github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp` | 1.31.0 → 1.33.0 | grpc1.83.2 |
| `github.com/cncf/xds/go` | 20251210132809-ee656c7534f5 → 20260202195803-dba9d589def2 (v0.0.0 pseudo-versions) | grpc1.83.2 |
| `github.com/envoyproxy/go-control-plane/envoy` | 1.36.0 → 1.37.0 | grpc1.83.2 |
| `github.com/envoyproxy/protoc-gen-validate` | 1.3.0 → 1.3.3 | grpc1.83.2 |
| `github.com/felixge/httpsnoop` | absent → 1.0.4 | grpc1.83.2 |
| `github.com/go-jose/go-jose/v4` | 4.1.3 → 4.1.4 | grpc1.83.2 |
| `github.com/google/s2a-go` | absent → 0.1.9 | grpc1.83.2 |
| `github.com/googleapis/enterprise-certificate-proxy` | absent → 0.3.11 | grpc1.83.2 |
| `github.com/googleapis/gax-go/v2` | absent → 2.17.0 | grpc1.83.2 |
| `github.com/spiffe/go-spiffe/v2` | 2.6.0 → 2.7.0 | grpc1.83.2 |
| `go.opentelemetry.io/contrib/detectors/gcp` | 1.39.0 → 1.44.0 | grpc1.83.2 |
| `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` | absent → 0.61.0 | grpc1.83.2 |
| `golang.org/x/crypto` | 0.48.0 → 0.58.0 | net0.62 |
| `golang.org/x/mod` | 0.34.0 → 0.41.0 | text0.43 |
| `golang.org/x/oauth2` | 0.34.0 → 0.36.0 | grpc1.83.2 |
| `golang.org/x/term` | 0.39.0 → 0.47.0 | net0.62 |
| `golang.org/x/tools` | 0.43.0 → 0.51.0 | text0.43 |

Other existing historical checksum entries remain, not new selected runtime
dependencies. Inspect
`go -C tools/sqlc mod graph` and the downloaded, checksum-verified module files
for the exact edges. net/text remain Go1.26.0, grpc Go1.25.0, within the existing
approved minimum. Compatibility is nevertheless proved by actual locked builds,
not those minima alone. No other dependency or toolchain changes are authorized.

Commands used to resolve the bounded graph (not routine unlocked build steps):

```sh
go -C tools/sqlc get golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 google.golang.org/grpc@v1.83.1
go -C tools/sqlc get google.golang.org/grpc@v1.83.2
go -C tools/sqlc get golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.83.2
go -C tools/sqlc mod tidy
```

## Required repeatable gates

`make sqlc` downloads/verifies the locked module and rebuilds locally. CI's
existing Baseline `make check` invokes non-mutating `sqlc diff --no-remote` and
real generated-output fixture tests. The fixture first generates a tiny local
SQLite model, then proves that the same Make target rejects stale and missing
output and invalid SQL without repairing the stale input. Schema/domain tests
exercise the actual generated code against pure-Go SQLite.

Existing Security `make security` now requires `make tool-security` first:

```sh
go -C tools/sqlc mod verify
go -C tools/sqlc build -trimpath -o ../../bin/tools/sqlc github.com/sqlc-dev/sqlc/cmd/sqlc
bin/tools/govulncheck -mode=binary bin/tools/sqlc
(cd tools/sqlc && ../../bin/tools/govulncheck -show traces github.com/sqlc-dev/sqlc/cmd/sqlc)
```

Both binary and source commands must exit0; tool/network/advisory errors are not
passing checks. App govulncheck/gosec/golangci-lint/npm audit remain in place.
Verbose scanning also identifies **uncalled** package advisory GO-2026-6094 /
GHSA-gcjh-h69q-9w9g in cel-go0.28.0. GitHub rates it Moderate; Go's record lists
`ext.NativeTypes`/`ext.ParseStructTag`. Neither is called in sqlc; its only ext
registration is `ext.Strings` in the vet implementation, and both symbol/source
scans report zero affected symbols. Our configuration invokes only local SQLite
generation/diff with remote execution disabled, not CEL vet/native struct input.
This is a documented not-reachable tool-package finding, **not** an application
exposure, suppression or claim that the whole dependency graph has no advisories.
cel-go remains pinned: a non-compatibility security upgrade of this separate
module is outside the approved exception. Independent review must verify this
disposition; a reachable finding or use of those functions requires renewed
owner disposition, not continued reliance on this assessment. Go/GitHub differ
on patched release metadata (0.30.0 vs0.29.0); no upgrade is inferred from either.
Make runs heavy jobs serially with process-local GOMAXPROCS2/-p1 and
GOMEMLIMIT768MiB/GOGC25; restricted worker additionally uses approved affinity2–5
and nice+10. No system/runtime limit or security configuration changes.

Regenerate using the patched graph with the preserved WIP config and compare to
WIP files, then regenerate with the corrected config. The intentional model diff
is only `AdministrativeRole.EndpointID: domain.EndpointID → *domain.EndpointID`
to represent SQL NULL global scope; no migration/query semantics change is
required for that fix. Repeat generation/diff must be drift-free. Exact executed
commands, failures, final results, head and CI receipt belong to the original
card's review report; this document defines the gate, not an everlasting clean
advisory result. No guarantee of future advisory absence is made.
