# Mandatary support and deployment matrix — approved design baseline

## 1. Status and evidence boundary

**Snapshot: 2026-10-26.** Nico approved the specified toolchains, maintenance commitments and target test scope within the approved Go/React/TypeScript/Vite/SQLite architecture. It does not claim that Mandatary builds, is compatible, or has passed any product test. No packages, toolchains, Docker images or software were installed, pulled or run to produce this document. Approved Go/Node/npm pins are explicit; other candidate first-build pins must be reviewed and exercised in P1.01, with conflicts escalated rather than silently substituted; rolling support is not an unchecked `latest` release artifact.

Primary release/policy/registry endpoints below were fetched directly, independently of the initial research summary. Registry publication proves existence and declared constraints, **not** absence of vulnerabilities, a formal LTS promise or mutual compatibility. Dependencies without explicit upstream support promises remain subject to advisory/source review; do not advertise a security-maintenance guarantee that their publisher does not make. Nico accepted the support-policy package and Debian13 replacement on 2026-10-26. Compatibility and security results remain unverified until the corresponding authorized implementation/CI checks run.

## 2. Approved toolchains and candidate direct dependency pins

### 2.1 Toolchains and frontend

| Component | Approved toolchain / candidate library pin / supported line | Retrieved primary evidence and limitation |
| --- | --- | --- |
| Go | Production/toolchain **1.27.3**; CI also **1.26.10**, `go` minimum **1.26.0** after module verification. Support only latest patched releases of the newest two Go release lines while upstream supports them. | https://go.dev/dl/?mode=json&include=all and https://go.dev/doc/devel/release list those patches, both security fixes published 2026-10-19; release policy supports a line until two newer major releases exist. Several approved-module current releases declare Go 1.26.0. TD §5 records the approved 1.27.3/1.26.10 tuple; no Go1.23 support promise remains. |
| Node.js / npm | **Node 24.22.1 LTS + bundled npm 11.19.1**. Support Node 24's security-maintained LTS line for frontend tooling; no Node runtime in production image. | https://nodejs.org/dist/index.json identifies that exact pair, release 2026-10-20, LTS Krypton. https://raw.githubusercontent.com/nodejs/Release/main/schedule.json puts Node 24 in Maintenance LTS from 2026-10-20 to EOL 2028-04-30. Node 22 EOL is 2027-04-30; Node 26's LTS date **2026-10-28 is still future** at this snapshot, so do not call it LTS now. |
| React / React DOM | **19.3.1 / 19.3.1**, retain approved React 19 major. | https://registry.npmjs.org/react/latest ; https://registry.npmjs.org/react-dom/latest . DOM peer requires React `^19.3.1`. These stable tags have no deprecation marker; not a formal LTS claim. |
| TypeScript | Candidate **7.0.2**, current stable line; locked compiler, strict typechecking. | https://registry.npmjs.org/typescript/latest reports Node `>=16.20.0`. Candidate needs actual React types/plugin/emit validation; no automatic major upgrade if P1.01 evidence fails. TD did not select a TypeScript major. |
| Vite / React plugin | Candidate **8.3.5 / @vitejs/plugin-react 6.1.2**. | https://registry.npmjs.org/vite/latest and https://registry.npmjs.org/@vitejs/plugin-react/latest both declare Node `^20.19.0 || >=22.12.0`; plugin peer requires Vite `^8.0.0`. Node 24 satisfies these declared ranges; this is not an executed build result. Optional plugin peers are not silently made mandatory dependencies. |
| Tailwind CSS | Candidate **4.3.3**, same approved framework. | https://registry.npmjs.org/tailwindcss/latest . Browser/CSS and bundler-plugin compatibility must be exercised; no unsupported claim that old Safari works. |
| shadcn / Radix | Candidate shadcn CLI **4.22.1**; example used primitive `@radix-ui/react-dialog` **1.3.1**. Pin each actually used primitive separately; do not invent a single global Radix version. | https://registry.npmjs.org/shadcn/latest declares Node `>=20.18.1`; https://registry.npmjs.org/@radix-ui/react-dialog/latest admits React 19 peers. Generated shadcn components become maintained source, not a remote automatic update service. Unused primitives need not be installed. |
| Browser test runner | Proposed **@playwright/test 1.64.1** for the existing browser-test requirement, pin its browser revisions. | https://registry.npmjs.org/@playwright/test/latest declares Node `>=20`; https://playwright.dev/docs/browsers distinguishes Chromium/Firefox/WebKit projects from actual branded-browser/device coverage. This selects a minor implementation testing tool, not another application architecture. |

### 2.2 Approved Go module candidates

For each row, the exact primary endpoint is `https://proxy.golang.org/<module>/@latest`; the returned version's `/@v/<version>.mod` was also fetched. Module proxy `Origin` identifies the upstream tag/repository. Pin generated checksums, review advisories and resolve the **whole** graph before P1.01 accepts a candidate; do not infer compatibility from these separate minima.

| Approved module | Candidate version | Retrieved Go directive / note |
| --- | --- | --- |
| `modernc.org/sqlite` | `v1.61.0` | Go 1.26.0; release 2026-10-21. Verify embedded SQLite via runtime query in P1.03, not by equating this module version with upstream SQLite version. |
| `github.com/sqlc-dev/sqlc` | `v1.31.1` | Go 1.26.0; toolchain suggestion Go 1.26.2; generated-query tool, not separate DB. |
| `github.com/pressly/goose/v3` | `v3.29.0` | Go 1.26.0; resolves earlier release-summary ambiguity. |
| `golang.org/x/crypto` | `v0.58.0` | Go 1.26.0; retain approved Argon2id/encryption use, not a FIPS claim. |
| `github.com/go-webauthn/webauthn` | `v0.18.2` | Go 1.26.0; toolchain suggestion Go 1.27.1. Verify supported protocol flags/ceremonies; version is not provider/device conformance evidence. |
| `github.com/pquerna/otp` | `v1.5.0` | Go 1.12; returned release date 2024-12-31. Lack of a recent tag is not evidence of active security maintenance or insecurity. Preserve the selected library; advisory/source-review and RFC-vector tests are required, and maintenance concerns are escalated instead of silently replacing it. |
| `github.com/modelcontextprotocol/go-sdk` | `v1.8.0` | Go 1.25.0. Test actual Streamable HTTP protocol negotiation with a real client; SDK and MCP protocol version are different numbers. |
| `github.com/moby/moby/client` | `v0.6.2` | Go 1.24. Keep the approved client module, not a different SDK. Validate daemon negotiation, endpoint identity and restricted calls. |

TD's permitted internal router/encryption alternatives remain alternatives; no new stack comparison or arbitrary dependency is introduced here. Exact frontend test-runner/library choices and pins must be documented in P1.01 before exposing code; no need to install a speculative package inventory in Step 0.

## 3. Approved maintenance and deprecation policy

These are Mandatary's approved operator/developer commitments, not upstream guarantees or already running scheduled jobs.

- **Every PR and release:** locked graph, checksum/integrity verification, source/dependency review and scanners from TD §2.3; rerun all extant security/authorization regressions, relevant migration/browser/integration checks and exact-head independent review. Registry compromise, withdrawn version or credible active-exploitation notice triggers immediate triage, not the next monthly window.
- **Routine review:** weekly advisory/feed review; monthly patch-pin refresh and maintenance window; quarterly major-line/support-matrix review and before each product phase release. A new major is evaluated rather than automatically selected. No dependency bot auto-merge.
- **Triage clock:** evaluate a relevant published advisory within **2 business days**; actively exploited or reachable Critical exposure gets immediate triage and target mitigation within **24 hours**; reachable High within **7 calendar days**; other relevant security fixes within **30 days**. If a fix cannot safely ship in the target window, disable affected exposure or obtain explicit Nico risk disposition. No SLA excuses releasing a reachable unresolved CVSS≥7 vulnerability: TD's release gate still blocks.
- **Release-line policy:** newest supported Go line primary, preceding supported line compatibility CI; Node selected LTS until a reviewed transition. For libraries/frontend projects without formal LTS, support the latest reviewed patched stable line compatible with this architecture, not arbitrary historical majors. Record lack of upstream policy; discover unmaintained/archived/security-abandoned components before release, escalate replacement as necessary.
- **Deprecation:** announce a supported-line/tool/host removal at least **90 days** before planned withdrawal when feasible; start EOL migration planning at least 90 days before upstream end. Never promise support beyond upstream security maintenance merely to preserve notice. Urgent security withdrawal can be immediate with written impact/migration instructions and Nico approval of resulting compatibility changes. No feature/security downgrade or discarded persistent data under a patch label.
- **Update verification:** regeneration/diff review for sqlc/goose; Go race/auth/selector/restore tests, locked npm build/type/tests and relevant browser tests; production image SBOM/digest and vulnerability checks once the image exists. No downgrading algorithms/MFA or widening permissions to make an upgrade pass.

## 4. Approved supported-environment test matrix

The table defines concrete **test targets**, not a claim that those tests have run. Require current security patches within each named supported line. Unsupported systems fail support claims, not necessarily technical execution. No implicit support for every derivative distribution or every desktop-compatible socket.

| Layer | Approved initial test/support target | Verification/primary evidence |
| --- | --- | --- |
| Production OS | **Ubuntu 24.04 LTS and 26.04 LTS; Debian 13**. Debian 12 host remains an optional compatibility target only if relevant LTS package coverage and test ownership are explicitly accepted. | https://ubuntu.com/about/release-cycle gives standard security maintenance through May 2029/May 2031. https://www.debian.org/releases/ gives Debian 13 full support to 2028-08-09 and LTS to 2030-06-30; Debian 12 full support ended 2026-07-11, LTS to 2028-06-30. Host LTS coverage is **not** a promise that a separate distroless image is maintained. |
| Docker host package/CPU | `linux/amd64` and `linux/arm64`, on the named OS lines. | https://docs.docker.com/engine/install/ubuntu/ explicitly lists Ubuntu 24.04/26.04 and amd64/arm64; https://docs.docker.com/engine/install/debian/ covers Debian distribution/architecture packaging. Build and run the actual artifact on both CPU targets; successful cross-compilation alone is insufficient. |
| Docker Engine | Candidate **29.9.2**, supported 29.x **latest security-patched** line; qualify the previous patch/minor only by fixture results and vendor maintenance evidence. Do not promise old Engine 19 merely because API 1.40 exists. | https://api.github.com/repos/moby/moby/releases/latest returned `docker-v29.9.2`, published 2026-10-20. https://docs.docker.com/reference/api/engine/ is lagging/internally inconsistent (matrix 29.8→1.55, example reports1.56); runtime negotiation/actual release metadata decide supported API. |
| Engine API | Negotiate highest common API. Declare **1.44** the proposed application minimum and test refusal below it, plus current daemon negotiation; do not hardcode a maximum from a stale table. | The same official matrix lists 29.0–29.2 minimum1.44 and later table minima1.40; a higher application minimum is a proposed bounded test surface, not a Docker universal requirement. P1.12/14 must validate SDK/Engine candidate compatibility and fail safely on unsupported API before product support is claimed. |
| Compose CLI | Candidate **5.6.1**, current stable `docker compose` plugin, exact CI pin. No blanket legacy v2.24 support promise. | https://api.github.com/repos/docker/compose/releases/latest returned `v5.6.1`, published 2026-10-21, `prerelease=false`. Baseline selected Compose, not a major version. P1.19 validates the actual Compose Specification file, hardening/health flags and clean install on the proposed target; CLI major is not file-format version. |
| macOS development | **macOS 15, 26 and 27**, latest security updates, native mock workflow. Go/Node architecture support must be checked for each Intel/Apple Silicon target; native real-socket access has no self-protection exemption and fails closed unless own-container identity is reliable; real tests use isolated controlled fixtures under security-contracts.md §S1.4. | https://support.apple.com/en-us/100100 lists security updates for these OS lines in the live snapshot. Apple does not thereby promise an indefinite fixed three-release support policy. Do not turn Go's lower macOS technical minimum into a security-maintenance promise. |
| Linux development | Ubuntu 24.04/26.04 LTS, Debian 13 on amd64/arm64; same Go/Node/npm pins. Mock-backend iteration/tests never require rebuilding the application container. | Approved developer workflow plus OS sources above; actual clean-checkout commands are TD §10.4, version outputs captured by P1.01. |
| Windows/WSL2 | Not first-class Phase 1 targets; WSL2 best effort only, no tested/support assertion. | No Windows support requirement was recorded; accepting this proposed initial matrix does not claim Go cannot execute on Windows. |
| Optional Docker Desktop/OrbStack/Colima | Developer convenience, not production-daemon equivalence. No native exception is approved: §S1.4 requires fail-closed identity and isolated real tests; default mocks remain available. | No unverified desktop version tuple is advertised as certified. Actual isolated Docker Engine fixture tests, not socket shape, establish adapter support. |
| Browser floor and rolling policy | **Chrome/Edge ≥155, Firefox ≥157, Safari ≥26**; within those floors, current stable + preceding major, latest patched builds. A preceding major no longer receiving fixes is compatibility-only, not security-recommended. Require a maintained OS/browser for security-sensitive deployment. | https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions?pageSize=2 returned Chrome156/155; https://product-details.mozilla.org/1.0/firefox_versions.json returned Firefox158.0.1; https://support.apple.com/en-us/100100 lists Safari27 and26 updates. https://edgeupdates.microsoft.com/api/products?view=enterprise returned Edge156.0.4314.42 (2026-10-22) and155.0.4283.62 (2026-10-16) for the stable channel. Floors are proposed compatibility boundaries, not promises that an obsolete prior major receives security fixes. Qualify exact branded browser fixtures at P1.01/16. |
| Browser evidence | Locked Playwright Chromium/Firefox/WebKit runs plus branded Chrome/Edge and actual Safari/WebAuthn smoke tests, exact versions recorded at release. Device-local keys/platform passkeys need provider/device evidence from the NIST map. | https://playwright.dev/docs/browsers . WebKit automation is not proof of Safari identity, OS keychain/passkey behavior or physical hardware; virtual authenticators prove RP behavior, not vendor biometric/FIPS internals. |

### Measurable matrix acceptance tests

- **SUP-01 / P1.01:** clean locked install/build/typecheck/race tests with Go1.27.3 primary and1.26.10 compatibility, Node24.22.1/npm11.19.1; CI records actual versions. Full graph constraints and generated output must pass; unsupported pins/deprecated packages or an unresolved scanner gate block acceptance.
- **SUP-02 / P1.03:** query actual embedded SQLite version; WAL/FKs/migrations/concurrency and restart on both CPU targets. Never substitute upstream SQLite headline version as evidence for modernc's build.
- **SUP-03 / P1.12–14:** same restricted-operation suite against Docker29 candidate with negotiation; API below1.44 denied before operations, incompatible server/client safe, unknown fields sanitized, SELF/authorization cases unchanged. Unsupported fixture target cannot be counted as green.
- **SUP-04 / P1.16–17:** auth/setup/step-up/recovery and user/policy flows at each declared browser floor and current stable supported engine; dark/light modes, CSP/CSRF/origin, secret leakage and required WebAuthn behavior. Record separate branded browser/manual-device evidence and known limitations.
- **SUP-05 / P1.19–20:** Compose5.6.1 clean install on every accepted OS×CPU combination, non-root/read-only/caps/data ownership/self-identity/setup token flow, both image digests and static linkage, Trivy and SBOM. Use the approved Debian13 base pinned to reviewed digests; do not retain the superseded Debian12 runtime baseline.
- **SUP-06 / each release:** document/source/advisory support check, EOL/removal notices and maintenance-window compliance; all extant security/authorization regressions and independent exact-head review. No auto-merge or silent exception.

## 5. Approved Debian13 runtime amendment

The superseded image was **`gcr.io/distroless/static-debian12:nonroot`**. The live official README now lists Debian13 and states that other image tags are deprecated and no longer updated: https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/README.md . Its current support policy lists Debian13 timelines, not an ongoing Debian12 stream: https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/SUPPORT_POLICY.md . This is stronger evidence than the earlier summary's unresolved suspicion. An old tag/digest still resolving does not establish security maintenance; no image pull was performed.

**Approved 2026-10-26:** amend only the base tag to **`gcr.io/distroless/static-debian13:nonroot`**, preserving a static Go binary, embedded assets, non-root runtime, read-only root, volume requirements and no extra runtime service. Pin the verified multi-architecture digest during authorized P1.19 work and rerun footprint/CA/timezone/architecture/security tests. TD §5 adopts this amendment. Actual digests/builds/architecture/runtime/security/footprint results are P1.19–20 release evidence, not Step 0 deliverables. Failure to meet the approved matrix/budgets blocks release and must be escalated; approval does not waive verification.

## 6. Deployment workflow qualification

Compose and Unraid operator runbooks must both demonstrate the host-local setup/recovery procedure in security-contracts.md §S3, using the actual container UID/GID and host data mapping without an interactive application-container shell. Unraid workflow compatibility is a required fixture/runbook outcome, not blanket certification of every Unraid/embedded-Engine version; record the exact tested host/Engine/API tuple before any support claim. Qualification uses an isolated controlled test environment or documented operator validation, never production Unraid Docker integration tests. Neither this matrix nor Step 0 approval authorizes a live deployment.

## 7. P1.05 approved frozen-password amendment and maintenance

Nico's original P1.05 comments95/98/99 select a portable pure-Go, fixed Unicode17
stabilized ordinary-NFC profile with version-matched assigned repertoire and a
narrow reviewed x/text0.43.0 source/table adaptation. This is an explicit password
compatibility contract across Go1.27.3 and1.26.10, not an upstream-current-Unicode
or general OS/browser support claim. Reject malformed/non-scalars/frozen17 Cn;
retain assigned/private-use/control/format characters and explicit user CGJ,
without inserted stream-safe CGJ, NFKC, trim or casefold. Immutable verifier
profile/version and bounded licensed reproduction/update rules are in
[the password contract](docs/password-authentication.md). The unchanged approved
x/crypto0.58.0 candidate is used for Argon2id; no alternate crypto/normalization
service, module replacement, build-tag spoof or toolchain downgrade is selected.

The project maintainers/coder must track upstream security changes to copied
normalization code explicitly under §3; module advisory scanning alone cannot
recognize/remediate the snapshot. Independent update review requires the official
fixed17 corpus, full repertoire/decomposition bounds, negative/fuzz/race tests,
both locked compiler semantics/golden outputs and full security regressions.
Stored canonicalization semantics are not silently upgraded with dependency pins.
Comment101's task-local finite race virtual-memory allowance does not change
production footprint promises, runtime configuration or any supported matrix gate.
