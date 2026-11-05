# Mandatary — Step 0 Technical Decisions & Architecture Baseline

## Status and Purpose

This document records the agreed **Step 0 foundational technical decisions** for **Mandatary**, resolving the 12 decision areas defined in `roadmap.md` and the open design questions in `project-notes.md`.

All decisions in this document are evaluated against Mandatary's two primary engineering principles:
1. **Security-First Architecture:** Default-deny authorization, defense-in-depth around the Docker socket, NIST SP 800-63B-4 AAL2 compliance, strict parameter validation, and zero raw Docker API proxying.
2. **Long-Term Maintainability:** Type-safe code generation, minimal external runtime dependencies, single static binary deployment, deterministic migrations, and fast container-free local iteration.

**Final decision authorization: 2026-10-26.** Nico approved the six final Step 0 recommendations with qualifications recorded below and in `step-0-reconciliation.md`. This baseline and its security/NIST/support contracts are approved design, not an implementation, compatibility-test result, or NIST conformance assertion. The existing 0.13 independent readiness gate determines Step 0 completion; a separate explicit Nico authorization is required for Phase 1 coding. No production deployment or PR merge is authorized.

---

## 1. Release Scope & Operation Catalog (Decision 0.1)

### 1.1 No Raw Docker Proxy
Mandatary **never** forwards raw HTTP requests or arbitrary query parameters to `/var/run/docker.sock`. Every supported container operation is implemented as a dedicated handler that validates caller authorization, parses a strict schema, invokes the official Docker Go SDK (`moby/client`), and constructs a sanitized response. Any Docker Engine operation not explicitly listed below is unavailable and returns `403 Forbidden` / `404 Not Found`.

### 1.2 Phase 1 Operation Catalog
| Operation | Granularity / Permission Key | Allowed Parameters & Constraints | Security & Sanitization Rules |
| :--- | :--- | :--- | :--- |
| **Logs** | `container:logs` | `tail` (max default 10,000 lines), `since`, `until`, `timestamps` (bool), `follow` (bool, bounded by session/grant expiry), `stdout`/`stderr` selection. | Stream is immediately terminated if the caller's token, session, or temporary grant expires or is revoked. |
| **Inspect (Status)** | `container:inspect_status` | None (identifies target container via endpoint + container selector). | Returns **only** safe operational metadata: container ID, name, image name & digest, running state/status, exit code, health check status, started/finished timestamps, port mappings, and safe labels. |
| **Inspect (Config)** | `container:inspect_config` | None. | Returns volume mounts, network settings, entrypoint/cmd, and resource limits. **Environment variables matching secret patterns** (`*KEY*`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*PASS*`, `*CREDENTIAL*`, `*DSN*`, or high-entropy values) are **redacted** (`[REDACTED]`). Raw unredacted environment variables are never exposed. |
| **Start** | `container:start` | None (cannot override container configuration or host mounts). | Starts an existing stopped container. Cannot create new containers. |
| **Stop** | `container:stop` | `timeout_seconds` (bounded: 1–300s, default 10s). | Gracefully stops a running container. |
| **Restart** | `container:restart` | `timeout_seconds` (bounded: 1–300s, default 10s). | Restarts a container within the bounded timeout. |

### 1.3 Phase 2 Operation Additions (`exec` & `discover`)
- **Discovery (`endpoint:discover`):** Optional independent permission allowing a principal to list containers on an endpoint without granting any operation permissions (see Section 8).
- **Exec (`container:exec`):** Introduced in Phase 2 under strict policy controls:
  - **Argument Array Only:** Requires an explicit `argv` string array (`["cmd", "arg1", ...]`). Shell wrappers (`sh -c`, `bash -c`) are rejected unless the policy rule explicitly enables `allow_shell: true`.
  - **Command Allowlisting:** Policy rules for `container:exec` support required command/prefix allowlists (e.g., allowing only `["php", "artisan", "migrate:status"]` or `["pg_isready"]`).
  - **Privilege Restrictions:** `Privileged: false` is hardcoded and cannot be overridden. `User` override defaults to the container's configured user; running as `root` (`0`) when the container defaults to non-root requires an explicit `allow_root_exec: true` policy flag.
  - **Resource & Time Bounds:** Mandatory execution timeout (default 60s, max configurable per policy), maximum buffered output capture (default 4 MB) for non-streaming API/MCP calls, and immediate process/stream termination upon credential or grant revocation.
  - **Interactive TTY:** API and MCP `exec` calls are strictly **non-interactive** (`Tty: false`, `AttachStdin: false`). Interactive TTY streaming (`Tty: true` over WebSocket) is restricted exclusively to the Phase 4 Container-Operations Web UI when explicitly permitted by policy.

---

## 2. Threat Model & Security Boundaries (Decision 0.2)

### 2.1 Trust Boundaries & Actors
- **Host Docker Socket (`/var/run/docker.sock`):** Treated as root-equivalent privilege on the target Docker host. Mandatary is the sole intermediary.
- **Self-Protection Invariant:** Mandatary blocks all visibility, inspection and operations targeting itself or protected Mandatary peers across API, MCP and later Operations UI. Identity is endpoint/daemon-qualified and corroborated from runtime/container identity, configured ID and protected labels; none is a name-only or unverified override. Missing/conflicting identity, recreation or lost event continuity closes the operational boundary and cancels active streams until trustworthy re-identification completes. `security-contracts.md` §S1 defines states, peer inventory, immutable-target dispatch and SELF negative acceptance cases. No policy, administrator or native-runtime exemption bypasses this invariant.
- **Policy Administrators:** Trusted to manage users, groups, agents, policies, and endpoints via the Policy Administration UI (`:8080`). Policy Administrators hold **zero** implicit container operation privileges.
- **Container Operators / Human Users:** Authenticated human users who may own agents or use the Phase 4 Operations UI (`:8081`) within their explicitly granted container permissions.
- **Non-Human Agents (API / MCP Clients):** Untrusted/semi-trusted automated principals constrained strictly by scoped Bearer tokens and default-deny policies.

### 2.2 Network Exposure & Reverse Proxy Assumptions
- In production, TLS termination is handled by a reverse proxy (e.g., Caddy, Traefik, Nginx) in front of Mandatary, or via native TLS configuration.
- Mandatary enforces `Secure`, `HttpOnly`, `SameSite=Lax` (or `Strict`) session cookies, CSRF protection on all state-changing browser routes, strict Content Security Policy (CSP) headers, and explicit Origin validation for WebAuthn and WebSocket endpoints.
- **Recommended Deployment Hardening:** The repository's production `docker-compose.yml` runs Mandatary as a non-root UID/GID with `read_only: true` root filesystem, `cap_drop: [ALL]`, `no-new-privileges: true`, and documents optional deployment alongside a read/write-restricted socket proxy.

### 2.3 Security Review & Release-Blocking Rubric
- Every release phase runs automated static analysis, vulnerability scanning, and authorization regression suites:
  - Go: `govulncheck`, `gosec`, `golangci-lint`
  - Frontend: `npm audit --audit-level=high`, ESLint security rules
  - Container Image: `trivy image --severity HIGH,CRITICAL`
- **Release Gate:** Any unresolved vulnerability with **CVSS v3/v4 >= 7.0 (High or Critical)** in reachable code or base image packages, or any failing negative authorization test, is an automatic **release blocker**.

---

## 3. Identity & Authorization Model (Decision 0.3)

### 3.1 Principals
1. **Human Users (`users`):** Have local credentials (password + MFA) and/or federated OIDC identity (Phase 3). A human user can be assigned administrative roles (`super_admin`, `endpoint_admin` in Phase 3/5) and/or belong to multiple `groups`.
2. **Groups (`groups`):** Logical collections of Human Users and/or Non-Human Agents used to assign shared policies.
3. **Non-Human Agents (`agents`):** First-class machine principals representing an external tool or AI agent. Every agent **must** be linked to either:
   - An **owning Human User** (`owner_user_id`) for direct individual accountability, OR
   - An **owning Group** (`owner_group_id`) for shared service agents.
   - *Important:* An agent does **not** automatically inherit its owning human user's personal permissions; the agent only receives permissions explicitly granted to the `agent_id` or to `groups` the agent is placed in.

### 3.2 API & MCP Authentication
- Agents authenticate to `/api/v1/*` and `/mcp` using scoped Bearer tokens with a recognizable prefix: `mdt_<random_base62_256bit>`.
- **Storage:** Only the **SHA-256 hash** of the token (plus a short non-secret token ID prefix for UI identification) is stored in SQLite. The plaintext token is displayed once at creation/rotation.
- **Lifecycle:** Tokens require an expiration date by default (configurable max TTL, default 90 days, with optional admin-approved non-expiring service tokens), support zero-downtime rotation (overlapping grace window), and support immediate single-click revocation.

### 3.3 Authorization Engine & Precedence
- **Unified Policy Engine:** A single Go `authz.Authorizer` package evaluates all requests from the REST API, MCP server, and Phase 4 Operations UI.
- **Precedence Rules (Evaluated in Order):**
  1. **Self-Protection Check:** Is the target container Mandatary itself? -> **DENY** (Hardcoded).
  2. **Authentication & Credential Status:** Is the session/token valid, unrevoked, and unexpired? -> If not, **DENY (401)**.
  3. **Explicit Deny Rules:** Does any active `effect = DENY` rule match the principal (directly or via any group membership), target `(endpoint_id, container_selector)`, and `operation`? -> **DENY (403)**.
  4. **Explicit Allow Rules:** Does any active, unexpired `effect = ALLOW` rule (permanent policy or active Phase 2 temporary grant) match the principal (directly or via group membership), target `(endpoint_id, container_selector)`, and `operation`, including parameter constraints (such as `exec` argv allowlists)? -> **ALLOW**.
  5. **Default Fallback:** -> **DENY (403)**.
- **Immediate Enforcement:** Authorization is evaluated dynamically on every request against SQLite (with cache invalidation on policy write) and re-verified on active streaming connections (`logs`, `exec`) whenever a policy, grant, session, or token is revoked.

### 3.4 Endpoint-Scoped Resource Identifiers
- From Phase 1, the local Docker socket is registered as endpoint `local` (UUID + slug `local`).
- Every container reference, policy rule, discovery result, access request, and usage metric is keyed by `(endpoint_id, container_selector)` so Phase 5 multi-host support requires zero breaking schema changes.

---

## 4. Authentication Assurance & NIST SP 800-63B-4 Alignment (Decision 0.4)

### 4.1 Target Assurance Level: NIST SP 800-63B-4 AAL2
Mandatary targets **NIST SP 800-63B-4 (July 2025) Authentication Assurance Level 2 (AAL2)** from Phase 1:
- Offers a **phishing-resistant authenticator** option via **FIDO2 / WebAuthn** (supporting YubiKey 5 series, security keys, and platform passkeys with UV/resident key options) in Phase 1.
- Also supports **TOTP** (RFC 6238, SHA-1/SHA-256, 6 digits, 30s period) as a configurable second factor.
- **Role Enforcement:** MFA (WebAuthn or TOTP) is **mandatory for all Policy Administrators** (enforced immediately upon initial setup/first login) and configurable as mandatory or optional for non-admin human users. Admins can further require phishing-resistant WebAuthn-only MFA per role/account.
- **Assurance separation:** AAL2 is a property of a successfully authenticated session/path with verified factors, not an account flag. Password-only, preauthentication, setup/recovery-only capabilities and agent bearer tokens are never represented as human AAL2 and cannot satisfy an AAL2 requirement. Server-bound assurance, authentication time, methods and current credential/control generation govern step-up. Applicable requirements, SHOULD dispositions, external/provider evidence limits and acceptance tests are maintained in `nist-authentication-mapping.md`; the approved architecture alone is not a conformance claim.

### 4.2 Local Password Policy (NIST SP 800-63B-4 Section 3.1.1)
- **Length Defaults:**
  - Minimum **15 characters** when an account uses password-only authentication (if permitted for non-admin accounts).
  - Minimum **8 characters** only while MFA is compulsory on every password-authentication path with no weaker fallback. Optional MFA alone does not qualify: a password usable alone must be at least 15 characters. Removing mandatory MFA first requires a compliant replacement password and invalidation of incompatible sessions.
  - Maximum length: **128 normalized Unicode code points** (exceeding NIST's >=64 recommendation), without truncation. Nico's P1.05 amendment selects **fixed Unicode17 stabilized ordinary NFC**, identical on both approved compilers: reject malformed/non-scalar encoding and frozen17 General_Category=Cn, retain assigned controls/format/private-use, explicit U+FFFD, spaces and emoji. No ASCII/IsPrint whitelist, NFKC, trimming, case folding or synthesized CGJ. Strict original JSON decoding precedes normalization; normalized length precedes whole-password screening and full canonical-UTF8 Argon2id. Immutable stored profile semantics and bounded upstream-derived implementation/provenance/maintenance are specified in [docs/password-authentication.md](docs/password-authentication.md); no silent historical-verifier relabeling or runtime-dependent Unicode semantics.
- **No Composition or Periodic Expiry Rules:** Never require upper/lowercase/number/symbol mixtures or periodic scheduled password resets.
- **Compromised Password Screening:**
  1. **Offline Blocklist:** Built-in bloom filter / compressed list of the top 100,000 common/breached passwords plus context-specific words (`mandatary`, `docker`, username, email, hostname).
  2. **Optional HIBP k-Anonymity Check:** Configurable toggle (`MANDATARY_PASSWORD_HIBP_ENABLED=true/false`, default `false` for strict offline privacy) to query the HaveIBeenPwned Range API using only a 5-character SHA-1 prefix.
  3. **Compromise Flag:** Admins can mark any account as "compromised", forcing a password change on next login and revoking active sessions.
- **Password Hashing:** **Argon2id** (`m=64MB, t=3, p=4`, 16-byte random salt) via `golang.org/x/crypto/argon2`.
- **Frontend UX:** Full support for password manager autofill, copy/paste in password fields, and a password visibility toggle.

### 4.3 Throttling, Recovery & Session Management
- **Rate Limiting & Brute-Force Protection:** Per-account and per-IP controls, five-failure escalating throttling and durable retry limits follow the NIST mapping. The consecutive-failure ceiling is at most 100 attempts for the specific authenticator, surviving restart/concurrency; it is not an unauthenticated whole-account lock switch. Bound attacker work before expensive verification, avoid extending lockouts indefinitely with rejected traffic, preserve independently bound authenticators/recovery, and test account-lockout denial-of-service resistance. Disable/rebind the exhausted authenticator via the approved recovery safeguards; never bypass assurance to unlock it.
- **Authenticator Lifecycle & Recovery:**
  - Upon enrolling MFA, the user receives **10 single-use high-entropy recovery codes** (stored hashed with Argon2id/SHA-256).
  - Users can enroll multiple WebAuthn security keys (e.g., primary YubiKey + backup YubiKey) and revoke individual authenticators after reauthenticating.
- **Phase 1 security notices:** Advance only security-relevant authenticator binding/removal/recovery and notification-address management from the existing SMTP design. Support at least two independently verified notification addresses, TLS-verified delivery, durable secret-free event/outbox state, bounded retry/failure visibility and safe repudiation. Recovery-only capabilities cannot authorize normal administration or mint AAL2; recognized recovery requires approved proofs, credential rebind and fresh authentication. `nist-authentication-mapping.md` specifies assurance, old/new-address notices, delivery-failure safeguards and tests. General access-request/approval notifications and webhooks remain Phase 2; no extra service/provider is selected.
- **Session Timeouts & Reauthentication:**
  - Maximum session lifetime: **12 hours** (configurable).
  - Idle session timeout: **30 minutes** (configurable).
  - **Step-up Reauthentication:** Modifying password/MFA settings, creating/rotating admin or agent credentials, exporting/restoring backups, or modifying security policies after >15 minutes since last authentication requires re-verifying WebAuthn or password+MFA.

### 4.4 Local vs. Authentik Federation Boundary (Phase 3)
- When Authentik OIDC is enabled in Phase 3:
  - **Authentik** owns password composition, breach checking, and primary MFA enrollment for federated users.
  - **Mandatary** validates the OIDC ID token signature, issuer, audience, nonce, and explicitly inspects the `acr` / `amr` claims (or configured Authentik group/assurance attributes) to verify that MFA (or phishing-resistant WebAuthn, if required by policy) was performed during authentication before granting an AAL2 administrative session.
  - Local authentication can be disabled entirely or kept solely as an emergency break-glass Super Admin path.

---

## 5. Technology Stack & Maintainability (Decision 0.5)

| Layer | Selected Technology | Rationale (Security & Maintainability) |
| :--- | :--- | :--- |
| **Backend Language** | **Go 1.27.3 primary; Go 1.26.10 compatibility CI** | Static binary (`CGO_ENABLED=0`); newest two upstream-supported security-patched lines per the approved support policy; full module graph/build verification required. |
| **HTTP Router & API** | Standard library `net/http` (`http.ServeMux`) + strict JSON schema middleware (or `chi` + `huma` / OpenAPI 3.1 validation) | Zero heavy framework lock-in; strict request validation rejects unknown fields (`DisallowUnknownFields`). |
| **MCP Server** | Streamable HTTP (`/mcp`) + optional CLI bridge (`mandatary mcp-stdio`) using `mcp-go` / official MCP JSON-RPC 2.0 spec | Supports both remote/containerized agents over HTTP with Bearer auth and local desktop MCP clients expecting `stdio`. |
| **Frontend Framework** | **React 19 + TypeScript + Vite (SPA)** | Mature ecosystem, strict TypeScript type safety, compiled to static assets and embedded directly into the Go binary via `embed.FS`. |
| **UI Styling & Theme** | **Tailwind CSS + shadcn/ui (Radix Primitives)** | Accessible (WAI-ARIA compliant), built-in support for **Dark and Light modes** from Phase 1, no runtime CSS-in-JS overhead. |
| **Database & Queries** | **SQLite (`modernc.org/sqlite`) + `sqlc` + `goose`** | Pure-Go SQLite (`CGO_ENABLED=0`), compile-time type-safe SQL via `sqlc` (eliminates SQL injection), and deterministic SQL migrations via `goose`. |
| **Cryptography & Auth** | `golang.org/x/crypto` (Argon2id, ChaCha20-Poly1305 / AES-256-GCM), `go-webauthn/webauthn` (FIDO2), `pquerna/otp` (TOTP) | Retained approved selections; library names do not establish conformance, FIPS validation, supported authenticator internals or actual compatibility. Evidence and applicable dispositions follow the NIST mapping. |
| **Container Base Image** | `gcr.io/distroless/static-debian13:nonroot`, production pinned to reviewed digest | Approved replacement for Debian 12; static Go + embedded SPA, no shell/package manager. Verify multi-architecture runtime, vulnerability status and budgets before release. |

**Development toolchain:** Node.js **24.22.1 LTS** and npm **11.19.1**; Node is not a production runtime. React 19, TypeScript, Vite, Tailwind CSS, shadcn/ui and the remaining selections stay unchanged. `support-and-deployment-matrix.md` is the approved maintenance/support contract: weekly advisory review, monthly patch review, quarterly line review, two-business-day advisory triage, immediate active-exploitation triage, tested/reviewed updates before merge, bounded deprecation and no upstream-EOL support guarantee. Candidate library pins are not verified builds: P1.01 must lock and actually exercise the entire graph. A failed approved toolchain/environment requirement is escalated, not silently replaced.

### Module Boundaries
- `internal/domain`: Pure domain types, identifiers, and error definitions.
- `internal/auth`: Password policy, Argon2id, TOTP, WebAuthn, OIDC (Phase 3), and session management.
- `internal/authz`: Default-deny policy evaluation engine, selector matching, and grant expiration monitor.
- `internal/docker`: `DockerBackend` interface, official Docker SDK adapter, response sanitizer, and fake/mock implementation for container-free testing.
- `internal/store`: `sqlc`-generated type-safe repository and `goose` migrations.
- `internal/api`: REST API handlers (`/api/v1`) and Admin UI API handlers.
- `internal/mcp`: MCP server tool registration and execution handlers (calling the shared `authz` + `docker` services).
- `internal/backup`: Envelope encryption and logical export/import service.

---

## 6. Storage, Encryption & Backup/Restore (Decision 0.6)

### 6.1 Embedded SQLite Configuration
- Stored in a dedicated persistent volume (`/data/mandatary.db`) with strict file permissions (`0600`).
- Initialized with `PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`, `PRAGMA foreign_keys = ON;`, and `PRAGMA busy_timeout = 5000;`.
- **Security-control durability qualification:** `NORMAL` remains the ordinary-storage baseline; security-control commits that authorize disclosure, consumption, revocation, retry disablement, quarantine or a related security-transition acknowledgement require a verified `synchronous=FULL` WAL writer in service and host-local helper, with the shared lock/order and file/directory synchronization in security-contracts §S3.1a. This is the selected SQLite stack's necessary durability detail for the approved atomic single-use/crash/revocation contract, not a new store or general power-loss guarantee. Sync failures fail closed; actual filesystem/hardware sync behavior must be tested. Logical restore cannot overwrite current control state.
- Separate read and write connection pools in Go (`MaxOpenConns(1)` for writer to prevent `SQLITE_BUSY`, concurrent readers for fast policy checks).

### 6.2 Secret Encryption at Rest (`MANDATARY_MASTER_KEY`)
- A 256-bit master key (`MANDATARY_MASTER_KEY`, provided via environment variable or Docker secret file `MANDATARY_MASTER_KEY_FILE`) is required at startup.
- All sensitive secrets stored in SQLite—including **TOTP seeds**, **outbound webhook HMAC secrets**, **SMTP credentials**, and **Phase 5 remote Docker TLS private keys / SSH keys**—are encrypted at rest using **AES-256-GCM** (or XChaCha20-Poly1305) with unique per-record nonces and HKDF-derived subkeys.

### 6.3 Backup & Restore Architecture
- **Format:** Versioned, signed JSON logical backup document (`schema_version`, `created_at`, `mandatary_version`, `integrity_hmac`).
- **Scope:**
  - Included in cleartext JSON: Users, groups, agent definitions, container policy rules, endpoint definitions, password/security settings, and (in Phase 3) policy-change audit logs.
  - Included as **envelope-encrypted ciphertext** (bound to `MANDATARY_MASTER_KEY`): Password hashes, TOTP seeds, WebAuthn credential records, active agent token hashes, and remote endpoint credentials.
  - **Excluded:** Active browser sessions and ephemeral rate-limit buckets.
- **Restore Modes:**
  1. **Full Restore (Same Master Key):** Imports the complete supported data transactionally, but imported credentials, historical roles/policies/grants and sensitive security settings remain inactive/quarantined absent trustworthy current revocation information. Explicit credential reissuance and administrative scope/setting reapproval are required; all browser sessions are invalidated. Import is not activation.
  2. **Clean Migration Restore (Strip Secrets / New Master Key):** Imports supported data with credentials/MFA stripped; re-enrollment/reissuance and explicit authorization/security-setting reapproval apply, not automatic historical policy activation.
- **Verification:** Every restore executes inside a single SQLite transaction, validates schema compatibility, and runs post-restore integrity checks before committing.
- **Authority and recovery:** `security-contracts.md` §S2 defines quiescence, current control generations, expired-grant preservation, quarantine, emergency-administrator recovery and RESTORE acceptance tests. Historical backup integrity cannot reconstruct unknown post-backup revocations without an external trusted current source. Host-controlled emergency recovery is outside ordinary AAL2 recovery and requires restricted re-enrollment before administration. There is no guarantee against malicious full-host rollback; no external revocation service is introduced.

---

## 7. Container Identity & Rule Lifecycle (Decision 0.7)

### 7.1 Composite Container Selector
Because Docker container IDs change whenever a container is recreated (e.g., `docker compose up -d`) and container names alone can be reassigned to a different workload, Mandatary binds policy rules to a **Composite Container Selector** scoped to an `endpoint_id`:
- **Required Base:** `endpoint_id` + `container_name` (exact match or explicit glob pattern if enabled by admin).
- **Recommended Identity Guardrails (Configurable per Rule):**
  - `compose_project` & `compose_service` labels (`com.docker.compose.project`, `com.docker.compose.service`) — automatically populated by default when creating a rule for a Compose-managed container.
  - `image_pattern` — e.g., `postgres:16*` or `ghcr.io/org/app:*` (prevents a rule for `db` from applying if a different image is launched under the name `db`).
  - **Strict Pinning Option:** Optional `pinned_container_id` or `pinned_image_digest` (`sha256:...`) for high-security workloads where any container recreation must require explicit administrator re-approval.

### 7.2 Lifecycle Behavior
- **Container Recreation (`docker compose up -d`):** If a rule uses the default `(endpoint_id, container_name, compose_project, compose_service, image_pattern)` selector, recreating the container with the same service and image seamlessly preserves the policy. If recreated with an unauthorized image, access fails closed (`403 Forbidden`).
- **Container Rename:** If a running container is renamed (`docker rename`), it no longer matches its original `container_name` selector and access fails closed immediately. If another container is renamed *into* a permitted `container_name`, the `compose_service` / `image_pattern` guardrails block unintended permission inheritance.
- **Container Deletion:** Policies targeting a deleted container remain in the policy store as "Inactive / Target Missing" (highlighted in the Admin UI) rather than being silently deleted, so administrators retain visibility and audit history.

---

## 8. Independent Discovery & Access-Request Workflow (Decision 0.8)

### 8.1 Independent All-Container Discovery Toggle
- **Scope & Default:** Configured **per principal (Agent or Group) per Endpoint**, defaulting to **OFF (`false`)**.
- **Behavior when OFF:** Listing containers via API (`GET /api/v1/containers`) or MCP (`list_containers`) returns **only** containers for which the caller holds at least one active operation permission (e.g., `container:logs` or `container:inspect_status`).
- **Behavior when ON:** The caller can list all non-Mandatary containers on that endpoint, receiving **strictly minimal inventory metadata**:
  - `endpoint_id`
  - `container_name`
  - `state` (`running`, `exited`, `paused`, `restarting`)
  - `compose_service` (if present)
- **Strict Separation:** Discovery (`endpoint:discover`) never grants `inspect_status`, `inspect_config`, `logs`, `start`, `stop`, `restart`, or `exec`.

### 8.2 Access-Request Workflow (Phase 2)
- **Request Submission:** An authenticated agent or user can invoke `request_container_access` (MCP) or `POST /api/v1/access-requests` specifying:
  - `endpoint_id`, `container_name`, requested `operations[]` (and optional `exec` command patterns), `requested_duration` (or permanent), and a human-readable `justification`.
  - Agents can request access to containers they discovered via `endpoint:discover` or by known `(endpoint_id, container_name)` without leaking whether an undiscovered container exists (unprivileged callers receive a generic `202 Accepted` response).
- **Deduplication & Cooldown:**
  - Duplicate pending requests for the same `(principal, endpoint_id, container_name, operations)` are deduplicated (updating the existing pending request timestamp rather than spamming notifications).
  - Denied requests enforce a configurable **resubmission cooldown** (default **60 minutes**) per `(principal, container_name)` before the agent can submit a new request.
- **Approval Options:** Administrators can **Deny**, **Approve Permanently** (creates a standard policy rule), or **Approve Temporarily** (creates a time-bounded grant with presets: `15m`, `1h`, `4h`, `24h`, or custom timestamp).
- **Expiration & In-Flight Operations:** A background ticker checks active grants every second; when a temporary grant expires or is manually revoked, any in-flight `logs --follow` or `exec` stream authorized by that grant has its Go `context.Context` immediately canceled.
- **Notification Channels:**
  - This section governs **Phase 2 access-request/approval notifications**. The approved Phase 1 security-lifecycle/address subset follows TD §4 and the NIST mapping's stricter durable delivery/failure contract; the three-attempt request-notice policy does not silently apply to security notices.
  - **Email (SMTP/Submission over TLS)** and **Outbound Webhooks (HTTPS)** with exponential backoff retry (3 attempts).
  - Outbound webhooks include an `X-Mandatary-Signature-256` HMAC-SHA256 header signed with the endpoint's encrypted webhook secret, and only deliver a deep-link to the Admin UI inbox (never embedding one-click unauthenticated approval tokens in emails or webhooks).

---

## 9. Usage Statistics, Audit Logs & Application Logging (Decision 0.9)

### 9.1 Usage Statistics
- **Attribution Tuple:** `(user_id, agent_id, endpoint_id, container_selector, operation)`. If an agent is owned by a human user, both `agent_id` and `owner_user_id` are recorded so administrators can view breakdowns by **User**, by **Agent**, by **Container**, and by **Operation**.
- **Outcome Tracking:** Counts are tracked in three distinct columns:
  1. `allowed_count` (authorized and executed)
  2. `denied_count` (blocked by policy `403`)
  3. `error_count` (authorized, but Docker execution failed)
- **Storage & Retention:** Aggregated into hourly and daily SQLite rollup tables (`usage_stats_hourly`, `usage_stats_daily`) plus a bounded recent-events ring buffer, with configurable retention (default **90 days**).

### 9.2 Policy-Change Audit Log (Phase 3)
- Distinct from operational usage statistics. Records every administrative action (policy creation/modification/deletion, access-request approval/denial, user/agent/credential lifecycle changes, endpoint changes, backup/restore events).
- **Fields:** `event_id`, `timestamp_utc`, `actor_user_id`, `actor_session_id`, `source_ip`, `action_type`, `target_resource`, `before_json` (redacted), `after_json` (redacted).
- **Retention:** Default **365 days** (configurable), included in logical backups, and read-only in the UI (never modifiable or deletable via the web interface).

### 9.3 Application-Wide Logging
- **Implementation:** Go standard library structured logger (`log/slog`).
- **Environment Variables:**
  - `MANDATARY_LOG_LEVEL`: `debug`, `info` (default), `warn`, `error`.
  - `MANDATARY_LOG_FORMAT`: `json` (default in container) or `text` (default in local dev).
- **Destination:** Standard output (`stdout`), following 12-factor container conventions.
- **Mandatory Redaction:** Custom `slog.LogValuer` types and middleware guarantee that passwords, `mdt_` bearer tokens, session cookies, TOTP seeds, recovery codes, WebAuthn challenges, `MANDATARY_MASTER_KEY`, and redacted container env vars are **never** emitted at any log level (including `debug`), verified by automated unit tests.

---

## 10. Deployment, Resource Budgets & Developer Workflow (Decision 0.10)

### 10.1 Network Listeners & Ports
- **Port `8080` (`MANDATARY_ADMIN_LISTEN_ADDR`, default `:8080`):** Serves the Policy Administration Web UI, the external REST API (`/api/v1/*`), and the MCP Server (`/mcp`).
- **Port `8081` (`MANDATARY_OPS_LISTEN_ADDR`, default `:8081`, Phase 4):** Serves the permission-bound Container-Operations Web UI and its operation-only backend routes.
  - Controlled by `MANDATARY_OPS_UI_ENABLED=true|false` (defaults to `false` until Phase 4, configurable thereafter).
  - Packaged inside the single Mandatary container image by default for operational simplicity, while also supporting running a second Mandatary container instance in `--ops-only` mode if an operator prefers container-level separation.
  - **Hard Invariant:** The `:8081` router does not mount any policy-mutation, user-management, or approval handlers; its handlers invoke the exact same `authz.Authorizer` as `/api/v1` and `/mcp`.

### 10.2 Measurable Footprint & Performance Budgets
Every phase release is measured against these concrete budgets in CI:
- **Production Container Image Size:** **<= 60 MB compressed** (target ~25–35 MB using `distroless/static` + embedded React SPA).
- **Idle Memory Usage (RSS):** **<= 50 MB** after startup with SQLite initialized and 1 local Docker endpoint connected.
- **Load Memory Usage (RSS):** **<= 150 MB** under the benchmark workload (20 concurrent API/MCP clients polling container status/logs + 5 active log streams).

### 10.3 First-Admin Bootstrap & Emergency Recovery
- **No Default Credentials:** Mandatary never ships with a default `admin/admin` password.
- **First-Start Bootstrap:** Empty-store-only high-entropy setup capability, **30-minute absolute lifetime**, atomic single-use consumption, and mandatory administrator password + MFA enrollment before setup completes. Log only a **secret-free setup URL**. Retrieve the token through the protected host-local control mechanism specified by `security-contracts.md` §S3; never put it in URL query strings, ordinary logs, errors or unrelated responses. Restrictive ownership/modes must match the actual runtime UID and Compose/Unraid host mapping. No interactive shell inside the distroless container is needed. Concurrent consumption, failure, expiry, restart/crash, reveal and log-canary acceptance tests are mandatory.
- **Emergency Recovery:** The host-local runbook in §§S2/S3 supports Compose and Unraid administration without an application-container shell. It grants only a one-time restricted re-enrollment capability, not direct administrator/AAL2 access, and cannot reactivate historical authority or bypass self-protection. Host control is an explicit trusted boundary, not protection against a malicious host.

### 10.4 Container-Free Local Development & CI Workflow
- **Local Iteration Without Container Rebuilds:**
  - `DockerBackend` has a full in-memory mock/fixture implementation (`MANDATARY_DEV_MOCK_DOCKER=true`) populated with realistic sample containers, logs, and states. This is the guaranteed container-build-free workflow. Native real-socket access has **no exemption** from reliable self-identification: it remains operationally fail-closed when own-container identity cannot be proven; desktop socket availability is not proof.
  - Developers run `make dev` (or `go run ./cmd/mandatary` + `npm --prefix web run dev` with Vite proxy) directly on macOS/Linux without building any Docker image.
- **Automated Testing:**
  - `go test -race ./...` and `npm --prefix web test` run all unit and authorization matrix tests in seconds using in-memory/temp-file SQLite and the mock `DockerBackend`.
  - CI additionally executes real-Docker integration against disposable fixtures in an isolated controlled environment, using a dedicated test daemon where practical. Mandatary runs containerized where needed to prove its own identity. Fixtures must assert the approved daemon/endpoint and reject a production socket; **never mount or operate against production Unraid's Docker socket**. See §S1.4. These are future implementation/release checks, not tests executed during Step 0.

---

## 11. Future Interface Contracts (Decision 0.11)

### 11.1 Multi-Administrator Roles & Authentik OIDC (Phase 3)
- **Admin Scopes:** Support two administrative roles in the schema from day one:
  1. `super_admin`: Can manage global settings, users/groups, identity providers, all endpoints, and all policies.
  2. `endpoint_admin`: Scoped to an assigned subset of `endpoint_id`s; can manage policies and approve access requests only for their assigned endpoints.
- **Authentik Integration:** Standard OIDC Authorization Code Flow with PKCE (`client_secret` encrypted at rest), supporting group-to-role mapping and `amr`/`acr` MFA assurance verification.

### 11.2 Remote Docker Endpoints (Phase 5)
- Mandatary will support two encrypted, authenticated remote Docker transports in Phase 5 (never unauthenticated TCP `2375`):
  1. **Docker Engine API over mTLS (`tcp://host:2376` with TLSVerify):** Mandatary validates the remote daemon's CA/server certificate and authenticates using an endpoint-specific client certificate and AES-256-GCM-encrypted private key.
  2. **Docker over SSH (`ssh://user@host`):** Connects using a dedicated host-pinned (`known_hosts` verified) Ed25519 SSH key.
- Endpoint health is monitored independently with circuit breakers so an unreachable remote endpoint never degrades operations on healthy endpoints.

---

## 12. Project Identity & Licensing (Decision 0.12)

- **Working Name:** **Mandatary** is confirmed as the working project name, binary name (`mandatary`), Go module path, and environment variable prefix (`MANDATARY_*`).
- **Trademark & Public Branding:** Legal/trademark clearance is deferred until prior to any public release or open-source publication; internal architecture keeps branding strings centralized in a single metadata package/config for easy renaming if ever needed.
- **License:** Private/internal repository during initial phased development; public license selection (e.g., Apache-2.0, MIT, or AGPLv3) is deferred until pre-public release.

---

## 13. Summary of Key Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `MANDATARY_MASTER_KEY` / `_FILE` | *(Required)* | 32-byte key (hex/base64) for AES-256-GCM encryption of DB secrets and backup envelopes. |
| `MANDATARY_DATA_DIR` | `/data` | Directory containing `mandatary.db` and WAL files. |
| `MANDATARY_DOCKER_SOCKET` | `unix:///var/run/docker.sock` | Local Docker endpoint URI for the `local` endpoint. |
| `MANDATARY_ADMIN_LISTEN_ADDR` | `:8080` | Listener address for Admin UI, `/api/v1`, and `/mcp`. |
| `MANDATARY_OPS_UI_ENABLED` | `false` | Enables the Phase 4 Container-Operations UI listener. |
| `MANDATARY_OPS_LISTEN_ADDR` | `:8081` | Listener address for the Phase 4 Container-Operations UI. |
| `MANDATARY_LOG_LEVEL` | `info` | Global structured log level (`debug`, `info`, `warn`, `error`). |
| `MANDATARY_LOG_FORMAT` | `json` | Log output format (`json` or `text`). |
| `MANDATARY_PASSWORD_HIBP_ENABLED` | `false` | Optional k-anonymity HaveIBeenPwned API check on password set. |
| `MANDATARY_DEV_MOCK_DOCKER` | `false` | Uses in-memory mock Docker backend for container-free local dev/testing. |
