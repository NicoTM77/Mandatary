# Mandatary — phased development roadmap

## Status and interpretation

This roadmap organizes the requirements in `project-notes.md`. The capabilities are requested requirements unless explicitly marked as candidates. Phase boundaries and acceptance criteria below remain the release plan, not evidence of completed work. `technical-decisions.md` is the approved Step 0 architecture baseline; selected technologies must not be reopened. `step-0-reconciliation.md` records the final approved decisions and traceability. Nico retained the P1.01–P1.20 structure and C1–C5 checkpoints; separate final Phase1 authorization is still withheld. `step-0-readiness.md` records the independent final gate. On2026-10-26 Nico approved the six qualified amendments: fail-closed/native-mock workflow, bounded Phase1 security notices/address management, maintenance/toolchain policy, inactive historical restore authority, protected host-local setup retrieval and Debian13 runtime. Supporting security/NIST/support contracts define acceptance, not executed product results. No other product phase or requirement is changed.

Step 0 produces decisions and a testable plan, not a product. Every subsequent phase must end with a deployable, documented, independently useful product that retains the capabilities of earlier releases. No phase is complete merely because its code exists.

The existing Hermes project `mandatary` (`p_9f037647`) and board `mandatary` are registered at `/workspaces/Mandatary`, with private repository `NicoTM77/Mandatary`. No product implementation, deployment, or Docker operations have begun. Architecture approval does not waive the Step 0 exit criteria or authorize Phase 1 coding.

## Shared release criteria — every product phase

These are proposed measurable release gates that apply from Phase 1 onward:

- A fresh installation using the repository's documented Docker Compose file starts successfully, passes its health/readiness checks, and completes that phase's end-to-end acceptance scenarios.
- Production image size and idle/load resource use are measured against budgets decided in Step 0. A failed budget requires remediation or explicit approval of a revised budget, not an unrecorded exception.
- The documented local development workflow runs the application and unit tests without building or rebuilding the application container for each iteration.
- CI runs unit tests, relevant integration/security regression tests, and build checks non-interactively. All required checks pass for the release artifact.
- Every exposed operation has positive and negative authorization tests through each applicable interface. Omitting a UI control or MCP tool is not a substitute for server-side enforcement. Revoked/expired credentials and permissions fail the applicable tests.
- Security review covers the changed attack surface; no unresolved critical/high-severity release-blocking finding under the rubric selected in Step 0 is accepted silently.
- Policy/settings persistence survives restart. A backup is restored into a fresh instance and compared against the documented backup scope; the restored instance passes authorization tests. Upgrade/data-migration tests preserve supported prior-version data, with recovery instructions exercised where applicable.
- Application-wide logging honors its documented environment-configured log level. Tests check that passwords, tokens, TOTP seeds, and other authentication secrets are not emitted in logs or responses.
- Shipped web interfaces work in both dark and light modes. Operator/developer documentation, configuration examples, supported-version policy, and known limitations match the delivered release.
- Acceptance results are recorded against a versioned release artifact. Undelivered later-phase features are clearly identified as unavailable rather than exposed as insecure stubs.

## Step 0 — Resolve foundations before development

**Outcome:** a reviewed decision package and implementation-ready backlog. **No product is expected.**

### Decision areas — approved outcomes in `technical-decisions.md` §§1–12

The numbered list preserves the original decision scope as the reconciliation checklist; it is not a request to reselect approved technologies. Approved outcomes and any genuinely missing acceptance details are mapped to the existing cards in `step-0-reconciliation.md`.

1. **Release scope and operation catalog:** choose the exact operations in Phase 1 and later additions. Approved Phase 1 catalog is logs, inspect-status, inspect-config, start, stop and restart (§1.2); exec and independent discovery are Phase 2 (§1.3). Decide exec modes, argument restrictions, streaming, cancellation, and timeouts before scheduling their implementation. Unsupported Docker operations remain unavailable.
2. **Threat model and security boundaries:** document trusted/untrusted actors, Docker socket compromise impact, deployment assumptions, reverse-proxy/TLS responsibilities, network exposure, secret management, and security-review/release-blocking criteria. Define how the intermediary prevents raw API bypasses.
3. **Identity and authorization model:** distinguish policy administrators, container operators, users/groups, and non-human agent principals. Choose initial API/MCP authentication, credential issuance/rotation/revocation, user attribution, rule precedence, default behavior, and policy-change enforcement. Plan endpoint-scoped resource identifiers now so later multi-host support does not require ambiguous container identities.
4. **Authentication assurance:** recheck the current final NIST SP 800-63 guidance; select a target assurance level, MFA defaults/role requirements, password-policy controls, enrollment/recovery/revocation, session expiration, and reauthentication rules. Decide whether to adopt the YubiKey-compatible FIDO2/WebAuthn candidate. If the chosen assurance level requires a phishing-resistant option, that option is a prerequisite for the first release claiming that level, not an optional future enhancement. Define local versus Authentik ownership and federated authentication-strength checks.
5. **Technology and maintainability:** choose backend language/runtime, current supported frontend frameworks, API/MCP libraries and transports, package management, testing tools, dependency/update policy, and module boundaries. Record why the choices meet security, maintenance, and footprint goals; do not select unsupported technology merely because it is newest.
6. **Storage and recovery:** choose embedded storage without a separate database service/container; evaluate SQLite. Define migrations, volumes/permissions, backup contents, consistent backup procedure, restore behavior, and treatment of credentials, sessions, MFA material, and secrets. Decide whether any historical rollback beyond backup/restore is in scope.
7. **Container identity and rule lifecycle:** specify behavior after rename, deletion, recreation, and label/image changes. Decide which identifiers or selectors bind permissions, and how unintended grant inheritance is prevented.
8. **Discovery and access requests:** decide scope/default of the independent discovery toggle, exposed metadata, requestable containers/functions, request deduplication, expiry/revocation semantics, behavior of in-flight operations, and email/webhook delivery/retry/security behavior.
9. **Statistics and logs:** define access-count semantics, user/agent attribution, failed/denied attempts, reporting windows, retention, and access controls. Define operational log levels, environment variable, redaction, and the distinction between usage statistics and later policy-change audit records.
10. **Deployment and development acceptance:** choose ports, initial supported host/CPU/browser versions, image/resource budgets and benchmark workload, Compose defaults, local setup/test commands, CI checks, and integration-test environment. Define first-admin bootstrap and secure recovery without default shared credentials.
11. **Future interface contracts:** define boundaries for later multi-admin/Authentik integration, multi-endpoint support, and the separate-port operations UI. Keep unresolved implementation details in the relevant later phase rather than pretending all future UX must be designed now. Authentik is the required provider. Approved Phase 4 UI packaging is same-container by default with optional `--ops-only` separation (§10.1).
12. **Project identity:** confirm the working name Mandatary, repository/organization destination, license, and public-release naming/legal checks. Naming clearance is required before committing to public branding, not necessarily before private implementation.

### Measurable exit criteria

- Each decision above has an explicit recorded outcome or a narrowly bounded later-phase decision with an owner, deadline, and explanation of why it does not block development.
- No unresolved decision affecting initial security boundaries, identity, policy semantics, storage, stack, or Phase 1 acceptance remains a development blocker.
- The threat model, architecture outline, operation/permission matrix, NIST requirements mapping, data model, and initial deployment/development workflow are reviewed.
- Numeric footprint budgets, the initial operation list, supported environments, and test commands are recorded rather than left as adjectives.
- The backlog maps each accepted requirement to a phase and acceptance test; candidates are explicitly accepted, rejected, or deferred.

## Phase 1 — Secure single-host Docker access product

**Usable outcome:** deploy Mandatary on one host, configure users/groups and per-container policies, and let an authenticated tool or agent perform the initial supported operations through the API or MCP server.

### Scope

- One local Docker endpoint, one policy-setting administrator, user/group and agent identities, and scoped API/MCP authentication.
- Policy-management web UI with dark/light modes, initial rule editing, and the authorization semantics selected in Step 0.
- Approved initial operations: logs, inspect-status/config, start, stop and restart (`technical-decisions.md` §1.2); no generic unrestricted Docker proxy. Exec and independent discovery remain Phase 2.
- Durable embedded policy storage, migrations, easy backup/restore, lightweight image, repository Compose deployment, environment-configured global logging, and basic persistent usage counts by user/container/function.
- Configurable local password policies and TOTP, with the authentication lifecycle and any additional authenticator necessary for the chosen assurance target. FIDO2/WebAuthn (including compatible YubiKeys/passkeys) is approved alongside TOTP in Phase 1 (§4); a target is not a claim of implemented conformance.
- Only security-relevant authenticator binding/removal/recovery notices and verified notification-address management advance from the existing SMTP design, with secure delivery, failures, recovery and assurance safeguards in the NIST mapping. General access-request/approval email and webhooks remain Phase2.
- CI-ready tests and local container-build-free iteration from the start.

### Measurable exit criteria

- From a clean Compose deployment, bootstrap an administrator, create a user/group and agent identity, grant a function on test container A, and successfully call it through both API and a real MCP client.
- Demonstrate denials for an unauthenticated caller, a second ungranted function, test container B, and each unsupported operation; verify policy/credential revocation and absence of an alternate forwarding bypass.
- Password-policy, TOTP enrollment/verification/recovery, brute-force controls, session expiry, and any required phishing-resistant authentication pass the Step 0 security scenarios.
- A restart preserves policies and usage counts. Backup/restore into a fresh instance reproduces the defined settings and correct allow/deny behavior.
- A predetermined sequence of operations produces exactly the expected user/container/function counts under the agreed counting rules.
- All shared release criteria pass. This is a usable restricted-access product even though approval workflows, federated/multiple administrators, and the operations UI are not yet available.

## Phase 2 — Agent discovery, approval workflow, and usage reporting

**Usable outcome:** agents can discover containers where permitted, request missing permissions, and obtain administrator-approved permanent or time-limited access; administrators can inspect usage.

### Scope

- Independent all-container discovery toggle without implicit operation grants.
- Requests for one or more functions on a specific container; administrator inbox and deny/permanent/temporary decisions.
- Email and webhook request notifications with the configured delivery behavior.
- User/container/function statistics UI using the defined retention and reporting periods.
- Extend the operation catalog with exec and any other Step 0-approved additions only with explicit policy checks and safe argument/stream handling.

### Measurable exit criteria

- With discovery disabled, the test agent sees only the agreed permitted scope; enabling it exposes the agreed inventory metadata but does not permit an ungranted operation.
- Request multiple functions; verify administrator notification through an email test recipient and a webhook test receiver, with no grant before approval.
- Denial leaves access blocked; permanent approval survives restart; temporary approval works before expiry and is denied afterward, including after restart. Test revocation and the specified handling of already-running operations.
- A forged or unauthorized approval is rejected. Repeated requests and notification failures behave according to documented deduplication/retry rules.
- The approved exec workflow succeeds only for authorized targets and allowed parameters; cross-container and unauthorized exec attempts fail through API and MCP.
- A known operation fixture produces exact expected statistics totals and breakdowns; retention and failed/denied counting match the recorded definitions.
- All Phase 1 regression tests and shared release criteria pass.

## Phase 3 — Multi-administrator identity, session visibility, and policy audit

**Usable outcome:** multiple administrators operate with individual identities, Authentik sign-in, session controls, and an attributable policy-change history.

### Scope

- Multiple policy-setting administrators with explicit administrative scopes/provisioning rules.
- Authentik OAuth-based sign-in, using the authentication protocol and assurance validation chosen during design.
- Administrators view their own browser sessions/login activity and revoke one or all other sessions.
- Policy-change audit log. Broader operation auditing is not silently added to scope.
- Adapt request routing and approval authorization for multiple administrators.

### Measurable exit criteria

- Two administrators sign in with separate Authentik identities; provisioning, role changes, deprovisioning, and required authentication strength follow the documented mapping. An ordinary user cannot obtain policy-setting privileges.
- Local and federated authentication paths both enforce their applicable authentication/MFA policy, without an alternate weaker path bypassing the selected assurance requirements.
- Using three browser sessions, revoke one other session and verify its next protected request fails while the current and third sessions remain valid. Then revoke all other sessions and verify only the current session remains valid.
- Login/session metadata is visible only within the agreed scope. Test documented Authentik/SSO behavior so reauthentication cannot silently defeat the intended revocation behavior.
- Create, change, and delete a policy; each change produces an attributable audit entry with the agreed timestamp, actor, action, and change details. Ordinary users cannot read or alter restricted audit data; retention and restoration behavior are tested.
- Request approval follows administrator scope and cannot be performed by an unauthorized administrator.
- All earlier regression tests and shared release criteria pass.

## Phase 4 — Permission-bound container-operations web UI

**Usable outcome:** authorized administrators can operate containers interactively in a browser without editing policies or receiving automatic unrestricted Docker access.

### Scope

- Operations equivalent to the shipped MCP server's supported operation catalog, including interactive behavior where applicable.
- Separate listener/port from policy management, suitable for routing to a different subdomain.
- Environment-variable switch to disable the operations interface.
- Implement the approved default same-container packaging plus optional separate `--ops-only` instance (`technical-decisions.md` §10.1), preserving the shared authorization boundary.

### Measurable exit criteria

- For every supported operation, a browser test demonstrates the permitted case and denied case against the same permission matrix used for API/MCP tests.
- An administrator with no relevant operation grant is denied. Operations-UI traffic cannot modify policies or implicitly grant access, even with crafted requests.
- Route the interfaces to different test subdomains; authentication, WebAuthn if supported, cookies/origins, and applicable streaming connections work without cross-origin authorization bypasses.
- Disable the operations UI through the documented environment variable; its listener/routes are unavailable while policy management, API, and MCP remain functional as documented.
- Both themes work; operations produce the same usage-count semantics as other interfaces. Any chosen separate-container mode has its own successful deployment and authorization tests.
- All earlier regression tests and shared release criteria pass.

## Phase 5 — Multi-endpoint and remote Docker management

**Usable outcome:** one Mandatary deployment governs containers across multiple local/remote Docker endpoints while preserving endpoint-specific identity and access boundaries.

### Scope

- Multiple Docker sockets/endpoints, including adding endpoints on remote systems.
- Selected authenticated/encrypted remote connection mechanism, endpoint credential lifecycle, health reporting, and isolation.
- Endpoint-aware policies, discovery, access requests, usage statistics, audit data, and operations UI.
- Finalize administrator endpoint scopes and cross-endpoint discovery behavior before implementation of this phase.

### Measurable exit criteria

- Connect at least two isolated test Docker endpoints, including one remote endpoint, and successfully run the supported API/MCP/UI operations on explicitly granted resources.
- Reuse a container name on both endpoints and demonstrate that a grant on one never authorizes access to the other. Test the chosen identity semantics after rename/recreation.
- Discovery and request approval expose only the endpoint scope allowed by the agreed rules. Temporary grants expire correctly on each endpoint.
- Wrong/untrusted remote credentials fail closed; rotation/revocation and endpoint removal behave as specified. An unreachable endpoint does not prevent operations on a healthy endpoint.
- No deployment instructions require an unauthenticated network-exposed Docker socket. Logs and UI do not reveal endpoint secrets.
- Statistics and policy audit records identify the correct endpoint/container. Backup/restore and supported upgrades preserve endpoint configuration without unintentionally reviving revoked authority.
- All earlier regression tests and shared release criteria pass, including resource budgets measured with the selected multi-endpoint workload.

## Requirement coverage and sequencing notes

- **Security and maintainability:** Step 0 and every release gate; never deferred to a final hardening release.
- **Framework selection, lightweight runtime, Compose, logging, CI tests, and easy local testing:** Step 0 decisions and Phase 1 delivery, retained thereafter.
- **Policy persistence and backup/restore:** Phase 1 onward; SQLite with `sqlc`/`goose` is approved in §§5–6.
- **Local account password policy, TOTP, NIST alignment, and YubiKey option:** Step 0 assurance decision and Phase 1 authentication, extended to federation in Phase 3.
- **Users/groups, per-container rules, API and MCP:** Phase 1; operation catalog expands in Phase 2.
- **Statistics:** Phase 1 collection and Phase 2 reporting.
- **Independent discovery, agent requests, email/webhook notifications, permanent/temporary grants:** Phase 2.
- **Multiple administrators, Authentik, own-session/login controls, and policy-change audit:** Phase 3.
- **Separate-port, optionally disabled operations UI with no rule changes or authorization bypass:** Phase 4; default same-container and optional `--ops-only` packaging are approved in §10.1.
- **Multiple/remote endpoints:** Phase 5; identifiers and isolation anticipated in Step 0.

Approved technology selections and numeric resource budgets are recorded in `technical-decisions.md` §§5 and 10.2; this roadmap does not invent replacements or effort estimates. Before each later phase, resolve its explicitly deferred design choices and convert the scenarios above into executable acceptance tests. Change phase sequencing only with a corresponding update to dependencies and usable-release criteria.
