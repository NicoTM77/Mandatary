# Mandatary — project notes

Working name: **Mandatary**, confirmed for private development by `technical-decisions.md` §12. Public branding/trademark clearance and a public license remain pre-public-release gates, not claims of legal clearance.

## Status and scope

Requirements recorded from Nico's instructions. `roadmap.md` defines phase boundaries and measurable release criteria. `technical-decisions.md` is Nico's approved Step 0 architecture baseline; its selected technologies are not open for reselection. The registered Hermes project `mandatary` (`p_9f037647`) and board `mandatary` use `/workspaces/Mandatary`; the repository is `NicoTM77/Mandatary` (private). Product implementation has not started. Approval of architecture is distinct from satisfying every Step 0 exit criterion and from authorization to start Phase 1. See `step-0-reconciliation.md` for the card-by-card assessment and `step-0-readiness.md` for the current independent readiness-gate record. Nico provisionally approved the P1.01–P1.20 structure, not implementation. `security-contracts.md`, `nist-authentication-mapping.md`, and `support-and-deployment-matrix.md` supply the follow-up contracts, complete standards mapping, approved support/toolchain policy, candidate dependency pins and specific acceptance tests. Nico approved the six final recommendations with qualifications on2026-10-26; the approved bounded changes are incorporated in TD. Implementation evidence remains unverified and Phase1 coding still requires separate authorization.

## Development priorities — agreed requirements

- Mandatary is a security-first application.
- Security and maintainability for future updates must be first-priority considerations throughout development, including architecture, implementation, testing, dependency selection, and release planning.
- Evaluate feature and implementation decisions against both priorities; do not treat security or maintainability as later-stage additions.

## Product concept

Develop a containerized application that acts as an intermediary for Docker access. The application is deployed as a container, receives access to the host system's Docker socket, and presents a polished web UI for administration.

Other tools and agents interact through an API and an MCP server, with access constrained by administrator-defined permissions.

## Requested capabilities

### Deployment and administration

- Deploy as a container.
- Connect to the system's Docker socket.
- Provide a user-friendly web administration UI.

### Web UI and frontend technology

- Provide both dark and light modes for the web UI, including the later-stage container-operations interface.
- Use up-to-date, supported web frameworks evaluated against security and maintainability. The approved frontend is React 19 + TypeScript + Vite, Tailwind CSS + shadcn/ui (Radix), with embedded static assets (`technical-decisions.md` §5). Go1.27.4 primary/1.26.11 compatibility and Node24.22.1/npm11.19.1 plus the support/update policy are approved. Candidate library pins require actual locked builds/tests in P1.01; the framework choice is not reopened.

### Lightweight deployment

- Keep the production container lightweight, considering both image size and runtime resource consumption. Approved budgets are ≤60 MB compressed image, ≤50 MB idle RSS, and ≤150 MB load RSS under the §10.2 workload.
- Include a Docker Compose file in the repository for easy deployment.

### Application-wide logging

- Provide consistent application-wide logging.
- Make the logging level configurable through a container environment variable.
- Approved logging: `MANDATARY_LOG_LEVEL` (`debug`, `info`, `warn`, `error`), `MANDATARY_LOG_FORMAT` (`json`/`text`), stdout, and mandatory secret redaction (`technical-decisions.md` §9.3).

### Testing and developer workflow

- Provide unit tests that can be integrated into CI/CD and run non-interactively in an automated pipeline.
- Make the application easy for developers to run and test locally without rebuilding the container for every change or test run.
- Provide a development/testing workflow that does not require building the application container first for each iteration; the approved mock Docker backend, `make dev`, Go race tests and frontend tests are specified in `technical-decisions.md` §10.4.

### Policy persistence and backup/restore

- Persist policy settings appropriately and durably.
- Policy storage must not require a separate database container or service; SQLite (`modernc.org/sqlite`) with `sqlc` and `goose` is approved (`technical-decisions.md` §§5–6).
- Provide an easy way to back up and restore policy settings and changes. The approved versioned logical backup, encrypted credential envelope, transactional full/clean restore, and session invalidation are defined in `technical-decisions.md` §6.3. Imported credentials and historical authority remain inactive absent trustworthy current revocation information until reissued/reapproved, with expired-grant semantics and security-setting reapproval preserved. Per-change rollback is not agreed; unknown revocation history/full-host rollback guarantees are expressly excluded (security-contracts §S2).

### Configurable account password policies

- Provide configurable password policies for accounts whose passwords are managed by Mandatary.
- The default policy must match the current final NIST password guidance. The verified baseline is NIST SP 800-63B-4 (July 2025), section 3.1.1; recheck the current final publication when implementing and deliberately review defaults as guidance changes.
- Baseline highlights (not a complete compliance checklist): require at least 15 characters for password-only authentication; NIST permits a minimum of eight when passwords are used only as part of MFA. Support a maximum length of at least 64 characters; do not impose character-class composition rules or routine periodic password changes. Require changes on evidence of compromise, reject common/expected/compromised passwords, rate-limit failed attempts, and support password managers/autofill and paste.
- Reference: https://csrc.nist.gov/pubs/sp/800/63/b/4/final and https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
- Approved password defaults and local/Authentik ownership are specified in `technical-decisions.md` §§4.2–4.4. Configurable controls must preserve the selected assurance requirements; the requirements-to-tests mapping remains subject to the reconciliation, not an assertion of implemented conformance.

### MFA and NIST-aligned login design

- Provide configurable TOTP as a second authentication factor.
- FIDO2/WebAuthn, including compatible YubiKeys and platform passkeys, is approved for Phase 1 alongside TOTP (`technical-decisions.md` §4.1), rather than proprietary OTP.
- Align login and authentication design with the current final NIST SP 800-63B guidance, extending beyond password composition to authenticator enrollment/binding, verification, recovery/replacement/revocation, throttling, session management, and reauthentication.
- Current reference: NIST SP 800-63B-4 (July 2025). The approved target is AAL2; it applies only to sessions/paths that actually establish AAL2, while password-only/nonadmin optional-MFA paths remain lower-assurance and cannot satisfy AAL2 authorization. Configurable MFA alone is not a claim of implemented NIST compliance or AAL2 conformance.
- NIST distinction: OTP authentication, including TOTP, is not phishing-resistant. At AAL2 a phishing-resistant authentication option must be offered; correctly implemented FIDO2/WebAuthn security-key authentication is the approved approach for this purpose.
- MFA is mandatory for policy administrators and configurable for non-admin humans; phishing-resistant-only policy is supported. Phase 1 enrollment, recovery, throttling and session rules are approved in `technical-decisions.md` §§4.1–4.3. Password-only non-admin sessions cannot be represented as AAL2.
- Only authenticator binding/removal/recovery/security notifications and verified notification-address management advance to Phase1 using the existing SMTP design, with secure delivery/failure/assurance safeguards in the NIST map. General access-request/approval notifications and webhooks remain Phase2.
- The local/federated boundary and Authentik assurance-claim validation are approved in `technical-decisions.md` §4.4 for Phase 3. Do not assume an OAuth login alone establishes MFA or the desired assurance level.
- References: https://pages.nist.gov/800-63-4/sp800-63b/aal/ ; https://pages.nist.gov/800-63-4/sp800-63b/authenticators/ ; https://pages.nist.gov/800-63-4/sp800-63b/session/ ; https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html

### Authorization

- Support different users and groups.
- Configure which functions each user/group can access for each container.
- Example functions explicitly requested: start, logs, and exec. The approved catalog is logs, inspect-status/config, start, stop and restart in Phase 1; exec is Phase 2 (`technical-decisions.md` §§1.2–1.3).
- Enforce the configured permissions for access through both the API and MCP server.

### API and MCP

- Provide an API for external tools and agents.
- Provide an MCP server exposing container operations within the caller's authorized scope.

### Independent container discovery

- Provide an optional toggle allowing an agent to list all containers independently of its per-container operation rules.
- Listing a container must not itself grant permission to operate on it.
- Approved Phase 2 toggle: per agent/group per endpoint, default off, with minimal inventory metadata and no implied operations (`technical-decisions.md` §8.1). Phase 1 must not expose independent discovery prematurely.

### Access-request workflow

- An agent can request access to one or more functions on a specific container.
- Notify the administrator of the request.
- Support email and webhook notifications for AI-agent access requests; these are Nico's preferred notification channels.
- Let the administrator deny the request or approve it permanently or temporarily.
- Approved temporary-grant presets, revocation/expiry and in-flight cancellation are specified in `technical-decisions.md` §8.2 for Phase 2.

### Usage statistics

- Keep statistics showing which user accessed which container, how often, and which functions they used.
- Support usage counts broken down by user, container, and function.
- Approved hourly/daily rollups, 90-day configurable retention, user/agent attribution, and separate allowed/denied/error counts are specified in `technical-decisions.md` §9.1. Collection is Phase 1; reporting UI is Phase 2.

## Later-stage requirements

These capabilities are explicitly requested for later development stages, not necessarily the initial release.

### Administrator session and login management

- Provide policy-setting administrators with a way to view their browser sessions and login activity.
- Allow an administrator to log out their other sessions individually, or log out all other sessions while retaining the current session.
- The scope is management of the administrator's own sessions; viewing or revoking other users' sessions is not an agreed requirement.
- Session/login metadata, history retention, and the interaction between Mandatary session revocation and Authentik sessions or reauthentication remain design questions.

### Policy-change audit log

- Add an audit log for changes to policies on the later-stage roadmap.
- Approved event fields, 365-day configurable retention, backup inclusion and read-only UI are specified in `technical-decisions.md` §9.2; implementation remains Phase 3.

### Container-operations UI

- Provide a web interface for administrators to perform container operations equivalent to those exposed through the MCP server.
- Separate container operations from policy management: the operations interface must not modify authorization rules, implicitly grant permissions, or bypass configured permissions merely because the caller is an administrator.
- Enforce the same authorization checks and operation permissions as the API and MCP server.
- Expose the container-operations UI on a separate port from the policy-management UI, replacing the earlier same-port/separate-path proposal. This supports independent reverse-proxy routing to separate subdomains.
- Allow the container-operations UI to be disabled via a container environment variable; the approved switch is `MANDATARY_OPS_UI_ENABLED` (default false), with listener `MANDATARY_OPS_LISTEN_ADDR` (default `:8081`).
- Approved Phase 4 packaging is one image/container by default with optional second-instance `--ops-only` deployment (`technical-decisions.md` §10.1). This is not authorization to implement it in Phase 1.
- Separating, disabling, or independently deploying the operations UI must preserve the same authorization enforcement; it must not introduce a permission bypass.

### Multiple administrators and OAuth

- Support multiple administrators.
- Provide OAuth support for administrator authentication/sign-in.
- Authentik is a required OAuth provider for the setup once authentication is implemented.
- Approved Phase 3 contracts are OIDC Authorization Code + PKCE, verified assurance claims, and `super_admin`/endpoint-scoped `endpoint_admin` roles (`technical-decisions.md` §§4.4, 11.1). Provisioning UX and additional-provider scope remain later-phase details.

### Multiple Docker endpoints and remote systems

- Support multiple Docker sockets/endpoints within one application instance.
- Allow administrators to add Docker endpoints from other systems remotely.
- Approved Phase 5 transports are verified mTLS or host-pinned SSH with encrypted endpoint credentials (`technical-decisions.md` §§6.2, 11.2); unauthenticated Docker TCP remains forbidden.

### Later-phase details within approved contracts

- Endpoint-scoped composite identities, role scopes and per-endpoint discovery are approved in §§3.4, 7, 8.1 and 11.1.
- Multi-admin notification routing and provisioning details belong to Phase 3; remote credential rotation/revocation and endpoint-removal details belong to Phase 5. Their foundational encryption/transport boundaries are already approved.

## Architecture baseline and remaining questions

The former open questions on stack, identities, credentials, operation granularity, deny precedence, container lifecycle, discovery, notifications, temporary grants and request deduplication are answered by `technical-decisions.md` §§1–12. Do not restart those decisions. `step-0-reconciliation.md` distinguishes genuine acceptance gaps from bounded later-phase details and records the approved final dispositions, traceability and bounded deferrals. The independent readiness verdict is maintained in step-0-readiness.md.

## Security topics — disposition against the approved baseline

- Root-equivalent Docker-socket risk, actors and deployment boundaries are approved in §2.
- Default-deny shared enforcement across API/MCP/future operations UI is approved in §3.3; hidden controls are not enforcement.
- No raw Docker forwarding and strict operation-specific validation are approved in §1.
- Explicit exec allowlists, privilege restrictions and bounds are approved for Phase 2 in §1.3.
- Policy-change audit logging is an agreed later-stage requirement above. Administrative lifecycle/approval audit coverage is approved in §9.2 for Phase 3; a broader executed-operation audit is not silently added.
- Separate discovery permission and minimal metadata are approved in §8.1.
