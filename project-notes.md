# Mandatary — project notes

Working name: **Mandatary**. This is not yet a final application name or a legally cleared trademark. The existing notes directory remains unchanged.

## Status and scope

Requirements recorded from Nico's instructions. The phased development plan, Step 0 decisions, and measurable release criteria are in `roadmap.md` alongside this file. Phase sequencing is a proposed plan; unresolved technology choices remain open. No implementation, technology stack selection, or Hermes Projects UI registration has been performed. Do not use or modify `/workspaces` for this project at present.

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
- Use up-to-date web frameworks, with framework choices and versions to be determined during development.
- Evaluate the latest framework releases at the time of selection against the agreed security and maintainability priorities; no framework or version is selected by these notes.

### Lightweight deployment

- Keep the production container lightweight, considering both image size and runtime resource consumption. Specific budgets remain to be determined.
- Include a Docker Compose file in the repository for easy deployment.

### Application-wide logging

- Provide consistent application-wide logging.
- Make the logging level configurable through a container environment variable.
- The variable name, supported levels, output format, and destinations remain undecided.

### Testing and developer workflow

- Provide unit tests that can be integrated into CI/CD and run non-interactively in an automated pipeline.
- Make the application easy for developers to run and test locally without rebuilding the container for every change or test run.
- Provide a development/testing workflow that does not require building the application container first for each iteration; exact tooling remains undecided.

### Policy persistence and backup/restore

- Persist policy settings appropriately and durably.
- Policy storage must not require a separate database container or service; SQLite is a candidate, not a finalized technology choice.
- Provide an easy way to back up and restore policy settings and changes. Backup scope, format, consistency guarantees, and restore behavior remain to be specified; per-change rollback is not yet an agreed requirement.

### Configurable account password policies

- Provide configurable password policies for accounts whose passwords are managed by Mandatary.
- The default policy must match the current final NIST password guidance. The verified baseline is NIST SP 800-63B-4 (July 2025), section 3.1.1; recheck the current final publication when implementing and deliberately review defaults as guidance changes.
- Baseline highlights (not a complete compliance checklist): require at least 15 characters for password-only authentication; NIST permits a minimum of eight when passwords are used only as part of MFA. Support a maximum length of at least 64 characters; do not impose character-class composition rules or routine periodic password changes. Require changes on evidence of compromise, reject common/expected/compromised passwords, rate-limit failed attempts, and support password managers/autofill and paste.
- Reference: https://csrc.nist.gov/pubs/sp/800/63/b/4/final and https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
- Configurable controls and allowed deviations from the default remain undecided. Password-policy ownership for Authentik-managed accounts must be resolved during authentication design; this does not imply Mandatary manages the identity provider's passwords.

### MFA and NIST-aligned login design

- Provide configurable TOTP as a second authentication factor.
- Consider YubiKey support as an additional authentication option. Preferred technical direction to evaluate: standards-based FIDO2/WebAuthn security-key support, including compatible YubiKeys, rather than assuming a particular proprietary OTP mode. This direction is a candidate, not a finalized implementation decision.
- Align login and authentication design with the current final NIST SP 800-63B guidance, extending beyond password composition to authenticator enrollment/binding, verification, recovery/replacement/revocation, throttling, session management, and reauthentication.
- Current reference: NIST SP 800-63B-4 (July 2025). Select and document the intended authentication assurance level and applicable requirements during design; configurable MFA alone is not a claim of NIST compliance or AAL2 conformance.
- NIST distinction: OTP authentication, including TOTP, is not phishing-resistant. At AAL2 a phishing-resistant authentication option must be offered; correctly implemented FIDO2/WebAuthn security-key authentication is the candidate approach to evaluate for this purpose.
- Whether MFA is optional or required for particular accounts/roles, its defaults, supported key models, recovery procedures, and implementation staging remain undecided.
- Define the boundary between Mandatary-managed authentication and Authentik-managed authentication, including how the application verifies required authentication strength for federated logins. Do not assume an OAuth login alone establishes MFA or the desired assurance level.
- References: https://pages.nist.gov/800-63-4/sp800-63b/aal/ ; https://pages.nist.gov/800-63-4/sp800-63b/authenticators/ ; https://pages.nist.gov/800-63-4/sp800-63b/session/ ; https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html

### Authorization

- Support different users and groups.
- Configure which functions each user/group can access for each container.
- Example functions explicitly requested: start, logs, and exec. These are examples, not a finalized operation list.
- Enforce the configured permissions for access through both the API and MCP server.

### API and MCP

- Provide an API for external tools and agents.
- Provide an MCP server exposing container operations within the caller's authorized scope.

### Independent container discovery

- Provide an optional toggle allowing an agent to list all containers independently of its per-container operation rules.
- Listing a container must not itself grant permission to operate on it.
- The exact metadata disclosed and whether this toggle is global, per agent, per user, or per group remain undecided.

### Access-request workflow

- An agent can request access to one or more functions on a specific container.
- Notify the administrator of the request.
- Support email and webhook notifications for AI-agent access requests; these are Nico's preferred notification channels.
- Let the administrator deny the request or approve it permanently or temporarily.
- Temporary-grant duration and expiration behavior remain to be specified.

### Usage statistics

- Keep statistics showing which user accessed which container, how often, and which functions they used.
- Support usage counts broken down by user, container, and function.
- Retention, reporting periods, presentation, agent-to-user attribution, and whether denied or failed attempts count are open design questions, not yet agreed requirements.

## Later-stage requirements

These capabilities are explicitly requested for later development stages, not necessarily the initial release.

### Administrator session and login management

- Provide policy-setting administrators with a way to view their browser sessions and login activity.
- Allow an administrator to log out their other sessions individually, or log out all other sessions while retaining the current session.
- The scope is management of the administrator's own sessions; viewing or revoking other users' sessions is not an agreed requirement.
- Session/login metadata, history retention, and the interaction between Mandatary session revocation and Authentik sessions or reauthentication remain design questions.

### Policy-change audit log

- Add an audit log for changes to policies on the later-stage roadmap.
- Event details, retention, storage, and presentation remain to be determined.

### Container-operations UI

- Provide a web interface for administrators to perform container operations equivalent to those exposed through the MCP server.
- Separate container operations from policy management: the operations interface must not modify authorization rules, implicitly grant permissions, or bypass configured permissions merely because the caller is an administrator.
- Enforce the same authorization checks and operation permissions as the API and MCP server.
- Expose the container-operations UI on a separate port from the policy-management UI, replacing the earlier same-port/separate-path proposal. This supports independent reverse-proxy routing to separate subdomains.
- Allow the container-operations UI to be disabled via a container environment variable; the variable name remains undecided.
- Consider hosting the container-operations UI in a separate container as an alternative deployment model; the final packaging remains undecided.
- Separating, disabling, or independently deploying the operations UI must preserve the same authorization enforcement; it must not introduce a permission bypass.

### Multiple administrators and OAuth

- Support multiple administrators.
- Provide OAuth support for administrator authentication/sign-in.
- Authentik is a required OAuth provider for the setup once authentication is implemented.
- Protocol details, administrator provisioning, division of administrative privileges, and support for additional providers remain undecided.

### Multiple Docker endpoints and remote systems

- Support multiple Docker sockets/endpoints within one application instance.
- Allow administrators to add Docker endpoints from other systems remotely.
- The remote connection mechanism and transport security remain undecided; this requirement does not imply exposing an unauthenticated Docker socket over the network.

### Related design questions — not yet decided

- How permissions and container identities are scoped to each Docker endpoint.
- Whether administrators manage all endpoints or only an assigned subset.
- How access-request notifications and approvals are routed among multiple administrators.
- How the independent all-container discovery toggle behaves across multiple endpoints.
- How remote endpoint credentials are stored, rotated, and revoked.

## Open design questions — not agreed requirements

- Final application name (working name: Mandatary) and implementation stack.
- User, group, and agent identity model; authentication method for UI, API, and MCP clients.
- Full set of supported Docker operations and the desired granularity of permissions.
- How rules interact when a user belongs to multiple groups; precedence of allows and denies.
- How permissions follow containers after rename, replacement, or recreation.
- Scope and metadata of the independent discovery toggle.
- Email/webhook notification configuration and administrative approval UI.
- Duration, revocation, and handling of already-running operations when temporary grants expire.
- Whether denied access requests may be resubmitted and how requests are deduplicated.

## Security topics to evaluate — assistant suggestions, not agreed scope

- Treat the Docker-socket-facing service as a privileged trust boundary; evaluate compromise impact before implementation.
- Default-deny enforcement with a shared authorization layer for API and MCP, rather than relying on hidden UI controls or tool visibility.
- Prevent unapproved access through raw Docker API forwarding, alternate endpoints, or overly broad operation parameters.
- Consider separate controls for exec and other sensitive operations, with explicit limits on their arguments and behavior.
- Policy-change audit logging is an agreed later-stage requirement above. Broader audit coverage for approvals, denials, and executed operations remains a suggestion to evaluate.
- Treat all-container discovery as a deliberate information-disclosure permission, separate from execution permissions.
