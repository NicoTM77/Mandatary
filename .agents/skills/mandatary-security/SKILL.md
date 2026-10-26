---
name: mandatary-security
description: Check and preserve Mandatary's security-first invariants covering Docker isolation, default-deny policy, identities, sessions, secrets, restore, and sensitive UI interactions.
---

# Mandatary security invariants

## Authority and decision boundary

Use for any Mandatary backend, frontend, storage, API/MCP, deployment or test change touching trust boundaries. Read `technical-decisions.md` and `roadmap.md`, then the relevant sections of `security-contracts.md`, `nist-authentication-mapping.md`, `step-0-readiness.md`, and `support-and-deployment-matrix.md`.

**Differentiate**: approved baseline; user-settled direction; proposed addendum; tests specified but not executed; code actually verified. In the ZIP snapshot (2026-10-26), Step 0 is **NOT READY**. Do not implement unresolved proposals without approval or assert NIST conformance from a mapping document.

## Mandatory trust-boundary checks

1. **Docker root-equivalent privilege** (`technical-decisions.md` §§1–2): never expose a raw socket or generic Docker API proxy through any interface. Use dedicated operation handlers, strict input schema/allowed parameters, official Docker SDK, and sanitized responses. Unknown operations fail denied.
2. **Self-protection** (TD §2.1; `security-contracts.md` S1): Mandatary cannot inspect/list/operate on itself or protected peers. Self-identification uncertainty, conflicting identities or lost daemon/event continuity **fails closed**; no name-only or insecure fallback. S1's native real-socket development exception remains an explicit open approval; do not invent an implementation bypass.
3. **Authorization** (TD §3.3): unified `authz.Authorizer` across REST, MCP and later Operations UI. Order: self-protection -> authentication validity -> explicit DENY -> explicit ALLOW with full scope/constraints -> default DENY. Recheck streaming authorization on revocation/expiry and cancel active streams; no owner-to-agent implicit permission inheritance.
4. **Container identity** (TD §7): endpoint-qualified selector and optional guardrails; reject cross-endpoint matches, renamed/replaced identity escalation and stale pinning. Test recreation, label/image mismatch, and stopped/deleted targets.
5. **Identity and sessions** (TD §4; NIST map): administrators require MFA; password-only or recovery-only sessions are **not** automatically AAL2; maintain assurance separation. Authenticate WebAuthn origin/RP/challenge, TOTP replay/clock, hashed single-use recovery and step-up operations. The detailed NIST mapping includes additional requirements and conflicts still awaiting disposition; do not flatten them into an unqualified compliance claim.
6. **Tokens and secrets** (TD §§3.2, 6, 9.3): only token hashes at rest, plaintext issued once; short nonsecret IDs for display. Master key required; encrypt specified secrets at rest; never log bearer tokens, cookies, passwords, MFA seeds, backup keys, or high-risk Docker environment values. Test with synthetic canaries. Preserve CSRF/CSP/Secure HttpOnly cookie/Origin checks and minimum privilege.
7. **Restore and rollback** (`security-contracts.md` S2): historical valid backup integrity does not prove present authority. No silent resurrection of old revoked grants/credentials/policies. Proposed quarantine/reapproval semantics are awaiting approval; do not treat restore continuity as settled. Test stale backups, concurrent imports, crashed restores, and wrong key as specified.
8. **Bootstrap** (TD §10.3; `security-contracts.md` S3): empty database, setup token one-use and time bound, mandatory admin MFA. The proposal to show a secret-free URL in stdout and disclose token through a protected channel needs Nico's approval; never put the secret into persistent logs as a convenient workaround.
9. **Security UI**: display permission scopes, deny/allow consequences, irreversibility, effective expiry, and server-confirmed results clearly. Client-side disabling/hiding is only UX—not authorization. Do not surface secret values in DOM, URL query strings, telemetry, console, or local storage. Support keyboard access, error states and session-expiry handling.
10. **Phase-specific boundaries** (TD §§1.3, 8, 10.1, 11; roadmap): do not implement Phase 2/3/4/5 features in Phase 1 by assumption. Proposed Phase 1 lifecycle security notifications versus Phase 2 notification capabilities remain a reviewed decision request.

## Test design and review

- Include explicit **negative and race-condition** tests before marking a security requirement satisfied: deny/default deny; invalid/expired/revoked sessions/grants; authz-stream revocation; wrong endpoint/target; self-target; token replay; secrets in logging; backup rollback.
- Use `security-contracts.md` S1/S2/S3 test identifiers, `nist-authentication-mapping.md` applicability/acceptance registers, and applicable Phase 1 card criteria. These are *planned acceptance criteria*, not passing tests.
- Verify claimed security results against actual executable tests and the exact reviewed commit. Never declare a security-sensitive exception compliant without tracked approval and evidence.
- Escalate to `reviewer` / orchestrator for any conflict, unclear trust boundary or security-sensitive decision. The junior must not independently implement these areas.
