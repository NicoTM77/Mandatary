---
name: mandatary-engineering
description: Apply Mandatary's approved Go, React, TypeScript, SQLite, Docker SDK, CI and phased-delivery engineering constraints when planning, implementing, or reviewing changes in the Mandatary repository.
---

# Mandatary engineering

## Applicability and authority

Use for any Mandatary design, implementation, test, refactor, or implementation-review task. This skill is **guidance derived from repository documents, not approval to begin implementation**. Before acting, read the relevant task and check these files in order:

1. `step-0-readiness.md` (current gate and outstanding approvals) and `step-0-reconciliation.md`.
2. `technical-decisions.md` (approved baseline) and `roadmap.md` (phase and exit criteria).
3. `security-contracts.md`, `nist-authentication-mapping.md`, `support-and-deployment-matrix.md` (newer detail, including items still proposed).
4. `phase-1-plan.md` (conditional implementation card proposal; **not** an executable queue).

If instructions disagree, **do not silently choose**. Record the conflicting sections and escalate through the existing Kanban decision process to Nico. New addenda can clarify the baseline but do not automatically supersede a decision that requires explicit approval. Task acceptance and approvals must be checked at execution time; the snapshot dated 2026-10-26 says **NOT READY**, but a later authorized gate decision may change that.

## No implementation before readiness

- While Step 0 remains blocked: only specifically authorized documentation, skill, design-review, and planning work; no production implementation, Phase 1 coding cards, dependency changes, actual Docker operations, merges, deployments, or automatic dispatch.
- Only begin Phase 1 work after the existing 0.13 gate has passed **and** Nico has explicitly approved the Phase 1 backlog. Do not treat the provisional P1.01–P1.20 plan as approval.
- Do not create duplicate Kanban cards, change dependency edges or assign work to junior/UX profiles without the orchestrator's authorization. `phase-1-plan.md` currently assigns proposed implementation cards to `coder`; reassignment is a separate decision.

## Approved architectural boundaries

- Backend: Go, standard-library `net/http` router (or a specifically approved thin alternative); strict JSON decoding, explicit validation, dedicated typed handlers, official `moby/client` Docker SDK. **Never proxy arbitrary Docker API requests**.
- Frontend: React 19, TypeScript, Vite SPA, Tailwind CSS, shadcn/ui and Radix primitives. Dark/light from Phase 1. Static frontend embedded in the Go binary using `embed.FS`. No unapproved Next.js/SSR migration or frontend runtime framework.
- Database: pure-Go SQLite (`modernc.org/sqlite`), type-safe `sqlc` queries, `goose` migrations; no unapproved extra persistent service, ORM or CGO dependency.
- Code organization follows `technical-decisions.md` §5 module boundaries (`internal/domain`, `auth`, `authz`, `docker`, `store`, `api`, `mcp`, `backup`). Keep permission decisions in the single `authz.Authorizer`, not duplicated across API, MCP or UI.
- API/MCP share policy enforcement. Admin UI/API/MCP on `:8080`; separate operations UI on `:8081` only in Phase 4 and without policy mutation routes.
- Defer out-of-phase functionality: Phase 2 access requests/discovery/exec, Phase 3 multi-admin/OIDC/policy audit, Phase 4 operations UI, Phase 5 remote endpoints unless a reviewed amendment specifically changes scope.

## Development workflow when authorized

1. Identify task ID, phase, exact acceptance tests, dependencies and approved changes. Inspect the actual branch/worktree and project docs before proposing code.
2. Keep the patch scoped, avoid speculative abstractions/new dependencies, and pin dependencies per the **approved** support matrix. Its candidate versions and image-amendment proposal are not final approvals.
3. Add failure-path and negative tests together with implementation. Prefer mock `DockerBackend` and temporary SQLite for fast container-free checks; real-socket tests only in explicitly approved isolated fixtures.
4. Once a build exists, run applicable checks: `go test -race ./...`, frontend unit tests, typecheck/lint/build, and applicable security checks. Do not claim tests executed before these commands exist.
5. Use project-managed worktrees/feature branches and existing GitHub credential wrapper if required by the task. Draft PR only. Do not merge, auto-merge, deploy, or modify GitHub integration/auth configuration.
6. Request independent review with the established native Kanban `kanban_request_review(reviewer="reviewer")` mechanism, when authorized. Review exact commit/head; new commits invalidate previous verification.
7. Report changed files, tests run and their actual results, unmet criteria, pending approvals, and specific residual risks. Never turn an untested specification into a conformance claim.

## Measurable gates

Read `roadmap.md` shared release criteria and `technical-decisions.md` §§2.3, 10.2–10.4. In particular, require negative authorization regression coverage; static analysis (`govulncheck`, `gosec`, `golangci-lint`, frontend audit/ESLint, image scanning) when relevant; and documented image/memory/CI budgets. A reachable unresolved High/Critical (CVSS >=7.0) vulnerability or failing negative authorization test blocks release. A green CI run is not automatic permission to merge or release.

## Collaboration

- `junior`: small, clearly bounded, low-risk work only; escalate architecture/security/schema/auth changes instead of making them.
- `ux-designer`: UI components and flows within the approved React stack; server authorization remains authoritative.
- `coder`: integration and complex implementation.
- `reviewer`: independently verify behavior, risks, tests and phase constraints; do not self-approve.

Reference only authoritative files and the current task status; never treat this skill itself as a source of new product requirements.
