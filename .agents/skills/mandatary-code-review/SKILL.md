---
name: mandatary-code-review
description: Independently review Mandatary change sets, tests, architecture, security invariants and Kanban gate compliance; issue evidence-based findings without self-approval or merge.
---

# Independent Mandatary review

## Gate before examining code

Use only as an independent reviewer, not as permission to start coding or to approve a blocked Step 0 gate. Start from the **actual Kanban task status**, assigned acceptance criteria, approvals, PR/base/head commit, and current dependencies. In the provided 2026-10-26 snapshot, `step-0-readiness.md` states **NOT READY** for Phase 1. `phase-1-plan.md` P1.01–P1.20 is conditional and assigned to `coder`; it has not been dispatched. Review documentation or skills if assigned, but do not convert the proposal into an implementation queue.

## Sources and precedence

Read task-specific sections of `roadmap.md`, `technical-decisions.md`, `step-0-readiness.md`, `step-0-reconciliation.md`, `security-contracts.md`, `nist-authentication-mapping.md`, `support-and-deployment-matrix.md`, and `phase-1-plan.md`. Distinguish approved decision from later proposal. Flag contradictions, missing owner approval and acceptance criteria that cannot be verified; do not resolve architectural conflicts unilaterally.

## Review procedure

1. Confirm reviewer is independent of implementer, identify PR, precise head SHA, base/diff, scope, related task IDs and dependency state. Never rely solely on implementer's summary.
2. Confirm only authorized files/scope changed; no unreviewed dependency, CI, Docker socket, credential, deployment or governance changes.
3. Map each acceptance criterion to concrete evidence: exact code path, executable test, output or justified unverified status. Documentation-only acceptance is not proof of product behavior.
4. Examine correctness, types, error handling, cancellation/concurrency, API contracts, migrations, maintainability and user-facing states. For React, apply installed relevant React/UX rules only where they fit React 19 + Vite (not Next.js/SSR).
5. Apply `mandatary-security` rigorously: authorization precedence, self-protection, secret redaction, session assurance, restoration, negative tests and trust-boundary violation. Review both allow and deny cases.
6. Run available targeted checks plus project CI commands where practical; distinguish independently executed checks from logs supplied by another agent. For docs-only PRs, verify internal cross-references and gate language rather than claiming nonexistent product tests.
7. Check `roadmap.md` phase-specific and shared release gates and any applicable support matrix. Report CVSS>=7 reachable unresolved issues and failed negative authz tests as blocking; do not waive release criteria.
8. Issue a structured verdict and send it through the **existing native Kanban review workflow**. After approval and successful exact-head native CI acceptance, perform the human-review handoff in `mandatary-engineering` §PR lifecycle and human-review handoff: mark the PR ready, ensure `NicoTM77` is assigned, request his review, and verify the unchanged head/base and remote handoff state before native task completion. A new commit requires re-evaluating the exact new head. Do not merge, auto-merge, enable merge queues or deploy; Nico controls merge.

## Approved PR handoff — completion condition

- Read and follow `.agents/skills/mandatary-engineering/SKILL.md` §PR lifecycle and human-review handoff. Nico has authorized the reviewer to change an approved, CI-accepted PR from draft to ready and request his review; the implementer still creates a draft.
- Use the existing approved GitHub wrapper. The relevant commands are `gh pr ready NUMBER`, `gh pr edit NUMBER --add-assignee NicoTM77`, and, when not already requested, `gh pr edit NUMBER --add-reviewer NicoTM77`, with the repository specified. Inspect current state first and make only missing changes. Do not remove other assignees or reviewers.
- Read back `state`, `isDraft`, `headRefOid`, `baseRefName`, `assignees`, and `reviewRequests`; check submitted reviews when needed to distinguish an already fulfilled request. Persist the PR URL, approved SHA/base, required-CI evidence and verified human-handoff state in the native completion summary/metadata.
- Failure to verify any required handoff step is a completion blocker, not grounds to weaken the acceptance contract. Record the exact failure and required operator action without a blind retry loop. An already merged/closed PR is handled as a verified human action under the shared exception, not converted back to ready.
- This changes the previous draft-preservation rule only at the successful independent-review handoff. It does not grant merge, auto-merge, deployment, downstream-release, credential or repository-policy authority.

## Required review output

- **Scope:** task ID, PR, exact reviewed commit SHA, relevant architecture sections.
- **Decision:** Approve / Request changes / Blocked by unresolved decision / Cannot verify; include rationale. Do not approve if mandatory acceptance is unverified.
- **Findings:** prioritized by severity with file/line reference, exploitation/failure scenario, acceptance impact and actionable remediation. Avoid noisy style-only nitpicks.
- **Evidence:** checks actually executed and results, targeted negative test coverage, missing tests, CI/head status.
- **Outstanding authority:** unresolved Step 0 approvals, phase boundaries, or owner decisions. Explicitly list any proposal that cannot be treated as approved.
- **Handoff:** what the implementer must change; what requires Nico's decision; whether re-review of a new commit is required; and, for approved PRs, verified ready state, `NicoTM77` assignment and human review request/review status (or the verified prior human merge/closure).

## Specific current review concerns

For the snapshot's pending Step 0 cards, prioritize the issues explicitly listed in `step-0-readiness.md` §3: native real-socket security boundary, Phase 1 security notifications, restore reactivation, setup-token disclosure, Debian12-to-Debian13 image proposal, and support/NIST policy details. These are **unapproved requests**, not implemented or accepted choices. For code after gate approval, apply the exact P1 task acceptance/negative tests and enforce branch/worktree/draft PR/independent review commitments described in `phase-1-plan.md`.
