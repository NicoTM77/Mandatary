# Mandatary

Mandatary is the working name for a security-first Docker access intermediary.
The planned application lets tools and agents use an API and MCP server within
administrator-defined, per-container permissions.

## Current status

Step 0 passed independent review; Nico merged the decision package in PR #2
and authorized the Phase 1 kickoff on 2026-11-03. Only P1.01 is released for
implementation. This checkout adds a loopback-only static development skeleton,
embedded React assets, locked developer commands and baseline tests/PR CI.
See [Container-free development](development.md) for exact setup and checks.

Authentication, policy enforcement, Docker access, MCP, storage and deployment
are **not available**. Architecture documents describe later planned product
capabilities, not implemented features or NIST conformance. Other Phase 1 cards
remain held for phased release, independent review and Nico-controlled merges.

## Documentation guide

Read these documents in order:

1. [Project notes](project-notes.md) — requested capabilities, development
   priorities, and the distinction between requirements, candidates, and open
   design questions.
2. [Development roadmap](roadmap.md) — Step 0 foundations, phased product scope,
   measurable acceptance criteria, and shared release gates.
3. [Technical decisions](technical-decisions.md) — the recorded Step 0 technical
   decisions and architecture baseline.

The working name is not a claim of trademark clearance. See the project notes
and technical decisions for naming and licensing context.
