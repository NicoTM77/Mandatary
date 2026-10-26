# Step 0 final readiness review — existing gate 0.13

## 1. Authority and current gate

**Decision date:2026-10-26. Status: independent round1 FAIL; narrow mapping correction prepared, exact-head re-review pending.** No PASS is asserted before the `reviewer` profile independently examines the actual documents after all twelve prerequisite tasks are complete. Original gate **0.13 `t_ddd96736`** and its twelve parent edges are preserved; no duplicate gate is created.

Nico approved all six qualified final recommendations. `technical-decisions.md` now incorporates the approved self-protection/native-mock, assurance/security-notice, support/toolchain, restore-quarantine, protected setup-disclosure and Debian13-runtime baseline. The acceptance/control documents below are part of that design. Product test specifications are **not executed results**. Step0 expects a reviewed design and implementation-ready backlog, not an application, CI installation, benchmark, tested image or operational deployment.

**Authorization boundary:** even a final PASS and completed Step0 do not authorize Phase1. No Phase1 coding, ready-to-dispatch cards, production Docker operations, deployment, PR merge, authentication changes or automatic decomposition. PR#2 remains draft. Nico alone controls GitHub merging and separate Phase1 authorization.

## 2. Decision deliverables and task traceability

| Existing task | Accepted scope and concrete design evidence | Future implementation verification |
| --- | --- | --- |
|0.01 `t_e4f5bb4f`|TD §§1/3.3: six permission keys, strict schemas, no proxy, API/MCP parity; Phase2 exec/discovery and Phase4 TTY boundaries.|P1.11–14/20 positive/negative catalog/expiry/revocation matrix.|
|0.02 `t_b5a17cdc`|TD §§2/3.3/10.4; security-contracts §S1: root-equivalent socket/actors/network boundaries, trusted daemon-qualified identity, all-state protected peers, missing/conflicting/recreation/stream failure semantics; mocks guaranteed, no native exemption.|SELF register; P1.11–14/19–20 isolated disposable Docker fixtures, dedicated daemon where practical, never production Unraid socket.|
|0.03 `t_281bba7b`|TD §§3/4.3/7/11.1: principal/owner model, no owner inheritance/admin implicit operations, tokens and default-deny/deny precedence.|P1.02/08/10–14 direct/group/credential/endpoint deny matrix.|
|0.04 `t_1af7c0f2`|TD §4; nist-authentication-mapping: applicable requirements→design→test/owner, official catalogue applicability, SHOULD dispositions, AAL2/lower-assurance split, mandatory admin MFA, optional nonadmin policy, secure recovery/notices/address/throttling.|P1.02–03/05–10/16/19–20 N63B4 tests and provider/device/governance evidence; no unconditional NIST conformance claim.|
|0.05 `t_92c5c52c`|TD §5; support matrix §§2–5: Go1.27.3/1.26.10,Node24.22.1/npm11.19.1,retained stack/modules,maintenance/support/triage/deprecation and approved Debian13 base.|SUP tests; P1.01 whole locked graph/real builds; P1.19–20 digests/runtime/security/CPU/budgets.|
|0.06 `t_239f5e2a`|TD §6; security-contracts §S2: SQLite/WAL/keys/migrations,logical signed/encrypted format,transactional restore,quarantine/current controls,reissue/reapproval/expiry,restricted emergency recovery and historical/host rollback limits.|RESTORE register; P1.02–03/08–09/18–20 restart/wrong-key/tamper/race/crash/revocation/settings cases.|
|0.07 `t_4f91fc1d`|TD §§3.4/7: endpoint-qualified selectors/optional guardrails/pins,rename/recreate/delete/label/image semantics.|P1.11–14 lifecycle and cross-endpoint matrix.|
|0.08 `t_01261cf2`|TD §§1.3/8: default-off discovery,no implied grants,request/dedup/cooldown,approval/temporary expiry/notification contract. Only approved security-lifecycle/address subset advances to Phase1.|General request/approval SMTP/webhook,grant/restart/retry tests remain Phase2; N63B4 security notices Phase1.|
|0.09 `t_4725c0a6`|TD §9: attribution/counts/retention,safe logging; collection Phase1,report UI Phase2,policy audit Phase3.|P1.04 redaction canaries; P1.15 exact expected totals/concurrency/restart/retention.|
|0.10 `t_e4846cd1`|TD §§9.3/10; security-contracts §§S1.4/S3; support matrix: environment/ports/commands,budgets/workload,nonroot distroless Compose/Unraid host-local setup/recovery,actual UID permissions,30-minute atomic token and mandatory admin MFA.|SETUP/SUP registers; P1.09/16/19–20 concurrency/expiry/failed-setup/restart/crash,isolated integration,release/resource/security evidence.|
|0.11 `t_6cfc4cb1`|TD §§3.4/4.4/10.1/11: later Authentik/multiadmin,operation-only router and packaging,remote mTLS/SSH contracts; bounded owners/deadlines in reconciliation.|Phase3–5 interface/endpoint/security tests; no future feature stubs in Phase1.|
|0.12 `t_86e68ae0`|TD §12: private working identity/existing repository; Nico owns public licensing/legal/branding gate before public publication.|No legal-clearance or public-release claim.|

## 3. Every exact roadmap Step 0 exit criterion

The quoted criteria are unchanged from `roadmap.md`. Main-agent design assessment is not the independent verdict. Reviewer must independently record PASS/FAIL for each and inspect the related detailed deliverables rather than trusting this crosswalk.

| Exact criterion | Evidence to examine | Main-agent design assessment |
| --- | --- | --- |
|“Each decision above has an explicit recorded outcome or a narrowly bounded later-phase decision with an owner, deadline, and explanation of why it does not block development.”|TD §§1–12; reconciliation final approvals/card crosswalk/bounded later-phase register.|Recorded. All six material approvals incorporated; no initial security/stack choice silently deferred.|
|“No unresolved decision affecting initial security boundaries, identity, policy semantics, storage, stack, or Phase 1 acceptance remains a development blocker.”|Approved baseline; §§S1–S3;NIST dispositions;support policy;actual parent-card acceptance/status.|Design decisions resolved subject to independent consistency review. Actual builds/tests/provider evidence are explicitly owning-task/release gates, not missing Step0 product.|
|“The threat model, architecture outline, operation/permission matrix, NIST requirements mapping, data model, and initial deployment/development workflow are reviewed.”|TD actors/socket/proxy/crypto/modules/principal model;SELF/RESTORE/SETUP/N63B4 specs;operator/developer workflows;independent reviewer report.|Prepared for final independent review. SQL migrations/application are Phase1 work; no invented test proof.|
|“Numeric footprint budgets, the initial operation list, supported environments, and test commands are recorded rather than left as adjectives.”|TD §§1.2/10.2/10.4;support matrix. ≤60MB compressed,≤50MB idle RSS,≤150MB load RSS at20 API/MCP clients+5 streams;Go race/frontend commands;CPU/OS/Engine/API/Compose/browser/native mock targets.|Recorded; actual measurements/builds/runtime/browser/device checks remain unverified until implementation.|
|“The backlog maps each accepted requirement to a phase and acceptance test; candidates are explicitly accepted, rejected, or deferred.”|R requirement coverage;reconciliation bounded deferrals;P1.01–20 measurable acceptance and C1–C5;NIST/SELF/RESTORE/SETUP/SUP test owners.|Recorded; graph and exact baseline traceability require final structural check and independent verification. No Phase1 dispatch authorized.|

## 4. Phase 1 proposal and implementation gates

- Retain twenty implementation keys and five checkpoints; no implementation cards are created here.
- Native `coder` profile: `gpt-6.1-sol`/`openai-codex`,reasoning `high`; native `reviewer`: same model/provider,reasoning `xhigh`. Configurations were inspected, not changed or overridden.
- Earliest relevant PR adds positive/negative security tests; P1.01 establishes real checks and nonempty failing-negative fixtures. P1.11 default-deny evaluation can proceed before login UI; operation exposure waits for integrated credentials and C1/C2.
- Every implementation PR runs applicable automated build/race/type/lint/security/dependency checks and all existing auth/authz regressions. Independent exact-head review and verified required CI are mandatory; changed head invalidates prior verification.
- C1 storage/safety/mock;C2 authentication-to-policy;C3 first API/MCP/UI vertical slice;C4 management/restore;C5 packaged acceptance/security/footprint. Each defines independently verifiable artifacts/results and owning reviews.
- Dependencies wait for reviewed completion and Nico-controlled prerequisite merge unless Nico explicitly authorizes stacking. GitHub App worker review is not misrepresented as GitHub-enforced human self-approval. No agent merges/auto-merges or deploys.
- Global `kanban.auto_decompose:false` was read from the current configuration and remains unchanged. No profile/reasoning/security configuration is modified.

## 5. Repository scope and verification record

Remote main commit `1d36737` (.agents addition) was merged normally as `d737e45` into the existing docs branch, without force-push/rebase. The `.agents/` tree is checked byte-for-byte against current `origin/main`, not merely against the previous branch. Its three project skills were read and preserved unchanged. No product/CI/dependency/runtime file is created by this documentation update.

Executed documentation checks: the parsed Phase1 task/checkpoint graph has **25 nodes/67 edges**, is acyclic and includes C1/C2 before operation exposure,C3 before management/restore and C4 before packaging. All original roadmap measurable-exit-criteria sections and shared release gates are byte-for-byte unchanged against `origin/main`; `git diff --check` passed. The current CSRC final-publication record and upstream distroless README were re-fetched; NIST remains the final SP800-63B-4 record and upstream lists the approved Debian13 static image. No upstream metadata is represented as a Mandatary test result.

Mapping checks passed: **105** main NIST design rows each reference named tests and P1 ownership; **119** distinct N63B4 test specifications retained unchanged; all **313** official `revision-63B` catalogue control IDs appear exactly with no missing/extra IDs. Security registers contain complete unique SELF-01–13,RESTORE-01–11 and SETUP-01–12 rows. These are document coverage checks, not executed product tests. Final diff-scope, GitHub head/draft and live-board results are recorded after their final checks. No build, application test, benchmark, image pull/scan, Docker operation, SMTP send or deployment result is claimed during Step0.

## 6. Independent review and final disposition

### Round1 — FAIL, native reviewer run16

The existing `reviewer` profile independently reviewed actual artifacts at **977d23344feeab7e919fe5f246b8618d3498ea30**, preserving the12 parent edges. Full criterion-by-criterion review and source/check evidence are in original0.13 comment29 and its attached report; historical failure evidence is retained. The reviewer independently confirmed25 nodes/67 edges,105 main rows/119 named specs/exact313 official controls,unchanged roadmap exit/shared sections and `.agents`,and no executed product tests.

| Roadmap Step0 criterion | Round1 result |
| --- | --- |
| Explicit decision outcomes/bounded owner+deadline deferrals | PASS |
| No unresolved foundational decision | PASS for decision disposition |
| Foundational artifacts including NIST mapping reviewed | FAIL — F1 |
| Numeric budgets/operations/environments/commands explicit | PASS |
| Requirement/phase/test/candidate traceability | FAIL — F1 |

**F1 — Medium, blocking:** `MFCTORS-8` (NIST §3.1.7.1 activation-secret erasure) linked only to W03/`N63B4-WA-UV`. Signed UV flags cannot establish authenticator-internal transient input erasure. The correction extends W04's existing `N63B4-WA-DEVICE-EVIDENCE` specification with explicit post-transaction activation-secret/biometric-sample/derived-data erasure evidence,distinguishes it from RP tests,and remaps MFCTORS-8 to W04/P1.07/16/19–20 with independent review. Unknown evidence stays unresolved for applicable release/conformance; no persistent credential/PIN-verifier deletion,new allowlist,product test or architecture selection is introduced. Exact-head re-review is required before declaring this finding closed.

**F2 — Low, nonblocking:** the review observed an earlier stale PR narrative. The orchestrator had refreshed PR#2 through the existing App during the review; readback confirms current approved-baseline and12-completed-prerequisite statements. Re-review must verify the current PR body rather than preserve superseded claims as present state.

Native changes-request returned the original card to `default`; an automatically dispatched triage run17 correctly left it blocked because reviewer-only no-edit wording was ambiguous for implementer rework. The interactive orchestrator's original user authority covers the narrow documentation correction/publication; that role distinction is clarified on the existing task. No extra Nico architectural approval is needed and no parent task is reopened. The gate stays uncompleted pending native reviewer re-review.

### Round2 — pending

The existing reviewer profile must review the corrected exact head,verify F1/F2 and rerun relevant regression/coverage/graph/scope checks. Final PASS/FAIL must be recorded on original0.13 and read back before final closure. A final PASS means Step0 is finished and ready to request Nico's separate Phase1 authorization,nothing more.
