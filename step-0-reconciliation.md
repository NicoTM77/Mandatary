# Mandatary — final Step 0 reconciliation

## Authority, scope and evidence

Nico's **2026-10-26 final Step 0 decisions** approve the six recommendations, with qualifications, and authorize documentation, architectural finalization and existing-card lifecycle management only. They do **not** authorize Phase 1 coding, deployment, PR merging or automatic decomposition. The earlier assessments remain in Git history and Kanban comments; their approval blockers are superseded by this explicit decision, not erased.

The existing Hermes project is `mandatary` (`p_9f037647`), board `mandatary`, workspace `/workspaces/Mandatary`, private repository `NicoTM77/Mandatary`. Existing cards and all twelve parent edges into 0.13 are retained. Seven previously completed decision cards and the unrelated workflow-validation card remain complete. Final authoritative lifecycle/readiness evidence is in `step-0-readiness.md` and the original card threads.

Remote `main` is authoritative for repository contents. Its independent `.agents/` commit `1d36737` was incorporated by normal merge into `docs/reconcile-step-0`; `.agents/` is preserved exactly, including the committed binary metadata files. Repository skills were read. Their historical NOT READY/proposal snapshots defer to current task status and Nico's explicit decisions; their security boundaries remain applicable. They are not edited to update those snapshots.

## Approved recommendation dispositions

| Approval | Final design and evidence | Existing task / implementation-test owners |
| --- | --- | --- |
| 1.1 Self-protection/native development | TD §§2.1/10.4; security-contracts §S1. Native mocks guarantee container-build-free iteration. No native self-protection exemption; missing/ambiguous identity is fail-closed. Real integration uses isolated disposable fixtures and dedicated test daemon where practical, never production Unraid socket. Identity recreation, multiple/stopped peers, dispatch races and active streams specified. | 0.02; P1.11–14/19–20; SELF acceptance register. |
| 1.2 Assurance/security notices | TD §4; full NIST mapping. Admin MFA mandatory, nonadmin policy unchanged. Password-only is never human AAL2. Adopt password/recovery/retry safeguards and advance only authenticator binding/removal/recovery/notification-address SMTP subset to Phase 1; requests/approval notices/webhooks remain Phase 2. Secure delivery, failures and assurance/recovery gates are specified. | 0.04; P1.02–03/05–10/16/19–20; N63B4 requirement → design → test/owner and official catalogue crosswalk. |
| 1.3 Maintenance/toolchains | TD §5; support matrix §§2–4. Go1.27.3 primary,1.26.10 compatibility CI, Node24.22.1 LTS/npm11.19.1. Retain React19/TS/Vite/Tailwind/shadcn and other stack choices. Approved support windows/update triggers/deprecation and tested/reviewed security updates; retry controls must resist avoidable account-lockout DoS. | 0.05, coordination 0.04; P1.01/05–08/19–20; SUP and N63B4 retry acceptance. |
| 1.4 Restore safety | TD §6; security-contracts §S2. Logical format, encrypted secrets and transactional import preserved; imported credentials/authority stay inactive absent trustworthy current revocation information until reissued/reapproved. Expired grants stay expired, security settings require explicit reapproval, emergency admin path is restricted. Unknown post-backup revocations and malicious full-host rollback cannot be guaranteed recoverable/preventable. | 0.06; P1.02–03/08–09/18–20; RESTORE acceptance register. |
| 1.5 Setup disclosure | TD §10.3; security-contracts §S3. Secret-free logged URL, protected host-local token retrieval for Compose/Unraid, no interactive distroless shell. Actual UID/permissions,30-minute absolute expiry,atomic single use, failure/restart/crash semantics and mandatory admin MFA. | 0.10; P1.04/08–09/16/19–20; SETUP acceptance register. |
| 1.6 Runtime/support | TD §5; support matrix §§4–6. Debian13 distroless nonroot replaces Debian12; production images use reviewed digests. CPU/environment/runtime/vulnerability/footprint verification remains mandatory before release, not claimed from upstream metadata. | 0.05/0.10; P1.01/12/14/16/19–20; SUP and resource/security release gates. |

## Original-card acceptance crosswalk

“Design complete” below describes substantive documentation acceptance; it is not a fabricated lifecycle transition. Inspect the live card and final readiness record for final status.

| Existing card | Approved design, positive/negative acceptance and disposition |
| --- | --- |
| 0.01 `t_e4f5bb4f` | Remains complete. TD §§1.1–1.3/3.3: six Phase 1 keys, strict parameter/schema contracts, unsupported-operation/raw-proxy rejection, API/MCP parity and stream expiry/revocation. P1.11–14/20. |
| 0.02 `t_b5a17cdc` | Design complete under approval1.1: TD §§2/3.3/10.4, §S1 identity/protected-peer/daemon boundaries and SELF register. Native limitation explicitly approved; no invented attestation exemption. Root-equivalent socket risk, actors, TLS/proxy assumptions and release rubric remain. |
| 0.03 `t_281bba7b` | Remains complete. TD §§3/4.3/7/11.1: first-class agents, owner XOR/no implicit inheritance, endpoint identity, hash-only scoped tokens and deny precedence. Allow/deny/revocation/expiry/cross-endpoint tests P1.02/08/10–14. |
| 0.04 `t_1af7c0f2` | Design complete under approval1.2: TD §4 and NIST requirement/design/test/applicability/SHOULD disposition register. Assurance, recovery, notice/address, retry/DoS, provider/governance evidence and conformance limits explicit. Actual implementation/device/governance evidence remains an owning-task/release obligation, not a missing Step 0 product. |
| 0.05 `t_92c5c52c` | Design complete under approvals1.3/1.6: approved stack/modules, toolchain tuple, maintenance/support/update/deprecation and Debian13 base. Candidate library minima are not actual compatibility tests; P1.01 locks/exercises graph, P1.19–20 runtime/security. |
| 0.06 `t_239f5e2a` | Design complete under approval1.4: TD §6, §S2 storage/encryption/migration/import integrity, present control state/quarantine/reauthorization and RESTORE scenarios. Same-key imports do not reactivate historical authority; secure emergency recovery and limitations explicit. |
| 0.07 `t_4f91fc1d` | Remains complete. TD §§3.4/7: endpoint-qualified selectors, rename/recreation/image/label/pin/missing-target tests. Optional guardrails protect only when configured; name-only grants remain deliberately broad. P1.11–14. |
| 0.08 `t_01261cf2` | Remains complete. TD §§1.3/8: default-off discovery/minimal metadata/no grant, generic requests,dedup/cooldown,permanent/temporary approvals,expiry/revocation/restart/retry tests before Phase 2 release. Only approved security-notice/address subset advances to Phase 1; general request/approval email/webhooks remain Phase 2. |
| 0.09 `t_4725c0a6` | Remains complete. TD §9: attribution,allowed/denied/error counts,retention,redaction and exact fixture totals. Collection Phase 1 (P1.15),report UI Phase 2,policy audit Phase 3. Setup disclosure resolved on0.10; no logging-secret exception. |
| 0.10 `t_e4846cd1` | Design complete under approvals1.1/1.5/1.6: TD §§9.3/10,§§S1.4/S3,support matrix. Host-local distroless-compatible setup,recovery,actual ownership,protected token state,expiry/concurrency/failure/crash tests; environment/resource/security acceptance. Product checks remain P1.19–20. |
| 0.11 `t_6cfc4cb1` | Remains complete. TD §§3.4/4.4/10.1/11: future role/federation/router/packaging/endpoint transport boundaries and eventual parity/denial tests. Phase 4 multi-instance safety is already constrained by §S1, not deferred self-protection. |
| 0.12 `t_86e68ae0` | Remains complete. TD §12: private Mandatary identity/existing destination. Public license/legal/branding checks belong to Nico before public release; no clearance claim or publication. |
| 0.13 `t_ddd96736` | Existing final gate, twelve prerequisite edges unchanged. Route to native `reviewer` only after all prerequisites complete; reviewer reads actual documents, verifies every exact R Step0 criterion and records explicit PASS/FAIL. Parent applies final closure only after verified verdict. No duplicate review card or implementation dispatch. |

## Bounded later-phase decisions

These are implementation details within approved architecture, not unresolved initial security/stack/policy choices. Nico owns any policy/architecture change; `coder` implements only after authorization; `reviewer` verifies before the milestone.

| Deferred detail | Owner / deadline | Non-blocking rationale |
| --- | --- | --- |
| Exec process/stream detail, discovery/request/grant UX and general SMTP/webhook retry scheduling | coder+reviewer before Phase2 acceptance; Nico for policy changes | Unavailable in Phase1; foundational identifier/authorization/expiry boundaries already specified. Phase1 security notices are explicitly excluded from this deferral. |
| Usage-report presentation/access control | coder+reviewer before Phase2 reporting implementation | Phase1 collects counts, not general-user report endpoints. |
| Multi-admin provisioning/routing, Authentik detailed claim/session integration | Nico for policy,coder+reviewer before Phase3 implementation | Phase1 single-admin/local-auth only; assurance/roles/endpoint contracts already constrain extensions. |
| Policy-audit screens/retention UX | coder+reviewer before Phase3 acceptance | Separate from Phase1 operational logging/counts and minimal security-notice events. |
| Operations UI UX/proxy packaging | coder+reviewer before Phase4 implementation | Listener absent in Phase1; no policy mutation/bypass or peer-protection exemption. |
| Remote endpoint credential lifecycle/removal/workload | Nico for policy,coder+reviewer before Phase5 implementation | Local endpoint only in Phase1; authenticated encrypted transports/endpoint identity already specified. |
| Public licensing/legal/trademark/public branding | Nico before any public release/publication | Private implementation does not imply legal clearance or public licensing. |

## Final readiness and Phase 1 boundary

`step-0-readiness.md` records the final criterion-by-criterion independent review and lifecycle evidence. `phase-1-plan.md` retains P1.01–P1.20 and C1–C5, measurable row acceptance, earliest-relevant security tests, automated CI and exact-head independent review. Its graph must be checked as an acyclic dependency order. No ready-to-dispatch Phase1 cards are created; automatic decomposition remains disabled. Even a PASS finishes only Step0 and recommends readiness for a separate Nico authorization; it does not authorize coding, merging or deployment.
