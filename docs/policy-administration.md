# Policy administration (P1.17)

Local, unreviewed contribution. This is not an approved product behaviour, not an independent review, and
not a NIST, FIPS or WCAG conformance claim. Test names below are real declarations; the evidence is the
executed tests, not this prose.

## What exists

The single policy administrator, signed in with a second factor, manages users, groups, agents and policy
rules through `/api/v1/admin/**` and four pages: Rules (`/policy`), Users, Groups and Agents
(`/policy/users`, `/policy/groups`, `/policy/agents`). There is no operations console: no page runs, starts,
stops, restarts, inspects or reads logs of a container.

**Authority is not permission.** The administrator role is the authority to write rules. It is not a rule and
allows no container operation; owning an agent allows none either. The only grant is an explicit rule that
names a user, a group or an agent (`TestTheAdministratorIsAnOrdinarySubjectOfRules`,
`TestPolicyAdministrationAB`). Every page states this.

## One mutation path

Every mutation goes through `Admin.mutate`: a fresh AAL2 session of the single administrator, no restore
quarantine, current control generations, one durable transaction, then the authority-change notification
that cuts open streams. There is no second, weaker route. Ordinary users, owners and agent tokens are
refused on every route (`TestOrdinaryUsersCannotManagePolicyOverDirectlyCraftedRequests`,
`TestPolicyAdministrationAB` "ordinary-user and agent-token policy mutations").

## Routes (29 administrative routes in total; the 12 of P1.10 are unchanged)

| Route | Boundary policy |
| --- | --- |
| `GET …/policy/{users,groups,agents,rules}` | session; the service refuses anyone but the administrator |
| `POST …/policy/rules/preview` | session (writes nothing; the service still refuses non-administrators) |
| `POST …/policy/rules` | `security-policy-change`; one rule per operation, all or none |
| `PUT …/policy/rules/{rule}` | edit effect, selector, caps in place; subject, operation and state are fixed |
| `POST …/policy/rules/{rule}/{enable,disable}`, `DELETE …/policy/rules/{rule}` | state change / removal |
| `POST …/users/{user}/{disable,enable}` | disabling ends the user's sessions and revokes the agents it owns |
| `POST …/groups/{group}/{disable,enable}`, `DELETE …/groups/{group}` | delete refused while anything relies on the group |
| `POST …/agents/{agent}/enable`, `PUT …/agents/{agent}/owner` | enable issues no token; transfer changes accountability only |

Not offered, deliberately: deleting users or agents, roles, a second administrator, editing a rule's subject
or operation (`TestAdministrativeRouteInventoryIsExactAndExplicit`).

## Semantics worth knowing

* **Cascades.** Disabling a user or group revokes the active agents it owns, because an agent with a disabled
  accountable owner must not keep working. Enabling anything revives nothing: tokens stay revoked and the
  agent stays disabled until enabled and issued a new token (`TestEnablingAUserDoesNotReviveItsAgentsOrTokens`,
  `TestAgentEnableRequiresAnActiveOwnerAndIssuesNoToken`). Memberships and rules are kept.
* **Rules.** Six operation keys only (`container:logs`, `inspect_status`, `inspect_config`, `start`, `stop`,
  `restart`), no wildcards. A cap the operation cannot accept (a tail cap on a Deny, a timeout cap on Logs)
  is refused, never silently dropped. Identical selectors share one immutable row. Editing or toggling is
  guarded by the current authority generation, so a restored or stale rule can only be deleted, never
  revived (`TestRuleStateTransitionsAreExactAndNeverReviveStaleOrRestoredRules`).
* **Targets.** A rule whose selector matches nothing is kept and flagged `missing`; when the endpoint
  cannot be verified every target is `unknown`, never `present` (`TestRulePageReportsMissingPresentAndUnknownTargetsAndNeverInventsAMatch`).
  Mandatary and its peers are never listed or previewed (`TestListEndpointContainersNeverNamesSelfOrPeersAndRequiresAVerifiedBackend`).
  In this build no Docker backend is composed in `cmd/mandatary`, so the page truthfully shows the endpoint
  as unverified with no inventory; the Docker-backed source is `auth.AuthorizerTargets`, wired by whoever
  composes the executor (the end-to-end test composes it).
* **The endpoint read survives an aborted request.** The inventory read behind the Rules page and the
  selector preview is detached from the HTTP request's cancellation and bounded only by an 8 s timeout
  (`TestEndpointReadIsDetachedFromCallerCancellationButBounded`). The production Docker adapter treats any
  error from that read as loss of the endpoint-wide safety proof, so an administrator closing the tab must
  not be able to make every principal's operations fail with `safety_unverified`. Reaching the 8 s deadline
  is a genuine backend fault and may still invalidate that proof; that is deliberate fail-closed behaviour.
* **Removal state is data.** `removal.allowed` and `blockers` come from the same function that refuses the
  deletion, so the page and the refusal cannot disagree (`TestIdentityPagesReportOwnershipMembershipRulesAndRemovalFromServerState`).
* **Empty lists are `[]`.** The web client decodes strictly and fails closed (`TestEmptyPagesUseEmptyArrays`).

## A/B denial evidence

`TestPolicyAdministrationAB` (package `auth_test`) runs the real SQLite store, the real Browser boundary
(cookie, Origin, CSRF, step-up), the real services, the shared authorizer, `ops.Service`, the REST adapter
and the official MCP server with a real MCP client over loopback HTTP. Only Docker is a mock, behind a spy
that counts operational calls before delegating. Sequence: administrator → user, group, agent, token →
grant on container A. Then, over **both** REST and MCP with the same outcome: A is allowed for exactly the
granted functions; B, the ungranted functions on A, a cap overrun, raw-proxy and exec paths, and the
administrator's own session and an administrator-owned agent are denied with zero Docker calls. Deny, disable,
tighten, delete, membership removal and owner disablement cut an open log stream within 15 s while the pull
interval is 30 s, so only the push path can pass. A deleted, recreated or re-labelled target stops matching.
Ordinary-user and agent-token mutation attempts leave a deterministic policy-state dump unchanged.

## Web

`web/src/api/policy.ts` (strict decoders, validated path segments, CSRF held inside `AccountApi`),
`web/src/containers/PolicyContainers.tsx` (outcome mapping per the UX contract §6, step-up in place without
replay, a 503 on a mutation is "outcome unknown"), nav group and exact document routes in `web/assets.go`.
P1.16's "Agents" nav item is relabelled "Agent tokens". Tokens are never handled by these pages; they link to
`/agents#agent=<id>` (a fragment: never sent to the server), which only preselects a server-listed agent.

## Known limits

* Component/integration evidence over a mock Docker backend, not real Docker.
* Restore approval of quarantined rules and memberships is P1.18; audit trail is Phase 3.
* No endpoint other than the single local one; no per-rule filtering link from Users/Groups/Agents.
