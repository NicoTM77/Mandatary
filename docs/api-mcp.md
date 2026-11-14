# REST API (`/api/v1`) and MCP adapters (P1.14)

`internal/api` (REST) and `internal/mcp` (MCP Streamable HTTP) are **thin
adapters**. Each one authenticates a Bearer agent token, decodes one strict
request and calls exactly one function, `ops.Service.Execute` (P1.13), which
owns authorization, self-protection and dispatch to the `DockerBackend`.
Neither adapter imports `docker`'s concrete client, builds a Docker request,
forwards a path, query or body, or decides authorization. The versioned
contract is pinned by `internal/api/testdata/contract-v1.json` (contract
version `1.0.0`); `tests/adapters` fails when the served contract and that
file differ.

## Boundaries

| Property | Rule |
| --- | --- |
| Credential | Exactly one `Authorization: Bearer mdt_…` header carrying a canonical agent token. Cookies, sessions, setup/recovery capabilities, JWTs, Basic, query-string tokens and caller-asserted identity/role/assurance are **not credentials** and yield `401` without storage access (SCOPE-MACHINE, TOKEN-NOT-PRESENCE). |
| Order | Origin check → route → method → **authenticate** → strict decode → `Execute`. Unauthenticated callers get `401` before any query, body or target is looked at, so there is no pre-authentication name or protected-target oracle (C1 O1). |
| Authentication gate | `authz.Authorizer.Authenticate` applies the credential-validity checks (installation/restore quarantine, generation, expiry, revocation, rotation window, agent state) with no backend contact. `Execute` repeats them; the adapters never rely on one check alone. |
| Authorization | Only `Execute`. A tool listing, a route that exists or a prior call is never evidence of authority. The administrator role grants no operation; an agent owned by an administrator inherits nothing. |
| Operations | Exactly the six approved keys: status, config, logs, start, stop, restart. Exec, container listing/discovery, access requests, image/volume/network operations and raw Docker access **do not exist** (they are absent, not denied). |
| Cross-origin | A request carrying an `Origin` header is refused (`403 forbidden_origin`) unless the origin is explicitly configured. No CORS header and no cookie is ever sent. Bearer clients are non-browser clients. |
| Methods | Read-only operations are `GET`; mutating ones are `POST`. No state-changing `GET` exists. Any other method on a known route is `405` with `Allow`. |
| Secrets | A presented token never appears in a response, error, log or `fmt` output (`api.Token` redacts itself). Error messages are fixed strings. `inspect_config` returns the P1.12 allowlisted, redacted structure unchanged. |

## REST routes

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/readyz` | Unauthenticated; `200`/`503` `{"ready":bool,"version":"1.0.0"}`. `503` until every configured endpoint has verified self-identity (SELF-01/02/07). |
| `GET` | `/api/v1/endpoints/{endpoint}/containers/{container}/status` | No parameters. |
| `GET` | `…/config` | No parameters. |
| `GET` | `…/logs` | Query: `tail` (1–10000), `stdout`, `stderr`, `timestamps` (`true`/`false`), `since`, `until` (RFC 3339), `follow` (`true`/`false`). |
| `POST` | `…/start` | No body. |
| `POST` | `…/stop` | Optional JSON body `{"timeout_seconds":1–300}`. |
| `POST` | `…/restart` | Optional JSON body `{"timeout_seconds":1–300}`. |

`{endpoint}` is an endpoint UUID or a configured slug (`local`); `{container}`
is a container name or full 64-hex ID, never prefixed with `/`. The route
inventory is exact: every other path, including double slashes, dot segments,
encoded separators, trailing slashes, alternate case and Docker-style paths, is
`404`; an encoded separator or control byte *inside* an identifier is
`400 invalid_request`. Nothing is path-cleaned or redirected.

### Strict schema

Query parameters and bodies are closed: an unknown, repeated, empty-named,
case-variant or other-operation parameter is `400`; values must have the
declared JSON/URL form (no `tail=all`, `tail=0`, numeric booleans, zoneless
timestamps, floats, `null`, duplicate JSON keys, trailing data, non-object
bodies). Only `stop`/`restart` accept a body (`application/json`, ≤ 4 KiB;
`415`/`413` otherwise); only `logs` accepts a query. Endpoint and container
can only come from the path. Docker options (`all`, `force`, `signal`, `v`,
`size`, `filters`, `path`, `host`, …) are unknown fields.

### Follow-mode logs (REST only)

`GET …/logs?follow=true` streams `application/x-ndjson`: one metadata line,
one `{"stream","text"}` line per frame, and exactly one terminal line,
`{"end":"eof"}` or `{"error":{…}}`. The stream holds an authorizer lease
(P1.13). Every authority-ending cause (revocation, expiry, quarantine, a policy
change) ends it with
`{"error":{"code":"forbidden","reason":"authorization_ended"}}` and no later
frame. Loss of the safety proof ends it with reason `safety_unverified` when the
backend transport reports the loss first (`docker.ErrUnverified`); if the
stream's own revalidation observes the lost proof first, the lease ends the
stream and the reason is `authorization_ended`, so a client must treat both as
"authorization ended, do not retry blindly". `tests/adapters`
(`TestFollowStreamEndsOnEveryRevocationOrExpiryCauseOverREST`) asserts the reason
per cause. Revocation is *pushed* when the code that changes authority
calls `ops.Service.NotifyAuthorityChange` (the `notify` hook of `auth.Admin`);
independently, every stream revalidates on its own interval (pull path), so a
change made without a push (for example a human-session revocation, P1.13 review
O1) still ends the stream within one interval. `tests/adapters` proves both
paths. The adapters never change authority themselves. Concurrent streams are
capped per credential (default 4) and overall (default 64) with `429
too_many_streams`. MCP has no follow mode (`follow` is an unknown argument).

## MCP

`POST /mcp` (Streamable HTTP, JSON responses, **stateless**: no
`Mcp-Session-Id` is issued or accepted as authority). Every HTTP request,
including `initialize` and `tools/list`, is authenticated before its body is
parsed; `tools/call` is authenticated and authorized again per call, so
authority is never carried by an MCP session. `GET`, `DELETE`, a trailing
slash, sub-paths and a query string on `/mcp` are refused. The server
advertises only the `tools` capability and serves no prompts, resources or
server-initiated requests. Request bodies are bounded to 64 KiB.

Tools (names, closed JSON Schemas and annotations are in the contract file):
`container_status`, `container_config`, `container_logs`, `container_start`,
`container_stop`, `container_restart`. Every tool takes required `endpoint` and
`container` strings plus the operation's parameters (same names, types and
bounds as REST, except `follow`). The catalog is identical for every
authenticated principal: **listing is not authorization.**

A failing tool call is a `CallToolResult` with `isError: true` whose
`structuredContent` is the common error object below; failures that happen
before the JSON-RPC layer (401, 403 origin, 404, 405, 413, 415) are plain HTTP
responses of the same shape. An unknown tool name is a protocol error and
reaches nothing.

## Common errors

Shape (REST body and MCP `structuredContent`):
`{"error":{"code","status","message","reason"?}}`. Messages are fixed strings.

| Code | Status | When |
| --- | --- | --- |
| `unauthenticated` | 401 | Missing/malformed/unknown/expired/revoked/rotated-out/disabled/stale-generation credential, or a non-agent credential. Carries `WWW-Authenticate: Bearer`. |
| `forbidden` | 403 | `reason`: `default_deny`, `restore_quarantined`, `safety_unverified`, `endpoint_inactive`, `parameter_cap_exceeded`, `authorization_ended`, `forbidden_origin`. |
| `invalid_request` | 400 | Schema violation; also an invalid identifier. |
| `not_found` | 404 | Unknown route or tool. A container that is missing *before authorization* is `403 default_deny` (protected, missing and ungranted targets are indistinguishable). A target that disappears *after* authorization, at dispatch (`docker.ErrTargetNotFound`), is `404 not_found` for that already-authorized caller; usage accounting counts it as an **error**, not a denial. |
| `method_not_allowed` | 405 | Known route, wrong method. |
| `payload_too_large` / `unsupported_media` | 413 / 415 | Body bounds / content type. |
| `too_many_streams` | 429 | Follow stream cap. |
| `canceled` | 499 | Caller disconnected, or any error that is `context.Canceled`. Same code on REST and as a structured MCP tool error; never `forbidden`. |
| `backend_failed` / `backend_unavailable` / `timeout` | 502 / 503 / 504 | Docker-side fault, no verified backend, deadline. `timeout` is any error that is `context.DeadlineExceeded` (for example a fired dispatch/open deadline); never `forbidden`. See [operations.md](operations.md) for the precedence between a departed caller and a fired deadline. |
| `internal` | 500 | Any unclassified error (text never exposed). |

Self-protected (self and labelled peers), missing, explicitly denied, ungranted
and stale-decision targets are all reported as the same
`403 default_deny` (TD §2.1: Mandatary and its peers are not visible to
callers); the precise reason stays server-side. Global states
(`restore_quarantined`, `safety_unverified`, `endpoint_inactive`) are not
target-specific and are reported as such.

## Composition and deployment

`api.Compose(rest, mcp, fallback)` reserves the machine namespaces (`/api/v1/readyz`, `/api/v1/endpoints/…`, `/mcp/…`; other `/api/v1` paths such as `setup` and `admin` belong to the human handlers):
nothing under them can fall through to the static site, and the exact
unrewritten path is dispatched (no path-cleaning mux). In the current binary the
adapters are composed with no executor (`Compose(nil, nil, static)`), so both
namespaces answer the common `404`: real Docker integration, the endpoint
registry and agent-token issuance UI are later rows (P1.16/P1.17/P1.19).
`tests/adapters` composes the real store, authorizer, `ops.Service`, both
adapters and the official go-sdk MCP client over loopback HTTP, with the mock
Docker backend behind an attempt-counting spy.

**Not delivered in this row:** a CLI stdio bridge. No bridge scope was
approved; adding one would need its own authentication design and must never be
a weaker path than Bearer-over-HTTP.

## Verification

`tests/adapters` runs one identical positive/negative matrix through REST (real
HTTP) and a real MCP client (go-sdk, Streamable HTTP) against the same
environment. Per case it asserts the expected status/code/reason, the **measured
Docker reach** (zero backend calls, lookup-only, or exactly one operational
call) and exact REST/MCP parity of class and success payload. Covered: all six
operations; unauthenticated, malformed, expired, revoked, rotated-out,
quarantined, disabled, stale-generation, non-agent and caller-asserted
credentials; restore quarantine and post-restore re-approval; cross-container,
cross-endpoint, admin-owned, deny-overrides-allow and parameter caps; SELF-10 on
every operation for self, stopped peer and an innocuously named labelled peer;
SELF-01/02/07 closing the surface; unsupported exec/discovery/raw tools and
routes; Docker-style paths, queries and alternate spellings; Origin/CORS/cookies;
MCP session independence; follow-stream revocation (token revoked, expired,
agent disabled, policy removed, deny added, quarantine, generation bump, safety
loss; push and pull); concurrency under `-race`.

Regenerate the contract fixture after an *intended* contract change with
`MANDATARY_UPDATE_CONTRACT=1 go test ./tests/adapters -run TestContractFixture`.

## Requirement-to-executable-test map

Every name below is a real test declaration; `TestAdapterCrosswalkNamesResolve`
fails if one is missing. Tests of `tests/adapters` run the real SQLite store,
authorizer, `ops.Service`, REST handler and the official MCP client over
loopback HTTP; they are component/integration evidence over the **mock** Docker
backend, not real-Docker, browser or hardware evidence and not a NIST/FIPS
claim.

| Acceptance / contract | Tests |
| --- | --- |
| Identical positive matrix over REST and a real MCP client, parity of class and payload | `TestMatrixAllowedOperationsOnTheGrantedTargetOverBothTransports`, `TestSuccessPayloadsAreTheSanitizedAllowlistedStructures` |
| Bearer auth: 401 for missing/malformed/non-agent/expired/revoked/rotated-out/quarantined/disabled/stale credentials, before any target (C1 O1), zero backend contact | `TestMatrixUnauthenticatedExpiredRevokedAndRestoredCredentialsAreRefusedBeforeAnyTarget`, `TestAuthenticationIsEvaluatedFirstAndOnlyAcceptsOneCanonicalBearerToken`, `TestAuthenticatorFailuresAreMappedAndNeverReachTheSharedService`, `TestAuthenticateVerifiesCredentialsWithoutAnyBackendContact` |
| Expired and restored credentials; restore quarantine; post-restore re-approval (RESTORE, C2 gate) | `TestMatrixRestoreQuarantineDeniesEveryCredentialUntilReapprovalAndRevocationsStayRevoked`, `TestMatrixRestoredInstallationOldCredentialsFailAndNewOnesNeedNewlyApprovedRules` |
| Cross-container, cross-endpoint, admin role grants nothing, deny overrides allow, parameter caps | `TestMatrixAuthorizationDenialsCrossContainerAdminRoleDenyOverridesAndCaps` |
| SELF-10 and SELF-01/02/07 through both adapters; readiness | `TestMatrixSELF10SelfAndPeerTargetsAreDeniedOnEveryOperationEvenWithAWildcardAllow`, `TestMatrixSELFSafetyStateClosesTheSurfaceAndReadinessReportsIt`, `TestReadinessReportsUnverifiedBackendsWithoutAuthentication` |
| Strict schemas; raw Docker option/query/body passthrough refused | `TestMatrixStrictSchemasRefuseMalformedUnknownAndPassthroughInputOnBothTransports`, `TestStrictSchemaRefusesEveryUnknownOrMalformedQueryAndBodyBeforeTheSharedService` |
| Unsupported exec/discovery/raw operations, unrecognized route/method/query, alternate routes never reach Docker | `TestMatrixUnsupportedExecDiscoveryAndRawOperationsDoNotExist`, `TestRawDockerPathsQueryPassthroughAndAlternateRoutesNeverReachDocker`, `TestUnknownMethodsAndQueriesOnKnownRoutesNeverReachDockerAndDefinedParametersStillWork`, `TestRouteInventoryIsExactAndRefusesEverythingElseBeforeAnyBackendOrAuthStateIsTouched`, `TestEncodedSeparatorsInIdentifiersAreInvalidRequestsNotRoutes`, `TestOperationCatalogIsExactlyTheSixApprovedKeysAndUnsupportedOnesAreAbsent`, `TestComposeReservesTheMachineNamespacesAndLeavesTheRestToTheFallback`, `TestServedBinaryReservesTheMachineNamespacesWithoutAnExecutor` |
| Tool listing is not authorization; MCP stateless, per-request authority, only tools | `TestMCPToolCatalogIsExactlyTheSixStrictToolsAndListingIsNotAuthorization`, `TestMCPServerAdvertisesOnlyToolsAndNoHiddenFeatures`, `TestMCPAuthorityIsEvaluatedPerRequestAndNeverCarriedByASession`, `TestMCPEveryHTTPRequestIsAuthenticatedBeforeItsBodyIsParsed`, `TestMCPRouteMethodQueryOriginAndBodyBoundaries`, `TestMCPHasNoFollowStreamingAndRESTFollowIsLogsOnly` |
| Follow streams: lease, revocation/expiry/policy/quarantine/safety end (push and pull), caps, authorization | `TestFollowStreamDeliversFramesAndEndsWhenTheClientLeaves`, `TestFollowStreamEndsOnEveryRevocationOrExpiryCauseOverREST`, `TestFollowRequestsAreAuthorizedAndBoundedLikeEveryOtherRequest` |
| Common errors map without leaking text; secrets/tokens never echoed or formatted | `TestSharedServiceErrorsMapToTheCommonErrorsAndNeverLeakTheirText`, `TestNoSecretOrTokenIsEverEchoedByAnyAdapterResponse`, `TestTokenAndRequestsNeverFormatTheirSecrets` |
| N63B4-SCOPE-MACHINE, N63B4-TOKEN-NOT-PRESENCE, N63B4-SESSION-COOKIE-CSRF (adapter side: no cookie, no CORS, no state-changing GET, Origin refused) | `TestAgentBearerNeverMintsCookiesSessionsOrAssuranceAndHumanCredentialsAreNotAgentCredentials`, `TestBrowserBoundaryNoCookiesNoCORSNoStateChangingGETAndBearerNeverMintsASession`, `TestBrowserBoundaryOriginIsRefusedAndNoCORSIsEverOffered` |
| N63B4-DOC-FACTOR-INVENTORY, PWD-ROUTE-PARITY, OOB/WALLET/RESTRICTED-UNSUPPORTED, SCOPE-FEDERATION, RECOVERY-NO-SESSION (no human-authentication, factor, recovery, setup, federation or access-request route or tool exists on the machine surface) | `TestAdapterNamespacesExposeNoHumanAuthenticationFactorRecoverySetupFederationOrAccessRequestSurface` |
| Versioned contract pinned | `TestContractFixtureIsCurrentAndExact` |
| Duplicate JSON object keys (top-level, retargeting identifier, nested) are rejected on the MCP wire by the real adapter+SDK exactly like REST: sanitized `invalid_request`, zero backend calls, zero usage; non-duplicate control reaches one stop | `TestMCPDuplicateObjectKeysAreRejectedOnTheWireWithZeroBackendAndUsageEffect` (REST: `TestStrictSchemaRefusesEveryUnknownOrMalformedQueryAndBodyBeforeTheSharedService`) |
| `canceled`/499 and `timeout`/504 mapping of context errors, identical on REST and structured MCP, never forbidden, no cause leakage, one accounted error | `TestContextErrorsMapToCanceled499AndTimeout504OnBothTransportsAndNeverToForbidden`, `TestClassifyContextErrorContractIsCanceled499AndTimeout504NeverForbidden` |
| P1.15 usage accounting is identical over REST and MCP (shared service; see [usage-accounting.md](usage-accounting.md)) | `TestUsageIsAccountedIdenticallyOverRESTAndMCP` |
| Concurrency under `-race` with racing revocation | `TestConcurrentRequestsOverBothTransportsAndRevocationAreRaceFree` |
