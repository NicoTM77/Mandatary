# Runtime configuration and redacted logging (P1.04)

## Delivered scope

The binary is still the **loopback-only static development skeleton**, with the
P1.03 required-key/repository boundary. Configuration/logging adds no setup,
login, recovery, API/MCP, Docker, mail, operations listener or authority. Do not
expose it as a production product. See [development.md](../development.md) for
locked toolchains and private test directories, and
[storage-repository.md](storage-repository.md) for the unchanged key/file,
quarantine, generation, WAL and durability contracts.

## Implemented settings

| Variable | Default | Validation / behavior |
| --- | --- | --- |
| `MANDATARY_LOG_LEVEL` | `info` | Exactly `debug`, `info`, `warn`, `error`; minimum severity, including the global slog/standard-log and HTTP error-log bridges. |
| `MANDATARY_LOG_FORMAT` | `json` | Exactly `json` or `text`; both write to **stdout**. Local `make dev` explicitly selects `text` unless overridden. |
| `MANDATARY_DATA_DIR` | `/data` | Absolute, already-clean path without control characters. The repository additionally enforces actual owner/ancestor/file safety; config parsing creates nothing. |
| `MANDATARY_MASTER_KEY` / `MANDATARY_MASTER_KEY_FILE` | Required; no generated/default key | Exactly one nonempty source, using P1.03 `store.LoadMasterKey` unchanged: nonzero 32-byte hex/base64 value, or protected key file. Missing, conflicting, invalid or unreadable sources deny before storage/listener access. Never put real values in commands, examples, logs or issue reports. |

Empty values select documented defaults (except key sources, which remain
required). Spellings are case-sensitive; whitespace, aliases such as `warning`,
custom numeric levels, and unknown format values are rejected, not normalized.
Invalid configuration returns process exit 1 with a fixed JSON ERROR event on
stdout (`startup failed`, `stage=configuration`), even when the requested format
was invalid. It does not echo values, dump the environment, read a master key,
create storage, or open a listener. Once log configuration is valid, key/storage
and listener failures use its selected format, fixed events and safe stage codes;
no raw error, path, SQL, DSN, key source or stack is logged. Close failures also
return nonzero rather than being hidden by `log.Fatal`/`os.Exit` before cleanup.

The approved TD §13 table describes the eventual Phase 1/4 product, not today's
implemented switches. `MANDATARY_ADMIN_LISTEN_ADDR`, `MANDATARY_DOCKER_SOCKET`,
`MANDATARY_DEV_MOCK_DOCKER`, `MANDATARY_OPS_UI_ENABLED`,
`MANDATARY_OPS_LISTEN_ADDR`, and `MANDATARY_PASSWORD_HIBP_ENABLED` are currently
**unavailable**. Any nonempty setting of one of these fails configuration,
including a nominal future default: silently accepting a no-op security setting
would be misleading. Unset them for this skeleton. The listener remains fixed
at `127.0.0.1:8080`. P1.12 owns the actual guaranteed container-free Docker mock;
P1.19 owns configurable production exposure. No native real-socket exception.
Unrecognized environment names are not enumerated or logged; this is not a
promise to detect misspelled arbitrary environment variables.

## Logging schema: deny by default

`internal/logging.New` wraps the standard `log/slog` JSON/text handler **before**
formatting or resolving values. A deny-by-default schema is deliberate: regexes,
entropy guesses and lists of known secrets cannot reliably recognize an unknown
password, short OTP, challenge, cookie or arbitrary error/payload. No debug-level
exception exists. The current schema admits:

- Fixed event messages: `development server started`, `startup failed`,
  `server failed`, `storage close failed`, `request completed`, `request panicked`.
- `method`: exact standard HTTP method enumeration, not arbitrary client input.
- `status`: integer 100–599; `duration`: nonnegative `slog.Duration`.
- `stage`: exactly `configuration`, `storage` or `listener`.
- Groups named `http`, `server`, `config`, or an inline group; their children
  pass through the same validation. Unknown groups also deny their descendants.

Everything else becomes `redacted="[REDACTED]"`, including unknown **keys and
group names**. Arbitrary messages become `[REDACTED]`. Errors, maps, structs,
slices, bytes, URLs, environment dumps, request/response objects, bearer tokens,
passwords, cookies, TOTP seeds, numeric OTPs, recovery/setup tokens and WebAuthn
challenges are not serialized. The handler never calls user `Error`, `String`,
`MarshalJSON`, or `LogValue` methods. `With`, `WithGroup`, and per-record attributes
share this boundary. `logging.Secret` supplies an additional opaque Stringer /
GoStringer / LogValuer guard (also for an ordinary slog handler); it is not secure
memory, a secret registry, a disclosure function or an erasure guarantee.

Use static event constants and correctly typed **operational** fields. Do not
encode application data/secrets into admitted status/duration fields. New useful
fields/events require a reviewed bounded schema extension with positive and
negative tests; do not bypass the boundary with a raw handler, `fmt.Print`, or a
separate logger. Preformatting arbitrary objects before calling a logger may run
user code before the handler; pass attributes, not formatted objects. No handler
can protect against deliberate direct writes to stdout/stderr or a malicious
process/host. Runtime fatal panics outside the installed HTTP boundary and
third-party/reverse-proxy logging remain their owners' integration obligations.

## HTTP behavior and data minimization

The middleware records only method/status/duration; no client IP, host, URL/path,
query/fragment, forwarded headers, cookies, body, resource/account ID or response
payload. Successful requests log at INFO, 4xx at WARN, and 5xx/panics at ERROR.
It does not inspect/read a body or alter the route/authorization surface. It
preserves first-final-status/implicit-200 behavior and supports the standard
`http.ResponseController` via `Unwrap`/`FlushError`. Direct optional writer
interfaces beyond that are not promised for future streaming adapters, which
must exercise their own integration tests.

Recovered panic values/stack traces are never formatted. Before commitment a
panic produces a generic 500; after commitment the middleware raises only
`http.ErrAbortHandler`, so net/http aborts without printing the original panic.
The server's separate `ErrorLog` is bridged through the same redaction handler.
This is not a generic response-body sanitizer: handlers own their public response
schemas, and a deliberately secret-bearing handler response is not repaired here.

No log files, auth history, fingerprinting, telemetry or log retention database
are added. The process writes only stdout; deployment operators must define
bounded collector access/retention/deletion and document it before production.
Do not inherit usage/audit 90/365-day retention for application logs. No consent
or extra personal-data processing is required by this change.

## Bootstrap/control-channel boundary

Per security-contracts §S3, ordinary logging has **no credential-disclosure
exception**. In particular, a token-bearing setup URL, error, cookie, response
trace or environment value is redacted at every severity/format. There is no
setup route/token or reveal helper in this PR. P1.09 must emit only a validated,
configured secret-free setup URL and deliver plaintext solely through its real
protected host-local terminal protocol, never slog/stdout container logging.
This logger does not offer a `reveal`, `unsafe` or redaction-disable switch.

`TestSecretTypeAndSeparateControlOutput` keeps a synthetic control sink distinct
from captured ordinary output. It establishes **only sink separation**, not UID,
TTY, permissions, locks, durability, lifetime, single use, or protected disclosure.
Those actual SETUP-03–12/RESTORE host-helper guarantees remain P1.09/19/20 work;
the synthetic sink is not a mock substitute for their acceptance evidence.

## Contract-to-test links and evidence limits

| Contract | Executable coverage in this PR | Still outside this card |
| --- | --- | --- |
| TD §9.3, R shared logging; P1.04 all 4 levels × both formats | `TestSecretCanariesAllLevelsAndFormats`, `TestLevelFilteringAndUsefulMetadata`, `TestLoggingConfiguration` | No claim that arbitrary outside writers/proxies are redacted. |
| SETUP-02 logging portion; NIST D-10, O04 / `N63B4-OTP-CLAIMS`, I09 / `N63B4-THREAT-BROWSER` logging portion | Canary matrix; `TestRequestAndErrorPathsNeverLogPayloads`; native HTTP panic/error-log test; runtime integration tests | Actual setup/recovery/browser/proxy flows and OTP replay/account-parity behavior stay with P1.06/08/09/16/19/20. |
| S3 ordinary/control separation | `TestSecretTypeAndSeparateControlOutput`; ordinary canary matrix includes synthetic setup token | Actual protected host disclosure is **not implemented/tested** here. |
| A08/A09, S10, I10 / `N63B4-GOV-RETENTION`, `N63B4-GOV-PRIVACY`, `N63B4-SESSION-MONITORING`, `N63B4-PRIVACY-REVIEW` | No IP/identity/path/body/headers, no persistence/telemetry/monitoring; schema and HTTP tests enforce exclusion | Deployment/operator-specific legal retention/privacy/control tailoring and redress evidence must be settled in owning product/release review; no NIST/federal conformance claim. |
| A05 / `N63B4-AAL-TIMEOUTS`, `REAUTH-*` mapping | No session configuration, session issuance, assurance or timeout change is introduced | P1.08 implements/tests 12h/30m clocks and prevents incompatible timeout settings; logging cannot establish AAL2. |
| SELF, RESTORE, N1/N2/R1/A1 | Existing storage/security regression suite retained unchanged; no authority/restore/bootstrap/notification transition added | Later owners still implement integrated SELF/RESTORE/authentication/notices/controlled-runtime acceptance. |
| SUP-01/06 and continuous checks | Existing locked build/race/frontend/generated-output/scanner commands include new packages automatically | Browser, OS×CPU, image, proxy, SMTP, real Docker, filesystem/device/provider and release budgets are not qualified by local logging tests. |

Run the documented `make install check negative-control`, on both approved Go
versions, then `make tools security`. Synthetic test failures report fixed
assertion names, not secret-bearing captured buffers. See the task/PR evidence
for actual commands, exact head, adverse-control results and scanner residuals;
this reference describes behavior, not an independent approval or release claim.
