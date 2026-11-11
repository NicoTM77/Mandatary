# First-administrator setup and host-local emergency recovery (P1.09)

Implements `security-contracts.md` §S3 / S3.1a / S3.1b / S3.2 and TD §10.3. This
page is the operator reference for what exists **in this change** and what does
not. Anything not listed under "Verified" below remains unverified.

## What exists

| Piece | Where |
| --- | --- |
| Control schema (`setup_state`, `setup_tokens`, `setup_attempts`, `setup_sessions`), migration `00011` | `internal/store/migrations`, `queries/setup.sql` |
| Descriptor-relative reveal-file primitives (0700 dir, 0600 file, no-follow, `O_EXCL`) | `internal/store/reveal.go` |
| Two-phase control transition under the shared lock (`ControlThen`) | `internal/store/repository.go` |
| Service: issue/rotate, reveal, exchange, enrol, complete, reconcile, status | `internal/auth/setup*.go` |
| HTTP adapter (`/api/v1/setup/*`), its own cookie, CSRF and 404-when-closed rule | `internal/auth/setup_http.go` |
| Host helper subcommands of the existing binary | `cmd/mandatary/setup_cli.go`, `terminal_linux.go`, `privdrop_linux.go` |
| Startup wiring (first-start issuance, secret-free URL log, maintenance loop) | `cmd/mandatary/main.go` |

The setup surface is **API only**. The browser form that posts to it (the
`/setup` page and its address/MFA screens) belongs to P1.16; until then no page is
served at the logged URL, and the API is what a browser form will call.

## Server configuration

| Variable | Meaning |
| --- | --- |
| `MANDATARY_PUBLIC_ORIGIN` | Trusted HTTPS origin, `https://host[:port]` only (no path, query, userinfo). The **only** source of the logged URL and of Host/Origin checks; no request header is consulted. Unset ⇒ setup is unavailable and nothing is issued. |
| `MANDATARY_SMTP_RELAY`, `MANDATARY_SMTP_TLS` (`implicit` or `starttls`), `MANDATARY_SMTP_SENDER`, `MANDATARY_NOTICE_CONTACT` | Verified-TLS relay for address-confirmation proofs and security notices. All four or none; requires `MANDATARY_PUBLIC_ORIGIN`. Without them the first administrator **cannot** be completed (an address proof is mandatory) and the log says so. Authenticated relays are not configurable in this change. |

On the first start of an **empty** store with a trusted origin the service issues
exactly one initial-setup generation and logs only

```
initial setup available  setup_url=https://<origin>/setup  generation=N  expires_at=<UTC>
```

A restart never issues another token. After expiry, consumption, a crash or an
uncertain reveal the log says `initial setup unavailable reason=rotation_required`
and only an explicit host rotation (below) can reopen setup, while no
administrator exists.

## Host-local helper

Run the **same static binary** on the host, as the mapped non-root service
identity (or as root with explicit `--uid/--gid`, after which it drops
privileges, clears supplementary groups and verifies it cannot regain root,
before touching any key, data or reveal file). It never starts the server, never
creates or migrates a store, never touches Docker, and accepts no secret via
argv, environment or stdin.

```
mandatary setup status
mandatary setup rotate
mandatary setup reveal
mandatary recovery reset-mfa --user NAME --acknowledge-all-factors-lost-risk [--replace-password]
mandatary recovery reveal    --user NAME
mandatary recovery restore-admin          # refuses: not available until the restore service (P1.18)
flags: --data-dir PATH   --master-key-file PATH   --uid N --gid N
```

Defaults: `--data-dir` ← `MANDATARY_DATA_DIR` (then `/data`), `--master-key-file` ←
`MANDATARY_MASTER_KEY_FILE`. The helper requires a key **file** (never the
`MANDATARY_MASTER_KEY` value). A helper built from a different revision than the
one that issued a token refuses to reveal it.

**Reveal** requires stdin, stdout and stderr to all be the process's real
controlling terminal (verified before any claim or plaintext access). Pipes,
redirections, `script`-style wrappers on a different tty, and a missing terminal
are refused without consuming anything. The token is written once to that
terminal only (never `slog`); the file is then unlinked and the state recorded.
Failure after the claim (write error, crash) makes that generation permanently
non-revealable — run `rotate` again.

### Initial setup

1. Start the server with `MANDATARY_PUBLIC_ORIGIN` and the notice relay set; read
   only the `setup_url` from the log.
2. On the host terminal: `mandatary setup reveal`; copy the token by hand.
3. Browser form (P1.16) → `POST /api/v1/setup/exchange` with `{"token": "…"}`.
   The first valid POST atomically consumes the token into one setup session that
   expires no later than the original 30-minute deadline.
4. Stage username, password (8–128 characters is acceptable *only because MFA is
   compulsory*) and 1–4 notification addresses; prove control of at least one
   address by the mailed code; begin and prove TOTP (SHA-256) with a live code.
5. `POST /api/v1/setup/complete`. Only now does the installation unlock. **No
   login session is issued**; the administrator performs an ordinary
   password + TOTP login (AAL2).

### Emergency MFA reset (administrator lost every second factor)

`mandatary recovery reset-mfa --user NAME --acknowledge-all-factors-lost-risk`
(optionally `--replace-password`) issues a separate-purpose generation bound to
that one existing active administrator, and ends that account's sessions and any
saved-code recovery capability **before** issuance. The old factors stay usable
until the replacement is proven, so an abandoned ceremony cannot lock the owner
out. Reveal with `mandatary recovery reveal --user NAME`, exchange as above, then
`totp` → `totp/confirm` (and `account` with only a new password when
`--replace-password` was chosen) → `complete`. Completion retires every old
second factor and saved code, queues independent notices to the existing
verified addresses, and still issues **no session**.

This is an application-specific trusted-host procedure. It is **not** NIST AAL2
account recovery or identity proofing; the acknowledgement flag records that
acceptance. Host/root/service-UID holders, Docker administrators and the host
terminal are trusted (§S3.1b trust limit). A web/API administrator role cannot
invoke it.

## Security properties and where they are tested

| Contract | Evidence (all executable in this change) |
| --- | --- |
| SETUP-01 empty store only, no defaults | `TestFirstAdminEndToEndThenOrdinaryAAL2Login`, `TestFirstAdminTransactionWinsOnce`, `TestHostRecoveryIssuanceScope`, `TestStartupWithoutTrustedOriginIssuesNothing`, `TestSetupSurfaceDoesNotExistWithoutALiveGeneration` |
| SETUP-02 no secret in logs/errors/mail/formatting | `TestNoSecretReachesLogsErrorsFormattingOrMail`, `TestOperatorViewsCarryNoSecretMaterial`, `TestSetupURLAdmitsOnlyTheSecretFreeShape`, `TestSetupReasonAndGenerationAreAllowlisted`, `TestSetupThroughServerHandlerAndLogHygiene`, `TestSetupErrorsNeverEchoInput` |
| SETUP-03 file/terminal/lock/race/crash | `TestTokenStoredOnlyAsDigestAndRevealedOnce`, `TestRevealTerminalFailureSemantics`, `TestUnsafeRevealLayoutFailsClosed`, `TestForgedRevealFileIsNeverShown`, `TestRevealCrashMatrix`, `TestExchangeCrashLeavesNoUsableTokenOrPlaintext`, `TestIssueCrashMatrix`, `TestSetupSQLiteSyncFailureIsFailClosed` (real SQLite xSync failure), `TestHelperAndServiceRaceOnOneGeneration`, `TestConcurrentRotationLeavesOneLiveGeneration`, `TestHostTerminalAcceptsOnlyTheControllingTerminal` (real pty child), `TestRevealDirectoryAdversarialEntries` |
| SETUP-04 absolute 30-minute expiry, clock | `TestExpiryIsAbsoluteAndImmutable`, `TestExpiredTokenFailsClosedEverywhere`, `TestRestartNeverIssuesAnotherInitialToken`, `TestClockRollbackDeniesSetupOperations`, `TestSetupTokenSchemaInvariants`, `TestSetupSessionIsBoundToItsConsumedTokenAndExpiry` |
| SETUP-05 replay/concurrency/guessing | `TestExchangeIsOneUseAndReplayDenied`, `TestConcurrentExchangeYieldsExactlyOneSession`, `TestGuessingCeilingRevokesGeneration`, `TestFailureWaitDeniesCorrectToken`, `TestSetupHTTPRequestHygiene`, `TestSetupSessionCookieAndCSRF` |
| SETUP-06/07/08 MFA before unlock, atomicity, wins once | `TestCompletionRequiresEveryPieceAndIsAtomic`, `TestCommitFailureRollsBackAtomically`, `TestNoUnlockWithoutDurableNoticeIntent`, `TestConcurrentCompletionCommitsOnce`, `TestCompleteCrashAfterCommitStaysCompleted`, `TestFirstAdminOverHTTP` |
| SETUP-09 recovery scope | `TestHostMFAResetEndToEnd`, `TestHostMFAResetWithPasswordReplacement`, `TestHostRecoveryIssuanceScope` |
| S3.1b helper identity/store rules | `TestCLIIdentityHandling`, `TestCLIRefusesMissingOrUnsafeKeyAndStore`, `TestCLIIssueRevealStatusProtocol`, `TestHelperFromDifferentBuildCannotReveal` |

## Limits — read before relying on this

* **Not verified here:** SETUP-10 (real Compose + proxy + browser), SETUP-11
  (Compose host runbook on each supported CPU), SETUP-12 (Unraid), and anything
  needing a real container runtime. P1.19 owns the deployment artifacts and
  those runs; no Docker was used.
* The `setgroups/setgid/setuid` privilege drop requires `CAP_SETUID/CAP_SETGID`.
  Only its refusal rules are unit-tested unprivileged; the successful drop is
  covered by the operator procedure, not by an automated test.
* The terminal proof and reveal protocol are Linux-only; other platforms refuse
  to reveal.
* The first administrator's mandatory MFA in this card is TOTP. WebAuthn-only
  accounts cannot use `reset-mfa`; WebAuthn registration stays in the normal
  post-login lifecycle.
* Restore-administrator recovery is intentionally refused until the restore
  service exists (P1.18).
* No SMTP credential can be stored by a command in this change.
* Control tables and the reveal directory are non-importable local state; no
  export path maps them (asserted structurally by
  `TestSetupControlStateIsNotPartOfAnyExportSurface`).
