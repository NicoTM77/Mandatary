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
mandatary recovery restore-admin --acknowledge-restore-recovery
mandatary recovery reveal    --restore-admin
flags: --data-dir PATH   --master-key-file PATH   --uid N --gid N
```

Defaults: `--data-dir` ← `MANDATARY_DATA_DIR` (then `/data`), `--master-key-file` ←
`MANDATARY_MASTER_KEY_FILE`. The helper requires a key **file** (never the
`MANDATARY_MASTER_KEY` value). A helper built from a different revision than the
one that issued a token refuses to reveal it.

**Reveal** requires stdin, stdout and stderr to all be the process's real
controlling terminal (verified before any claim or plaintext access). Pipes,
redirections and a missing or non-controlling terminal are refused without
consuming anything. Any pty that is the process's own session-controlling
terminal is accepted, including one a `script`-style wrapper allocated: terminal
capture by the host operator is a trusted-host matter (§S3.1b trust limit), not
something the helper can detect. The token is written once to that
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
that one existing active administrator. In the **same transaction that creates
the generation** (security-contracts.md §S3.2: before issuance) it ends that
account's sessions and durably retires every old second factor (TOTP/WebAuthn),
saved code, code batch and restricted recovery capability. Retired factors carry
the *protective* provenance, so they never lower the account's assurance floor
and are never revived. From that moment nothing issued before the ceremony can
sign in or start a recovery: the old password plus the old TOTP no longer reaches
AAL2, and the account has no usable administrator login until completion.

An **abandoned, expired or failed ceremony is recovered only by explicit host
re-issuance** (`reset-mfa` again; it rotates the previous generation and starts a
new 30-minute window). Issuing is therefore a deliberate, disruptive host action:
run it only when the second factors really are lost or compromised. There is no
per-account credential-generation bump; the installation-wide generation is
shared by every account, so invalidation is done by revoking the account's own
credential records.

Reveal with `mandatary recovery reveal --user NAME`, exchange as above, then
`totp` → `totp/confirm` (and `account` with only a new password when
`--replace-password` was chosen) → `complete`. Completion settles the retirement of every old
second factor and saved code, queues independent notices to the existing
verified addresses, and still issues **no session**.

This is an application-specific trusted-host procedure. It is **not** NIST AAL2
account recovery or identity proofing; the acknowledgement flag records that
acceptance. Host/root/service-UID holders, Docker administrators and the host
terminal are trusted (§S3.1b trust limit). A web/API administrator role cannot
invoke it.

### Restore-administrator recovery (RESTORE-08, S2.2.5)

A restore ends in persisted restore quarantine with every session revoked and no
imported record effective (`docs/backup-restore.md`). The quarantine is ended by
exactly one thing: this host-authorized ceremony. It is the same mechanism as
above (protected reveal to the controlling terminal, the shared control-state
lock, a 30-minute single-use token) with its own purpose, `restore_recovery`.

```
mandatary recovery restore-admin --acknowledge-restore-recovery   # issues; prints no token
mandatary recovery reveal --restore-admin                         # writes the token once to the terminal
```

* **Only inside a restore quarantine.** Issuing, revealing and completing each
  re-read the persisted control state and refuse unless `restore_quarantined` is
  set and the restore, credential, session and authority generations are all
  non-zero (a restore rotates all of them; a fresh installation has none of them).
  No archive is read. `status` prints `restore recovery eligible`.
* **Deliberate.** The acknowledgement flag is required, `--user`,
  `--replace-password` and the MFA-reset acknowledgement are refused, and it is
  never issued automatically at startup. `reveal` accepts `--user` **or**
  `--restore-admin`, never both.
* **One new administrator.** The exchanged token opens the same web setup
  surface (the page says it is a recovery of a restored installation): a **new**
  username, a fresh password, a confirmed notification address and a **fresh**
  authenticator. Completion creates that account with the administrator role and
  ends quarantine in the **same transaction**. A second account, a second
  authenticator or a replacement password is refused.
* **It revives nothing.** No restored account, role, factor, saved code, address,
  agent credential or session becomes effective, none is re-bound to the new
  account, and no manifest entry or imported authority is approved. The restored
  administrator's password and authenticator do not sign in. Control generations
  are never lowered or reset.
* **No session.** Completion issues no session. The new administrator signs in
  through the ordinary password + authenticator login (AAL2) and then reapproves
  restored records one by name (`docs/backup-restore.md` §10).
* **Refused when the quarantine is gone.** A token whose quarantine ended (for
  example an earlier completion or a competing recovery) completes nothing.

Tests: `internal/auth/restore_recovery_test.go` (eligibility, exactly-one admin,
nothing approved or revived, backup credentials cannot leave quarantine, the
capability is not a session, one-time token/guess limits, a failed import, crash
points), `restore_recovery_http_test.go` (the real HTTP surface),
`cmd/mandatary/restore_admin_cli_test.go` and `cli_test.go` (the helper's
protocol and refusals) and the `TestRecoveryUIBrowser` scenarios.

This is an application-specific trusted-host procedure and is **not** NIST AAL2
account recovery or identity proofing. Host/root/service-UID holders are trusted
(§S3.1b trust limit).

## Security properties and where they are tested

| Contract | Evidence (all executable in this change) |
| --- | --- |
| SETUP-01 empty store only, no defaults | `TestFirstAdminEndToEndThenOrdinaryAAL2Login`, `TestFirstAdminTransactionWinsOnce`, `TestHostRecoveryIssuanceScope`, `TestStartupWithoutTrustedOriginIssuesNothing`, `TestSetupSurfaceDoesNotExistWithoutALiveGeneration` |
| SETUP-02 no secret in logs/errors/mail/formatting | `TestNoSecretReachesLogsErrorsFormattingOrMail`, `TestOperatorViewsCarryNoSecretMaterial`, `TestSetupURLAdmitsOnlyTheSecretFreeShape`, `TestSetupReasonAndGenerationAreAllowlisted`, `TestSetupThroughServerHandlerAndLogHygiene`, `TestSetupErrorsNeverEchoInput` |
| SETUP-03 file/terminal/lock/race/crash | `TestTokenStoredOnlyAsDigestAndRevealedOnce`, `TestRevealTerminalFailureSemantics`, `TestUnsafeRevealLayoutFailsClosed`, `TestForgedRevealFileIsNeverShown`, `TestRevealCrashMatrix`, `TestExchangeCrashLeavesNoUsableTokenOrPlaintext`, `TestIssueCrashMatrix`, `TestSetupSQLiteSyncFailureIsFailClosed` (real SQLite xSync failure), `TestHelperAndServiceRaceOnOneGeneration`, `TestConcurrentRotationLeavesOneLiveGeneration`, `TestHostTerminalAcceptsOnlyTheControllingTerminal` (real pty child), `TestRevealDirectoryAdversarialEntries` |
| SETUP-04 absolute 30-minute expiry, clock | `TestExpiryIsAbsoluteAndImmutable`, `TestExpiredTokenFailsClosedEverywhere`, `TestRestartNeverIssuesAnotherInitialToken`, `TestClockRollbackDeniesSetupOperations`, `TestSetupTokenSchemaInvariants`, `TestSetupSessionIsBoundToItsConsumedTokenAndExpiry` |
| SETUP-05 replay/concurrency/guessing | `TestExchangeIsOneUseAndReplayDenied`, `TestConcurrentExchangeYieldsExactlyOneSession`, `TestGuessingCeilingRevokesGeneration`, `TestFailureWaitDeniesCorrectToken`, `TestSetupHTTPRequestHygiene`, `TestSetupSessionCookieAndCSRF` |
| SETUP-06/07/08 MFA before unlock, atomicity, wins once | `TestCompletionRequiresEveryPieceAndIsAtomic`, `TestCommitFailureRollsBackAtomically`, `TestNoUnlockWithoutDurableNoticeIntent`, `TestConcurrentCompletionCommitsOnce`, `TestCompleteCrashAfterCommitStaysCompleted`, `TestFirstAdminOverHTTP` |
| SETUP-09 recovery scope | `TestHostMFAResetEndToEnd`, `TestHostMFAResetIssuanceInvalidatesOldCredentials`, `TestHostMFAResetWithPasswordReplacement`, `TestHostRecoveryIssuanceScope` |
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
* Restore-administrator recovery is delivered by P1.18 (below). The helper only
  issues and reveals; the web setup page drives the enrolment. Nothing here
  verified it on a real host: it is exercised with the real services over a real
  SQLite installation, a real loopback TLS mail receiver and real browsers, with
  the host helper's terminal proof covered by its own protocol tests.
* No SMTP credential can be stored by a command in this change.
* The adapter uses the connection's own peer address and never a forwarded header.
  Behind a reverse proxy that address is the proxy, so the per-address traffic
  smoothing is coarse; the durable per-purpose guess counters (wait after five
  failures, generation revoked at 100) are the actual brute-force control. These
  counters are global per purpose, so an unauthenticated client that can reach the
  setup endpoint can keep the backoff engaged and delay the legitimate exchange
  (availability only; it cannot learn or consume the token). Block the endpoint
  at the proxy/network if that is a concern; host rotation resets the counters.
* **Exclusive reveal across real processes (P1.18.4 AUTH-09-L3).** The one-time
  reveal is claimed durably before any plaintext is read, so concurrent helpers
  cannot both be shown a generation. This is proven with real OS processes
  (`cmd/mandatary/cli_subprocess_test.go`: the test binary re-executed as helpers
  against one synthetic temporary installation, released together by a stdin gate):
  exactly one of several contenders is shown the token and the others refuse
  cleanly; a claimant that exits right after the display leaves nothing to replay
  and `mandatary setup rotate` recovers with a new generation that supersedes the
  old token; racing rotate and reveal never displays a generation twice. The
  fixture uses a throw-away key and token, no controlling terminal and no live
  helper; the in-process tests remain.
* The first automatic issuance happens at first empty-store start even when no
  mail relay is configured (the log warns; the address proof cannot then be sent).
  Configure the relay and run `mandatary setup rotate` to get a usable window.
* The deployment's reverse proxy must not log request bodies; that proxy
  configuration is P1.19 / SETUP-10 work and is not exercised here.
* Control tables and the reveal directory are non-importable local state; no
  export path maps them (asserted structurally by
  `TestSetupControlStateIsNotPartOfAnyExportSurface`).
