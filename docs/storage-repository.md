# P1.03 repository and secret boundary

## Delivered surface and limits

`internal/store` now supplies `Open`, `Read`, `ReadActive`, `Write`, `Control`,
`EncryptSecret`/`DecryptSecret` and encrypted SMTP record storage. The binary
opens this repository **before** starting its unchanged loopback/static-only
HTTP listener. Missing/invalid/ambiguous master-key input, a wrong existing key,
unsafe storage or missing control state aborts startup with a fixed redacted
error. There are still no authentication, setup, policy, Docker, MCP, SMTP
sender or backup/restore endpoints. Import, token reveal/consumption and factor
verification remain their owning rows, not callable placeholders.

## Configuration and filesystem contract

- Supply exactly one of `MANDATARY_MASTER_KEY` or `MANDATARY_MASTER_KEY_FILE`.
  The key is exactly 32 decoded bytes, hex or standard padded base64;
  empty/all-zero/incorrect-size inputs fail. The file accepts one final LF,
  has a bounded read, must be a regular single-linked owner-only file owned by
  the runtime UID or root, and is opened no-follow within an `os.Root` after
  validating its ancestor directories. There is no auto-generated/default key,
  source precedence, plaintext-string interpretation or fallback after failure.
- `MANDATARY_DATA_DIR` defaults to `/data`. Its parent must already exist. The
  final directory may be created with 0700; existing directories must already
  have 0700 and the configured numeric owner/group. Ancestors must be owned by
  root/the configured UID and not group/world writable. Symlink directories,
  unsafe modes/owners and symlink/hardlinked files are refused, not repaired.
- The database, persistent `control.lock`, WAL and shared-memory files have
  0600 and the configured UID/GID. All descriptor-relative opens are no-follow;
  path/directory/database/lock/sidecar identities are rechecked. Never copy,
  replace, unlink or chmod these files while a process uses the installation.
  `PERSIST_WAL` is set on **every physical connection**, including pool
  replacements, so an idle helper closing cannot unlink another process's
  WAL/SHM identity. A nonparticipating SQLite writer is unsupported.
- `Options.OwnerUID/OwnerGID` come from trusted deployment configuration, never
  existing file ownership. The startup path uses the process UID/GID. The
  future host helper must verify/drop to the configured mapped identity before
  opening files; this card neither implements privilege drop nor claims the
  Compose/Unraid mappings are qualified.
- `ExistingOnly` refuses missing files/stores and schema creation/upgrades.
  Existing installations are preflighted with Goose's non-creating store query,
  never `Provider.GetDBVersion` (which can initialize a missing version table).
  Missing/empty/incomplete/duplicate/unapplied/unknown migration history denies
  without repairing the schema or version rows. Only a fresh service open may
  initialize history; a recognized v1 service open may upgrade to v2.
  The P1.09 helper must additionally verify the trusted build/schema/
  installation and host/container mount mapping. This primitive is not a
  runnable recovery helper or a detector of malicious host/copied-volume rollback.

An interrupted fresh migration/key binding leaves unusable state rather than
silently reinitializing it. An existing unrecognized/empty/corrupt store, missing
installation control or missing/tampered key binding never becomes fresh setup.
Migration 00002 adds local key metadata and SMTP ciphertext slots; the original
00001 bytes are unchanged. A valid v1 upgrade preserves existing rows. Full
down/up is destructive **test-only** reset, not a production recovery procedure.

## Concurrency, durability and delivery ordering (R1 / S3.1a)

The writer pool is bounded to one connection; a separate read-only pool permits
four concurrent readers. Every physical writer receives WAL, foreign keys ON,
busy_timeout=5000 and synchronous=FULL via its connection DSN. These values are
read back before migration and on the exact connection before every write.
Readers also receive FK/busy settings, mode=ro and query_only. This implementation
uses FULL for **all** repository writes; TD permits ordinary NORMAL but does not
require a lower-durability writer. A mutated/unsafe pragma fails rather than
being silently repaired for a pending transition.

Every writer acquires the **persistent shared advisory-lock inode first**,
then obtains its SQLite connection and starts its transaction. Distinct file
descriptions serialize goroutines and separate helper/service processes. Lock
and database contention are bounded, cancellable and fail closed. Never take a
SQLite write transaction and then try to enter this coordination domain.

`Write` commits a callback transaction, syncs the database/WAL/lock and data
directory, and verifies identities before returning success. `Control` uses the
same path and additionally retains the shared lock through `afterDurable`.
Only that callback may perform delivery/acknowledgement dependent on the commit;
it must be bounded and cannot reenter the repository. The transaction callback
must not disclose/acknowledge before commit. Commit/sync/uncertain delivery
failure poisons the handle: no new operation may continue through it. Returning
an error after commit does not imply rollback; future protocols must reconcile
persisted non-revealable state, never infer successful delivery or reuse a token.
Reads recheck handle health after waiting for their pool slot, before invoking
record callbacks and before reporting success. Callers must discard callback
results on any error; a read callback must not disclose data or acknowledge
success before `Read` returns. This is not cancellation of an already-running
callback or a replacement for the owning service's dispatch revalidation.
P1.09 owns the actual PENDING/AVAILABLE/CLAIMED/RETRIEVED protocol, terminal
checks, file issuance/unlink/expiry and reconciliation; these are not implemented
by a generic transaction callback.

The test-only VFS intercepts real pinned modernc SQLite `xSync`, injecting
`SQLITE_IOERR_FSYNC` and recording only successfully synced file images. The
modeled persistence-loss fixture reconstructs SQLite from those images, discards
unsynced writes, and proves that an actual NORMAL write can be lost while an
acknowledged FULL commit survives. It is not just a process-kill test. The ABI
adapter contains explicit test-only unsafe C-allocation/function-pointer
interop, with no production hook or scanner exclusions. The model assumes
successful sync is honored. **No physical power-cut, filesystem/controller/
firmware guarantee, network-filesystem qualification or production Unraid test
is claimed.** Supported installation storage must be local and independently
qualified under P1.09/19/20; this fixture does not certify every local mount.

## Encryption and cryptographic inventory (N1 / A1)

Version-1 envelopes are:

```
version(1) || random HKDF salt(32) || random GCM nonce(12) || ciphertext || tag(16)
```

AES-256-GCM uses a fresh per-write subkey derived by HKDF-SHA256 from the master
key, random salt and length-framed context. Associated data binds the versioned
format, random 256-bit installation identity, purpose and record ID. Swapping
records, purposes, installations, keys, salts, nonces, payload or tags fails
without returning plaintext. Input sizes and purposes are bounded; unknown
versions/purposes fail. Only `totp` and `smtp` are public internal-store purposes;
the key-check namespace is private. Future webhook/endpoint encryption has no
Phase 1 callable interface.

The primitive is Go standard-library `crypto/aes`, `crypto/cipher`, `crypto/hkdf`,
`crypto/sha256` and OS-backed `crypto/rand.Reader`, exercised on the locked Go
1.27.4 and 1.26.11 builds. Every seal obtains a fresh 256-bit salt and 96-bit
nonce; entropy failure denies with no deterministic fallback. A separate
installation-bound authenticated known-text check detects the wrong master key
at startup even before any SMTP/TOTP records exist. The master key and local
metadata are not archive import fields. SMTP plaintext is never a SQL argument;
only the envelope is stored. TOTP lifecycle code must bind encrypted material to
its authenticator ID and restrict plaintext access to binding/verification.
No future sender, TOTP verifier, password hash, backup service or key rotation is
implemented here. Under approved NIST D-07 / `N63B4-PWD-KEYED`, this master key is
**not a password pepper**: the additional keyed verifier iteration is not selected
for Phase 1 because independent custody, rotation/loss and restore would require
another reviewed key lifecycle. The eventual Argon2id verifier retains its
DB-only offline-attack residual; encrypted archives do not remove that risk.

Errors are fixed sentinels with no input/SQL/crypto/filesystem cause wrapping.
Key pointer **and value** formatting/Go-syntax/slog are redacted. No store code
logs secret data. Tests use synthetic in-memory canaries and fail messages that
do not print their value. Best-effort buffer clearing is not a Go heap-erasure
or forensic storage-erasure guarantee. This algorithm/build inventory is **not**
NIST/FIPS validation, CMVP/federal procurement evidence, a product AAL claim or a
promise that all OS RBG providers are qualified. Those conditional evidence
requirements remain A1/P1.19–20; no federal profile is enabled here.

## Inactive authority and phase boundaries

`Read` is a coherent read-only snapshot including required live control state;
it intentionally allows quarantined records for diagnostics/restricted recovery.
It is **not** an authorization decision. `ReadActive` checks the same snapshot's
quarantine and all four positive, exact current generations before calling its
record callback. Missing/zero/stale generations or a missing control record deny,
never default active. Neither API checks factor proof, record state, achieved
assurance, expiry/trusted UTC, selectors, policy or runtime self-identity: the
owning P1.05–11/13 services must add those checks and dispatch cancellation.

There is no activation or archive import API. Fresh controls and records remain
quarantined. P1.18 must exclude local controls/key metadata from import, retain
quarantine and require credential reissue and per-scope reapproval; historical
backup integrity is not current authority. SELF identity cannot be loaded from
this database. No human AAL2 session, bootstrap/recovery credential, real mail,
Docker call or broader release readiness follows from a repository read.

## Contract-to-executable-test map

Run the full locked `make install check negative-control`, `make tools security`
and `go test -race -count=1 -v ./...`; the compatibility selector is documented in
`development.md`. The ARM64 job executes on a native ARM64 runner rather than
substituting cross-compilation. Exact-head results belong in the PR/card handoff.

| Contract / bounded portion | Executable evidence |
| --- | --- |
| TD6.1 / SUP-02 actual SQLite, WAL/FKs/busy/pools, 0600, concurrent readers/writers and restart | `TestRepositoryRestartConcurrencyAndPragmas`; all inherited migration/owner/FK/usage/reopen tests |
| R1 / S3.1a lock first, shared persistent inode, FULL not NORMAL, poisoned-handle denial | `TestWriterSyncFailureAndLockOrder`, `TestServiceAndHelperSharePersistentLock`, `TestControlDurableCallback`, `TestQueuedControlDeniesAfterUncertainDelivery`, `TestQueuedReadRechecksHealth` (Read/ReadActive, healthy/poisoned), `TestReadDeniesPoisonDuringCallback` |
| R1 actual SQLite sync denial / modeled persistence loss | `TestSQLiteSyncFailurePreventsAcknowledgement`, `TestSQLiteFULLSurvivesModeledPersistenceLoss` (real adverse NORMAL control) |
| SETUP-01/03/11 storage portion | `TestRepositoryRejectsUnsafeStorage`, `TestHelperCannotCreateOrMigrate`, `TestExistingOpenRejectsInvalidMetadataWithoutMutation` (helper/service; schema/version-row snapshots), `TestExistingV1UpgradePreservesRowsAndHelperDoesNotMigrate`, `TestUnrecognizedExistingStoreNeverBecomesFresh`, `TestStartupRequiresKeyBeforeOpeningStorage` |
| TD6.2 / N1 encrypted SMTP, startup key check, canaries | `TestMasterKeyBoundary`, `TestZeroKeyIsInvalid`, `TestRepositoryKeyAndEncryptedSMTPPersistence`, `TestKeyBindingCannotBeReinitialized` |
| N63B4-OTP-SEED / CRYPTO-INVENTORY / RANDOM-EVIDENCE primitive portion | `TestAuthenticatedRecordEncryption`: positive, wrong-key/installation, every-byte tamper, truncation, purpose/ID substitution, fresh nonce/salt and entropy-failure cases |
| RESTORE-05/06/07/11 / N63B4-RESTORE-AUTH-STATE local control portion | `TestAuthorityNeverDefaultsActive`; inherited generation/retry/outbox structural tests |
| N63B4-PWD-HASH / LOOKUP-STORAGE / RECOVERY-CODE-LIFECYCLE / WA-CHALLENGE / BINDING-RECORDS persistence portion | inherited `TestAuthenticatorAndSessionStructure`, `TestCredentialNullMaterialAndAccountBinding`, `TestPopulatedMigrationReopenAndDown` and binding/control tests; cryptographic password/code/factor verification remains P1.05–08, not a repository capability |
| N63B4-PWD-KEYED approved nonselection | explicit D-07 inventory above; no pepper/verifier route or separate-custody claim |
| Continuous regression and scope | all `tests/security`, tooling/frontend tests and real route-negative-control; generated-output drift gate; all three Go scanners + npm high gate |

Full SELF/RESTORE/SETUP/NIST ceremonies, real TLS/mail/browser/device/runtime
matrix, deployed hardware durability, packaged CPU/OS qualification and release
budgets remain their explicitly later owning rows. Unknown/unexecuted targets
are not passing checks.
