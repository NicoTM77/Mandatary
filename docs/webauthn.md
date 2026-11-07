# P1.07 WebAuthn component

This internal service mounts no auth route in the application. Component checks
are not a product/conformance claim. Normal session issuance/transport and step-up remain
P1.08, host bootstrap P1.09, full account-security UI and branded-browser/device
qualification P1.16, restore import P1.18, packaged qualification P1.19/20.

## Current protocol boundary

* `go-webauthn/webauthn v0.18.2` is pinned with checksums; ES256 (ECDSA P-256 /
  SHA-256) alone is requested and admitted at registration. Unsupported algorithms
  cannot be selected by changing client options. Actual COSE key type, algorithm,
  curve and point are validated even for `none` attestation; an algorithm label
  alone is insufficient. No legacy U2F/AppID, wallet,
  native opaque-origin or cross-origin ceremony is selected.
* RP ID and HTTPS origins are explicit trusted deployment input, not request
  Host, Origin or forwarded headers. RP ID cannot be a public suffix; each
  configured origin must be its exact host or a subdomain. No HTTP/localhost
  production exception exists. Browser fixtures use a synthetic HTTPS RP mapped
  to the loopback fixture only.
* Every registration and assertion requests **required UV**, checks actual
  ceremony UV and UP, and validates challenge, client-data type/origin, RP hash
  and protocol signatures. Enrollment-time `uvInitialized` is not current UV.
  Possession-only/password+single-factor-key is deliberately not offered here;
  there is no TOTP fallback for WebAuthn-only policy. `FactorProof` remains an
  observation, not a session, AAL badge, administrative capability or independently
  reusable bearer. P1.08 must bind observations to the same ceremony and recheck
  all live credential/session/control state before issuing normal authority.
* Account-first assertions support resident and nonresident credentials; requiring
  resident storage at creation is an explicit option. This is **not** evidence of
  usernameless/conditional UI, provider sync, physical hardware or Safari support.
  Device-local activation can be PIN or biometric: UV never identifies which.
* Challenges use the library's CSPRNG and are stored in installation-, purpose-
  and record-bound AEAD envelopes, with 300-second absolute expiry (also capped
  by the originating session), account/session/purpose/config/generation binding
  and atomic one-use consumption. There are at most16 unconsumed/unexpired
  ceremonies per account. Consumed/expired WebAuthn challenge rows and their
  envelopes are pruned on the next admitted ceremony. At most16 current bound,
  unrevoked keys are admitted per account (disabled keys still occupy a slot).
  The final binding transaction rechecks this limit across concurrent completions.
  Recovery can replace a full set atomically, never leaving17 committed live keys.
  Input responses are at most32768 bytes, external key IDs at most1024 bytes;
  four non-waiting process-wide work slots bound ceremony/parser/crypto work
  across service handles. Saturation denies without consuming proof. Peer traffic
  admission remains explicit in assertion/report adapters; future public routes
  must also bound request sizes and validated-peer traffic. No unauthenticated
  registration route is introduced. Terminal/unowned registration ceremonies are
  rejected before attestation parsing; all state is rechecked at commit.
* Credential AEAD envelopes bind account/RP/key association; verification checks
  public key, external credential ID, counter and BE/BS metadata against the
  protected record. The RP never stores an authenticator private key, PIN,
  biometric sample or template. Public-key/account association changes and
  envelope substitution fail rather than silently migrating a credential.
* BE is immutable; BS=true with BE=false fails. BE=true/BS=false is not the same
  as backed up. Zero counters are legitimate. For BE=false, nonzero counter
  regression/equality denies. BE=true nonmonotonic counters retain the maximum
  and clone-warning observation without asserting cloning or promoting strength;
  challenge single-use still applies. Neither flags nor counters prove hardware
  nonexportability or absence of sharing/cloning.
* Shared `Repository.Control`/FULL writer serializes challenge consumption,
  actual signature/protocol verification, counters, authenticator-scoped failures
  and lifecycle notice intent, across handles/processes. Stale/disabled snapshots
  deny before real proof work, preventing speculative overrun of the remaining
  retry budget. To avoid recursive repository locking, only an untrusted candidate
  envelope is precomputed with the pinned library's counter/flag update helpers;
  it is committed only after the real serialized verifier's complete result is
  byte-identical. Drift denies, never promotes candidate data. Successful proof
  observations recheck expiry/clock/session/key/caller state after crypto. At most100
  evaluated failures disable the specific credential; non-sliding password-style
  backoff and bounded IP admission are reused. Possession observation alone never
  resets failures; completed suitable-strength reset belongs P1.08. Storage sync
  failure is not a successful proof/transition. Any callback error after real
  proof evaluation terminally denies the handle **before releasing Control**:
  a statement-time rollback cannot discard consumption/accounting and admit
  another evaluation. Genuine pre-verification denials remain uncharged.
  Pending ceremonies use complete current-generation ownership inventory, while
  new allowlists offer only live keys and the selected key is rechecked under
  Control. Another key's disablement/expiry/revocation cannot charge a valid
  independent backup's pending assertion; the original allowlist is not widened.
* Additional enrollment/removal requires fresh server-persisted maximum-account
  evidence; required last-factor removal denies. WebAuthn-only removal cannot
  count TOTP as its remaining required key. Removal revokes normal sessions and
  uses the existing protective notification/repair path; ordinary binding commits
  two-address-capable independent outbox intent atomically or rolls back.
  Serialized reauthorization can normally deny after freshness expiry or
  concurrent invalidation without poisoning healthy storage. This is distinct
  from actual admission/read/write/commit/sync uncertainty after narrow protective
  authority is established, which still stops affected/in-flight acceptance.
  The same distinction applies to the shared TOTP removal/report paths.
* Narrow compromise reporting accepts a still-bound password to revoke an owned
  key and its sessions, including the last required key, with protective notice
  intent. It grants no replacement authority and never relaxes WebAuthn-only
  policy. `BeginRecoveredRegistration`/`FinishRecoveredRegistration` consume only
  the existing saved-code+still-bound-password restricted capability. Their
  challenge binds that capability ID, account, password revision (through the
  capability), generations, configuration and absolute deadline, separately from
  normal session ceremonies. Valid new UP+UV proof atomically binds the new key,
  revokes previous WebAuthn keys, consumes replacement authority and records both
  replacement/recovery notice intents; failures roll back authority-increasing
  changes. The capability cannot issue a session or normal assertion, and the
  existing TOTP continuation still cannot satisfy WebAuthn-only policy. Fresh
  policy-satisfying normal authentication remains mandatory after replacement.

## Device/provider evidence and limits

The following primary sources are evidence inputs, **not a supported-device
certification or an admission allowlist**:

* [Yubico FIDO manual](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html),
  [firmware5.7 scope](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html),
  [PIN/UV protocol](https://docs.yubico.com/yesdk/users-manual/application-fido2/pin-uv-auth-protocols.html),
  [YSA-2024-03](https://www.yubico.com/support/security-advisories/ysa-2024-03/).
  Model, firmware, PIN configuration, internal protection and advisory scope
  must be qualified separately; no blanket “YubiKey5 nonextractable” assertion.
* [Apple passkey security](https://support.apple.com/en-us/102195) and
  [Face ID matching](https://support.apple.com/guide/security/facial-matching-security-sece151358d1/web).
  E2EE/account-2FA architecture statements and limited image-disposal statements
  do not establish every device/build's full per-transaction erasure, activation
  retries, biometric performance/PAD or all-path AAL2-equivalent recovery.
* [Google Password Manager architecture](https://security.googleblog.com/2022/10/SecurityofPasskeysintheGooglePasswordManager.html)
  and [cross-platform PIN rollout](https://blog.google/innovation-and-ai/technology/safety-security/google-password-manager-passkeys-update-september-2024/).
  Platform/provider scope must not be inferred from browser brand. Android
  hardware statements do not automatically qualify desktop or every OEM/build.

**W04/MFCTORS-8 remains UNKNOWN:** no tested real-device/firmware/build-specific
proof establishes erasure of transient activation secret, biometric sample and
transaction-derived biometric material after **every** authentication transaction.
UV=true does not pass this examination. Persistent private key, reference
biometric and PIN verifier are distinct and are not required to be destroyed
between uses. Reset-time deletion is not transaction-end erasure evidence.

**B.2/sync evidence remains partial/UNKNOWN:** approved key generation/RBG, numeric
export encryption strength, local private-key operation, authenticated-only
access and AAL2-equivalent MFA across **all** sync enrollment/recovery paths,
user-controlled protection and complete management UI need exact provider/build
review. Vendor E2EE and account-2FA descriptions alone cannot close this matrix.

No blanket provider ban, universal hardware allowlist, AAL3/federal-enterprise,
FIPS/CMVP or implemented NIST conformance claim is introduced. Missing evidence
blocks the corresponding applicable release/conformance profile. Real-device,
wireless/hybrid/proximity, biometric/PAD/erasure and approved-RBG obligations remain
visible for owning P1.16/19/20 qualification and independent review; no virtual
fixture is reported as physical-device evidence. PIN-activated compatible keys
provide the intended non-biometric option, but actual hardware support still
requires its qualified fixture. RP revocation invalidates the account binding,
not every private-key/cloud copy; do not promise global erasure/sharing detection.

## Test commands and current evidence limits

After locked `make install build`:

```
go test -race -count=1 ./...
make browser-install browser-test
```

Playwright1.64.1 locks its Chromium revision. The browser test uses a **test-only**
loopback TLS adapter and virtual CTAP2 authenticator with resident/nonresident,
valid signed UV, replay and signed UV downgrade cases. It is not the product
login/session/CSRF/UI or branded-browser/device suite. There is no skip fallback.
Browser acceptance requires actual browser/virtual-authenticator execution; it
is distinct from optional browser-process hardening. The earlier unconditional
`chromiumSandbox: true` fixture setting and sandbox prohibition were introduced
in this WIP, not required by the approved baseline. Following the owner’s
reconciliation, the fixture uses Playwright’s documented default launch security
configuration (no sandbox override or custom sandbox flags; Playwright documents
`chromiumSandbox` as false by default at
https://playwright.dev/docs/api/class-browsertype#browser-type-launch-option-chromium-sandbox).
Only host resolution
of the synthetic RP to loopback and proxy avoidance are configured. The fixture
validates the exact synthetic origin/port, blocks requests outside its local
route/method allowlist and disables service workers. It serves trusted repository
HTML only, with disposable synthetic account/key material; it must not browse
arbitrary external content. This is not a production-browser recommendation or
authority to change host, AppArmor, container or production security settings.

Earlier native SIGTRAP and hosted `No usable sandbox` runs42329099897/42341070413
are retained as **failed executions**, not protocol evidence. New execution after
reconciliation must pass the complete suite; there is no skip fallback. The
separate arm64 default10-minute timeout was addressed with explicit20-minute
per-package and30-minute job budgets; run42341070413 subsequently passed arm64
with no test removed. Final-head evidence must still be rechecked.

Component fixtures include concurrent one-use/restart/counter retention,
credential-specific retry ceiling/non-sliding backoff/independent backup key,
and actual SQLite WAL xSync failure at challenge creation, binding, good/bad
assertion, report, removal, recovered binding and terminal retry invalidation/
notice expansion. The detailed component-to-contract crosswalk is
[webauthn-acceptance.md](webauthn-acceptance.md). Exact commands, logs, SHAs and
final regression/CI outcomes belong to the original Kanban card; this remains a
draft pending complete exact-head checks and independent review, not approval.
