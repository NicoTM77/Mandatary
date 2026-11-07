# P1.07 WebAuthn component — work in progress

This internal service is not yet a complete P1.07 handoff. No auth route is
mounted by the application. Normal session issuance/transport and step-up remain
P1.08, host bootstrap P1.09, full account-security UI and branded-browser/device
qualification P1.16, restore import P1.18, packaged qualification P1.19/20.

## Current protocol boundary

* `go-webauthn/webauthn v0.18.2` is pinned with checksums; ES256 (ECDSA P-256 /
  SHA-256) alone is requested and admitted at registration. Unsupported algorithms
  cannot be selected by changing client options. No legacy U2F/AppID, wallet,
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
  ceremonies per account. The current implementation still needs its final
  retention, resource-bound and abuse review before acceptance.
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
  counters, authenticator-scoped failures and lifecycle notice intent. At most100
  evaluated failures disable the specific credential; non-sliding password-style
  backoff and bounded IP admission are reused. Possession observation alone never
  resets failures; completed suitable-strength reset belongs P1.08. Storage sync
  failure is not a successful proof/transition.
* Additional enrollment/removal requires fresh server-persisted maximum-account
  evidence; required last-factor removal denies. WebAuthn-only removal cannot
  count TOTP as its remaining required key. Removal revokes normal sessions and
  uses the existing protective notification/repair path; ordinary binding commits
  two-address-capable independent outbox intent atomically or rolls back.

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
Native browser launch and source scanners currently fail under the restricted
worker's ordinary2GiB virtual envelope; these failures are NOT passes. Hosted
exact-head baseline/browser/security execution is still required. Primary
Go1.27.3 full race regression, module verification, sqlc diff, vet and frontend
lint/type/unit checks have executed successfully during implementation; these
are intermediate results, not final-head independent approval. Exact commands,
logs, SHAs and remaining implementation gaps belong to the original Kanban card.
