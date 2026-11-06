# P1.06 authenticator lifecycle — implementation work in progress

This branch is not accepted or release-ready. No authentication or mail route is
mounted by the static server. These internal services do not implement P1.07
WebAuthn, P1.08 normal-session issuance/middleware, P1.09 host bootstrap/recovery,
P1.16 browser/address management, or P1.18 restore import. Component evidence is
not a NIST/FIPS, supported-device, delivery-to-inbox, or product AAL2 claim.

## Component contracts

* Selected `pquerna/otp v1.5.0`; its integer-counter RFC4226 HMAC primitive is
  used for six-digit, 30-second TOTP. SHA1 and SHA256 are explicit allowed
  algorithms. New seeds contain 32 random bytes. The bounded window is current
  step ±1; negative/unrepresentable supported civil times fail closed. Library
  input trimming and float time-counter conversion are not used as authority.
* Pending enrollment is session-bound, at most ten minutes, never usable before
  proof. Existing AAL2-capable accounts require fresh maximum-account-strength
  server-persisted session evidence; first AAL1→MFA binding is distinct. No
  account enrollment flag, caller assurance parameter, recovery token, or agent
  token substitutes for normal-session evidence. WebAuthn-only policy has no
  TOTP-only continuation.
* Seeds are encrypted with the installation/purpose/record-bound repository
  envelope. Replay decisions, accepted counter and output hash, and durable
  authenticator failure/backoff are serialized under Repository.Control. Both
  the authenticator counter and verifier period admit at most one acceptance;
  recent equal output cannot be replayed across adjacent window counters.
* Ten recovery-only codes are issued through fresh completed MFA, including
  initial issuance after qualifying authentication. Each has 128 random secret
  bits plus a random record identifier. SHA256 covers the exact full encoding;
  the code is never an ordinary MFA login alternative. Stored hashes cannot
  redisplay the secret. Regeneration revokes the preceding batch/capabilities.
* Normal recovery requires one saved code AND the still-bound password. The
  atomic transaction consumes it, issues one replacement saved code (the E08
  saved-code lifecycle, not general code-list regeneration), records notice
  intent, revokes normal sessions and creates a ten-minute restricted capability.
  A recovery capability may prove one replacement TOTP; it cannot create a
  normal/AAL2 session or satisfy normal lifecycle administration. Reenrollment
  invalidates prior TOTP bindings. Subsequent fresh policy-satisfying normal
  authentication remains required, owned by P1.08.
* Lost issuance/recovery/enrollment response does not roll back consumption or
  permit redisplay. Use an independently stored remaining saved code or bound
  authenticator; all-factor-loss needs the separately authorized P1.09 trusted
  host path. A code alone, two saved codes, notification receipt, or newly chosen
  password does not establish the selected recovery combination.

## N1 delivery boundary under construction

Lifecycle events and per-recipient immutable address/version snapshots commit
under the FULL writer before ordinary transition acknowledgement. At least one
current confirmed address is required; any number including two is supported.
SMTP configuration is trusted deployment input with a secret-free HTTPS origin,
explicit sender/contact, and implicit TLS or mandatory STARTTLS. Verification
uses certificate chains/hostnames and TLS≥1.2 before SMTP authentication or DATA;
there is no plaintext or certificate-verification bypass. SMTP passwords are
retrieved only from the existing encrypted repository slot.

Dispatcher policy: at most 32 records/invocation, four durable concurrent leases,
30-second lease, ten-second network deadline, eight attempts/72-hour maximum age,
60/120/240/480/960/1920/3600-second bounded backoff. Pending, relay-accepted,
failed, and schema-supported bounced states are distinct. Exhausted work stays
failed and visible; it is not silently deleted. Stable Message-ID and persisted
attempts mean a send/ack crash can duplicate a message (at-least-once), never a
promise of exactly-once delivery or human receipt. Sending does not hold the
security-control lock. The provisional component retention marker is 30 days;
actual deployment privacy/retention/contact qualification remains P1.19/20 and
must not turn failed records into silently dropped notices.

**Still required before P1.06 acceptance:** finish and exercise protective
revocation/outbox-failure behavior, bounded capacity, retry/repair/failure and
crash fixtures, lifecycle adversarial/restart/durability coverage, exact-head
locked checks and independent native review. The eventual runbook/crosswalk must
identify unimplemented later-row integrations rather than mark them passed.

## Current verification limits

Local locked Go1.27.3/Node24.22.1/npm11.19.1 install/build and internal non-race
regressions ran successfully. New RFC/window, proof-before-bind, encrypted-store,
concurrent replay/period, session denial, revocation, recovery consumption and
restricted reenrollment tests plus a real loopback TLS SMTP receiver have passed.
RED/GREEN logs are retained in the task scratch evidence directory. This is not
final-head acceptance evidence. A local 2GiB race run failed in ThreadSanitizer
allocation; local lint attempts exhausted the ordinary 2GiB virtual envelope
(including a reattempt with independently checksum-matched current pinned tools).
Those failed checks are **not passed**; hosted exact-head CI and final review
remain required. No global resource limit/security/toolchain pin was changed.
