# P1.05 — internal local-password contract

## Scope, authority and call boundary

This slice supplies `internal/auth` password establishment policy, strict original
JSON-string decoding, Argon2id verification, storage-backed proof throttling,
protective compromise marking and conditional password replacement. It exposes
**no login, recovery, setup, session, MFA, REST or MCP route**. The existing static
listener remains unchanged. An observed `Proof` is not a session, authorization
capability, administrator login, completed recovery, phishing resistance or AAL2.
Future P1.06–09/14/16 callers must enforce transport, ceremony authorization,
actual factors, freshness, generation rechecks and security-notice delivery.

Nico's P1.05 amendments in original card t_832524c8 comments95/98/99 authorize the
fixed Unicode17 stabilized-NFC repertoire and reviewed bounded upstream-derived
ordinary-NFC adaptation. Comment101 authorizes a larger **finite virtual-address
allowance for necessary race children only**, not a new resident-memory/product
budget. These approvals do not release descendants or waive independent review.
The current CSRC final record and online §3.1.1 were re-read during implementation:
SP800-63B-4, July2025 remains the referenced final baseline. No NIST/FIPS/AAL2,
CMVP/RBG certification, full-platform or deployment qualification is claimed.

## Immutable password profile and order

`mdt-pwd-u17-nfc-cn-v1` means:

1. Validate **original** encoding. For JSON, pass the original bounded string token
   to `DecodePasswordJSON` before any ordinary unmarshal. It rejects malformed
   UTF8, unpaired UTF16 escapes, null/non-string/multiple values; paired escapes
   and explicitly supplied U+FFFD are valid. Future adapters must independently
   bound the complete envelope and reject unknown fields/trailing values.
2. Reject non-scalars and General_Category=Cn using **frozen Unicode17** data,
   independently of compiler/browser categories. Surrogates are not scalars;
   noncharacters are Cn. Assigned controls, format characters, private-use,
   explicit U+FFFD, ASCII spaces and emoji are retained. Newly assigned characters
   after17 remain unsupported until an explicitly reviewed new profile.
3. Compute ordinary NFC17 with canonical decomposition/order/composition and
   algorithmic Hangul. No implicit CGJ insertion; explicit user CGJ is preserved.
   No NFKC, case folding, trimming, substring mutation, composition rule or truncation.
4. Count **normalized Unicode code points**. Defaults: minimum15 if usable alone;
   minimum8 only when every password path requires MFA; maximum128. Merely
   enrolling an optional factor never qualifies for8. Settings cannot reduce the
   floors or exceed128. Existing schema guards also reject a short-password
   policy downgrade. No periodic expiry, hint or KBA feature is introduced.
5. Screen the entire canonical prospective password against the offline list,
   exact context values/derivatives and optionally HIBP. A rejected listed choice
   returns a safe fixed reason and guidance, never the supplied secret.
6. Hash the **full canonical UTF8** with approved Argon2id.

`Policy.Validate` is the shared establishment/change/reset/setup policy entry
point. The caller supplies trusted contextual username/email/hostname values;
service replacement currently supplies its stored username, while future account
ceremonies must provide their applicable verified address/deployment context.
Browser length display is advisory: later UI must use this server contract,
retain original input for strict decoding, permit managers/autofill/paste and
show the endpoint-representation warning. Browser `normalize()` or UTF16 `.length`
is not an independent authority. Browser/manager/accessibility evidence is P1.16,
not a completed browser claim here.

## Bounded ordinary NFC implementation and proof

The private `nfc17` source is a narrow snapshot of authenticated
`golang.org/x/text v0.43.0`, upstream commit
`ac40b0f06c159afb5bfca4d1860f8b4b60dbc160`. It is not a whole-module fork/replace,
external runtime, handmade Unicode algorithm or release-tag override. The original
Unicode17 table is selected unconditionally; Go1.26's upstream default Unicode15
is not used. The six original source hashes, retained source ranges/functions,
adapted hashes and exact adaptation are in `upstream-sha256.json`, `snapshot.json`
and `adaptation.patch`. Both original BSD and Unicode licenses are retained.

Retained closure: one-shot Bytes/quickSpan/doAppendInner/decomposeSegment/
appendQuick; NFC property lookup/recomposition map; input/trie support;
insertFlush/insertDecomposed/insertSingle/insertOrdered; reserve/reset/flush;
Hangul decomposition/composition and rune-slot operations. Removed entry points
include streaming Transform/Reader/Writer/Iter, append-to-prior-output/merge/
patchTail/backward-boundary repair and CGJ insertion. The upstream packed tables
retain their exact layout. Explicit bit masks on proven scalar/table widths
preserve upstream conversions; accumulated positions/counters are checked ints.
No composition, stable equal-CCC ordering or Hangul decision is replaced.

For raw scalar count R, recursive canonical/Hangul decomposition count D and NFC
output n: nonempty mappings give `R(raw) <= D(raw) = D(n) <= 4*R(n)`.
`TestFrozenCanonicalResourceProof` independently audits official frozen UnicodeData,
including Hangul, maximum expansion4, assigned mapped scalars and packed
compatibility-derived leading/trailing nonstarter counts<=3. Thus eligible
normalized<=128 implies raw<=512 scalars and raw UTF8<=2048 bytes. The independent
4096-byte decoded cap and512-scalar guard cannot exclude such a password.
The original JSON token cap32768 admits even512 fully escaped astral scalars
(6146 bytes including quotes), with room for whitespace; adapters still bound
and validate their own whole envelope. Oversize input is explicitly denied, never
reported as successfully normalized or silently clipped.

An admitted whole input decomposes to at most2048 scalars/8192 four-byte-slot
bytes. Buffer capacity is2050 slots/8200 bytes (two retained spare slots), output
budget8192, counter guard2048; packed counter accumulation<=1536. Independent
pre-write slot/byte/output/index guards remain, even if counter assumptions fail.
Errors return no partial secret, and append loops check negative results/progress.
The reorder buffer is fixed per call (Properties slots plus8200-byte storage),
with bounded8192-byte output and bounded input/copies; no unbounded append queue.
Canonical ordering can be quadratic but at most the admitted2048-slot work, not
attacker-unbounded streaming. `BenchmarkBoundedNFC` records allocations/CPU for
511 adversarial raw scalars; parallel/race, >255 offsets and undersized internal
budget tests exercise the independent checks. These are component measurements,
not the unchanged TD production image/idle/load budget qualification.

Official conformance is separate from password policy: all20034 Unicode17 rows,
all6 corpus parts, five NFC equalities per row and1094978 additional singleton
checks, plus full1114112-codepoint repertoire crosscheck. Raw admission is not
closed under expansion:257 U+0344 become514 normalized scalars; fuzz idempotence
re-enters the raw-input API only when its output is in that API's domain.
The production password policy still rejects normalized lengths above128.

## Reproducibility, provenance and maintenance

Python3 (stdlib only) is build tooling, not a runtime dependency. `make sqlc`
already downloads/verifies the locked tools/sqlc graph including x/text0.43.0.
Then:

```sh
make password-check
# Explicit offline normalization reproduction (comparison only):
python3 scripts/regenerate-password-nfc.py --check \
  --upstream "$(go env GOMODCACHE)/golang.org/x/text@v0.43.0/unicode/norm"
# Omit --check only during a reviewed regeneration, then inspect the full diff.
```

Regeneration validates each original source hash, applies the exact checked
adaptation without fuzzy matching, verifies adapted hashes, validates decompressed
Unicode inputs/licenses, and rebuilds the GC ranges without compiler categories.
It never fetches changed latest data. `make password-check` also regenerates the
blocklist into a temporary file and byte-compares it. CI runs this on both Go
builds; a Node fixture proves stale output/changed source/data fail without repair.
Fixed-salt Argon outputs plus canonical accept/reject/count/membership data have
one golden contract digest in `TestCrossToolchainPasswordContract` under both
locked compilers. Pins are not substituted for this execution evidence.

Frozen input URLs: `https://www.unicode.org/Public/17.0.0/ucd/` for
UnicodeData.txt, NormalizationTest.txt, DerivedNormalizationProps.txt,
CompositionExclusions.txt, ReadMe.txt; GC uses `extracted/DerivedGeneralCategory.txt`.
`data-sha256.json` records decompressed hashes/sizes; Unicode data license is
preserved in LICENSE-UNICODE. HTTPS retrieval/checksum identity is not a publisher
signature claim. Do not regenerate from an unversioned latest URL.

Project maintainers/coder own this copied component; independent reviewer owns
update acceptance. Apply the existing weekly advisory/monthly patch/quarterly
support review and two-business-day/immediate-exploitation triage. Module scanners
do **not** automatically identify/remediate copied source: explicitly examine
upstream x/text security fixes and diff this retained closure. Re-run the complete
corpus, repertoire/resource audits, fuzz/race/golden vectors and both locked full
pipelines. Any change to supported repertoire/canonical bytes needs a new immutable
profile and explicit eligibility/migration review; never silently relabel hashes.

### Offline full-password list

Source: SecLists `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`,
commit `4afe4d3de0a5d227c59ae2f162d22b93b4c27bfd`, raw file
SHA256 `1472aafa2561df5e3293aee252aee3ca660c12b399a283cf808bb01b39be388b`.
The public, synthetic-test-only corpus is bundled compressed with its SecLists
license; it is not a subscriber credential fixture. `blocklistgen` verifies the
raw checksum/exact100000 input entries, canonicalizes with the same profile,
deduplicates and sorts full SHA256 membership digests. SHA256 here is public-list
membership, **never** the human password verifier. There is no Bloom false-positive
probability; only the ordinary cryptographic digest-collision residual. No
substring deny. Exact service/context values plus suffixes empty/1/123/123!/!/
password are screened, without transforming the password's case/spaces.

100000 entries are a bounded baseline, not proof of comprehensive breach coverage
or multilingual adequacy. Review corpus relevance and new advisories with the
maintenance cadence. Update source commit/checksum/license/provenance together,
regenerate under both compilers, inspect membership changes and re-run positive/
negative tests. List updates affect new establishment/replacement, not historical
login acceptance; evidence of actual compromise uses protective marking/replacement,
not a surprise list-triggered login denial or periodic-expiry rule.

### Optional HIBP

`Policy.WithHIBP()` is explicit opt-in; default policy performs zero network calls.
The future config/ceremony adapter owns informed opt-in; the currently static
binary still refuses unimplemented HIBP environment configuration rather than
pretending it is wired. Offline screening always runs first. Only a five-uppercase-
hex SHA1 prefix goes to fixed `https://api.pwnedpasswords.com/range/`, using padding,
no body/full hash/password/user identity/cookies/auth header, no ambient proxy or
redirect forwarding, bounded1MiB response and2-second deadline. No response cache
is retained. Prefix disclosure still leaks partial information to the service and
network metadata; it is not zero-information privacy. SHA1 is HIBP protocol lookup,
not storage/signature security. Non200/malformed/oversize/timeout/network failures
fall back to the mandatory offline floor; they do not silently disable it or echo
remote diagnostics. A known positive range result rejects the prospective value.
No actual user password was sent to HIBP in testing.

## Verification, throttles, replacement and failure semantics

PHC is exactly Argon2id v19, m65536KiB/t3/p4, random16-byte salt and full32-byte
output using x/crypto0.58.0. Strict total length, parameter order, strict base64,
salt/output lengths and profile are checked before KDF allocation. Unsafe/unknown/
missing profiles/costs deny; no opportunistic raw/Unicode15/17 retries, guessed
legacy support, bulk migration or cost downgrade. Current profile is the only
production historical profile. Synthetic unsupported-profile fixtures stay denied.
Current establishment minima/blocklist are not re-applied at login. A later
cost-only rehash must preserve stored canonicalization semantics; no different
cost version is currently accepted. Semantic upgrades require explicitly eligible
fresh authorized replacement, not a matching-legacy-hash guess.

The stored active binding must match current positive installation/user/credential/
authority generations, non-quarantine, active/uncompromised user, unrevoked/bound/
unexpired non-exhausted password, supported format and stored8..128 length with
15 if usable alone. A serialized FULL `Repository.Control` covers proof, post-KDF
state/time recheck and conditional failure/reset; the OS lock precedes SQLite.
One non-waiting process-wide KDF admission slot bounds multiple Service handles;
there is no unbounded waiter queue. Separate-process control locks prevent
speculative concurrent work from exceeding the remaining durable retry budget.
Admitted control work has an independent10-second deadline. Caller cancellation
before proof evaluation denies; a disconnect after actual evaluation cannot erase
the failure charge or poison the service as though storage failed. An already
authorized protective report also completes under its bounded control context,
not the untrusted client's transport lifetime. This is not new report authority.

IP mitigation:30 admitted requests per fixed60-second window; IPv4-mapped
addresses canonicalized; IPv6 grouped by/64. Peer must be a parsed validated
address, not arbitrary forwarded input. At most4096 process-ephemeral HMAC-keyed
buckets; expired windows evict at capacity, exhaustion denies. No IP history/log or
fingerprinting database. A busy shared NAT can receive a temporary denial; rejected
traffic does not slide its window. New IPs/restarts do not reset the durable
password factor count. Five actual failures start1-second delay, doubling every
five failures through64seconds. Attempts during the stored wait do no KDF, do not
increase the failure count and cannot slide the deadline.100 actual consecutive
failures disable only that password binding; reuse requires a separately authorized
rebind. Independently bound factors/recovery records are not disabled by username.
No CAPTCHA, IP trust-based MFA bypass or whole-account unauthenticated lock switch.

Unknown users/wrong passwords return the same empty proof and fixed ErrDenied;
unthrottled unknown, inactive, compromised or malformed-binding cases do one
same-cost dummy verifier evaluation. This is comparable verifier-work parity,
**not constant-time database/HTTP service**: pre-verification IP/admission/account
wait/quarantine/storage denials are intentionally cheaper. Future adapters must
preserve generic401/body parity and not expose factor state via errors; full
protected HTTP route/session parity remains P1.08/14/16 acceptance. Throttle
windows are a residual timing/availability signal, not an account-existence promise.

Password success resets only its own count if the account is genuinely maximum-
password-only (no currently usable stronger factor). Compulsory/pending-MFA and
optional-MFA-but-capable-of-stronger-auth proofs reset nothing. Later completed
appropriate-strength ceremonies own exact used-factor resets; no unused/disabled
factor is reset here. Expired/stale/revoked/exhausted stronger records do not
incorrectly suppress the password-only consecutive-failure reset.

`MarkCompromised` is a separately authorized protective primitive, not an endpoint
or permission check. It sets the flag and revokes only affected user sessions,
without waiting for SMTP. A failed security-control write after real proof work or
protective report poisons the repository handle before releasing control; no
subsequent proof may succeed through uncertain state. Repair/reconciliation and
explicit repetition of the failed protective action are required before reopening;
restart is not a claimed recovery protocol for an unpersisted report. Raw SQL,
malicious host rollback and uncoordinated external database writers are outside
the supported protocol. Real SQLite xSync faults, transaction-abort triggers,
post-failure denials and existing persistence-loss tests exercise this boundary.

Replacement is **not authorization**: only a later fresh appropriate-strength
ceremony may call it. The observed verifier is solely a concurrency precondition.
Policy/HIBP/KDF work occurs outside the storage lock; commit rechecks the exact
user, binding/lifecycle/retry state, generations and time. Migration00003 adds a
monotonic password_revision (not authority), incremented on each report/replacement;
this prevents a repeated report of an already-compromised account from being lost
during expensive replacement. Integer type/nonnegative constraints fail closed on
overflow. Unchanged passwords are rejected, new verifier/profile/count are
committed atomically with scoped session revocation and compromise clearing.
Disabled/revoked/missing/imported/quarantined credentials are not activated. Fresh
initial/recovery reenrollment, notices and restored-authority approval remain their
owning rows. No production legacy-password migration is invented.

## Test/evidence map and limitations

See `nist-authentication-mapping.md` P1.05 implementation crosswalk. Permanent
coverage includes official corpus/repertoire/bounds/adversarial ordering, strict
JSON, golden two-toolchain contract, salts/full suffix/unsafe PHC/RNG failure,
whole list/context/guidance, HIBP privacy/fallback, proof parity/work,8/15 fallback,
100-attempt/non-sliding waits, shared NAT, actual close/reopen, concurrent handles
and separate processes, stronger-factor reset separation, post-KDF expiry,
compromise/session scope, replacement/repeated-report races, transaction failure
and real SQLite xSync fail-closed behavior. Fuzz seeds run in ordinary CI; bounded
active fuzz/bench outputs and full exact-head CI must be recorded as executed,
not inferred from the presence of targets.

No real Docker/socket/Unraid operations, real mail or real credential test occurs.
N1 lifecycle-notice delivery, integrated sessions/authorization/SELF/RESTORE/SETUP,
provider/device/RBG/federal cryptography evidence, actual browser UI, isolated
production-image/platform/runtime and TD footprint qualification remain owning
later gates. These are explicit unverified boundaries, not waived requirements.
The authorized Argon2id approved-scheme/keyed-iteration SHOULD departures remain:
no NIST-approved/FIPS claim, no pepper/hardware custody, and residual database-theft
offline guessing exposure. Linux getrandom/Go crypto/rand use and correct salt
length are implementation facts, not proof of a validated approved RBG deployment.
