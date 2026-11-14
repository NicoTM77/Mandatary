import { expect, test } from 'vitest';
import { EMPTY_SELECTOR, OPERATIONS, assessSelector, describeSelector, isStateChanging, normalizeSelector, ruleSentence, selectorKey, validateCaps, validateSelector, type SelectorDraft } from './selector';

const draft = (patch: Partial<SelectorDraft>): SelectorDraft => ({ ...EMPTY_SELECTOR, ...patch });
const DIGEST = `sha256:${'a'.repeat(64)}`;
const ID = 'b'.repeat(64);

// ───────────────────────── catalogue ─────────────────────────

test('the operation catalogue is exactly the six approved Phase 1 keys, nothing else', () => {
  expect(OPERATIONS.map((op) => op.key)).toEqual(['container:logs', 'container:inspect_status', 'container:inspect_config', 'container:start', 'container:stop', 'container:restart']);
});

test('only start, stop and restart change a container; the others only read', () => {
  expect(OPERATIONS.filter((op) => isStateChanging(op.key)).map((op) => op.key)).toEqual(['container:start', 'container:stop', 'container:restart']);
});

test('a log-tail ceiling belongs only to logs and a stop-timeout ceiling only to stop and restart', () => {
  const caps = Object.fromEntries(OPERATIONS.map((op) => [op.key, op.cap ?? null]));
  expect(caps).toEqual({
    'container:logs': 'logTailMax',
    'container:inspect_status': null,
    'container:inspect_config': null,
    'container:start': null,
    'container:stop': 'stopTimeoutMax',
    'container:restart': 'stopTimeoutMax',
  });
});

// ───────────────────────── validation (convenience only) ─────────────────────────

test('an empty selector is missing only its container name', () => {
  expect(validateSelector(EMPTY_SELECTOR)).toEqual({ containerName: 'Enter the container name.' });
});

test('a name with a backslash, control character or more than 255 characters is refused with a reason on the field', () => {
  expect(validateSelector(draft({ containerName: 'a\\b' })).containerName).toMatch(/backslash/i);
  expect(validateSelector(draft({ containerName: 'a\nb' })).containerName).toMatch(/line break|control/i);
  expect(validateSelector(draft({ containerName: 'x'.repeat(256) })).containerName).toMatch(/255/);
  expect(validateSelector(draft({ containerName: 'x'.repeat(255) }))).toEqual({});
});

test('a pinned container id must be 64 lowercase hex characters and a digest must be sha256: plus 64 lowercase hex', () => {
  expect(validateSelector(draft({ containerName: 'web', pinnedContainerId: 'abc123' })).pinnedContainerId).toMatch(/64/);
  expect(validateSelector(draft({ containerName: 'web', pinnedContainerId: 'B'.repeat(64) })).pinnedContainerId).toMatch(/lowercase/i);
  expect(validateSelector(draft({ containerName: 'web', pinnedContainerId: ID }))).toEqual({});
  // Off-by-one on either side of 64 is refused, and so is a 64-character value that is not hexadecimal.
  expect(validateSelector(draft({ containerName: 'web', pinnedContainerId: 'a'.repeat(63) })).pinnedContainerId).toMatch(/64/);
  expect(validateSelector(draft({ containerName: 'web', pinnedContainerId: 'a'.repeat(65) })).pinnedContainerId).toMatch(/64/);
  expect(validateSelector(draft({ containerName: 'web', pinnedContainerId: `${'a'.repeat(63)}g` })).pinnedContainerId).toMatch(/64/);
  expect(validateSelector(draft({ containerName: 'web', pinnedImageDigest: 'sha256:abc' })).pinnedImageDigest).toMatch(/sha256:/);
  expect(validateSelector(draft({ containerName: 'web', pinnedImageDigest: DIGEST }))).toEqual({});
});

test('an exact name that contains pattern characters is flagged, a pattern name is not', () => {
  expect(validateSelector(draft({ containerName: 'web-*' })).containerName).toMatch(/pattern/i);
  expect(validateSelector(draft({ containerName: 'web-*', nameIsPattern: true }))).toEqual({});
});

test('whitespace around values is ignored when validating and when normalising', () => {
  expect(validateSelector(draft({ containerName: '  web  ' }))).toEqual({});
  expect(normalizeSelector(draft({ containerName: '  web ', composeProject: ' p ', imagePattern: ' i:* ' }))).toEqual({ ...EMPTY_SELECTOR, containerName: 'web', composeProject: 'p', imagePattern: 'i:*' });
});

test('caps must be whole numbers inside the ranges the evaluator enforces', () => {
  expect(validateCaps({ logTailMax: '0', stopTimeoutMax: '' }, ['container:logs']).logTailMax).toMatch(/1.*10,?000/);
  expect(validateCaps({ logTailMax: '10001', stopTimeoutMax: '' }, ['container:logs']).logTailMax).toBeDefined();
  expect(validateCaps({ logTailMax: '1.5', stopTimeoutMax: '' }, ['container:logs']).logTailMax).toBeDefined();
  expect(validateCaps({ logTailMax: '500', stopTimeoutMax: '' }, ['container:logs'])).toEqual({});
  expect(validateCaps({ logTailMax: '', stopTimeoutMax: '301' }, ['container:stop']).stopTimeoutMax).toMatch(/1.*300/);
  expect(validateCaps({ logTailMax: '', stopTimeoutMax: '30' }, ['container:restart'])).toEqual({});
});

test('a cap for an operation that is not selected is ignored rather than sent', () => {
  expect(validateCaps({ logTailMax: '99999', stopTimeoutMax: '99999' }, ['container:start'])).toEqual({});
});

// ───────────────────────── guardrail assessment ─────────────────────────

const allow = { effect: 'allow' as const, operations: ['container:logs'] as const };
const allowRestart = { effect: 'allow' as const, operations: ['container:restart'] as const };
const deny = { effect: 'deny' as const, operations: ['container:restart'] as const };

test('an exact name alone is "name only": it works, but a different image under that name would match too', () => {
  const result = assessSelector(draft({ containerName: 'web' }), allow);
  expect(result.level).toBe('name_only');
  expect(result.needsAcknowledgement).toBe(false);
  expect(result.notes.join(' ')).toMatch(/image/i);
});

test('a Compose pair or an image pattern makes an exact name "guarded"', () => {
  expect(assessSelector(draft({ containerName: 'web', composeProject: 'shop', composeService: 'web' }), allow).level).toBe('guarded');
  expect(assessSelector(draft({ containerName: 'web', imagePattern: 'ghcr.io/org/web:*' }), allow).level).toBe('guarded');
});

test('a pinned container id or digest is "pinned" and says recreation needs a new approval', () => {
  const result = assessSelector(draft({ containerName: 'web', pinnedContainerId: ID }), allow);
  expect(result.level).toBe('pinned');
  expect(result.notes.join(' ')).toMatch(/recreat/i);
  expect(assessSelector(draft({ containerName: 'web', pinnedImageDigest: DIGEST }), allow).level).toBe('pinned');
});

test('a name pattern with literal characters and no guardrail is "pattern"; with a guardrail it is "guarded"', () => {
  expect(assessSelector(draft({ containerName: 'web-*', nameIsPattern: true }), allow).level).toBe('pattern');
  expect(assessSelector(draft({ containerName: 'web-*', nameIsPattern: true, imagePattern: 'nginx:*' }), allow).level).toBe('guarded');
});

test('a pattern with no literal characters is "broad" until any identity check is set', () => {
  expect(assessSelector(draft({ containerName: '*', nameIsPattern: true }), allow).level).toBe('broad');
  expect(assessSelector(draft({ containerName: '?*', nameIsPattern: true }), allow).level).toBe('broad');
  expect(assessSelector(draft({ containerName: '*', nameIsPattern: true, composeProject: 'shop' }), allow).level).toBe('guarded');
});

test('a broad Allow, or a state-changing Allow on an unguarded pattern, must be acknowledged; reads on a plain pattern and every Deny need nothing', () => {
  expect(assessSelector(draft({ containerName: '*', nameIsPattern: true }), allow).needsAcknowledgement).toBe(true);
  expect(assessSelector(draft({ containerName: 'web-*', nameIsPattern: true }), allowRestart).needsAcknowledgement).toBe(true);
  expect(assessSelector(draft({ containerName: 'web-*', nameIsPattern: true }), allow).needsAcknowledgement).toBe(false);
  expect(assessSelector(draft({ containerName: '*', nameIsPattern: true }), deny).needsAcknowledgement).toBe(false);
  expect(assessSelector(draft({ containerName: 'web' }), allowRestart).needsAcknowledgement).toBe(false);
});

test('a broad Deny is described as protective, not as a risk', () => {
  const result = assessSelector(draft({ containerName: '*', nameIsPattern: true }), deny);
  expect(result.headline).toMatch(/blocks/i);
});

test('the assessment never says Mandatary itself can be reached: the self-protection note is always present for broad matches', () => {
  expect(assessSelector(draft({ containerName: '*', nameIsPattern: true }), allow).notes.join(' ')).toMatch(/Mandatary itself/i);
});

// ───────────────────────── keys, chips, sentences ─────────────────────────

test('selectorKey ignores surrounding whitespace so a preview is not wrongly marked stale', () => {
  expect(selectorKey(draft({ containerName: 'web' }))).toBe(selectorKey(draft({ containerName: ' web ' })));
  expect(selectorKey(draft({ containerName: 'web' }))).not.toBe(selectorKey(draft({ containerName: 'web', nameIsPattern: true })));
});

test('describeSelector lists only the guardrails that are set, in a fixed order', () => {
  expect(describeSelector(draft({ containerName: 'web' }))).toEqual([]);
  expect(describeSelector(draft({ containerName: 'web', imagePattern: 'nginx:*', composeProject: 'shop', composeService: 'web', pinnedContainerId: ID, pinnedImageDigest: DIGEST }))).toEqual([
    'Compose project shop',
    'Compose service web',
    'Image nginx:*',
    `Container ID ${'b'.repeat(12)}…`,
    `Digest sha256:${'a'.repeat(12)}…`,
  ]);
});

test('a rule reads as one sentence naming the effect, subject, action and target', () => {
  expect(ruleSentence({ effect: 'allow', subjectKind: 'agent', subjectName: 'ci-runner', operation: 'container:logs', target: 'edge-proxy', nameIsPattern: false })).toBe('Allow agent ci-runner to read logs of edge-proxy');
  expect(ruleSentence({ effect: 'deny', subjectKind: 'group', subjectName: 'contractors', operation: 'container:stop', target: 'db-*', nameIsPattern: true })).toBe('Deny group contractors from stopping containers matching db-*');
  expect(ruleSentence({ effect: 'allow', subjectKind: 'user', subjectName: 'sam', operation: 'container:inspect_config', target: 'edge-proxy', nameIsPattern: false })).toBe('Allow user sam to inspect the configuration of edge-proxy');
});
