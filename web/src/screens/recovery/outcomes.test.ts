import { expect, test } from 'vitest';
import { approvalOutcomeOf, exportReasonOf, refusalOf, restoreOutcomeOf, type FailedCall } from './outcomes';

const call = (status: number, code: string, extra: Partial<FailedCall> = {}): FailedCall => ({ status, code, ...extra });

// ───────────────────────── export ─────────────────────────

test('export: every failure is "no file", and only the documented classes get their own words', () => {
  expect(exportReasonOf(call(403, 'forbidden'))).toBe('denied');
  expect(exportReasonOf(call(400, 'invalid_request'))).toBe('invalid_request');
  expect(exportReasonOf(call(415, 'unsupported_media_type'))).toBe('invalid_request');
  expect(exportReasonOf(call(429, 'rate_limited'))).toBe('rate_limited');
  expect(exportReasonOf(call(503, 'unavailable'))).toBe('unavailable');
  expect(exportReasonOf(call(0, 'network'))).toBe('unavailable');
  expect(exportReasonOf(call(500, ''))).toBe('unavailable');
});

// ───────────────────────── restore ─────────────────────────

test('restore: a failure that carries installation_state is the "quarantine, nothing imported" page, whatever its status', () => {
  const state = { installationState: 'restore_quarantine' };
  expect(restoreOutcomeOf(call(503, 'unavailable', state))).toEqual({ kind: 'ended', ended: { kind: 'incomplete', cause: 'failed' } });
  expect(restoreOutcomeOf(call(409, 'restore_superseded', state))).toEqual({ kind: 'ended', ended: { kind: 'incomplete', cause: 'superseded' } });
  expect(restoreOutcomeOf(call(422, 'archive_inconsistent', state))).toEqual({ kind: 'ended', ended: { kind: 'incomplete', cause: 'failed' } });
});

test('restore: superseded means the first transaction committed even if the body lost the state field', () => {
  expect(restoreOutcomeOf(call(409, 'restore_superseded'))).toEqual({ kind: 'ended', ended: { kind: 'incomplete', cause: 'superseded' } });
});

test('restore: no usable answer is never "nothing changed": a lost connection, a timeout, a proxy error or an undecodable 2xx', () => {
  const unconfirmed = { kind: 'ended', ended: { kind: 'unconfirmed' } };
  expect(restoreOutcomeOf(call(0, 'network'))).toEqual(unconfirmed);
  expect(restoreOutcomeOf(call(200, 'invalid_response'))).toEqual(unconfirmed);
  expect(restoreOutcomeOf(call(500, ''))).toEqual(unconfirmed);
  expect(restoreOutcomeOf(call(502, ''))).toEqual(unconfirmed);
  expect(restoreOutcomeOf(call(504, ''))).toEqual(unconfirmed);
  expect(restoreOutcomeOf(call(503, ''))).toEqual(unconfirmed);
});

test('restore: the documented 503 `unavailable` without installation_state is the service saying it did not start', () => {
  expect(restoreOutcomeOf(call(503, 'unavailable'))).toEqual({ kind: 'form', state: { kind: 'rejected', reason: 'unavailable' } });
});

test('restore: 409 provenance_unverified asks for the acknowledgement and is not a refusal', () => {
  expect(restoreOutcomeOf(call(409, 'provenance_unverified'))).toEqual({ kind: 'form', state: { kind: 'needs_acknowledgement' } });
});

test('restore: each 422 class maps to its own words; an unknown 422 is treated as unreadable, never reflected', () => {
  for (const code of ['archive_malformed', 'archive_unsupported_version', 'archive_integrity_failed', 'archive_inconsistent'] as const) {
    expect(restoreOutcomeOf(call(422, code))).toEqual({ kind: 'form', state: { kind: 'rejected', reason: code } });
  }
  expect(restoreOutcomeOf(call(422, 'something_new'))).toEqual({ kind: 'form', state: { kind: 'rejected', reason: 'archive_malformed' } });
});

test('restore: the remaining refusals change nothing and keep the person on the form', () => {
  const rejected = (reason: string) => ({ kind: 'form', state: { kind: 'rejected', reason } });
  expect(restoreOutcomeOf(call(403, 'forbidden'))).toEqual(rejected('denied'));
  expect(restoreOutcomeOf(call(429, 'rate_limited'))).toEqual(rejected('rate_limited'));
  expect(restoreOutcomeOf(call(400, 'invalid_request'))).toEqual(rejected('invalid_request'));
  expect(restoreOutcomeOf(call(415, 'unsupported_media_type'))).toEqual(rejected('invalid_request'));
  expect(restoreOutcomeOf(call(404, 'not_found'))).toEqual(rejected('invalid_request'));
});

test('restore: a 409 `restore_quarantine` with no installation_state is never read as an import having happened', () => {
  const outcome = restoreOutcomeOf(call(409, 'restore_quarantine'));
  expect(outcome.kind).toBe('form');
});

test('restore: no failure is ever mapped to a "complete" page: only a 200 with a decoded report can be', () => {
  for (const status of [0, 200, 400, 403, 404, 409, 415, 422, 429, 500, 502, 503, 504]) {
    for (const code of ['', 'network', 'invalid_response', 'unavailable', 'forbidden', 'provenance_unverified', 'restore_superseded']) {
      const outcome = restoreOutcomeOf(call(status, code));
      if (outcome.kind === 'ended') expect(outcome.ended.kind).not.toBe('complete');
    }
  }
});

// ───────────────────────── approvals ─────────────────────────

test('approvals: a conflict lists every refusal with its fixed reason', () => {
  const outcome = approvalOutcomeOf(
    call(409, 'conflict', {
      items: [
        { kind: 'user_membership', id: 'u:g', reason: 'subject_not_active' },
        { kind: 'agent', id: 'a-1', reason: 'owner_not_active' },
        { kind: 'user', id: 'u-2', reason: 'compromised' },
        { kind: 'role', id: 'r-1', reason: 'single_administrator' },
      ],
    }),
  );
  expect(outcome).toEqual({
    kind: 'conflict',
    failures: [
      { kind: 'user_membership', id: 'u:g', reason: 'subject_not_active' },
      { kind: 'agent', id: 'a-1', reason: 'owner_not_active' },
      { kind: 'user', id: 'u-2', reason: 'compromised' },
      { kind: 'role', id: 'r-1', reason: 'single_administrator' },
    ],
  });
});

test('approvals: a reason the page does not know becomes `other`, a kind it does not know is dropped, and an empty conflict is a plain refusal', () => {
  expect(refusalOf('subject_not_active')).toBe('subject_not_active');
  expect(refusalOf('brand_new_reason')).toBe('other');
  expect(refusalOf('__proto__')).toBe('other');
  expect(approvalOutcomeOf(call(409, 'conflict', { items: [{ kind: 'user', id: 'u', reason: 'brand_new_reason' }] }))).toEqual({ kind: 'conflict', failures: [{ kind: 'user', id: 'u', reason: 'other' }] });
  expect(approvalOutcomeOf(call(409, 'conflict', { items: [{ kind: 'toString', id: 'u', reason: 'compromised' }] }))).toEqual({ kind: 'rejected', reason: 'invalid' });
  expect(approvalOutcomeOf(call(409, 'conflict'))).toEqual({ kind: 'rejected', reason: 'invalid' });
});

test('approvals: still-quarantined, denied, rate-limited and malformed requests each have their own words', () => {
  expect(approvalOutcomeOf(call(409, 'restore_quarantine'))).toEqual({ kind: 'rejected', reason: 'still_quarantined' });
  expect(approvalOutcomeOf(call(403, 'forbidden'))).toEqual({ kind: 'rejected', reason: 'denied' });
  expect(approvalOutcomeOf(call(429, 'rate_limited'))).toEqual({ kind: 'rejected', reason: 'rate_limited' });
  expect(approvalOutcomeOf(call(400, 'invalid_request'))).toEqual({ kind: 'rejected', reason: 'invalid' });
  expect(approvalOutcomeOf(call(404, 'no_restore'))).toEqual({ kind: 'rejected', reason: 'invalid' });
});

test('approvals: every 5xx and every lost answer is "outcome unknown", including the documented 503, which can follow a commit', () => {
  for (const [status, code] of [
    [503, 'unavailable'],
    [500, ''],
    [502, ''],
    [0, 'network'],
    [200, 'invalid_response'],
  ] as const) {
    expect(approvalOutcomeOf(call(status, code)), `${status} ${code}`).toEqual({ kind: 'rejected', reason: 'outcome_unknown' });
  }
});
