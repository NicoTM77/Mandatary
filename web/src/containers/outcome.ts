import { commonReason, type ApiResult } from '../api/http';

/**
 * The ONE place a signed-in call's HTTP result becomes a page-level outcome (docs/ui §6.3). Reasons are
 * presentation reasons, never server text. A 403 `step_up_required` / `assurance_unavailable` comes from
 * the Browser boundary before any service ran; every other 403 is the one public refusal.
 */
export type Outcome =
  | { kind: 'ok' }
  | { kind: 'ended' }
  | { kind: 'step_up' }
  | { kind: 'assurance_unavailable' }
  | { kind: 'denied' }
  | { kind: 'common'; reason: 'rate_limited' | 'unavailable' | 'invalid_request' };

export function outcomeOf(result: ApiResult<unknown>): Outcome {
  if (result.ok) return { kind: 'ok' };
  if (result.status === 401) return { kind: 'ended' };
  if (result.status === 403) {
    if (result.code === 'step_up_required') return { kind: 'step_up' };
    if (result.code === 'assurance_unavailable') return { kind: 'assurance_unavailable' };
    return { kind: 'denied' };
  }
  if (result.status === 409) return { kind: 'denied' };
  return { kind: 'common', reason: commonReason(result.status) };
}

export type CommonFailure = 'rate_limited' | 'unavailable' | 'invalid_request';

/** `denied` or a common failure, for forms that only distinguish those. */
export function failureReason(outcome: Outcome): 'denied' | CommonFailure {
  return outcome.kind === 'common' ? outcome.reason : 'denied';
}
