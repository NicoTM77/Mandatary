/**
 * Minimal same-origin JSON transport for the admin application (P1.16.3).
 *
 * Rules enforced here, once, for every call:
 *  - same-origin only: the path is a constant starting with "/api/v1/", never built from input;
 *  - credentials are the HttpOnly cookie (`same-origin`); no Authorization header, no storage;
 *  - never cached, never follows a redirect, sends no Referer;
 *  - the CSRF token is a request HEADER supplied by the caller from memory, never a cookie/query/body;
 *  - request bodies are JSON; the response body is parsed only into a typed value by a caller-supplied
 *    decoder, and a failure exposes ONLY a short lowercase error code and (for password rejection) the
 *    fixed server guidance string. A response body is never copied into an Error, log or the DOM;
 *  - nothing is logged. This module must never reference `console`.
 */

/** One refused record of a 409 `conflict` (P1.18 approvals). All three members are short fixed tokens; see `decodeConflictItems`. */
export interface ConflictItem {
  kind: string;
  id: string;
  reason: string;
}

/**
 * A failed call keeps only: the status, the short error code, the fixed guidance string and - for the P1.18 routes - two documented
 * fields: `installationState` (only the exact value `restore_quarantine`: the restore's first transaction committed) and `items`
 * (a 409 `conflict`'s refused records). Both are validated strictly and DROPPED when they are not exactly the documented shape.
 */
export type ApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; code: string; guidance?: string; installationState?: 'restore_quarantine'; items?: ConflictItem[] };

export type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

export const defaultFetcher: Fetcher = (input, init) => globalThis.fetch(input, init);

const TIMEOUT_MS = 20_000;
/** Server error codes are short snake_case tokens. Anything else is dropped, so free text cannot reach the UI. */
const CODE_PATTERN = /^[a-z][a-z_]{0,39}$/;
const MAX_GUIDANCE = 300;
/** `backup.MaxApprovalsPerRequest`: a conflict cannot name more records than a request may carry. */
const MAX_CONFLICT_ITEMS = 500;
/** Kinds and reasons are fixed snake_case codes; an id is a service id (<= 128) or a membership `<id>:<id>` (<= 257). */
const CODE_TOKEN = /^[a-z][a-z_]{0,39}$/;
const ID_TOKEN = /^[A-Za-z0-9_.:-]{1,257}$/;

export interface RequestOptions<T> {
  /** Server-derived CSRF token, held in memory by the caller. */
  csrf?: string;
  body?: unknown;
  /** Returns null for a malformed body, which fails the call closed. Omit for 204 endpoints. */
  decode?: (value: unknown) => T | null;
  /** For a successful response that is not JSON (the backup download). Returns null to fail closed. Takes precedence over `decode`. */
  read?: (response: Response) => Promise<T | null>;
  /** This call's own time bound in milliseconds (default 20 s). An abort is a status-0 `network` outcome, exactly like a lost connection. */
  timeoutMs?: number;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

export async function send<T = null>(fetcher: Fetcher, method: Method, path: string, options: RequestOptions<T> = {}): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.csrf) headers['X-CSRF-Token'] = options.csrf;
  let body: string | undefined;
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(options.body);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetcher(path, { method, headers, body, credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal });
  } catch {
    return { ok: false, status: 0, code: 'network' };
  } finally {
    clearTimeout(timer);
  }
  if (response.ok) {
    if (options.read !== undefined) {
      let data: T | null;
      try {
        data = await options.read(response);
      } catch {
        data = null;
      }
      return data === null ? { ok: false, status: response.status, code: 'invalid_response' } : { ok: true, status: response.status, data };
    }
    if (response.status === 204 || options.decode === undefined) return { ok: true, status: response.status, data: null as T };
    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      return { ok: false, status: response.status, code: 'invalid_response' };
    }
    const data = options.decode(parsed);
    return data === null ? { ok: false, status: response.status, code: 'invalid_response' } : { ok: true, status: response.status, data };
  }
  let code = '';
  let guidance: string | undefined;
  let installationState: 'restore_quarantine' | undefined;
  let items: ConflictItem[] | undefined;
  try {
    const parsed: unknown = await response.json();
    if (isRecord(parsed)) {
      if (typeof parsed.error === 'string' && CODE_PATTERN.test(parsed.error)) code = parsed.error;
      if (typeof parsed.guidance === 'string' && parsed.guidance.length > 0 && parsed.guidance.length <= MAX_GUIDANCE) guidance = parsed.guidance;
      if (parsed.installation_state === 'restore_quarantine') installationState = 'restore_quarantine';
      items = decodeConflictItems(parsed.items);
    }
  } catch {
    // Not JSON (for example a plain-text 404/405): the status alone is the outcome.
  }
  const failure: ApiResult<T> = { ok: false, status: response.status, code };
  if (guidance !== undefined) failure.guidance = guidance;
  if (installationState !== undefined) failure.installationState = installationState;
  if (items !== undefined) failure.items = items;
  return failure;
}

/** A conflict's refused records: a bounded list of `{kind, id, reason}` whose members are short fixed tokens. Anything else is dropped whole. */
function decodeConflictItems(value: unknown): ConflictItem[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_CONFLICT_ITEMS) return undefined;
  const out: ConflictItem[] = [];
  for (const item of value as unknown[]) {
    if (!isRecord(item) || typeof item.kind !== 'string' || typeof item.id !== 'string' || typeof item.reason !== 'string') return undefined;
    if (!CODE_TOKEN.test(item.kind) || !ID_TOKEN.test(item.id) || !CODE_TOKEN.test(item.reason)) return undefined;
    out.push({ kind: item.kind, id: item.id, reason: item.reason });
  }
  return out;
}

/** Maps a failed call to the presentation reason shared by every network-backed form. */
export function commonReason(status: number): 'rate_limited' | 'unavailable' | 'invalid_request' {
  if (status === 429) return 'rate_limited';
  if (status === 400 || status === 415) return 'invalid_request';
  return 'unavailable';
}
