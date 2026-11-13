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

export type ApiResult<T> = { ok: true; status: number; data: T } | { ok: false; status: number; code: string; guidance?: string };

export type Fetcher = (input: string, init: RequestInit) => Promise<Response>;

export const defaultFetcher: Fetcher = (input, init) => globalThis.fetch(input, init);

const TIMEOUT_MS = 20_000;
/** Server error codes are short snake_case tokens. Anything else is dropped, so free text cannot reach the UI. */
const CODE_PATTERN = /^[a-z][a-z_]{0,39}$/;
const MAX_GUIDANCE = 300;

export interface RequestOptions<T> {
  /** Server-derived CSRF token, held in memory by the caller. */
  csrf?: string;
  body?: unknown;
  /** Returns null for a malformed body, which fails the call closed. Omit for 204 endpoints. */
  decode?: (value: unknown) => T | null;
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
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetcher(path, { method, headers, body, credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal });
  } catch {
    return { ok: false, status: 0, code: 'network' };
  } finally {
    clearTimeout(timer);
  }
  if (response.ok) {
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
  try {
    const parsed: unknown = await response.json();
    if (isRecord(parsed)) {
      if (typeof parsed.error === 'string' && CODE_PATTERN.test(parsed.error)) code = parsed.error;
      if (typeof parsed.guidance === 'string' && parsed.guidance.length > 0 && parsed.guidance.length <= MAX_GUIDANCE) guidance = parsed.guidance;
    }
  } catch {
    // Not JSON (for example a plain-text 404/405): the status alone is the outcome.
  }
  return guidance === undefined ? { ok: false, status: response.status, code } : { ok: false, status: response.status, code, guidance };
}

/** Maps a failed call to the presentation reason shared by every network-backed form. */
export function commonReason(status: number): 'rate_limited' | 'unavailable' | 'invalid_request' {
  if (status === 429) return 'rate_limited';
  if (status === 400 || status === 415) return 'invalid_request';
  return 'unavailable';
}
