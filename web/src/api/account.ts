import { defaultFetcher, isRecord, send, type ApiResult, type Fetcher } from './http';

/** Browser account API (`internal/auth/login_http.go`). */

export type LoginStep = { step: 'factor'; next: ReadonlyArray<'totp' | 'webauthn' | 'no-mfa'> } | { step: 'session' };

/** Server-derived session view. The UI shows these labels and never computes or upgrades them. */
export interface SessionView {
  username: string;
  assurance: 'password-only' | 'aal2';
  methods: string[];
  phishingResistant: boolean;
  authenticatedAt: number;
  expiresAt: number;
  stepUpRequired: boolean;
}

const KNOWN_NEXT = ['totp', 'webauthn', 'no-mfa'] as const;

function decodeLogin(value: unknown): { step: LoginStep; csrf: string } | null {
  if (!isRecord(value)) return null;
  if (value.step === 'session') return { step: { step: 'session' }, csrf: '' };
  const offered: unknown = value.next;
  if (value.step !== 'factor' || !Array.isArray(offered) || typeof value.csrf_token !== 'string' || value.csrf_token === '') return null;
  // Unknown steps are dropped, never guessed at: the UI offers only what it understands.
  const next = KNOWN_NEXT.filter((known) => offered.includes(known));
  return { step: { step: 'factor', next }, csrf: value.csrf_token };
}

function decodeSession(value: unknown): { view: SessionView; csrf: string } | null {
  if (!isRecord(value)) return null;
  const { username, assurance, methods, csrf_token: csrf } = value;
  if (
    typeof username !== 'string' ||
    (assurance !== 'password-only' && assurance !== 'aal2') ||
    !Array.isArray(methods) ||
    !methods.every((method) => typeof method === 'string') ||
    typeof csrf !== 'string' ||
    csrf === '' ||
    typeof value.phishing_resistant !== 'boolean' ||
    typeof value.authenticated_at !== 'number' ||
    typeof value.expires_at !== 'number' ||
    typeof value.step_up_required !== 'boolean'
  ) {
    return null;
  }
  return {
    csrf,
    view: { username, assurance, methods, phishingResistant: value.phishing_resistant, authenticatedAt: value.authenticated_at, expiresAt: value.expires_at, stepUpRequired: value.step_up_required },
  };
}

/**
 * Holds the preauth/session CSRF token in a private field. The password is an argument of ONE call and
 * is not retained; the HttpOnly session cookie is the browser's.
 */
export class AccountApi {
  #csrf = '';
  readonly #fetcher: Fetcher;

  constructor(fetcher: Fetcher = defaultFetcher) {
    this.#fetcher = fetcher;
  }

  forget(): void {
    this.#csrf = '';
  }

  async login(username: string, password: string): Promise<ApiResult<LoginStep>> {
    const result = await send(this.#fetcher, 'POST', '/api/v1/login', { body: { username, password }, decode: decodeLogin });
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.step };
  }

  /** The authenticator is chosen by the server; the page has no authenticator identifier. */
  loginTotp(code: string): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', '/api/v1/login/totp', { csrf: this.#csrf, body: { code } });
  }

  loginNoMfa(): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', '/api/v1/login/no-mfa', { csrf: this.#csrf, body: {} });
  }

  async session(): Promise<ApiResult<SessionView>> {
    const result = await send(this.#fetcher, 'GET', '/api/v1/session', { decode: decodeSession });
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.view };
  }

  logout(): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', '/api/v1/logout', { csrf: this.#csrf, body: {} });
  }
}
