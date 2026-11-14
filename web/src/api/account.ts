import { defaultFetcher, isRecord, send, type ApiResult, type Fetcher, type RequestOptions } from './http';

/** Browser account API (`internal/auth/login_http.go`, `security_http.go`). */

/** A usable authenticator app of the account: a random, non-secret record id and when it was added (Unix s). */
export interface TotpChoice {
  id: string;
  addedAt: number;
}

export type LoginStep = { step: 'factor'; next: ReadonlyArray<'totp' | 'webauthn' | 'no-mfa'>; totpFactors: readonly TotpChoice[] } | { step: 'session' };

export type StepUpMethodName = 'password' | 'totp' | 'webauthn';

/** Server-derived session view. The UI shows these labels and never computes or upgrades them. */
export interface SessionView {
  username: string;
  administrator: boolean;
  assurance: 'password-only' | 'aal2';
  methods: string[];
  phishingResistant: boolean;
  authenticatedAt: number;
  expiresAt: number;
  stepUpRequired: boolean;
  /** The proofs the SERVER would accept for a step-up of this session now, in preference order. */
  stepUpMethods: readonly StepUpMethodName[];
  totpFactors: readonly TotpChoice[];
}

/** A WebAuthn ceremony issued by the server: its id and the options for the browser. */
export interface Ceremony {
  id: string;
  options: unknown;
}

export function decodeCeremony(value: unknown): Ceremony | null {
  if (!isRecord(value) || typeof value.id !== 'string' || value.id === '' || !isRecord(value.options)) return null;
  return { id: value.id, options: value.options };
}

const KNOWN_NEXT = ['totp', 'webauthn', 'no-mfa'] as const;
const KNOWN_STEP_UP: readonly StepUpMethodName[] = ['webauthn', 'totp', 'password'];

export function decodeTotpChoices(value: unknown): TotpChoice[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return null;
  const out: TotpChoice[] = [];
  for (const row of value as unknown[]) {
    if (!isRecord(row) || typeof row.id !== 'string' || row.id === '' || typeof row.added_at !== 'number') return null;
    out.push({ id: row.id, addedAt: row.added_at });
  }
  return out;
}

function decodeLogin(value: unknown): { step: LoginStep; csrf: string } | null {
  if (!isRecord(value)) return null;
  if (value.step === 'session') return { step: { step: 'session' }, csrf: '' };
  const offered: unknown = value.next;
  if (value.step !== 'factor' || !Array.isArray(offered) || typeof value.csrf_token !== 'string' || value.csrf_token === '') return null;
  const factors = decodeTotpChoices(value.totp_factors);
  if (factors === null) return null;
  // Unknown steps are dropped, never guessed at: the UI offers only what it understands.
  const next = KNOWN_NEXT.filter((known) => offered.includes(known));
  return { step: { step: 'factor', next, totpFactors: factors }, csrf: value.csrf_token };
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
  // The two members added by slice 2 are optional on the wire so an older server still loads.
  const offered: unknown = value.step_up_methods ?? [];
  const factors = decodeTotpChoices(value.totp_factors);
  if (!Array.isArray(offered) || factors === null) return null;
  return {
    csrf,
    view: {
      username,
      administrator: value.administrator === true,
      assurance,
      methods,
      phishingResistant: value.phishing_resistant,
      authenticatedAt: value.authenticated_at,
      expiresAt: value.expires_at,
      stepUpRequired: value.step_up_required,
      stepUpMethods: KNOWN_STEP_UP.filter((known) => offered.includes(known)),
      totpFactors: factors,
    },
  };
}

/**
 * Holds the preauth/session CSRF token in a private field. The password is an argument of ONE call and
 * is not retained; the HttpOnly session cookie is the browser's. Every signed-in call of the other API
 * modules goes through `request`, so the token never leaves this class.
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

  /**
   * Sends a same-origin state-changing request (POST unless the caller names PUT or DELETE) carrying the current
   * CSRF token. `path` is always a constant of the caller plus identifiers validated by `safeSegment`.
   */
  request<T = null>(path: string, options: Omit<RequestOptions<T>, 'csrf'> & { method?: 'POST' | 'PUT' | 'DELETE' } = {}): Promise<ApiResult<T>> {
    const { method = 'POST', ...rest } = options;
    return send(this.#fetcher, method, path, { ...rest, csrf: this.#csrf });
  }

  read<T>(path: string, decode: (value: unknown) => T | null): Promise<ApiResult<T>> {
    return send(this.#fetcher, 'GET', path, { decode });
  }

  async login(username: string, password: string): Promise<ApiResult<LoginStep>> {
    const result = await send(this.#fetcher, 'POST', '/api/v1/login', { body: { username, password }, decode: decodeLogin });
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.step };
  }

  /** The authenticator is chosen by the server unless the account has several: then one of its own is named. */
  loginTotp(code: string, authenticatorId?: string): Promise<ApiResult<null>> {
    return this.request('/api/v1/login/totp', { body: authenticatorId === undefined ? { code } : { code, authenticator_id: authenticatorId } });
  }

  loginNoMfa(): Promise<ApiResult<null>> {
    return this.request('/api/v1/login/no-mfa', { body: {} });
  }

  loginKeyBegin(): Promise<ApiResult<Ceremony>> {
    return this.request('/api/v1/login/webauthn/begin', { body: {}, decode: decodeCeremony });
  }

  loginKeyFinish(id: string, response: unknown): Promise<ApiResult<null>> {
    return this.request('/api/v1/login/webauthn/finish', { body: { id, response } });
  }

  async session(): Promise<ApiResult<SessionView>> {
    const result = await send(this.#fetcher, 'GET', '/api/v1/session', { decode: decodeSession });
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.view };
  }

  logout(): Promise<ApiResult<null>> {
    return this.request('/api/v1/logout', { body: {} });
  }
}
