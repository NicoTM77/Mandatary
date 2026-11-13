import type { Fetcher } from '../api/http';

/**
 * Test-only stand-in for the Go adapters (`internal/auth/setup_http.go`, `login_http.go`): same paths,
 * statuses and JSON shapes, CSRF header enforced on unsafe methods. It exists so container tests can
 * exercise outcome mapping; the REAL services are exercised by the browser tests (web/tests/*). It is
 * not imported by the application, so it is not part of the production bundle. All values are synthetic.
 */

export interface Recorded {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  init: RequestInit;
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export function empty(status = 204): Response {
  return new Response(null, { status });
}

export type Handler = (request: Recorded) => Response | Promise<Response>;

export class FakeServer {
  readonly requests: Recorded[] = [];
  readonly #routes = new Map<string, Handler>();

  route(method: string, path: string, handler: Handler): this {
    this.#routes.set(`${method} ${path}`, handler);
    return this;
  }

  readonly fetcher: Fetcher = async (input, init) => {
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries((init.headers ?? {}) as Record<string, string>)) headers[key.toLowerCase()] = value;
    const method = init.method ?? 'GET';
    const recorded: Recorded = { method, path: input, headers, body: typeof init.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined, init };
    this.requests.push(recorded);
    const handler = this.#routes.get(`${method} ${input}`);
    return handler ? handler(recorded) : json(404, { error: 'not_found' });
  };

  calls(method: string, path: string): Recorded[] {
    return this.requests.filter((request) => request.method === method && request.path === path);
  }
}

export const SETUP_CSRF = 'synthetic-setup-csrf-0001';
export const SESSION_CSRF = 'synthetic-session-csrf-0001';

export interface SetupViewJson {
  purpose: string;
  expires_at: number;
  csrf_token: string;
  replace_password: boolean;
  target_user: string;
  account_staged: boolean;
  totp_begun: boolean;
  totp_proven: boolean;
  addresses: Array<{ id: string; address: string; confirmed: boolean }> | null;
  mail_configured: boolean;
}

export function setupView(overrides: Partial<SetupViewJson> = {}): SetupViewJson {
  return {
    purpose: 'initial_setup',
    expires_at: Math.floor(Date.now() / 1000) + 30 * 60,
    csrf_token: SETUP_CSRF,
    replace_password: false,
    target_user: '',
    account_staged: false,
    totp_begun: false,
    totp_proven: false,
    addresses: null,
    mail_configured: true,
    ...overrides,
  };
}

/** Rejects an unsafe request without the setup CSRF header exactly as the adapter does (403 forbidden). */
export function requireCsrf(request: Recorded, token: string, ok: () => Response): Response {
  return request.headers['x-csrf-token'] === token ? ok() : json(403, { error: 'forbidden' });
}
