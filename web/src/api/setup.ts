import { defaultFetcher, isRecord, send, type ApiResult, type Fetcher } from './http';

/** Setup API (`internal/auth/setup_http.go`). Paths are constants; nothing here is built from input. */
const BASE = '/api/v1/setup/';

export interface SetupAddressView {
  id: string;
  address: string;
  confirmed: boolean;
}

/** The server's setup-session view WITHOUT the CSRF token, which stays inside `SetupApi`. */
export interface SetupView {
  purpose: string;
  expiresAt: number;
  replacePassword: boolean;
  targetUser: string;
  accountStaged: boolean;
  totpBegun: boolean;
  totpProven: boolean;
  addresses: SetupAddressView[];
  mailConfigured: boolean;
}

export interface TotpBegin {
  algorithm: string;
  digits: number;
  period: number;
  /** Reveal-once seed. The caller owns it and must drop it as soon as the state that shows it ends. */
  secret: string;
}

interface DecodedView {
  view: SetupView;
  csrf: string;
}

function decodeAddresses(value: unknown): SetupAddressView[] | null {
  if (value === null) return []; // Go encodes an empty slice as null.
  if (!Array.isArray(value)) return null;
  const rows: SetupAddressView[] = [];
  for (const item of value) {
    if (!isRecord(item) || typeof item.id !== 'string' || typeof item.address !== 'string' || typeof item.confirmed !== 'boolean') return null;
    rows.push({ id: item.id, address: item.address, confirmed: item.confirmed });
  }
  return rows;
}

function decodeView(value: unknown): DecodedView | null {
  if (!isRecord(value)) return null;
  const addresses = decodeAddresses(value.addresses);
  if (
    addresses === null ||
    typeof value.purpose !== 'string' ||
    typeof value.expires_at !== 'number' ||
    typeof value.csrf_token !== 'string' ||
    value.csrf_token === '' ||
    typeof value.replace_password !== 'boolean' ||
    typeof value.account_staged !== 'boolean' ||
    typeof value.totp_begun !== 'boolean' ||
    typeof value.totp_proven !== 'boolean' ||
    typeof value.mail_configured !== 'boolean'
  ) {
    return null;
  }
  const target = value.target_user;
  return {
    csrf: value.csrf_token,
    view: {
      purpose: value.purpose,
      expiresAt: value.expires_at,
      replacePassword: value.replace_password,
      targetUser: typeof target === 'string' ? target : '',
      accountStaged: value.account_staged,
      totpBegun: value.totp_begun,
      totpProven: value.totp_proven,
      addresses,
      mailConfigured: value.mail_configured,
    },
  };
}

function decodeTotp(value: unknown): TotpBegin | null {
  if (!isRecord(value) || typeof value.secret !== 'string' || value.secret === '' || typeof value.algorithm !== 'string' || typeof value.digits !== 'number' || typeof value.period !== 'number') return null;
  return { secret: value.secret, algorithm: value.algorithm, digits: value.digits, period: value.period };
}

function decodeComplete(value: unknown): { username: string } | null {
  if (!isRecord(value) || value.login_required !== true) return null;
  return { username: typeof value.username === 'string' ? value.username : '' };
}

/**
 * Holds the setup session's CSRF token in a private field (memory only, never storage, DOM or URL). The
 * HttpOnly setup cookie is managed by the browser; this object never sees it.
 */
export class SetupApi {
  #csrf = '';
  readonly #fetcher: Fetcher;

  constructor(fetcher: Fetcher = defaultFetcher) {
    this.#fetcher = fetcher;
  }

  /** Drops the in-memory token (session ended or the page is leaving setup). */
  forget(): void {
    this.#csrf = '';
  }

  async #adopt(result: ApiResult<DecodedView>): Promise<ApiResult<SetupView>> {
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.view };
  }

  /** The pasted token is sent once in the body and is never kept. */
  exchange(token: string): Promise<ApiResult<SetupView>> {
    return send(this.#fetcher, 'POST', `${BASE}exchange`, { body: { token }, decode: decodeView }).then((result) => this.#adopt(result));
  }

  session(): Promise<ApiResult<SetupView>> {
    return send(this.#fetcher, 'GET', `${BASE}session`, { decode: decodeView }).then((result) => this.#adopt(result));
  }

  /** `mfa_reset` sends ONLY the password: the server refuses a username or addresses for that purpose. */
  account(values: { username?: string; password: string; addresses?: string[] }): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', `${BASE}account`, { csrf: this.#csrf, body: values });
  }

  sendProof(addressId: string): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', `${BASE}addresses/proof`, { csrf: this.#csrf, body: { address_id: addressId } });
  }

  confirmAddress(addressId: string, proof: string): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', `${BASE}addresses/confirm`, { csrf: this.#csrf, body: { address_id: addressId, proof } });
  }

  /** The server accepts "SHA1" or "SHA256" exactly (not "SHA-256"). SHA256 is the documented setup choice. */
  beginTotp(): Promise<ApiResult<TotpBegin>> {
    return send(this.#fetcher, 'POST', `${BASE}totp`, { csrf: this.#csrf, body: { algorithm: 'SHA256' }, decode: decodeTotp });
  }

  confirmTotp(code: string): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', `${BASE}totp/confirm`, { csrf: this.#csrf, body: { code } });
  }

  complete(): Promise<ApiResult<{ username: string }>> {
    return send(this.#fetcher, 'POST', `${BASE}complete`, { csrf: this.#csrf, body: {}, decode: decodeComplete });
  }
}
