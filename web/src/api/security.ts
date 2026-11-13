import { defaultFetcher, isRecord, send, type ApiResult, type Fetcher } from './http';
import { decodeCeremony, type AccountApi, type Ceremony } from './account';

/**
 * Account-security API client (`internal/auth/security_http.go`, `recovery_http.go`,
 * `agents_http.go`). Secrets (a pasted password, a TOTP code, the TOTP seed, saved recovery codes, an
 * agent token) are return values or arguments of ONE call; nothing here keeps, logs or stores them.
 * Every path is a constant of this module; the only dynamic segments are server-issued agent and
 * credential identifiers, validated against a strict pattern before use.
 */

export interface TotpRowView {
  id: string;
  addedAt: number;
  status: 'active' | 'disabled';
}

export interface KeyRowView {
  id: string;
  addedAt: number;
}

export interface AddressRowView {
  id: string;
  address: string;
  confirmed: boolean;
}

export interface NoticeCounts {
  pending: number;
  failed: number;
  bounced: number;
  quarantined: number;
  protective: number;
  unknown: boolean;
}

export interface Inventory {
  totp: TotpRowView[];
  keys: KeyRowView[];
  maxKeys: number;
  webauthnAvailable: boolean;
  recoveryRemaining: number;
  addresses: AddressRowView[];
  maxAddresses: number;
  notices: NoticeCounts;
}

export interface TotpProvisioning {
  authenticatorId: string;
  /** Reveal-once seed. The caller shows it in exactly one state and drops it. */
  seed: string;
  algorithm: string;
  digits: number;
  period: number;
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function decodeList<T>(value: unknown, row: (item: Record<string, unknown>) => T | null): T[] | null {
  if (!Array.isArray(value)) return null;
  const out: T[] = [];
  for (const item of value as unknown[]) {
    if (!isRecord(item)) return null;
    const decoded = row(item);
    if (decoded === null) return null;
    out.push(decoded);
  }
  return out;
}

function decodeInventory(value: unknown): Inventory | null {
  if (!isRecord(value)) return null;
  const totp = decodeList(value.totp, (row) =>
    typeof row.id === 'string' && isCount(row.added_at) && (row.status === 'active' || row.status === 'disabled') ? { id: row.id, addedAt: row.added_at, status: row.status === 'active' ? ('active' as const) : ('disabled' as const) } : null,
  );
  const keys = decodeList(value.keys, (row) => (typeof row.id === 'string' && isCount(row.added_at) ? { id: row.id, addedAt: row.added_at } : null));
  const addresses = decodeList(value.addresses, (row) => (typeof row.id === 'string' && typeof row.address === 'string' && typeof row.confirmed === 'boolean' ? { id: row.id, address: row.address, confirmed: row.confirmed } : null));
  const codes = value.recovery_codes;
  const notices = value.notices;
  if (
    totp === null ||
    keys === null ||
    addresses === null ||
    !isRecord(codes) ||
    !isCount(codes.remaining) ||
    !isRecord(notices) ||
    !isCount(notices.pending) ||
    !isCount(notices.failed) ||
    !isCount(notices.bounced) ||
    !isCount(notices.quarantined) ||
    !isCount(notices.protective) ||
    typeof notices.unknown !== 'boolean' ||
    !isCount(value.max_keys) ||
    !isCount(value.max_addresses) ||
    typeof value.webauthn_available !== 'boolean'
  ) {
    return null;
  }
  return {
    totp,
    keys,
    maxKeys: value.max_keys,
    webauthnAvailable: value.webauthn_available,
    recoveryRemaining: codes.remaining,
    addresses,
    maxAddresses: value.max_addresses,
    notices: { pending: notices.pending, failed: notices.failed, bounced: notices.bounced, quarantined: notices.quarantined, protective: notices.protective, unknown: notices.unknown },
  };
}

function decodeProvisioning(value: unknown): TotpProvisioning | null {
  if (!isRecord(value)) return null;
  const { authenticator_id: id, secret, algorithm, digits, period } = value;
  if (typeof id !== 'string' || id === '' || typeof secret !== 'string' || secret === '' || typeof algorithm !== 'string' || !isCount(digits) || !isCount(period)) return null;
  return { authenticatorId: id, seed: secret, algorithm, digits, period };
}

function decodeCodes(value: unknown): string[] | null {
  if (!isRecord(value) || !Array.isArray(value.codes) || value.codes.length === 0 || !value.codes.every((code) => typeof code === 'string' && code !== '')) return null;
  return value.codes as string[];
}

function decodeAddressId(value: unknown): string | null {
  if (!isRecord(value) || !isRecord(value.address) || typeof value.address.id !== 'string' || value.address.id === '') return null;
  return value.address.id;
}

/** Signed-in account security: step-up, authenticators, recovery codes, addresses. */
export class SecurityApi {
  readonly #account: AccountApi;

  constructor(account: AccountApi) {
    this.#account = account;
  }

  inventory(): Promise<ApiResult<Inventory>> {
    return this.#account.read('/api/v1/account/security', decodeInventory);
  }

  stepUpPassword(password: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/stepup/password', { body: { password } });
  }

  stepUpTotp(password: string, code: string, authenticatorId?: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/stepup/totp', { body: authenticatorId === undefined ? { password, code } : { password, code, authenticator_id: authenticatorId } });
  }

  stepUpKeyBegin(): Promise<ApiResult<Ceremony>> {
    return this.#account.request('/api/v1/stepup/webauthn/begin', { body: {}, decode: decodeCeremony });
  }

  stepUpKeyFinish(id: string, response: unknown): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/stepup/webauthn/finish', { body: { id, response } });
  }

  beginTotp(): Promise<ApiResult<TotpProvisioning>> {
    return this.#account.request('/api/v1/account/totp', { body: {}, decode: decodeProvisioning });
  }

  confirmTotp(authenticatorId: string, code: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/totp/confirm', { body: { authenticator_id: authenticatorId, code } });
  }

  /** A success ends every session of the account (the server revokes them): the caller must go to sign-in. */
  removeTotp(authenticatorId: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/totp/remove', { body: { authenticator_id: authenticatorId } });
  }

  keyBegin(): Promise<ApiResult<Ceremony>> {
    return this.#account.request('/api/v1/account/webauthn/register/begin', { body: {}, decode: decodeCeremony });
  }

  keyFinish(id: string, response: unknown): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/webauthn/register/finish', { body: { id, response } });
  }

  /** As `removeTotp`: success ends every session. */
  removeKey(authenticatorId: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/webauthn/remove', { body: { authenticator_id: authenticatorId } });
  }

  /** Reveal-once: the ten codes are returned here and can never be fetched again. */
  issueCodes(): Promise<ApiResult<string[]>> {
    return this.#account.request('/api/v1/account/recovery-codes', { body: {}, decode: decodeCodes });
  }

  addAddress(address: string): Promise<ApiResult<string>> {
    return this.#account.request('/api/v1/account/addresses', { body: { address }, decode: decodeAddressId });
  }

  sendAddressProof(id: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/addresses/proof', { body: { id } });
  }

  confirmAddress(id: string, code: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/addresses/confirm', { body: { id, code } });
  }

  removeAddress(id: string): Promise<ApiResult<null>> {
    return this.#account.request('/api/v1/account/addresses/remove', { body: { id } });
  }
}

export interface RecoveryStart {
  expiresAt: number;
  methods: ReadonlyArray<'totp' | 'webauthn'>;
  /** Reveal-once replacement saved code; absent when the capability is resumed after a reload. */
  replacementCode?: string;
}

function decodeRecovery(value: unknown): { start: RecoveryStart; csrf: string } | null {
  if (!isRecord(value) || typeof value.csrf_token !== 'string' || value.csrf_token === '' || !isCount(value.expires_at) || !Array.isArray(value.methods)) return null;
  const methods = (['totp', 'webauthn'] as const).filter((known) => (value.methods as unknown[]).includes(known));
  const start: RecoveryStart = { expiresAt: value.expires_at, methods };
  if (typeof value.replacement_code === 'string' && value.replacement_code !== '') start.replacementCode = value.replacement_code;
  return { start, csrf: value.csrf_token };
}

/**
 * Restricted recovery (saved code → ten-minute re-enrolment capability). The capability is the server's
 * `__Host-` cookie; its CSRF token lives only in this object. It never touches the session API.
 */
export class RecoveryApi {
  #csrf = '';
  readonly #fetcher: Fetcher;

  constructor(fetcher: Fetcher = defaultFetcher) {
    this.#fetcher = fetcher;
  }

  async start(username: string, password: string, code: string): Promise<ApiResult<RecoveryStart>> {
    const result = await send(this.#fetcher, 'POST', '/api/v1/recovery', { body: { username, password, code }, decode: decodeRecovery });
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.start };
  }

  /** Resumes a live capability after a reload (the replacement code is never shown again). */
  async state(): Promise<ApiResult<RecoveryStart>> {
    const result = await send(this.#fetcher, 'GET', '/api/v1/recovery/state', { decode: decodeRecovery });
    if (!result.ok) return result;
    this.#csrf = result.data.csrf;
    return { ok: true, status: result.status, data: result.data.start };
  }

  beginTotp(): Promise<ApiResult<TotpProvisioning>> {
    return send(this.#fetcher, 'POST', '/api/v1/recovery/totp', { csrf: this.#csrf, body: {}, decode: decodeProvisioning });
  }

  confirmTotp(authenticatorId: string, code: string): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', '/api/v1/recovery/totp/confirm', { csrf: this.#csrf, body: { authenticator_id: authenticatorId, code } });
  }

  keyBegin(): Promise<ApiResult<Ceremony>> {
    return send(this.#fetcher, 'POST', '/api/v1/recovery/webauthn/begin', { csrf: this.#csrf, body: {}, decode: decodeCeremony });
  }

  keyFinish(id: string, response: unknown): Promise<ApiResult<null>> {
    return send(this.#fetcher, 'POST', '/api/v1/recovery/webauthn/finish', { csrf: this.#csrf, body: { id, response } });
  }

  forget(): void {
    this.#csrf = '';
  }
}

// ───────────────────────── agent credentials ─────────────────────────

export type CredentialStatusName = 'active' | 'overlapping' | 'rotated_out' | 'expired' | 'revoked' | 'quarantined' | 'stale';
const CREDENTIAL_STATUSES: readonly string[] = ['active', 'overlapping', 'rotated_out', 'expired', 'revoked', 'quarantined', 'stale'];

export interface CredentialMeta {
  id: string;
  displayId: string;
  status: CredentialStatusName;
  expiresAt: number | null;
  overlapUntil: number | null;
  nonExpiring: boolean;
}

export interface AgentMeta {
  id: string;
  name: string;
  state: string;
  credentials: CredentialMeta[];
}

/** Server identifiers become a URL path segment only after matching this strict pattern. */
const SAFE_SEGMENT = /^[A-Za-z0-9._-]{1,128}$/;

export function safeSegment(value: string): string | null {
  return SAFE_SEGMENT.test(value) && value !== '.' && value !== '..' ? value : null;
}

function decodeCredential(row: unknown): CredentialMeta | null {
  if (!isRecord(row) || typeof row.id !== 'string' || typeof row.display_id !== 'string' || typeof row.status !== 'string' || !CREDENTIAL_STATUSES.includes(row.status)) return null;
  const expires = row.expires_at === null || row.expires_at === undefined ? null : row.expires_at;
  const overlap = row.overlap_until === null || row.overlap_until === undefined ? null : row.overlap_until;
  if ((expires !== null && !isCount(expires)) || (overlap !== null && !isCount(overlap))) return null;
  return { id: row.id, displayId: row.display_id, status: row.status as CredentialStatusName, expiresAt: expires, overlapUntil: overlap, nonExpiring: row.non_expiring === true };
}

function decodeAgents(value: unknown): AgentMeta[] | null {
  if (!isRecord(value) || !Array.isArray(value.agents)) return null;
  const out: AgentMeta[] = [];
  for (const agent of value.agents as unknown[]) {
    // An agent with no credential yet may be serialised as null rather than [].
    const rows = isRecord(agent) && agent.credentials === null ? [] : isRecord(agent) ? agent.credentials : undefined;
    if (!isRecord(agent) || typeof agent.id !== 'string' || typeof agent.name !== 'string' || typeof agent.state !== 'string' || !Array.isArray(rows)) return null;
    const credentials: CredentialMeta[] = [];
    for (const row of rows as unknown[]) {
      const decoded = decodeCredential(row);
      if (decoded === null) return null;
      credentials.push(decoded);
    }
    out.push({ id: agent.id, name: agent.name, state: agent.state, credentials });
  }
  return out;
}

export interface IssuedToken {
  /** Reveal-once bearer token. */
  token: string;
  credential: CredentialMeta;
  rotatedOut: CredentialMeta[];
}

function decodeIssued(value: unknown): IssuedToken | null {
  if (!isRecord(value) || typeof value.token !== 'string' || value.token === '') return null;
  const credential = decodeCredential(value.credential);
  if (credential === null) return null;
  const rotatedOut: CredentialMeta[] = [];
  if (value.rotated_out !== undefined && value.rotated_out !== null) {
    if (!Array.isArray(value.rotated_out)) return null;
    for (const row of value.rotated_out as unknown[]) {
      const decoded = decodeCredential(row);
      if (decoded === null) return null;
      rotatedOut.push(decoded);
    }
  }
  return { token: value.token, credential, rotatedOut };
}

const AGENT_BASE = '/api/v1/admin/agents';

export class AgentsApi {
  readonly #account: AccountApi;

  constructor(account: AccountApi) {
    this.#account = account;
  }

  list(): Promise<ApiResult<AgentMeta[]>> {
    return this.#account.read(AGENT_BASE, decodeAgents);
  }

  issue(agentId: string): Promise<ApiResult<IssuedToken>> {
    const id = safeSegment(agentId);
    if (id === null) return Promise.resolve({ ok: false, status: 400, code: 'invalid_request' });
    return this.#account.request(`${AGENT_BASE}/${id}/credentials`, { body: {}, decode: decodeIssued });
  }

  rotate(agentId: string): Promise<ApiResult<IssuedToken>> {
    const id = safeSegment(agentId);
    if (id === null) return Promise.resolve({ ok: false, status: 400, code: 'invalid_request' });
    return this.#account.request(`${AGENT_BASE}/${id}/credentials/rotate`, { body: {}, decode: decodeIssued });
  }

  revoke(agentId: string, credentialId: string): Promise<ApiResult<null>> {
    const agent = safeSegment(agentId);
    const credential = safeSegment(credentialId);
    if (agent === null || credential === null) return Promise.resolve({ ok: false, status: 400, code: 'invalid_request' });
    return this.#account.request(`${AGENT_BASE}/${agent}/credentials/${credential}/revoke`, { body: {} });
  }
}
