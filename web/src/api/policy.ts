import type { AgentRow, AgentsData, GroupRow, GroupsData, InventoryRow, MemberRow, NamedAccount, OwnerRef, Removal, RuleDraft, RuleRow, RulesData, SubjectOption, TargetStatus, UserRow, AccountState, RuleState } from '../screens/policy/contract';
import type { Effect, Operation, SelectorDraft, SubjectKind } from '../screens/policy/selector';
import { OPERATIONS } from '../screens/policy/selector';
import type { AccountApi } from './account';
import { isRecord, type ApiResult } from './http';
import { safeSegment } from './security';

/**
 * Policy-administration API client (`internal/auth/policy_admin_http.go`, `agents_http.go`). Every path is a constant of
 * this module; the only dynamic segments are server-issued identifiers that must match a strict pattern before they are
 * used (`safeSegment`). The CSRF token lives inside AccountApi. Nothing here holds, logs or stores a response: the
 * containers keep the decoded data in component state only.
 *
 * Decoders fail closed: a body that is not exactly the documented shape is `invalid_response` (the page then says it
 * could not load, never an empty list). The server is the authority for every value; nothing here validates policy.
 */

const BASE = '/api/v1/admin';
const POLICY = `${BASE}/policy`;

const ACCOUNT_STATES: readonly string[] = ['active', 'disabled', 'quarantined'];
const OPERATION_KEYS: readonly string[] = OPERATIONS.map((operation) => operation.key);

function isState(value: unknown): value is AccountState {
  return typeof value === 'string' && ACCOUNT_STATES.includes(value);
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function strings(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const item of value as unknown[]) {
    if (typeof item !== 'string') return null;
    out.push(item);
  }
  return out;
}

function list<T>(value: unknown, row: (item: Record<string, unknown>) => T | null): T[] | null {
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

function decodeRemoval(value: unknown): Removal | null {
  if (!isRecord(value) || typeof value.allowed !== 'boolean') return null;
  if (value.allowed) return { allowed: true };
  const blockers = strings(value.blockers);
  return blockers === null ? null : { allowed: false, blockers };
}

function named(row: Record<string, unknown>): NamedAccount | null {
  return typeof row.id === 'string' && typeof row.name === 'string' && isState(row.state) ? { id: row.id, name: row.name, state: row.state } : null;
}

// ───────────────────────── users ─────────────────────────

function decodeUsers(value: unknown): UserRow[] | null {
  if (!isRecord(value)) return null;
  return list(value.users, (row) => {
    const groups = strings(row.groups);
    const owned = strings(row.owned_agents);
    const removal = decodeRemoval(row.removal);
    if (typeof row.id !== 'string' || typeof row.username !== 'string' || !isState(row.state) || typeof row.administrator !== 'boolean' || groups === null || owned === null || !isCount(row.rule_count) || removal === null) return null;
    return { id: row.id, username: row.username, state: row.state, administrator: row.administrator, groups, ownedAgents: owned, ruleCount: row.rule_count, removal };
  });
}

// ───────────────────────── groups ─────────────────────────

function decodeMember(row: Record<string, unknown>): MemberRow | null {
  if ((row.kind !== 'user' && row.kind !== 'agent') || typeof row.id !== 'string' || typeof row.name !== 'string' || !isState(row.state) || !isState(row.membership)) return null;
  return { kind: row.kind, id: row.id, name: row.name, state: row.state, membership: row.membership };
}

function decodeGroups(value: unknown): GroupsData | null {
  if (!isRecord(value) || !isRecord(value.candidates)) return null;
  const groups = list<GroupRow>(value.groups, (row) => {
    const members = list(row.members, decodeMember);
    const owned = strings(row.owned_agents);
    const removal = decodeRemoval(row.removal);
    if (typeof row.id !== 'string' || typeof row.name !== 'string' || !isState(row.state) || members === null || owned === null || !isCount(row.rule_count) || removal === null) return null;
    return { id: row.id, name: row.name, state: row.state, members, ownedAgents: owned, ruleCount: row.rule_count, removal };
  });
  const users = list(value.candidates.users, named);
  const agents = list(value.candidates.agents, named);
  return groups === null || users === null || agents === null ? null : { groups, candidates: { users, agents } };
}

// ───────────────────────── agents ─────────────────────────

function decodeAgents(value: unknown): AgentsData | null {
  if (!isRecord(value) || !isRecord(value.owners)) return null;
  const agents = list<AgentRow>(value.agents, (row) => {
    const groups = strings(row.groups);
    const removal = decodeRemoval(row.removal);
    const owner = row.owner;
    if (
      typeof row.id !== 'string' ||
      typeof row.name !== 'string' ||
      !isState(row.state) ||
      groups === null ||
      !isCount(row.live_tokens) ||
      !isCount(row.rule_count) ||
      removal === null ||
      !isRecord(owner) ||
      (owner.kind !== 'user' && owner.kind !== 'group') ||
      typeof owner.id !== 'string' ||
      typeof owner.name !== 'string' ||
      !isState(owner.state)
    ) {
      return null;
    }
    return { id: row.id, name: row.name, state: row.state, owner: { kind: owner.kind, id: owner.id, name: owner.name, state: owner.state }, groups, liveTokens: row.live_tokens, ruleCount: row.rule_count, removal };
  });
  const users = list(value.owners.users, named);
  const groups = list(value.owners.groups, named);
  return agents === null || users === null || groups === null ? null : { agents, owners: { users, groups } };
}

// ───────────────────────── rules ─────────────────────────

function decodeSubject(row: Record<string, unknown>): SubjectOption | null {
  if ((row.kind !== 'user' && row.kind !== 'group' && row.kind !== 'agent') || typeof row.id !== 'string' || typeof row.name !== 'string' || !isState(row.state)) return null;
  const subject: SubjectOption = { kind: row.kind, id: row.id, name: row.name, state: row.state };
  if (row.administrator === true) subject.administrator = true;
  return subject;
}

function optionalText(value: unknown): string | null {
  if (value === undefined || value === null) return '';
  return typeof value === 'string' ? value : null;
}

function decodeSelector(value: unknown): SelectorDraft | null {
  if (!isRecord(value) || typeof value.container_name !== 'string' || typeof value.name_is_glob !== 'boolean') return null;
  const project = optionalText(value.compose_project);
  const service = optionalText(value.compose_service);
  const image = optionalText(value.image_pattern);
  const pinnedId = optionalText(value.pinned_container_id);
  const digest = optionalText(value.pinned_image_digest);
  if (project === null || service === null || image === null || pinnedId === null || digest === null) return null;
  return { containerName: value.container_name, nameIsPattern: value.name_is_glob, composeProject: project, composeService: service, imagePattern: image, pinnedContainerId: pinnedId, pinnedImageDigest: digest };
}

function decodeTarget(value: unknown): TargetStatus | null {
  if (!isRecord(value)) return null;
  if (value.status === 'present' && isCount(value.matches)) return { kind: 'present', matches: value.matches };
  if (value.status === 'missing') return { kind: 'missing' };
  if (value.status === 'unknown') return { kind: 'unknown' };
  return null;
}

function cap(value: unknown): number | null | undefined {
  if (value === null || value === undefined) return null;
  return isCount(value) ? value : undefined;
}

function decodeRule(row: Record<string, unknown>): RuleRow | null {
  const subject = isRecord(row.subject) ? decodeSubject(row.subject) : null;
  const selector = decodeSelector(row.selector);
  const target = decodeTarget(row.target);
  const tail = cap(row.log_tail_max);
  const timeout = cap(row.stop_timeout_max);
  const effect: Effect | null = row.effect === 'ALLOW' ? 'allow' : row.effect === 'DENY' ? 'deny' : null;
  const state: RuleState | null = isState(row.state) ? row.state : null;
  if (typeof row.id !== 'string' || subject === null || selector === null || target === null || tail === undefined || timeout === undefined || effect === null || state === null) return null;
  if (typeof row.operation !== 'string' || !OPERATION_KEYS.includes(row.operation)) return null;
  return { id: row.id, subject, effect, operation: row.operation as Operation, selector, limits: { logTailMax: tail, stopTimeoutMax: timeout }, state, target };
}

function decodeInventoryRow(row: Record<string, unknown>): InventoryRow | null {
  const project = optionalText(row.compose_project);
  const service = optionalText(row.compose_service);
  if (typeof row.name !== 'string' || typeof row.short_id !== 'string' || typeof row.image !== 'string' || typeof row.running !== 'boolean' || project === null || service === null) return null;
  const out: InventoryRow = { name: row.name, shortId: row.short_id, image: row.image, running: row.running };
  if (project !== '') out.composeProject = project;
  if (service !== '') out.composeService = service;
  return out;
}

function decodeRules(value: unknown): RulesData | null {
  if (!isRecord(value) || !isRecord(value.endpoint)) return null;
  const rules = list(value.rules, decodeRule);
  const subjects = list(value.subjects, decodeSubject);
  const inventory = value.inventory === null || value.inventory === undefined ? null : list(value.inventory, decodeInventoryRow);
  const { name, safety } = value.endpoint;
  if (rules === null || subjects === null || typeof name !== 'string' || (safety !== 'verified' && safety !== 'unverified')) return null;
  if (value.inventory !== null && value.inventory !== undefined && inventory === null) return null;
  return { rules, subjects, endpoint: { name, safety }, inventory };
}

export type PreviewResult = { available: false } | { available: true; matches: InventoryRow[] };

function decodePreview(value: unknown): PreviewResult | null {
  if (!isRecord(value) || typeof value.available !== 'boolean') return null;
  if (!value.available) return { available: false };
  const matches = list(value.matches, decodeInventoryRow);
  return matches === null ? null : { available: true, matches };
}

// ───────────────────────── requests ─────────────────────────

function selectorBody(selector: SelectorDraft): Record<string, unknown> {
  const body: Record<string, unknown> = { container_name: selector.containerName, name_is_glob: selector.nameIsPattern };
  if (selector.composeProject !== '') body.compose_project = selector.composeProject;
  if (selector.composeService !== '') body.compose_service = selector.composeService;
  if (selector.imagePattern !== '') body.image_pattern = selector.imagePattern;
  if (selector.pinnedContainerId !== '') body.pinned_container_id = selector.pinnedContainerId;
  if (selector.pinnedImageDigest !== '') body.pinned_image_digest = selector.pinnedImageDigest;
  return body;
}

function invalid<T>(): Promise<ApiResult<T>> {
  return Promise.resolve({ ok: false, status: 400, code: 'invalid_request' });
}

export class PolicyApi {
  readonly #account: AccountApi;

  constructor(account: AccountApi) {
    this.#account = account;
  }

  users(): Promise<ApiResult<UserRow[]>> {
    return this.#account.read(`${POLICY}/users`, decodeUsers);
  }

  groups(): Promise<ApiResult<GroupsData>> {
    return this.#account.read(`${POLICY}/groups`, decodeGroups);
  }

  agents(): Promise<ApiResult<AgentsData>> {
    return this.#account.read(`${POLICY}/agents`, decodeAgents);
  }

  rules(): Promise<ApiResult<RulesData>> {
    return this.#account.read(`${POLICY}/rules`, decodeRules);
  }

  preview(selector: SelectorDraft): Promise<ApiResult<PreviewResult>> {
    return this.#account.request(`${POLICY}/rules/preview`, { body: { selector: selectorBody(selector) }, decode: decodePreview });
  }

  // identities ----------------------------------------------------------------

  createUser(username: string): Promise<ApiResult<null>> {
    return this.#account.request(`${BASE}/users`, { body: { username } });
  }

  userLifecycle(id: string, action: 'disable' | 'enable'): Promise<ApiResult<null>> {
    const user = safeSegment(id);
    return user === null ? invalid() : this.#account.request(`${BASE}/users/${user}/${action}`, { body: {} });
  }

  createGroup(name: string): Promise<ApiResult<null>> {
    return this.#account.request(`${BASE}/groups`, { body: { name } });
  }

  groupLifecycle(id: string, action: 'disable' | 'enable'): Promise<ApiResult<null>> {
    const group = safeSegment(id);
    return group === null ? invalid() : this.#account.request(`${BASE}/groups/${group}/${action}`, { body: {} });
  }

  deleteGroup(id: string): Promise<ApiResult<null>> {
    const group = safeSegment(id);
    return group === null ? invalid() : this.#account.request(`${BASE}/groups/${group}`, { method: 'DELETE' });
  }

  addMember(groupId: string, kind: 'user' | 'agent', memberId: string): Promise<ApiResult<null>> {
    const group = safeSegment(groupId);
    const member = safeSegment(memberId);
    return group === null || member === null ? invalid() : this.#account.request(`${BASE}/groups/${group}/members/${kind}/${member}`, { method: 'PUT' });
  }

  removeMember(groupId: string, kind: 'user' | 'agent', memberId: string): Promise<ApiResult<null>> {
    const group = safeSegment(groupId);
    const member = safeSegment(memberId);
    return group === null || member === null ? invalid() : this.#account.request(`${BASE}/groups/${group}/members/${kind}/${member}`, { method: 'DELETE' });
  }

  createAgent(name: string, owner: OwnerRef): Promise<ApiResult<null>> {
    return this.#account.request(`${BASE}/agents`, { body: owner.kind === 'user' ? { name, owner_user_id: owner.id } : { name, owner_group_id: owner.id } });
  }

  agentLifecycle(id: string, action: 'disable' | 'enable'): Promise<ApiResult<null>> {
    const agent = safeSegment(id);
    return agent === null ? invalid() : this.#account.request(`${BASE}/agents/${agent}/${action}`, { body: {} });
  }

  transferAgent(id: string, owner: OwnerRef): Promise<ApiResult<null>> {
    const agent = safeSegment(id);
    return agent === null ? invalid() : this.#account.request(`${BASE}/agents/${agent}/owner`, { method: 'PUT', body: owner.kind === 'user' ? { owner_user_id: owner.id } : { owner_group_id: owner.id } });
  }

  // rules ---------------------------------------------------------------------

  createRules(draft: RuleDraft): Promise<ApiResult<null>> {
    return this.#account.request(`${POLICY}/rules`, {
      body: {
        subject: { kind: draft.subject.kind satisfies SubjectKind, id: draft.subject.id },
        effect: draft.effect === 'allow' ? 'ALLOW' : 'DENY',
        operations: draft.operations,
        selector: selectorBody(draft.selector),
        log_tail_max: draft.caps.logTailMax,
        stop_timeout_max: draft.caps.stopTimeoutMax,
      },
    });
  }

  updateRule(id: string, draft: RuleDraft): Promise<ApiResult<null>> {
    const rule = safeSegment(id);
    if (rule === null) return invalid();
    return this.#account.request(`${POLICY}/rules/${rule}`, {
      method: 'PUT',
      body: { effect: draft.effect === 'allow' ? 'ALLOW' : 'DENY', selector: selectorBody(draft.selector), log_tail_max: draft.caps.logTailMax, stop_timeout_max: draft.caps.stopTimeoutMax },
    });
  }

  ruleLifecycle(id: string, action: 'enable' | 'disable'): Promise<ApiResult<null>> {
    const rule = safeSegment(id);
    return rule === null ? invalid() : this.#account.request(`${POLICY}/rules/${rule}/${action}`, { body: {} });
  }

  deleteRule(id: string): Promise<ApiResult<null>> {
    const rule = safeSegment(id);
    return rule === null ? invalid() : this.#account.request(`${POLICY}/rules/${rule}`, { method: 'DELETE' });
  }
}
