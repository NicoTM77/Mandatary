import type { AgentsData, GroupsData, InventoryRow, RuleRow, RulesData, SubjectOption, UserRow } from '../screens/policy/contract';
import { EMPTY_SELECTOR } from '../screens/policy/selector';

/**
 * Synthetic data for the P1.17 gallery and presentational tests ONLY. Every name starts with "sample-", every image and
 * address uses the reserved .invalid domain, and every id is a short label, never a real UUID or container id. Nothing here
 * is, or may be replaced with, a real account, token or container.
 */
const HEX_A = 'a1'.repeat(32);
const HEX_B = 'b2'.repeat(32);

export const POLICY_FIXTURE = {
  hexId: HEX_A,
  digest: `sha256:${HEX_B}`,
} as const;

export const subjects: readonly SubjectOption[] = [
  { kind: 'user', id: 'u-admin', name: 'sample-admin', state: 'active', administrator: true },
  { kind: 'user', id: 'u-sam', name: 'sample-sam', state: 'active' },
  { kind: 'user', id: 'u-robin', name: 'sample-robin', state: 'disabled' },
  { kind: 'group', id: 'g-ops', name: 'sample-ops', state: 'active' },
  { kind: 'group', id: 'g-contractors', name: 'sample-contractors', state: 'active' },
  { kind: 'agent', id: 'a-ci', name: 'sample-ci-runner', state: 'active' },
  { kind: 'agent', id: 'a-billing', name: 'sample-billing-bot', state: 'active' },
];

const subject = (kind: SubjectOption['kind'], id: string): SubjectOption => {
  const found = subjects.find((candidate) => candidate.kind === kind && candidate.id === id);
  if (!found) throw new Error(`fixture subject ${kind}:${id}`);
  return found;
};

export const users: readonly UserRow[] = [
  { id: 'u-admin', username: 'sample-admin', state: 'active', administrator: true, groups: [], ownedAgents: [], ruleCount: 1, removal: { allowed: false, blockers: ['is the policy administrator'] } },
  { id: 'u-sam', username: 'sample-sam', state: 'active', administrator: false, groups: ['sample-ops'], ownedAgents: ['sample-ci-runner'], ruleCount: 2, removal: { allowed: false, blockers: ['owns agent sample-ci-runner', 'has 2 rules', 'belongs to sample-ops'] } },
  { id: 'u-robin', username: 'sample-robin', state: 'disabled', administrator: false, groups: ['sample-contractors'], ownedAgents: [], ruleCount: 0, removal: { allowed: false, blockers: ['belongs to sample-contractors'] } },
  { id: 'u-fresh', username: 'sample-fresh', state: 'active', administrator: false, groups: [], ownedAgents: [], ruleCount: 0, removal: { allowed: true } },
  { id: 'u-restored', username: 'sample-restored', state: 'quarantined', administrator: false, groups: [], ownedAgents: [], ruleCount: 1, removal: { allowed: true } },
];

export const groups: GroupsData = {
  groups: [
    {
      id: 'g-ops',
      name: 'sample-ops',
      state: 'active',
      members: [
        { kind: 'user', id: 'u-sam', name: 'sample-sam', state: 'active', membership: 'active' },
        { kind: 'agent', id: 'a-ci', name: 'sample-ci-runner', state: 'active', membership: 'active' },
        { kind: 'user', id: 'u-restored', name: 'sample-restored', state: 'quarantined', membership: 'quarantined' },
      ],
      ownedAgents: ['sample-billing-bot'],
      ruleCount: 1,
      removal: { allowed: false, blockers: ['has 3 members', 'owns agent sample-billing-bot', 'has 1 rule'] },
    },
    {
      id: 'g-contractors',
      name: 'sample-contractors',
      state: 'disabled',
      members: [{ kind: 'user', id: 'u-robin', name: 'sample-robin', state: 'disabled', membership: 'active' }],
      ownedAgents: [],
      ruleCount: 1,
      removal: { allowed: false, blockers: ['has 1 member', 'has 1 rule'] },
    },
    { id: 'g-empty', name: 'sample-empty', state: 'active', members: [], ownedAgents: [], ruleCount: 0, removal: { allowed: true } },
  ],
  candidates: {
    users: [
      { id: 'u-admin', name: 'sample-admin', state: 'active' },
      { id: 'u-sam', name: 'sample-sam', state: 'active' },
      { id: 'u-robin', name: 'sample-robin', state: 'disabled' },
      { id: 'u-fresh', name: 'sample-fresh', state: 'active' },
    ],
    agents: [
      { id: 'a-ci', name: 'sample-ci-runner', state: 'active' },
      { id: 'a-billing', name: 'sample-billing-bot', state: 'active' },
    ],
  },
};

export const agents: AgentsData = {
  agents: [
    { id: 'a-ci', name: 'sample-ci-runner', state: 'active', owner: { kind: 'user', id: 'u-sam', name: 'sample-sam', state: 'active' }, groups: ['sample-ops'], liveTokens: 1, ruleCount: 2, removal: { allowed: false, blockers: ['has 1 live token', 'has 2 rules'] } },
    { id: 'a-billing', name: 'sample-billing-bot', state: 'active', owner: { kind: 'group', id: 'g-ops', name: 'sample-ops', state: 'active' }, groups: [], liveTokens: 0, ruleCount: 1, removal: { allowed: false, blockers: ['has 1 rule'] } },
    { id: 'a-retired', name: 'sample-retired', state: 'disabled', owner: { kind: 'user', id: 'u-robin', name: 'sample-robin', state: 'disabled' }, groups: [], liveTokens: 0, ruleCount: 0, removal: { allowed: true } },
  ],
  owners: {
    users: [
      { id: 'u-admin', name: 'sample-admin', state: 'active' },
      { id: 'u-sam', name: 'sample-sam', state: 'active' },
      { id: 'u-robin', name: 'sample-robin', state: 'disabled' },
    ],
    groups: [
      { id: 'g-ops', name: 'sample-ops', state: 'active' },
      { id: 'g-contractors', name: 'sample-contractors', state: 'disabled' },
    ],
  },
};

export const inventory: readonly InventoryRow[] = [
  { name: 'sample-edge-proxy', shortId: 'a1a1a1a1a1a1', image: 'registry.example.invalid/sample/edge:1.4', running: true, composeProject: 'sample-shop', composeService: 'edge' },
  { name: 'sample-billing-worker', shortId: 'c3c3c3c3c3c3', image: 'registry.example.invalid/sample/billing:2.0', running: true, composeProject: 'sample-shop', composeService: 'billing' },
  { name: 'sample-db', shortId: 'd4d4d4d4d4d4', image: 'registry.example.invalid/sample/db:16', running: false },
];

export const rules: readonly RuleRow[] = [
  {
    id: 'r1',
    subject: subject('agent', 'a-ci'),
    effect: 'allow',
    operation: 'container:logs',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy', composeProject: 'sample-shop', composeService: 'edge' },
    limits: { logTailMax: 500, stopTimeoutMax: null },
    state: 'active',
    target: { kind: 'present', matches: 1 },
  },
  {
    id: 'r2',
    subject: subject('group', 'g-ops'),
    effect: 'allow',
    operation: 'container:inspect_status',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-*', nameIsPattern: true, imagePattern: 'registry.example.invalid/sample/*' },
    limits: { logTailMax: null, stopTimeoutMax: null },
    state: 'active',
    target: { kind: 'present', matches: 3 },
  },
  {
    id: 'r3',
    subject: subject('agent', 'a-ci'),
    effect: 'allow',
    operation: 'container:restart',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy', composeProject: 'sample-shop', composeService: 'edge' },
    limits: { logTailMax: null, stopTimeoutMax: 30 },
    state: 'active',
    target: { kind: 'present', matches: 1 },
  },
  {
    id: 'r4',
    subject: subject('group', 'g-contractors'),
    effect: 'deny',
    operation: 'container:stop',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-db*', nameIsPattern: true },
    limits: { logTailMax: null, stopTimeoutMax: null },
    state: 'active',
    target: { kind: 'present', matches: 1 },
  },
  {
    id: 'r5',
    subject: subject('agent', 'a-billing'),
    effect: 'allow',
    operation: 'container:logs',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-old-worker', composeProject: 'sample-shop', composeService: 'old-worker' },
    limits: { logTailMax: 200, stopTimeoutMax: null },
    state: 'active',
    target: { kind: 'missing' },
  },
  {
    id: 'r6',
    subject: subject('user', 'u-sam'),
    effect: 'allow',
    operation: 'container:inspect_config',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy', pinnedContainerId: HEX_A, pinnedImageDigest: `sha256:${HEX_B}` },
    limits: { logTailMax: null, stopTimeoutMax: null },
    state: 'disabled',
    target: { kind: 'present', matches: 1 },
  },
  {
    id: 'r7',
    subject: subject('user', 'u-admin'),
    effect: 'allow',
    operation: 'container:inspect_status',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy', imagePattern: 'registry.example.invalid/sample/edge:*' },
    limits: { logTailMax: null, stopTimeoutMax: null },
    state: 'active',
    target: { kind: 'present', matches: 1 },
  },
  {
    id: 'r8',
    subject: { kind: 'user', id: 'u-restored', name: 'sample-restored', state: 'quarantined' },
    effect: 'allow',
    operation: 'container:start',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-db' },
    limits: { logTailMax: null, stopTimeoutMax: null },
    state: 'quarantined',
    target: { kind: 'unknown' },
  },
  {
    id: 'r9',
    subject: subject('group', 'g-ops'),
    effect: 'allow',
    operation: 'container:start',
    selector: { ...EMPTY_SELECTOR, containerName: 'sample-*', nameIsPattern: true },
    limits: { logTailMax: null, stopTimeoutMax: null },
    state: 'active',
    target: { kind: 'present', matches: 3 },
  },
];

export const rulesData: RulesData = {
  rules,
  subjects,
  endpoint: { name: 'Local (Docker socket on this host)', safety: 'verified' },
  inventory,
};

export const rulesDataUnverified: RulesData = {
  ...rulesData,
  rules: rules.map((rule) => ({ ...rule, target: { kind: 'unknown' } })),
  endpoint: { name: 'Local (Docker socket on this host)', safety: 'unverified' },
  inventory: null,
};

export const rulesDataEmpty: RulesData = { ...rulesData, rules: [] };
