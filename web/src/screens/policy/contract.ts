/**
 * Presentation contract for the P1.17 management screens (P1.17.1): users, groups, agents and policy rules.
 *
 * Same rules as the P1.16 contract (src/screens/contract.ts): every screen is a STATELESS function of
 * (`load`, `mutation`, data, callbacks). The containers written in P1.17.2 own fetching, CSRF, step-up,
 * timers, routing and every security decision, and translate HTTP outcomes into these states with the table in
 * docs/ui/p1.17-policy-management-ux-contract.md §6. A screen never calls `fetch`, touches storage, interprets a
 * status code, or decides whether anything is permitted.
 *
 * Authority: nothing in this file grants, evaluates or enforces anything. A button that is shown, hidden or
 * disabled is presentation; the server refuses every request that is not authorised, whatever the page showed.
 * Policy-administration authority and Docker operation permission are different things: the administrator role
 * grants NO container operation, owning an agent grants NO access, and a rule is the only thing that does.
 *
 * Secrets: none of these screens handles a secret. Agent tokens are revealed by the P1.16 Agents page
 * (src/containers/AgentsContainer.tsx + <SecretReveal>) and only there; this contract deliberately has no token
 * field, so a token cannot reach a management screen by accident.
 */
import type { CapName, Effect, Operation, SelectorDraft, SubjectKind } from './selector';

export type { CapName, Effect, Operation, SelectorDraft, SubjectKind };

// ───────────────────────── shared ─────────────────────────

/**
 * What the container knows about the list. `denied` is the ONE outcome for "not the policy administrator",
 * "no second factor" and "authority changed": the server does not distinguish them to the caller, so neither may
 * the page. `failed` is any other failure (never rendered as an empty list). A 401 never reaches a screen: the
 * signed-in frame shows "Your session ended".
 */
export type Load<T> = { kind: 'loading' } | { kind: 'ready'; data: T } | { kind: 'failed' } | { kind: 'denied' };

export type AccountState = 'active' | 'disabled' | 'quarantined';

/**
 * Outcome of the most recent command. `target` names what it was about: a row id, `create` (the create form) or
 * `editor` (the rule editor); an outcome without a target belongs to the page. A screen shows an outcome only
 * where its target is. `step_up_required` is NOT a reason: the container opens the P1.16 StepUpGate in place and
 * leaves the form as it was (the blocked request is not replayed, so the person presses the button again).
 */
export type MutationReason =
  | 'denied'
  | 'not_found'
  | 'conflict'
  | 'invalid'
  /**
   * HTTP 503 on a mutation. The service reports a failed policy notification AFTER a durable commit as the same
   * `unavailable`, so a 503 never proves the change did not happen. The page says so and asks for a reload.
   */
  | 'outcome_unknown'
  | 'rate_limited';

export type Mutation =
  | { kind: 'idle' }
  | { kind: 'working'; target?: string }
  /** `message` is a plain sentence the container builds from names it already shows ("Added ci-runner to ops."). */
  | { kind: 'done'; message: string; target?: string }
  | { kind: 'rejected'; reason: MutationReason; target?: string };

/** The set of lifecycle actions on an account-like thing. */
export type LifecycleAction = 'disable' | 'enable' | 'delete';

export interface PendingAction {
  action: LifecycleAction;
  id: string;
}

/**
 * Whether a thing can be deleted, decided by the SERVER and sent as data. Deletion is refused while anything still
 * refers to it (owned agents, rules, memberships: the schema is ON DELETE RESTRICT); `blockers` are short plain
 * phrases naming what, so a disabled Delete button can say why. Never computed from what the page happens to show.
 */
export type Removal = { allowed: true } | { allowed: false; blockers: readonly string[] };

/**
 * Lifecycle actions the backend actually supports. An action that is not listed is not rendered at all (D-NAV-1:
 * never offer a control for something that does not exist). Anything listed must work end to end.
 */
export type SupportedActions = readonly LifecycleAction[];

export interface SubjectRef {
  kind: SubjectKind;
  id: string;
}

/** Where "Rules for this …" leads. The container decides the URL; the screen only renders a link. */
export type RulesHref = (subject: SubjectRef) => string;

// ───────────────────────── users ─────────────────────────

export interface UserRow {
  id: string;
  username: string;
  state: AccountState;
  /** True for the single policy administrator. Shown as authority, never as a container permission. */
  administrator: boolean;
  /** Names of groups this user is an active member of. */
  groups: readonly string[];
  /** Names of agents this user owns (accountability only). */
  ownedAgents: readonly string[];
  /** Rules that name this user directly (not through a group). */
  ruleCount: number;
  removal: Removal;
}

export interface UsersScreenProps {
  load: Load<readonly UserRow[]>;
  mutation: Mutation;
  pending: PendingAction | null;
  actions: SupportedActions;
  rulesHref?: RulesHref;
  onRetry: () => void;
  onCreate: (values: { username: string }) => void;
  onAsk: (action: LifecycleAction, id: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}

// ───────────────────────── groups ─────────────────────────

export interface MemberRow {
  kind: 'user' | 'agent';
  id: string;
  name: string;
  /** State of the user/agent itself. */
  state: AccountState;
  /** State of the membership. `quarantined` memberships came from a restore and grant nothing until approved. */
  membership: AccountState;
}

export interface GroupRow {
  id: string;
  name: string;
  state: AccountState;
  members: readonly MemberRow[];
  /** Names of agents this group owns (accountability only). */
  ownedAgents: readonly string[];
  ruleCount: number;
  removal: Removal;
}

export interface NamedAccount {
  id: string;
  name: string;
  state: AccountState;
}

export interface GroupsData {
  groups: readonly GroupRow[];
  /** Everyone who could be added; the screen removes people who are already members of the group in question. */
  candidates: { users: readonly NamedAccount[]; agents: readonly NamedAccount[] };
}

export type PendingGroupAction = PendingAction | { action: 'remove_member'; id: string; kind: 'user' | 'agent'; memberId: string };

export interface GroupsScreenProps {
  load: Load<GroupsData>;
  mutation: Mutation;
  pending: PendingGroupAction | null;
  actions: SupportedActions;
  rulesHref?: RulesHref;
  onRetry: () => void;
  onCreate: (values: { name: string }) => void;
  onAddMember: (values: { groupId: string; kind: 'user' | 'agent'; memberId: string }) => void;
  onAskRemoveMember: (groupId: string, kind: 'user' | 'agent', memberId: string) => void;
  onAsk: (action: LifecycleAction, id: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}

// ───────────────────────── agents (identity, not credentials) ─────────────────────────

/** Exactly one owner, a user XOR a group (enforced by the service and by SQLite; the form can only express one). */
export interface OwnerRef {
  kind: 'user' | 'group';
  id: string;
}

export interface AgentRow {
  id: string;
  name: string;
  state: AccountState;
  owner: { kind: 'user' | 'group'; id: string; name: string; state: AccountState };
  /** Names of groups the agent is an active member of. */
  groups: readonly string[];
  /** Tokens the agent can authenticate with right now. The tokens themselves are never here. */
  liveTokens: number;
  ruleCount: number;
  removal: Removal;
}

export interface AgentsData {
  agents: readonly AgentRow[];
  owners: { users: readonly NamedAccount[]; groups: readonly NamedAccount[] };
}

export type AgentAction = LifecycleAction | 'transfer';

export interface PendingAgentAction {
  action: AgentAction;
  id: string;
}

export interface AgentsScreenProps {
  load: Load<AgentsData>;
  mutation: Mutation;
  pending: PendingAgentAction | null;
  actions: readonly AgentAction[];
  rulesHref?: RulesHref;
  /** The P1.16 Agents page, where tokens are issued, rotated and revealed once. Never reimplemented here. */
  credentialsHref: (agentId: string) => string;
  onRetry: () => void;
  onCreate: (values: { name: string; owner: OwnerRef }) => void;
  onTransferOwner: (values: { agentId: string; owner: OwnerRef }) => void;
  onAsk: (action: AgentAction, id: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}

// ───────────────────────── rules ─────────────────────────

export interface SubjectOption {
  kind: SubjectKind;
  id: string;
  name: string;
  state: AccountState;
  /** The policy administrator. Offered like anyone else: the role grants nothing, so a rule is the only way to give it access. */
  administrator?: boolean;
}

/**
 * Whether a rule's selector currently matches anything. Decided by the server from the endpoint's container list
 * (Authorizer.InspectEndpointPolicyTargets): `missing` is "Inactive / Target missing" (TD §7.2); `unknown` means the
 * endpoint cannot currently be inspected (backend not verified) and is NEVER shown as present.
 */
export type TargetStatus = { kind: 'present'; matches: number } | { kind: 'missing' } | { kind: 'unknown' };

/** `quarantined` = imported by a restore and waiting for explicit approval (P1.18); it grants nothing. */
export type RuleState = 'active' | 'disabled' | 'quarantined';

export interface RuleRow {
  id: string;
  subject: SubjectOption;
  effect: Effect;
  operation: Operation;
  selector: SelectorDraft;
  limits: { logTailMax: number | null; stopTimeoutMax: number | null };
  state: RuleState;
  target: TargetStatus;
}

export interface InventoryRow {
  /** Container name without a leading slash. Mandatary itself and its peers are never listed. */
  name: string;
  /** First 12 hex characters of the container id. */
  shortId: string;
  image: string;
  running: boolean;
  composeProject?: string;
  composeService?: string;
}

/** `unverified`: Mandatary cannot currently prove which container is itself, so it refuses every operation (SELF-01). */
export interface EndpointView {
  name: string;
  safety: 'verified' | 'unverified';
}

export interface RulesData {
  rules: readonly RuleRow[];
  subjects: readonly SubjectOption[];
  endpoint: EndpointView;
  /** For "start from a running container". Null when the endpoint cannot be listed. */
  inventory: readonly InventoryRow[] | null;
}

export type PreviewState =
  | { kind: 'idle' }
  | { kind: 'checking' }
  /** `forKey` is selectorKey() of the selector that was checked; the screen marks the result stale once the fields differ. */
  | { kind: 'ready'; forKey: string; matches: readonly InventoryRow[] }
  /** The endpoint cannot be inspected right now. The rule can still be saved; it just can't be previewed. */
  | { kind: 'unavailable' };

export interface RuleDraft {
  subject: SubjectRef;
  effect: Effect;
  /** One rule is stored per operation. Editing an existing rule has exactly one. The server must apply all or none. */
  operations: readonly Operation[];
  selector: SelectorDraft;
  caps: Record<CapName, number | null>;
  /** True only when the person ticked the box shown for a broad Allow. The server does not trust it. */
  acknowledgedBroad: boolean;
}

export type RuleEditorState = { kind: 'closed' } | { kind: 'create'; initial?: Partial<Pick<RuleDraft, 'subject' | 'effect'>> } | { kind: 'edit'; id: string };

export interface RulesScreenProps {
  load: Load<RulesData>;
  mutation: Mutation;
  editor: RuleEditorState;
  pending: PendingAction | null;
  preview: PreviewState;
  onRetry: () => void;
  onNew: () => void;
  onEdit: (id: string) => void;
  onCloseEditor: () => void;
  /** `editingId` is null when creating. Called once, at submit, with every field the server needs. */
  onSubmit: (draft: RuleDraft, editingId: string | null) => void;
  onPreview: (selector: SelectorDraft) => void;
  onAsk: (action: LifecycleAction, id: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
  /** Show only the rules that name this subject directly (by kind and immutable id). Set from the `#subject=` link; absent shows every rule. */
  subjectFilter?: SubjectRef | null;
  /** Leave the subject filter and show every rule again. */
  onClearSubjectFilter?: () => void;
}
