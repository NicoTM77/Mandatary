import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AccountApi } from '../api/account';
import type { ApiResult } from '../api/http';
import { PolicyApi } from '../api/policy';
import { SecurityApi } from '../api/security';
import { AgentsScreen } from '../screens/policy/agentIdentity';
import type { AgentAction, AgentsData, GroupsData, Load, LifecycleAction, Mutation, MutationReason, PendingAction, PendingAgentAction, PendingGroupAction, PreviewState, RuleDraft, RuleEditorState, RulesData, SelectorDraft, UserRow } from '../screens/policy/contract';
import { GroupsScreen } from '../screens/policy/groups';
import { AGENT_TOKENS_ROUTE } from '../screens/policy/nav';
import { RulesScreen } from '../screens/policy/rules';
import { selectorKey } from '../screens/policy/selector';
import { UsersScreen } from '../screens/policy/users';
import type { Navigate } from './LoginContainer';
import { outcomeOf } from './outcome';
import { SignedIn, type SignedInContext } from './SignedIn';
import { StepUpGate, useStepUp } from './StepUpGate';

/**
 * Policy administration (P1.17.2): Rules, Users, Groups and Agents over `/api/v1/admin/**`.
 *
 * The screens are stateless presentation (P1.17.1). These containers own fetching, the CSRF token (inside AccountApi),
 * step-up, and the mapping of HTTP outcomes to screen states (docs/ui/p1.17 §6). Every decision is the server's:
 * a hidden link, a disabled button or a successful-looking page never grants or protects anything, and the same
 * routes refuse anyone who is not the policy administrator signed in with a second factor, whatever this code sends.
 *
 * Nothing here handles a secret. A token is issued and revealed only on the Agent tokens page.
 */

// ───────────────────────── shared plumbing ─────────────────────────

/** Why a command was refused, as the screen's vocabulary (docs/ui §6). A 503 or a lost connection is never "nothing changed". */
export function reasonOf(result: ApiResult<unknown>): MutationReason {
  switch (result.status) {
    case 400:
    case 415:
    case 422:
      return 'invalid';
    case 403:
      return 'denied';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 429:
      return 'rate_limited';
    default:
      return 'outcome_unknown';
  }
}

/** A list that loads, reloads after every command, and ignores any response older than the latest request. */
function useManagedList<T>(fetcher: () => Promise<ApiResult<T>>, navigate: Navigate) {
  const [load, setLoad] = useState<Load<T>>({ kind: 'loading' });
  const latest = useRef(0);
  const fetchRef = useRef(fetcher);
  useEffect(() => {
    fetchRef.current = fetcher;
  });

  const refetch = useCallback(() => {
    const ticket = ++latest.current;
    void fetchRef.current().then((result) => {
      if (ticket !== latest.current) return;
      if (result.ok) setLoad({ kind: 'ready', data: result.data });
      else if (result.status === 401) navigate('/login');
      else if (result.status === 403) setLoad({ kind: 'denied' });
      else setLoad({ kind: 'failed' });
    });
  }, [navigate]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  return {
    load,
    refetch,
    retry: () => {
      setLoad({ kind: 'loading' });
      refetch();
    },
  };
}

/** Runs commands: working → done / rejected, step-up in place, and a refetch after anything that may have changed state. */
function useCommands(context: SignedInContext, refetch: () => void) {
  const { api, view, navigate, refresh } = context;
  const sec = useMemo(() => new SecurityApi(api), [api]);
  const [mutation, setMutation] = useState<Mutation>({ kind: 'idle' });
  const stepUp = useStepUp(sec, view, refresh, () => setMutation({ kind: 'idle' }));

  /**
   * Resolves true when the command succeeded. `label` names the action in the step-up panel. `removesRow` is for a
   * command that deletes the row it was about: its confirmation is shown for the page, because the row (and anything
   * shown under it) is gone as soon as the list is re-read.
   */
  async function run(target: string | undefined, label: string, call: () => Promise<ApiResult<unknown>>, message: string, removesRow = false): Promise<boolean> {
    setMutation(target === undefined ? { kind: 'working' } : { kind: 'working', target });
    const result = await call();
    const outcome = outcomeOf(result);
    if (outcome.kind === 'ok') {
      setMutation(target === undefined || removesRow ? { kind: 'done', message } : { kind: 'done', message, target });
      refetch();
      return true;
    }
    if (outcome.kind === 'ended') {
      navigate('/login');
      return false;
    }
    if (outcome.kind === 'step_up' || outcome.kind === 'assurance_unavailable') {
      // The blocked request is not replayed: the person verifies, then presses the button again.
      setMutation({ kind: 'idle' });
      stepUp.show(label, outcome.kind === 'assurance_unavailable');
      return false;
    }
    const reason = reasonOf(result);
    setMutation(target === undefined ? { kind: 'rejected', reason } : { kind: 'rejected', reason, target });
    if (reason === 'outcome_unknown' || reason === 'not_found' || reason === 'conflict') refetch();
    return false;
  }

  return { mutation, setMutation, run, gate: <StepUpGate controls={stepUp} view={view} /> };
}

function usePolicy(api: AccountApi): PolicyApi {
  return useMemo(() => new PolicyApi(api), [api]);
}

function verb(action: LifecycleAction): string {
  switch (action) {
    case 'disable':
      return 'Disabled';
    case 'enable':
      return 'Enabled';
    case 'delete':
      return 'Deleted';
  }
}

function actionLabel(action: string, noun: string): string {
  return `${action.charAt(0).toUpperCase()}${action.slice(1)} a ${noun}`;
}

// ───────────────────────── users ─────────────────────────

export function UsersContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="policy-users">
      {(context) => <UsersPage {...context} />}
    </SignedIn>
  );
}

function UsersPage(context: SignedInContext) {
  const policy = usePolicy(context.api);
  const { load, retry, refetch } = useManagedList(() => policy.users(), context.navigate);
  const commands = useCommands(context, refetch);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const rows: readonly UserRow[] = load.kind === 'ready' ? load.data : [];

  return (
    <>
      {commands.gate}
      <UsersScreen
        load={load}
        mutation={commands.mutation}
        pending={pending}
        actions={['disable', 'enable']}
        onRetry={retry}
        onCreate={({ username }) => {
          void commands.run('create', 'Add a user', () => policy.createUser(username), `Added ${username}. They have no access until a rule or group gives them some.`);
        }}
        onAsk={(action, id) => {
          commands.setMutation({ kind: 'idle' });
          setPending({ action, id });
        }}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending === null || pending.action === 'delete') return;
          const row = rows.find((candidate) => candidate.id === pending.id);
          const { action, id } = pending;
          void commands.run(id, actionLabel(action, 'user'), () => policy.userLifecycle(id, action), `${verb(action)} ${row?.username ?? 'the user'}.`).then(() => setPending(null));
        }}
      />
    </>
  );
}

// ───────────────────────── groups ─────────────────────────

export function GroupsContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="policy-groups">
      {(context) => <GroupsPage {...context} />}
    </SignedIn>
  );
}

function GroupsPage(context: SignedInContext) {
  const policy = usePolicy(context.api);
  const { load, retry, refetch } = useManagedList(() => policy.groups(), context.navigate);
  const commands = useCommands(context, refetch);
  const [pending, setPending] = useState<PendingGroupAction | null>(null);
  const data: GroupsData | null = load.kind === 'ready' ? load.data : null;
  const groupName = (id: string) => data?.groups.find((group) => group.id === id)?.name ?? 'the group';

  return (
    <>
      {commands.gate}
      <GroupsScreen
        load={load}
        mutation={commands.mutation}
        pending={pending}
        actions={['disable', 'enable', 'delete']}
        onRetry={retry}
        onCreate={({ name }) => {
          void commands.run('create', 'Add a group', () => policy.createGroup(name), `Added ${name}. It has no members and no rules yet.`);
        }}
        onAddMember={({ groupId, kind, memberId }) => {
          const member = (kind === 'user' ? data?.candidates.users : data?.candidates.agents)?.find((candidate) => candidate.id === memberId)?.name ?? `the ${kind}`;
          void commands.run(groupId, 'Add a member', () => policy.addMember(groupId, kind, memberId), `Added ${member} to ${groupName(groupId)}.`);
        }}
        onAskRemoveMember={(groupId, kind, memberId) => {
          commands.setMutation({ kind: 'idle' });
          setPending({ action: 'remove_member', id: groupId, kind, memberId });
        }}
        onAsk={(action, id) => {
          commands.setMutation({ kind: 'idle' });
          setPending({ action, id });
        }}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending === null) return;
          const current = pending;
          const name = groupName(current.id);
          const call =
            current.action === 'remove_member'
              ? { label: 'Remove a member', request: () => policy.removeMember(current.id, current.kind, current.memberId), message: `Removed a member from ${name}.`, removesRow: false }
              : current.action === 'delete'
                ? { label: 'Delete a group', request: () => policy.deleteGroup(current.id), message: `Deleted ${name}.`, removesRow: true }
                : { label: actionLabel(current.action, 'group'), request: () => policy.groupLifecycle(current.id, current.action as 'disable' | 'enable'), message: `${verb(current.action)} ${name}.`, removesRow: false };
          void commands.run(current.id, call.label, call.request, call.message, call.removesRow).then(() => setPending(null));
        }}
      />
    </>
  );
}

// ───────────────────────── agents (identity) ─────────────────────────

export function PolicyAgentsContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="policy-agents">
      {(context) => <PolicyAgentsPage {...context} />}
    </SignedIn>
  );
}

function PolicyAgentsPage(context: SignedInContext) {
  const policy = usePolicy(context.api);
  const { load, retry, refetch } = useManagedList(() => policy.agents(), context.navigate);
  const commands = useCommands(context, refetch);
  const [pending, setPending] = useState<PendingAgentAction | null>(null);
  const data: AgentsData | null = load.kind === 'ready' ? load.data : null;
  const agentName = (id: string) => data?.agents.find((agent) => agent.id === id)?.name ?? 'the agent';

  return (
    <>
      {commands.gate}
      <AgentsScreen
        load={load}
        mutation={commands.mutation}
        pending={pending}
        actions={['disable', 'enable', 'transfer'] satisfies AgentAction[]}
        credentialsHref={(agentId) => `${AGENT_TOKENS_ROUTE}#agent=${encodeURIComponent(agentId)}`}
        onRetry={retry}
        onCreate={({ name, owner }) => {
          void commands.run('create', 'Add an agent', () => policy.createAgent(name, owner), `Added ${name}. It has no token and no access yet.`);
        }}
        onTransferOwner={({ agentId, owner }) => {
          void commands.run(agentId, 'Change an agent’s owner', () => policy.transferAgent(agentId, owner), `Changed who is accountable for ${agentName(agentId)}. Its access is unchanged.`).then(() => setPending(null));
        }}
        onAsk={(action, id) => {
          commands.setMutation({ kind: 'idle' });
          setPending({ action, id });
        }}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending === null || (pending.action !== 'disable' && pending.action !== 'enable')) return;
          const { action, id } = pending;
          void commands.run(id, actionLabel(action, 'agent'), () => policy.agentLifecycle(id, action), `${verb(action)} ${agentName(id)}.`).then(() => setPending(null));
        }}
      />
    </>
  );
}

// ───────────────────────── rules ─────────────────────────

export function RulesContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="policy-rules">
      {(context) => <RulesPage {...context} />}
    </SignedIn>
  );
}

function RulesPage(context: SignedInContext) {
  const policy = usePolicy(context.api);
  const { load, retry, refetch } = useManagedList(() => policy.rules(), context.navigate);
  const commands = useCommands(context, refetch);
  const [editor, setEditor] = useState<RuleEditorState>({ kind: 'closed' });
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [preview, setPreview] = useState<PreviewState>({ kind: 'idle' });
  const checked = useRef(0);
  const data: RulesData | null = load.kind === 'ready' ? load.data : null;

  const closeEditor = () => {
    checked.current++;
    setPreview({ kind: 'idle' });
    setEditor({ kind: 'closed' });
  };

  const submit = (draft: RuleDraft, editingId: string | null) => {
    const count = draft.operations.length;
    const message = editingId === null ? (count === 1 ? 'Added the rule.' : `Added ${count} rules.`) : 'Saved the rule.';
    const label = editingId === null ? 'Add a rule' : 'Edit a rule';
    void commands
      .run('editor', label, () => (editingId === null ? policy.createRules(draft) : policy.updateRule(editingId, draft)), message)
      .then((ok) => {
        // The editor's own outcome stays under it on failure, so the draft survives; on success it moves to the page.
        if (!ok) return;
        closeEditor();
        commands.setMutation({ kind: 'done', message });
      });
  };

  const onPreview = (selector: SelectorDraft) => {
    const ticket = ++checked.current;
    setPreview({ kind: 'checking' });
    void policy.preview(selector).then((result) => {
      if (ticket !== checked.current) return;
      if (!result.ok) {
        if (result.status === 401) context.navigate('/login');
        setPreview({ kind: 'unavailable' });
      } else if (result.data.available) {
        setPreview({ kind: 'ready', forKey: selectorKey(selector), matches: result.data.matches });
      } else {
        setPreview({ kind: 'unavailable' });
      }
    });
  };

  return (
    <>
      {commands.gate}
      <RulesScreen
        load={load}
        mutation={commands.mutation}
        editor={editor}
        pending={pending}
        preview={preview}
        onRetry={retry}
        onNew={() => {
          commands.setMutation({ kind: 'idle' });
          setEditor({ kind: 'create' });
        }}
        onEdit={(id) => {
          commands.setMutation({ kind: 'idle' });
          setPreview({ kind: 'idle' });
          setEditor({ kind: 'edit', id });
        }}
        onCloseEditor={closeEditor}
        onSubmit={submit}
        onPreview={onPreview}
        onAsk={(action, id) => {
          commands.setMutation({ kind: 'idle' });
          setPending({ action, id });
        }}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending === null) return;
          const { action, id } = pending;
          const rule = data?.rules.find((candidate) => candidate.id === id);
          const call = action === 'delete' ? () => policy.deleteRule(id) : () => policy.ruleLifecycle(id, action);
          const what = rule ? `the rule for ${rule.subject.name}` : 'the rule';
          void commands.run(id, actionLabel(action, 'rule'), call, `${verb(action)} ${what}.`, action === 'delete').then(() => setPending(null));
        }}
      />
    </>
  );
}
