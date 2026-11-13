import { useRef, useState, type KeyboardEvent } from 'react';
import { Button, EmptyState, Icon, PageHeader, Panel, RadioGroup, SelectField, TextField } from '../../ui';
import type { AgentRow, AgentsData, AgentsScreenProps, NamedAccount, OwnerRef } from './contract';
import { validateIdentifier } from './names';
import { AccountStateBadge, AuthorityNote, Fact, Facts, LifecycleConfirm, ManagedLoad, MutationNotice, RemovalBlockers, RulesLink, isWorking, names, plural } from './shared';

const OWNER_NOTE = 'The owner is accountable for the agent. Owning it gives neither the owner nor the agent any access.';

function activeOnly(accounts: readonly NamedAccount[], except?: string) {
  return accounts.filter((account) => account.state === 'active' && account.id !== except).map((account) => ({ value: account.id, label: account.name }));
}

/**
 * Owner picker: a user XOR a group. The form can only express one of them (a radio, then one select), which mirrors the
 * rule the service and SQLite enforce. Only active accounts are offered; if there are none of a kind, that choice says so.
 */
function OwnerFields({ owners, kind, onKind, error, except }: { owners: AgentsData['owners']; kind: 'user' | 'group'; onKind: (kind: 'user' | 'group') => void; error?: string; except?: string }) {
  const users = activeOnly(owners.users, kind === 'user' ? except : undefined);
  const groups = activeOnly(owners.groups, kind === 'group' ? except : undefined);
  const current = kind === 'user' ? users : groups;
  return (
    <div className="space-y-3">
      <RadioGroup
        name="owner-kind"
        legend="Owner"
        value={kind}
        onChange={(next) => onKind(next === 'group' ? 'group' : 'user')}
        hint={OWNER_NOTE}
        options={[
          { value: 'user', label: 'A user', hint: users.length === 0 && kind !== 'user' ? 'There is no other active user.' : 'One person is accountable for this agent.', disabled: users.length === 0 && kind !== 'user' },
          { value: 'group', label: 'A group', hint: groups.length === 0 && kind !== 'group' ? 'There is no other active group.' : 'A shared service agent that a group is accountable for.', disabled: groups.length === 0 && kind !== 'group' },
        ]}
      />
      <SelectField name="owner" label={kind === 'user' ? 'Owning user' : 'Owning group'} placeholder={kind === 'user' ? 'Choose a user' : 'Choose a group'} options={current} error={error} className="max-w-sm" />
    </div>
  );
}

function ownerFrom(form: HTMLFormElement, kind: 'user' | 'group'): OwnerRef | null {
  const id = String(new FormData(form).get('owner') ?? '');
  return id === '' ? null : { kind, id };
}

function CreateAgent({ data, props }: { data: AgentsData; props: AgentsScreenProps }) {
  const form = useRef<HTMLFormElement>(null);
  const [kind, setKind] = useState<'user' | 'group'>(data.owners.users.some((u) => u.state === 'active') ? 'user' : 'group');
  const [nameError, setNameError] = useState<string | undefined>();
  const [ownerError, setOwnerError] = useState<string | undefined>();
  const busy = isWorking(props.mutation, 'create');
  return (
    <form
      ref={form}
      method="post"
      noValidate
      aria-label="Add an agent"
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault();
        const name = String(new FormData(event.currentTarget).get('name') ?? '');
        const nameProblem = validateIdentifier(name, 'agent name');
        const owner = ownerFrom(event.currentTarget, kind);
        const ownerProblem = owner ? undefined : `Choose the owning ${kind}.`;
        setNameError(nameProblem);
        setOwnerError(ownerProblem);
        if (nameProblem) {
          event.currentTarget.querySelector<HTMLElement>('input[name="name"]')?.focus();
          return;
        }
        if (!owner) {
          event.currentTarget.querySelector<HTMLElement>('select')?.focus();
          return;
        }
        props.onCreate({ name: name.trim(), owner });
      }}
    >
      <MutationNotice mutation={props.mutation} target="create" onReload={props.onRetry} />
      <TextField name="name" label="Agent name" hint="Letters and digits first, then letters, digits and . _ - @ + (up to 64, no spaces)." error={nameError} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} mono readOnly={busy} className="max-w-sm" />
      <OwnerFields owners={data.owners} kind={kind} onKind={setKind} error={ownerError} />
      <Button type="submit" icon="plus" busy={busy} busyLabel="Adding…">
        Add agent
      </Button>
    </form>
  );
}

function TransferOwner({ agent, owners, props }: { agent: AgentRow; owners: AgentsData['owners']; props: AgentsScreenProps }) {
  const [kind, setKind] = useState<'user' | 'group'>(agent.owner.kind);
  const [error, setError] = useState<string | undefined>();
  const busy = isWorking(props.mutation, agent.id);
  const onKeyDown = (event: KeyboardEvent<HTMLFormElement>) => {
    if (event.key === 'Escape' && !busy) {
      event.stopPropagation();
      props.onCancel();
      document.getElementById(`agent-${agent.id}-transfer`)?.focus();
    }
  };
  return (
    <form
      method="post"
      noValidate
      aria-label={`Change the owner of ${agent.name}`}
      onKeyDown={onKeyDown}
      className="mt-3 space-y-4 rounded-control border border-line-strong bg-sunken p-4"
      onSubmit={(event) => {
        event.preventDefault();
        const owner = ownerFrom(event.currentTarget, kind);
        if (!owner) {
          setError(`Choose the new owning ${kind}.`);
          event.currentTarget.querySelector('select')?.focus();
          return;
        }
        setError(undefined);
        props.onTransferOwner({ agentId: agent.id, owner });
      }}
    >
      <p className="font-medium">Change the owner of {agent.name}</p>
      <p className="text-sm text-muted">Only who is accountable changes. {agent.name} keeps exactly the access it has now, and the old and new owner gain or lose none.</p>
      <OwnerFields owners={owners} kind={kind} onKind={setKind} error={error} except={agent.owner.id} />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" busy={busy} busyLabel="Changing…">
          Change owner
        </Button>
        <Button variant="secondary" onClick={props.onCancel} disabled={busy}>
          Keep current owner
        </Button>
      </div>
    </form>
  );
}

function AgentItem({ agent, data, props }: { agent: AgentRow; data: AgentsData; props: AgentsScreenProps }) {
  const { actions, pending, mutation, rulesHref, credentialsHref, onAsk, onCancel, onConfirm } = props;
  const mine = pending?.id === agent.id ? pending : null;
  const id = (action: string) => `agent-${agent.id}-${action}`;
  const lifecycle = agent.state !== 'quarantined';
  return (
    <li className="py-4 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Icon name="bot" className="size-5 text-muted" />
          <h3 className="font-semibold">{agent.name}</h3>
          <AccountStateBadge state={agent.state} />
        </div>
        {lifecycle ? (
          <div className="flex flex-wrap items-center gap-2">
            {actions.includes('transfer') && agent.state === 'active' ? (
              <Button id={id('transfer')} variant="secondary" icon="edit" aria-label={`Change the owner of ${agent.name}`} onClick={() => onAsk('transfer', agent.id)}>
                Change owner
              </Button>
            ) : null}
            {actions.includes('disable') && agent.state === 'active' ? (
              <Button id={id('disable')} variant="secondary" aria-label={`Disable ${agent.name}`} onClick={() => onAsk('disable', agent.id)}>
                Disable
              </Button>
            ) : null}
            {actions.includes('enable') && agent.state === 'disabled' ? (
              <Button id={id('enable')} variant="secondary" aria-label={`Enable ${agent.name}`} onClick={() => onAsk('enable', agent.id)}>
                Enable
              </Button>
            ) : null}
            {actions.includes('delete') ? (
              <Button id={id('delete')} variant="danger" icon="trash" aria-label={`Delete ${agent.name}`} disabled={!agent.removal.allowed} onClick={() => onAsk('delete', agent.id)}>
                Delete
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
      {agent.state === 'quarantined' ? <p className="mt-2 text-sm text-muted">Restored from a backup and waiting for approval. It has no usable tokens and holds no access until it is approved.</p> : null}
      <Facts>
        <Fact label="Owner">
          {agent.owner.kind === 'user' ? 'User' : 'Group'} {agent.owner.name}
          {agent.owner.state !== 'active' ? ` (${agent.owner.state === 'disabled' ? 'disabled' : 'waiting for approval'})` : ''}
          <span className="block text-muted">Accountability only: it gives {agent.owner.name} no access to this agent, and gives the agent none of {agent.owner.name}’s.</span>
        </Fact>
        <Fact label="Groups">{names(agent.groups)}</Fact>
        <Fact label="Tokens">
          {plural(agent.liveTokens, 'token')} usable now ·{' '}
          <a href={credentialsHref(agent.id)} className="font-medium text-accent-text underline underline-offset-2">
            Manage tokens<span className="sr-only"> for {agent.name}</span>
          </a>
        </Fact>
        <Fact label="Rules">
          <RulesLink count={agent.ruleCount} subjectName={agent.name} href={rulesHref?.({ kind: 'agent', id: agent.id })} />
        </Fact>
      </Facts>
      {actions.includes('delete') && lifecycle ? <RemovalBlockers removal={agent.removal} /> : null}
      {mine?.action === 'transfer' ? <TransferOwner agent={agent} owners={data.owners} props={props} /> : null}
      {mine && (mine.action === 'disable' || mine.action === 'enable' || mine.action === 'delete') ? (
        <LifecycleConfirm noun="agent" action={mine.action} name={agent.name} returnFocusId={id(mine.action)} busy={isWorking(mutation, agent.id)} onConfirm={onConfirm} onCancel={onCancel} />
      ) : null}
      <div className="mt-3 empty:hidden">
        <MutationNotice mutation={mutation} target={agent.id} onReload={props.onRetry} />
      </div>
    </li>
  );
}

/**
 * Agents as identities (P1.17.1, F-A): who an agent is, who is accountable for it and which groups it belongs to. Credentials are NOT
 * managed here: "Manage tokens" leads to the P1.16 Agent tokens page, the only place a token is issued, rotated or revealed (once).
 */
export function AgentsScreen(props: AgentsScreenProps) {
  const { load, mutation, onRetry } = props;
  return (
    <div className="space-y-6">
      <PageHeader title="Agents" description="Non-human principals that call the API and MCP server. An agent has exactly one owner and gets access only from rules that name it or a group it belongs to." />
      <AuthorityNote />
      <MutationNotice mutation={mutation} onReload={onRetry} />
      <ManagedLoad load={load} label="agents" area="agents" onRetry={onRetry}>
        {(data) => (
          <>
            <Panel title="Add an agent" description="A new agent has no tokens and no access. Issue it a token on the Agent tokens page and give it access with a rule, or by adding it to a group.">
              <CreateAgent data={data} props={props} />
            </Panel>
            <Panel title="All agents" description={`${data.agents.length} ${data.agents.length === 1 ? 'agent' : 'agents'}`}>
              {data.agents.length === 0 ? (
                <EmptyState title="No agents yet" description="Add an agent above, then issue it a token. Until a rule allows something, an agent can’t operate any container." headingLevel={3} />
              ) : (
                <ul className="divide-y divide-line">
                  {data.agents.map((agent) => (
                    <AgentItem key={agent.id} agent={agent} data={data} props={props} />
                  ))}
                </ul>
              )}
            </Panel>
          </>
        )}
      </ManagedLoad>
    </div>
  );
}
