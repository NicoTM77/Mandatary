import { useState } from 'react';
import { Badge, Button, ConfirmPanel, EmptyState, Icon, PageHeader, Panel, SelectField } from '../../ui';
import type { GroupRow, GroupsData, GroupsScreenProps, MemberRow, NamedAccount } from './contract';
import { AccountStateBadge, AuthorityNote, CreateNameForm, Fact, Facts, LifecycleConfirm, ManagedLoad, MutationNotice, RemovalBlockers, RulesLink, isWorking, names } from './shared';

function MemberItem({ group, member, props }: { group: GroupRow; member: MemberRow; props: GroupsScreenProps }) {
  const { pending, onAskRemoveMember, onConfirm, onCancel, mutation } = props;
  const removing = pending?.action === 'remove_member' && pending.id === group.id && pending.kind === member.kind && pending.memberId === member.id;
  const triggerId = `member-${group.id}-${member.kind}-${member.id}-remove`;
  return (
    <li className="py-2.5 first:pt-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Icon name={member.kind === 'user' ? 'user' : 'bot'} className="size-4 text-muted" />
          <span className="font-medium">{member.name}</span>
          <span className="text-sm text-muted">{member.kind === 'user' ? 'User' : 'Agent'}</span>
          {member.state !== 'active' ? <AccountStateBadge state={member.state} /> : null}
          {member.membership === 'quarantined' ? (
            <Badge tone="warning" icon="clock">
              Membership waiting for approval
            </Badge>
          ) : member.membership === 'disabled' ? (
            <Badge tone="neutral" icon="ban">
              Membership disabled
            </Badge>
          ) : null}
        </div>
        <Button id={triggerId} variant="danger" aria-label={`Remove ${member.name} from ${group.name}`} onClick={() => onAskRemoveMember(group.id, member.kind, member.id)}>
          Remove
        </Button>
      </div>
      {member.membership === 'quarantined' ? <p className="mt-1 text-sm text-muted">This membership came from a restore. It grants nothing until it is approved explicitly.</p> : null}
      {removing ? (
        <div className="mt-3">
          <ConfirmPanel
            title={`Remove ${member.name} from ${group.name}?`}
            confirmLabel={`Remove ${member.name}`}
            busyLabel="Removing…"
            busy={isWorking(mutation, group.id)}
            onConfirm={onConfirm}
            onCancel={onCancel}
            returnFocusId={triggerId}
          >
            Rules for {group.name} stop applying to {member.name} straight away, and that includes any Deny rules, so {member.name} may gain access that another rule allows. Rules that name {member.name} directly, or another group it is in,
            still apply.
          </ConfirmPanel>
        </div>
      ) : null}
    </li>
  );
}

function AddMember({ group, candidates, props }: { group: GroupRow; candidates: GroupsData['candidates']; props: GroupsScreenProps }) {
  const [error, setError] = useState<string | undefined>();
  const present = new Set(group.members.map((member) => `${member.kind}:${member.id}`));
  const option = (kind: 'user' | 'agent') => (account: NamedAccount) => ({
    value: `${kind}:${account.id}`,
    label: account.state === 'active' ? account.name : `${account.name} (${account.state === 'disabled' ? 'disabled' : 'waiting for approval'})`,
    disabled: account.state !== 'active',
  });
  const users = candidates.users.filter((account) => !present.has(`user:${account.id}`)).map(option('user'));
  const agents = candidates.agents.filter((account) => !present.has(`agent:${account.id}`)).map(option('agent'));
  const groups = [users.length > 0 ? { label: 'Users', options: users } : null, agents.length > 0 ? { label: 'Agents', options: agents } : null].filter((entry) => entry !== null);
  const busy = isWorking(props.mutation, group.id);

  if (groups.length === 0) return <p className="mt-3 text-sm text-muted">Everyone who exists is already a member of {group.name}.</p>;
  return (
    <form
      method="post"
      noValidate
      aria-label={`Add a member to ${group.name}`}
      className="mt-3 flex flex-wrap items-end gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        const value = String(new FormData(event.currentTarget).get('member') ?? '');
        const split = value.indexOf(':');
        const kind = value.slice(0, split);
        if (split < 0 || (kind !== 'user' && kind !== 'agent')) {
          setError('Choose who to add.');
          event.currentTarget.querySelector('select')?.focus();
          return;
        }
        setError(undefined);
        props.onAddMember({ groupId: group.id, kind, memberId: value.slice(split + 1) });
      }}
    >
      <SelectField name="member" label="Add a member" placeholder="Choose a user or agent" groups={groups} error={error} disabled={busy} className="min-w-0 flex-1 basis-60" />
      <Button type="submit" variant="secondary" icon="plus" busy={busy && props.pending === null} busyLabel="Adding…">
        Add to {group.name}
      </Button>
    </form>
  );
}

function GroupItem({ group, data, props }: { group: GroupRow; data: GroupsData; props: GroupsScreenProps }) {
  const { actions, pending, mutation, rulesHref, onAsk, onCancel, onConfirm } = props;
  const lifecyclePending = pending && pending.id === group.id && (pending.action === 'disable' || pending.action === 'enable' || pending.action === 'delete') ? pending.action : null;
  const id = (action: string) => `group-${group.id}-${action}`;
  const lifecycle = group.state !== 'quarantined';
  return (
    <li className="py-5 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Icon name="users" className="size-5 text-muted" />
          <h3 className="font-semibold">{group.name}</h3>
          <AccountStateBadge state={group.state} />
        </div>
        {lifecycle ? (
          <div className="flex flex-wrap items-center gap-2">
            {actions.includes('disable') && group.state === 'active' ? (
              <Button id={id('disable')} variant="secondary" aria-label={`Disable ${group.name}`} onClick={() => onAsk('disable', group.id)}>
                Disable
              </Button>
            ) : null}
            {actions.includes('enable') && group.state === 'disabled' ? (
              <Button id={id('enable')} variant="secondary" aria-label={`Enable ${group.name}`} onClick={() => onAsk('enable', group.id)}>
                Enable
              </Button>
            ) : null}
            {actions.includes('delete') ? (
              <Button id={id('delete')} variant="danger" icon="trash" aria-label={`Delete ${group.name}`} disabled={!group.removal.allowed} onClick={() => onAsk('delete', group.id)}>
                Delete
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
      <Facts>
        <Fact label="Owns agents">{names(group.ownedAgents)}</Fact>
        <Fact label="Rules">
          <RulesLink count={group.ruleCount} subjectName={group.name} href={rulesHref?.({ kind: 'group', id: group.id })} />
        </Fact>
      </Facts>
      {actions.includes('delete') && lifecycle ? <RemovalBlockers removal={group.removal} /> : null}
      {lifecyclePending ? <LifecycleConfirm noun="group" action={lifecyclePending} name={group.name} returnFocusId={id(lifecyclePending)} busy={isWorking(mutation, group.id)} onConfirm={onConfirm} onCancel={onCancel} /> : null}

      <section aria-label={`Members of ${group.name}`} className="mt-4 rounded-control border border-line bg-sunken p-4">
        <h4 className="mb-2 text-sm font-semibold">Members</h4>
        {group.members.length === 0 ? (
          <p className="text-sm text-muted">No members yet, so rules for this group apply to nobody.</p>
        ) : (
          <ul className="divide-y divide-line">
            {group.members.map((member) => (
              <MemberItem key={`${member.kind}:${member.id}`} group={group} member={member} props={props} />
            ))}
          </ul>
        )}
        <AddMember group={group} candidates={data.candidates} props={props} />
      </section>
      <div className="mt-3 empty:hidden">
        <MutationNotice mutation={mutation} target={group.id} onReload={props.onRetry} />
      </div>
    </li>
  );
}

/**
 * Groups and membership (P1.17.1, F-G). Membership is explicit and separate from ownership: putting an agent in a group is
 * the only way group rules reach it. Every command about one group (lifecycle, add or remove a member) uses the group id as its
 * mutation target, so its outcome appears under that group.
 */
export function GroupsScreen(props: GroupsScreenProps) {
  const { load, mutation, onRetry, onCreate } = props;
  return (
    <div className="space-y-6">
      <PageHeader title="Groups" description="Collections of users and agents that share rules. Rules for a group reach its explicit members, and nobody else. Owning an agent doesn’t make it a member." />
      <AuthorityNote />
      <MutationNotice mutation={mutation} onReload={onRetry} />
      <ManagedLoad load={load} label="groups" area="groups" onRetry={onRetry}>
        {(data) => (
          <>
            <Panel title="Add a group" description="A new group is empty and has no rules, so it allows nothing yet.">
              <CreateNameForm
                ariaLabel="Add a group"
                label="Group name"
                noun="group name"
                hint="Letters and digits first, then letters, digits and . _ - @ + (up to 64, no spaces)."
                submitLabel="Add group"
                busyLabel="Adding…"
                mutation={mutation}
                onSubmit={(name) => onCreate({ name })}
                onReload={onRetry}
              />
            </Panel>
            <Panel title="All groups" description={`${data.groups.length} ${data.groups.length === 1 ? 'group' : 'groups'}`}>
              {data.groups.length === 0 ? (
                <EmptyState title="No groups yet" description="Groups are optional. Use one when several users or agents should share the same access." headingLevel={3} />
              ) : (
                <ul className="divide-y divide-line">
                  {data.groups.map((group) => (
                    <GroupItem key={group.id} group={group} data={data} props={props} />
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
