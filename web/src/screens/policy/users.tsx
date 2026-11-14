import { Button, EmptyState, PageHeader, Panel } from '../../ui';
import type { UserRow, UsersScreenProps } from './contract';
import { AccountStateBadge, AdministratorBadge, AuthorityNote, CreateNameForm, Fact, Facts, LifecycleConfirm, ManagedLoad, MutationNotice, RemovalBlockers, RulesLink, isWorking, names } from './shared';

function UserItem({ row, props }: { row: UserRow; props: UsersScreenProps }) {
  const { actions, pending, mutation, rulesHref, onAsk, onCancel, onConfirm } = props;
  const mine = pending?.id === row.id ? pending : null;
  const busy = isWorking(mutation, row.id);
  const lifecycle = !row.administrator && row.state !== 'quarantined';
  const id = (action: string) => `user-${row.id}-${action}`;
  return (
    <li className="py-4 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h3 className="font-semibold">{row.username}</h3>
          <AccountStateBadge state={row.state} />
          {row.administrator ? <AdministratorBadge /> : null}
        </div>
        {lifecycle ? (
          <div className="flex flex-wrap items-center gap-2">
            {actions.includes('disable') && row.state === 'active' ? (
              <Button id={id('disable')} variant="secondary" aria-label={`Disable ${row.username}`} onClick={() => onAsk('disable', row.id)}>
                Disable
              </Button>
            ) : null}
            {actions.includes('enable') && row.state === 'disabled' ? (
              <Button id={id('enable')} variant="secondary" aria-label={`Enable ${row.username}`} onClick={() => onAsk('enable', row.id)}>
                Enable
              </Button>
            ) : null}
            {actions.includes('delete') ? (
              <Button id={id('delete')} variant="danger" icon="trash" aria-label={`Delete ${row.username}`} disabled={!row.removal.allowed} onClick={() => onAsk('delete', row.id)}>
                Delete
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
      {row.administrator ? (
        <p className="mt-2 text-sm text-muted">
          This account manages access. It has no container operations unless a rule names it, and it can’t be disabled or deleted from this page.
        </p>
      ) : null}
      {row.state === 'quarantined' ? <p className="mt-2 text-sm text-muted">Restored from a backup and waiting for approval. It can’t sign in or hold access until it is approved.</p> : null}
      <Facts>
        <Fact label="Groups">{names(row.groups)}</Fact>
        <Fact label="Owns agents">{names(row.ownedAgents)}</Fact>
        <Fact label="Rules">
          <RulesLink count={row.ruleCount} subjectName={row.username} href={rulesHref?.({ kind: 'user', id: row.id })} />
        </Fact>
      </Facts>
      {actions.includes('delete') && lifecycle ? <RemovalBlockers removal={row.removal} /> : null}
      {mine && (mine.action === 'disable' || mine.action === 'enable' || mine.action === 'delete') ? (
        <LifecycleConfirm noun="user" action={mine.action} name={row.username} returnFocusId={id(mine.action)} busy={busy} onConfirm={onConfirm} onCancel={onCancel} />
      ) : null}
      <div className="mt-3 empty:hidden">
        <MutationNotice mutation={mutation} target={row.id} onReload={props.onRetry} />
      </div>
    </li>
  );
}

/**
 * Users (P1.17.1, F-U). A user is an account that can hold rules and group memberships. Creating one grants nothing:
 * a new user has no rule, no group and no sign-in method until the administrator (and enrolment) provide them.
 */
export function UsersScreen(props: UsersScreenProps) {
  const { load, mutation, onRetry, onCreate } = props;
  return (
    <div className="space-y-6">
      <PageHeader title="Users" description="People who can sign in to Mandatary. A new user starts with no access at all." />
      <AuthorityNote />
      <MutationNotice mutation={mutation} onReload={onRetry} />
      <ManagedLoad load={load} label="users" area="users" onRetry={onRetry}>
        {(rows) => (
          <>
            <Panel title="Add a user" description="Creating a user gives them no access. Add them to groups, or write rules that name them, to allow anything.">
              <CreateNameForm
                ariaLabel="Add a user"
                label="Username"
                noun="username"
                hint="Letters and digits first, then letters, digits and . _ - @ + (up to 64, no spaces)."
                submitLabel="Add user"
                busyLabel="Adding…"
                mutation={mutation}
                onSubmit={(username) => onCreate({ username })}
                onReload={onRetry}
              />
            </Panel>
            <Panel title="All users" description={`${rows.length} ${rows.length === 1 ? 'user' : 'users'}`}>
              {rows.length === 0 ? (
                <EmptyState title="No users yet" description="Add the first user above. Until a rule allows something, nobody can operate a container." headingLevel={3} />
              ) : (
                <ul className="divide-y divide-line">
                  {rows.map((row) => (
                    <UserItem key={row.id} row={row} props={props} />
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
