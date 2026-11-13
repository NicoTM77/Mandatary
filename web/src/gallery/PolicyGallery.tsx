import type { ReactNode } from 'react';
import { AgentsScreen } from '../screens/policy/agentIdentity';
import type { AgentsScreenProps, GroupsScreenProps, RulesScreenProps, UsersScreenProps } from '../screens/policy/contract';
import { GroupsScreen } from '../screens/policy/groups';
import { POLICY_NAV } from '../screens/policy/nav';
import { RulesScreen } from '../screens/policy/rules';
import { selectorKey } from '../screens/policy/selector';
import { UsersScreen } from '../screens/policy/users';
import { AdminShell, AutoFocusContext, SyntheticBadge, ThemeToggle, type NavItem } from '../ui';
import { agents, groups, inventory, rules, rulesData, rulesDataEmpty, rulesDataUnverified, users } from './policyFixtures';

const noop = () => undefined;

const ALL = ['disable', 'enable', 'delete'] as const;

const usersBase: UsersScreenProps = { load: { kind: 'ready', data: users }, mutation: { kind: 'idle' }, pending: null, actions: ALL, rulesHref: () => '#g-rules', onRetry: noop, onCreate: noop, onAsk: noop, onCancel: noop, onConfirm: noop };
const groupsBase: GroupsScreenProps = { load: { kind: 'ready', data: groups }, mutation: { kind: 'idle' }, pending: null, actions: ALL, rulesHref: () => '#g-rules', onRetry: noop, onCreate: noop, onAddMember: noop, onAskRemoveMember: noop, onAsk: noop, onCancel: noop, onConfirm: noop };
const agentsBase: AgentsScreenProps = {
  load: { kind: 'ready', data: agents },
  mutation: { kind: 'idle' },
  pending: null,
  actions: ['transfer', 'disable', 'enable', 'delete'],
  rulesHref: () => '#g-rules',
  credentialsHref: () => '#g-agents',
  onRetry: noop,
  onCreate: noop,
  onTransferOwner: noop,
  onAsk: noop,
  onCancel: noop,
  onConfirm: noop,
};
const rulesBase: RulesScreenProps = { load: { kind: 'ready', data: rulesData }, mutation: { kind: 'idle' }, editor: { kind: 'closed' }, pending: null, preview: { kind: 'idle' }, onRetry: noop, onNew: noop, onEdit: noop, onCloseEditor: noop, onSubmit: noop, onPreview: noop, onAsk: noop, onCancel: noop, onConfirm: noop };

const r1 = rules[0];
const r2 = rules[1];
const r3 = rules[2];
const r4 = rules[3];
const r6 = rules[5];
const r9 = rules[8];

interface Specimen {
  flow: string;
  name: string;
  group: 'g-users' | 'g-groups' | 'g-agents' | 'g-rules' | 'g-editor';
  node: ReactNode;
}

const SPECIMENS: readonly Specimen[] = [
  { flow: 'U-a', group: 'g-users', name: 'Ready: administrator, active, disabled, waiting for approval', node: <UsersScreen {...usersBase} /> },
  { flow: 'U-b', group: 'g-users', name: 'Confirm disabling a user', node: <UsersScreen {...usersBase} pending={{ action: 'disable', id: 'u-sam' }} /> },
  { flow: 'U-c', group: 'g-users', name: 'Confirm deleting; a blocked delete says why', node: <UsersScreen {...usersBase} pending={{ action: 'delete', id: 'u-fresh' }} /> },
  { flow: 'U-d', group: 'g-users', name: 'Name already used (create rejected)', node: <UsersScreen {...usersBase} mutation={{ kind: 'rejected', reason: 'conflict', target: 'create' }} /> },
  { flow: 'U-e', group: 'g-users', name: 'Result could not be confirmed (503 after commit)', node: <UsersScreen {...usersBase} mutation={{ kind: 'rejected', reason: 'outcome_unknown', target: 'u-sam' }} /> },
  { flow: 'U-f', group: 'g-users', name: 'Done', node: <UsersScreen {...usersBase} mutation={{ kind: 'done', message: 'Added sample-fresh. They have no access yet.', target: 'create' }} /> },
  { flow: 'U-g', group: 'g-users', name: 'Loading', node: <UsersScreen {...usersBase} load={{ kind: 'loading' }} /> },
  { flow: 'U-h', group: 'g-users', name: 'Load failed (never an empty list)', node: <UsersScreen {...usersBase} load={{ kind: 'failed' }} /> },
  { flow: 'U-i', group: 'g-users', name: 'Not the policy administrator', node: <UsersScreen {...usersBase} load={{ kind: 'denied' }} /> },

  { flow: 'G-a', group: 'g-groups', name: 'Ready: members, a disabled group, an empty group', node: <GroupsScreen {...groupsBase} /> },
  { flow: 'G-b', group: 'g-groups', name: 'Confirm removing a member (a Deny may stop applying)', node: <GroupsScreen {...groupsBase} pending={{ action: 'remove_member', id: 'g-ops', kind: 'agent', memberId: 'a-ci' }} /> },
  { flow: 'G-c', group: 'g-groups', name: 'Confirm disabling a group', node: <GroupsScreen {...groupsBase} pending={{ action: 'disable', id: 'g-ops' }} /> },
  { flow: 'G-d', group: 'g-groups', name: 'Add member rejected: restored membership conflicts', node: <GroupsScreen {...groupsBase} mutation={{ kind: 'rejected', reason: 'conflict', target: 'g-ops' }} /> },
  { flow: 'G-e', group: 'g-groups', name: 'Empty', node: <GroupsScreen {...groupsBase} load={{ kind: 'ready', data: { ...groups, groups: [] } }} /> },

  { flow: 'A-a', group: 'g-agents', name: 'Ready: user-owned, group-owned, disabled', node: <AgentsScreen {...agentsBase} /> },
  { flow: 'A-b', group: 'g-agents', name: 'Change owner (accountability only)', node: <AgentsScreen {...agentsBase} pending={{ action: 'transfer', id: 'a-ci' }} /> },
  { flow: 'A-c', group: 'g-agents', name: 'Confirm disabling (tokens revoked)', node: <AgentsScreen {...agentsBase} pending={{ action: 'disable', id: 'a-ci' }} /> },
  { flow: 'A-d', group: 'g-agents', name: 'Create rejected: invalid owner', node: <AgentsScreen {...agentsBase} mutation={{ kind: 'rejected', reason: 'invalid', target: 'create' }} /> },
  {
    flow: 'A-e',
    group: 'g-agents',
    name: 'No active users: only a group can own',
    node: <AgentsScreen {...agentsBase} load={{ kind: 'ready', data: { agents: [], owners: { users: [{ id: 'u-robin', name: 'sample-robin', state: 'disabled' }], groups: agents.owners.groups } } }} />,
  },

  { flow: 'R-a', group: 'g-rules', name: 'Ready: Allow, Deny, guarded, pinned, disabled, waiting for approval, target missing', node: <RulesScreen {...rulesBase} /> },
  { flow: 'R-b', group: 'g-rules', name: 'No rules yet (default deny)', node: <RulesScreen {...rulesBase} load={{ kind: 'ready', data: rulesDataEmpty }} /> },
  { flow: 'R-c', group: 'g-rules', name: 'Mandatary can’t verify itself: everything refused, status unknown', node: <RulesScreen {...rulesBase} load={{ kind: 'ready', data: rulesDataUnverified }} /> },
  { flow: 'R-d', group: 'g-rules', name: 'Confirm deleting a Deny (loosens access)', node: <RulesScreen {...rulesBase} pending={{ action: 'delete', id: r4?.id ?? '' }} /> },
  { flow: 'R-e', group: 'g-rules', name: 'Confirm disabling an Allow (ends access, cuts streams)', node: <RulesScreen {...rulesBase} pending={{ action: 'disable', id: r1?.id ?? '' }} /> },
  { flow: 'R-f', group: 'g-rules', name: 'Result could not be confirmed', node: <RulesScreen {...rulesBase} mutation={{ kind: 'rejected', reason: 'outcome_unknown', target: r3?.id }} /> },
  { flow: 'R-g', group: 'g-rules', name: 'Ordinary user: not the policy administrator', node: <RulesScreen {...rulesBase} load={{ kind: 'denied' }} /> },
  { flow: 'R-h', group: 'g-rules', name: 'Loading', node: <RulesScreen {...rulesBase} load={{ kind: 'loading' }} /> },

  { flow: 'E-a', group: 'g-editor', name: 'Add a rule: blank', node: <RulesScreen {...rulesBase} editor={{ kind: 'create' }} /> },
  {
    flow: 'E-b',
    group: 'g-editor',
    name: 'Edit a guarded Allow, with matches previewed',
    node: <RulesScreen {...rulesBase} editor={{ kind: 'edit', id: r1?.id ?? '' }} preview={{ kind: 'ready', forKey: r1 ? selectorKey(r1.selector) : '', matches: inventory.slice(0, 1) }} />,
  },
  { flow: 'E-c', group: 'g-editor', name: 'Edit a broad Allow: needs an explicit tick', node: <RulesScreen {...rulesBase} editor={{ kind: 'edit', id: r9?.id ?? '' }} preview={{ kind: 'unavailable' }} /> },
  { flow: 'E-d', group: 'g-editor', name: 'Edit a pinned rule (recreation ends the match)', node: <RulesScreen {...rulesBase} editor={{ kind: 'edit', id: r6?.id ?? '' }} /> },
  { flow: 'E-e', group: 'g-editor', name: 'Edit a Deny with a pattern', node: <RulesScreen {...rulesBase} editor={{ kind: 'edit', id: r4?.id ?? '' }} /> },
  {
    flow: 'E-f',
    group: 'g-editor',
    name: 'Refused while saving, preview in progress',
    node: <RulesScreen {...rulesBase} editor={{ kind: 'edit', id: r2?.id ?? '' }} mutation={{ kind: 'rejected', reason: 'denied', target: 'editor' }} preview={{ kind: 'checking' }} />,
  },
];

const GROUPS: ReadonlyArray<readonly [Specimen['group'], string, string]> = [
  ['g-users', 'Users', 'F-U · user create, disable, enable, delete'],
  ['g-groups', 'Groups', 'F-G · membership is explicit and separate from ownership'],
  ['g-agents', 'Agents', 'F-A · identity and ownership; tokens are managed (and revealed once) on the Agent tokens page'],
  ['g-rules', 'Rules', 'F-R · explicit Allow and Deny; missing targets stay visible'],
  ['g-editor', 'Rule editor', 'F-R · create and edit; guardrails, limits and a preview of what matches'],
];

function SpecimenFigure({ specimen }: { specimen: Specimen }) {
  return (
    <figure className="min-w-0">
      <figcaption className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        <span className="rounded bg-sunken px-1.5 py-0.5 font-mono text-xs text-muted">{specimen.flow}</span>
        <span className="font-semibold">{specimen.name}</span>
        <SyntheticBadge />
      </figcaption>
      <div className="rounded-panel border border-dashed border-line-strong bg-bg p-3 sm:p-4">{specimen.node}</div>
    </figure>
  );
}

const SHELL_NAV: readonly NavItem[] = [
  { id: 'overview', label: 'Overview', href: '?synthetic=policy-shell' },
  { id: 'security', label: 'Account security', href: '?synthetic=policy-shell', group: 'Account', icon: 'shield' },
  { id: 'agent-tokens', label: 'Agent tokens', href: '?synthetic=policy-shell', group: 'Account', icon: 'key' },
  ...POLICY_NAV.map((item) => ({ ...item, href: `?synthetic=policy-shell${item.id === 'policy-rules' ? '' : `-${item.id.replace('policy-', '')}`}` })),
];

const SHELL_PAGES = new Map<string, { id: string; screen: ReactNode }>([
  ['policy-shell', { id: 'policy-rules', screen: <RulesScreen {...rulesBase} /> }],
  ['policy-shell-users', { id: 'policy-users', screen: <UsersScreen {...usersBase} /> }],
  ['policy-shell-groups', { id: 'policy-groups', screen: <GroupsScreen {...groupsBase} /> }],
  ['policy-shell-agents', { id: 'policy-agents', screen: <AgentsScreen {...agentsBase} /> }],
]);

const ONLY_PREFIX = 'policy-only-';

/**
 * Entry for `?synthetic=policy` (all states), `?synthetic=policy-only-<flow>` (one state alone on a page, for focused audits and screenshots)
 * and `?synthetic=policy-shell[-users|-groups|-agents]` (the admin shell).
 */
export default function PolicyGallery({ view }: { view: string }) {
  const shell = SHELL_PAGES.get(view);
  const only = view.startsWith(ONLY_PREFIX) ? SPECIMENS.find((specimen) => specimen.flow === view.slice(ONLY_PREFIX.length)) : undefined;
  return <AutoFocusContext.Provider value={false}>{shell ? <ShellView id={shell.id}>{shell.screen}</ShellView> : only ? <OnlyView specimen={only} /> : <StateGallery />}</AutoFocusContext.Provider>;
}

function ShellView({ id, children }: { id: string; children: ReactNode }) {
  return (
    <AdminShell nav={SHELL_NAV} currentId={id} account={{ username: 'sample-admin', assurance: 'aal2', freshnessNote: 'Verified 4 minutes ago' }} onSignOut={noop}>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <SyntheticBadge>Synthetic shell view: nothing here is connected</SyntheticBadge>
        <a href="?synthetic=policy" className="text-sm font-medium text-accent-text underline underline-offset-2">
          Back to state gallery
        </a>
      </div>
      {children}
    </AdminShell>
  );
}

/** One specimen alone inside the shell, so an audit sees one h1, one main and a realistic page. */
function OnlyView({ specimen }: { specimen: Specimen }) {
  return (
    <AdminShell nav={SHELL_NAV} currentId={specimen.group === 'g-users' ? 'policy-users' : specimen.group === 'g-groups' ? 'policy-groups' : specimen.group === 'g-agents' ? 'policy-agents' : 'policy-rules'} account={{ username: 'sample-admin', assurance: 'aal2' }} onSignOut={noop}>
      <div className="mb-4">
        <SyntheticBadge>{`Synthetic ${specimen.flow}: ${specimen.name}`}</SyntheticBadge>
      </div>
      {specimen.node}
    </AdminShell>
  );
}

const INDEX: ReadonlyArray<readonly [string, string]> = GROUPS.map(([id, title]) => [id, title] as const);

function StateGallery() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight">Policy management screens: synthetic state gallery</h1>
            <p className="text-sm text-muted">P1.17.1 design baseline. Fixtures only: no server, no real accounts, no working administration.</p>
          </div>
          <ThemeToggle />
        </div>
      </header>
      <div className="mx-auto max-w-5xl gap-8 px-4 py-6 sm:px-6 lg:grid lg:max-w-7xl lg:grid-cols-[13rem_minmax(0,1fr)]">
        <nav aria-label="Screens" className="mb-6 lg:sticky lg:top-4 lg:mb-0 lg:self-start">
          <ul className="flex flex-wrap gap-1.5 lg:block lg:space-y-0.5">
            {INDEX.map(([id, label]) => (
              <li key={id}>
                <a href={`#${id}`} className="block rounded-control px-2.5 py-1.5 text-sm text-fg hover:bg-sunken lg:min-h-9">
                  {label}
                </a>
              </li>
            ))}
            <li>
              <a href="?synthetic=policy-shell" className="block rounded-control px-2.5 py-1.5 text-sm font-medium text-accent-text hover:bg-accent-soft">
                Admin shell view
              </a>
            </li>
          </ul>
        </nav>
        <main id="main-content" tabIndex={-1} className="min-w-0 space-y-14 outline-none">
          <h2 className="sr-only">Specimens</h2>
          {GROUPS.map(([id, title, note]) => (
            <section key={id} id={id} aria-labelledby={`${id}-h`} className="scroll-mt-24 space-y-4">
              <div>
                <h2 id={`${id}-h`} className="text-xl font-semibold">
                  {title}
                </h2>
                <p className="text-sm text-muted">{note}</p>
              </div>
              <div className="space-y-8">
                {SPECIMENS.filter((specimen) => specimen.group === id).map((specimen) => (
                  <SpecimenFigure key={specimen.flow} specimen={specimen} />
                ))}
              </div>
            </section>
          ))}
        </main>
      </div>
    </div>
  );
}
