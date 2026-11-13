import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { agents, groups, users } from '../../gallery/policyFixtures';
import { ThemeProvider } from '../../theme';
import { AgentsScreen } from './agentIdentity';
import type { AgentsScreenProps, GroupsScreenProps, UsersScreenProps } from './contract';
import { GroupsScreen } from './groups';
import { UsersScreen } from './users';

afterEach(cleanup);

const noop = () => undefined;
const ALL = ['disable', 'enable', 'delete'] as const;

const usersProps = (patch: Partial<UsersScreenProps> = {}): UsersScreenProps => ({ load: { kind: 'ready', data: users }, mutation: { kind: 'idle' }, pending: null, actions: ALL, onRetry: noop, onCreate: noop, onAsk: noop, onCancel: noop, onConfirm: noop, ...patch });
const groupsProps = (patch: Partial<GroupsScreenProps> = {}): GroupsScreenProps => ({ load: { kind: 'ready', data: groups }, mutation: { kind: 'idle' }, pending: null, actions: ALL, onRetry: noop, onCreate: noop, onAddMember: noop, onAskRemoveMember: noop, onAsk: noop, onCancel: noop, onConfirm: noop, ...patch });
const agentsProps = (patch: Partial<AgentsScreenProps> = {}): AgentsScreenProps => ({
  load: { kind: 'ready', data: agents },
  mutation: { kind: 'idle' },
  pending: null,
  actions: ['transfer', 'disable', 'enable', 'delete'],
  credentialsHref: (id) => `/agents?agent=${id}`,
  onRetry: noop,
  onCreate: noop,
  onTransferOwner: noop,
  onAsk: noop,
  onCancel: noop,
  onConfirm: noop,
  ...patch,
});

function mount(ui: ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

function type(label: string | RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function row(heading: string) {
  const item = screen.getByRole('heading', { level: 3, name: heading }).closest('li');
  if (!item) throw new Error(`no row for ${heading}`);
  return within(item);
}

// ───────────────────────── every management page ─────────────────────────

const PAGES: ReadonlyArray<readonly [string, (load: 'loading' | 'failed' | 'denied') => ReactElement, string]> = [
  ['users', (kind) => <UsersScreen {...usersProps({ load: { kind } })} />, 'Users'],
  ['groups', (kind) => <GroupsScreen {...groupsProps({ load: { kind } })} />, 'Groups'],
  ['agents', (kind) => <AgentsScreen {...agentsProps({ load: { kind } })} />, 'Agents'],
];

for (const [name, page, title] of PAGES) {
  test(`${name}: administrative authority is stated as distinct from operation permission on the page`, () => {
    mount(page('loading'));
    expect(screen.getByRole('heading', { level: 1, name: title })).toBeTruthy();
    expect(screen.getByText('Managing access isn’t the same as having it')).toBeTruthy();
    expect(screen.getByText(/allows no container operation by itself/)).toBeTruthy();
    expect(screen.getByText(/Owning an agent allows none either/)).toBeTruthy();
  });

  test(`${name}: loading is a polite status, and nothing that could change access is shown while it loads`, () => {
    mount(page('loading'));
    expect(screen.getByRole('status').textContent).toContain(`Loading ${name}…`);
    expect(screen.queryByRole('form')).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
  });

  test(`${name}: a failed load is an error with a retry, never an empty list`, () => {
    const onRetry = vi.fn();
    mount(
      name === 'users' ? <UsersScreen {...usersProps({ load: { kind: 'failed' }, onRetry })} /> : name === 'groups' ? <GroupsScreen {...groupsProps({ load: { kind: 'failed' }, onRetry })} /> : <AgentsScreen {...agentsProps({ load: { kind: 'failed' }, onRetry })} />,
    );
    expect(screen.getByRole('alert').textContent).toContain(`Couldn’t load ${name}`);
    expect(screen.queryByText(/No (users|groups|agents) yet/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  test(`${name}: an ordinary user sees a refusal that names no one, and no form or list`, () => {
    mount(page('denied'));
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain('Policy administration isn’t available to this session');
    expect(alert.textContent).toContain('Mandatary refuses every request from them whatever their browser sends');
    expect(screen.queryByRole('form')).toBeNull();
    expect(screen.queryByRole('list')).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
  });
}

// ───────────────────────── users ─────────────────────────

test('the administrator is shown as authority, with no container operations and no way to disable or delete them here', () => {
  mount(<UsersScreen {...usersProps()} />);
  const admin = row('sample-admin');
  expect(admin.getByText('Policy administrator')).toBeTruthy();
  expect(admin.getByText(/has no container operations unless a rule names it/)).toBeTruthy();
  expect(admin.queryByRole('button')).toBeNull();
});

test('a restored account is marked as waiting for approval and cannot be acted on from here', () => {
  mount(<UsersScreen {...usersProps()} />);
  const restored = row('sample-restored');
  expect(restored.getByText('Waiting for approval')).toBeTruthy();
  expect(restored.queryByRole('button')).toBeNull();
});

test('only the lifecycle actions the backend supports are rendered', () => {
  mount(<UsersScreen {...usersProps({ actions: ['disable'] })} />);
  expect(screen.queryAllByRole('button', { name: /^Enable / })).toHaveLength(0);
  expect(screen.queryAllByRole('button', { name: /^Delete / })).toHaveLength(0);
  expect(screen.getByRole('button', { name: 'Disable sample-sam' })).toBeTruthy();
});

test('a user with dependants has Delete disabled and the reasons are written next to it', () => {
  mount(<UsersScreen {...usersProps()} />);
  const sam = row('sample-sam');
  expect((sam.getByRole('button', { name: 'Delete sample-sam' }) as HTMLButtonElement).disabled).toBe(true);
  expect(sam.getByText(/Can’t be deleted yet: owns agent sample-ci-runner; has 2 rules; belongs to sample-ops\./)).toBeTruthy();
  expect((row('sample-fresh').getByRole('button', { name: 'Delete sample-fresh' }) as HTMLButtonElement).disabled).toBe(false);
});

test('Disable and Enable are offered according to the account state', () => {
  mount(<UsersScreen {...usersProps()} />);
  expect(row('sample-sam').queryByRole('button', { name: 'Enable sample-sam' })).toBeNull();
  expect(row('sample-robin').getByRole('button', { name: 'Enable sample-robin' })).toBeTruthy();
  expect(row('sample-robin').queryByRole('button', { name: 'Disable sample-robin' })).toBeNull();
});

test('asking to disable reports the action and the id; the confirmation names the user and states the consequence', () => {
  const onAsk = vi.fn();
  const { rerender } = mount(<UsersScreen {...usersProps({ onAsk })} />);
  fireEvent.click(screen.getByRole('button', { name: 'Disable sample-sam' }));
  expect(onAsk).toHaveBeenCalledExactlyOnceWith('disable', 'u-sam');
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  rerender(
    <ThemeProvider>
      <UsersScreen {...usersProps({ pending: { action: 'disable', id: 'u-sam' }, onConfirm, onCancel })} />
    </ThemeProvider>,
  );
  const group = screen.getByRole('group', { name: 'Disable sample-sam?' });
  expect(group.textContent).toContain('can’t sign in or use Mandatary while disabled');
  expect(group.textContent).toContain('grant nothing until you enable them again');
  fireEvent.click(within(group).getByRole('button', { name: 'Disable sample-sam' }));
  expect(onConfirm).toHaveBeenCalledTimes(1);
});

test('cancelling a confirmation calls onCancel and returns focus to the button that opened it', () => {
  const onCancel = vi.fn();
  mount(<UsersScreen {...usersProps({ pending: { action: 'disable', id: 'u-sam' }, onCancel })} />);
  fireEvent.keyDown(screen.getByRole('group', { name: 'Disable sample-sam?' }), { key: 'Escape' });
  expect(onCancel).toHaveBeenCalledTimes(1);
  expect(document.activeElement?.id).toBe('user-u-sam-disable');
});

test('while a user command is running its confirm button announces progress and a repeat press is ignored', () => {
  const onConfirm = vi.fn();
  mount(<UsersScreen {...usersProps({ pending: { action: 'delete', id: 'u-fresh' }, mutation: { kind: 'working', target: 'u-fresh' }, onConfirm })} />);
  const busy = screen.getByRole('button', { name: 'Deleting…' });
  expect(busy.getAttribute('aria-busy')).toBe('true');
  fireEvent.click(busy);
  expect(onConfirm).not.toHaveBeenCalled();
});

test('creating a user: the form posts nothing natively, reports an empty name inline and calls nothing', () => {
  const onCreate = vi.fn();
  mount(<UsersScreen {...usersProps({ onCreate })} />);
  const form = screen.getByRole('form', { name: 'Add a user' });
  expect(form.getAttribute('method')).toBe('post');
  expect(form.hasAttribute('action')).toBe(false);
  expect(fireEvent.submit(form)).toBe(false);
  const input = screen.getByLabelText('Username');
  expect(input.getAttribute('aria-invalid')).toBe('true');
  expect(document.getElementById(input.getAttribute('aria-describedby')?.split(' ').at(-1) ?? '')?.textContent).toBe('Enter the username.');
  expect(document.activeElement).toBe(input);
  expect(onCreate).not.toHaveBeenCalled();
});

test('creating a user: a name outside the identifier rule is refused inline; a good one is trimmed and sent once', () => {
  const onCreate = vi.fn();
  mount(<UsersScreen {...usersProps({ onCreate })} />);
  const form = screen.getByRole('form', { name: 'Add a user' });
  type('Username', 'ada lovelace');
  fireEvent.submit(form);
  expect(onCreate).not.toHaveBeenCalled();
  expect(within(form).getByText(/Use letters and digits first/)).toBeTruthy();
  type('Username', '  sample-ada  ');
  fireEvent.submit(form);
  expect(onCreate).toHaveBeenCalledExactlyOnceWith({ username: 'sample-ada' });
});

test('after a successful create the field is cleared and the outcome is announced politely', () => {
  const { rerender } = mount(<UsersScreen {...usersProps()} />);
  type('Username', 'sample-ada');
  rerender(
    <ThemeProvider>
      <UsersScreen {...usersProps({ mutation: { kind: 'done', message: 'Added sample-ada. They have no access yet.', target: 'create' } })} />
    </ThemeProvider>,
  );
  expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe('');
  expect(screen.getByRole('status').textContent).toContain('Added sample-ada. They have no access yet.');
});

test('a 503 after a possible commit is reported as "could not confirm", never as "nothing changed", and offers a reload', () => {
  const onRetry = vi.fn();
  mount(<UsersScreen {...usersProps({ mutation: { kind: 'rejected', reason: 'outcome_unknown', target: 'u-sam' }, onRetry })} />);
  const alert = within(row('sample-sam').getByRole('alert').parentElement as HTMLElement);
  expect(alert.getByText('Mandatary couldn’t confirm the result')).toBeTruthy();
  expect(alert.getByText(/may or may not have been saved/)).toBeTruthy();
  expect(screen.queryByText(/Nothing was changed/)).toBeNull();
  fireEvent.click(alert.getByRole('button', { name: 'Reload the list' }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

test('every refusal reason has its own plain-language title and says what to do', () => {
  const titles = new Map([
    ['denied', 'That change wasn’t allowed'],
    ['not_found', 'That no longer exists'],
    ['conflict', 'That conflicts with what exists'],
    ['invalid', 'That wasn’t accepted'],
    ['rate_limited', 'Too many attempts'],
  ] as const);
  for (const [reason, title] of titles) {
    const { unmount } = mount(<UsersScreen {...usersProps({ mutation: { kind: 'rejected', reason } })} />);
    expect(screen.getByRole('alert').textContent, reason).toContain(title);
    unmount();
  }
});

test('names are rendered as text: markup in a username cannot create elements', () => {
  const hostile = [{ ...(users[3] as (typeof users)[number]), id: 'u-x', username: '<img src=x onerror=alert(1)>' }];
  const { container } = mount(<UsersScreen {...usersProps({ load: { kind: 'ready', data: hostile } })} />);
  expect(container.querySelector('img')).toBeNull();
  expect(screen.getByRole('heading', { level: 3 }).textContent).toBe('<img src=x onerror=alert(1)>');
});

test('the rules link names its subject for screen readers', () => {
  mount(<UsersScreen {...usersProps({ rulesHref: (subject) => `/policy?${subject.kind}=${subject.id}` })} />);
  const link = row('sample-sam').getByRole('link');
  expect(link.getAttribute('href')).toBe('/policy?user=u-sam');
  expect(link.textContent).toBe('View rules for sample-sam');
});

// ───────────────────────── groups ─────────────────────────

test('membership and ownership are explained as different things, and an empty group says its rules reach nobody', () => {
  mount(<GroupsScreen {...groupsProps()} />);
  expect(screen.getByText(/Owning an agent doesn’t make it a member/)).toBeTruthy();
  expect(within(screen.getByRole('region', { name: 'Members of sample-empty' })).getByText(/rules for this group apply to nobody/)).toBeTruthy();
});

test('a restored membership is labelled and says it grants nothing until approved', () => {
  mount(<GroupsScreen {...groupsProps()} />);
  const members = within(screen.getByRole('region', { name: 'Members of sample-ops' }));
  expect(members.getByText('Membership waiting for approval')).toBeTruthy();
  expect(members.getByText(/grants nothing until it is approved explicitly/)).toBeTruthy();
});

test('removing a member warns that the group’s Deny rules stop applying too, and confirms by name', () => {
  const onAskRemoveMember = vi.fn();
  const onConfirm = vi.fn();
  const { rerender } = mount(<GroupsScreen {...groupsProps({ onAskRemoveMember })} />);
  fireEvent.click(screen.getByRole('button', { name: 'Remove sample-ci-runner from sample-ops' }));
  expect(onAskRemoveMember).toHaveBeenCalledExactlyOnceWith('g-ops', 'agent', 'a-ci');
  rerender(
    <ThemeProvider>
      <GroupsScreen {...groupsProps({ pending: { action: 'remove_member', id: 'g-ops', kind: 'agent', memberId: 'a-ci' }, onConfirm })} />
    </ThemeProvider>,
  );
  const group = screen.getByRole('group', { name: 'Remove sample-ci-runner from sample-ops?' });
  expect(group.textContent).toContain('that includes any Deny rules');
  expect(group.textContent).toContain('may gain access that another rule allows');
  fireEvent.click(within(group).getByRole('button', { name: 'Remove sample-ci-runner' }));
  expect(onConfirm).toHaveBeenCalledTimes(1);
});

test('the add-member list offers users and agents in groups, leaves out existing members, and keeps disabled accounts visible but unavailable', () => {
  mount(<GroupsScreen {...groupsProps()} />);
  const form = screen.getByRole('form', { name: 'Add a member to sample-ops' });
  const select = within(form).getByLabelText('Add a member') as HTMLSelectElement;
  expect(Array.from(select.querySelectorAll('optgroup'), (group) => group.label)).toEqual(['Users', 'Agents']);
  const labels = Array.from(select.querySelectorAll('option'), (option) => option.textContent);
  expect(labels).toEqual(['Choose a user or agent', 'sample-admin', 'sample-robin (disabled)', 'sample-fresh', 'sample-billing-bot']);
  expect((within(select).getByRole('option', { name: 'sample-robin (disabled)' }) as HTMLOptionElement).disabled).toBe(true);
});

test('adding a member with nothing chosen is refused inline; choosing an agent reports kind and id once', () => {
  const onAddMember = vi.fn();
  mount(<GroupsScreen {...groupsProps({ onAddMember })} />);
  const form = screen.getByRole('form', { name: 'Add a member to sample-ops' });
  expect(fireEvent.submit(form)).toBe(false);
  expect(within(form).getByText('Choose who to add.')).toBeTruthy();
  expect(onAddMember).not.toHaveBeenCalled();
  fireEvent.change(within(form).getByLabelText('Add a member'), { target: { value: 'agent:a-billing' } });
  fireEvent.submit(form);
  expect(onAddMember).toHaveBeenCalledExactlyOnceWith({ groupId: 'g-ops', kind: 'agent', memberId: 'a-billing' });
});

test('disabling a group warns that Deny rules in it may stop applying', () => {
  mount(<GroupsScreen {...groupsProps({ pending: { action: 'disable', id: 'g-ops' } })} />);
  const group = screen.getByRole('group', { name: 'Disable sample-ops?' });
  expect(group.textContent).toContain('Deny rules in it may stop applying too');
});

test('a group with members cannot be deleted and says what is in the way', () => {
  mount(<GroupsScreen {...groupsProps()} />);
  const ops = screen.getByRole('heading', { level: 3, name: 'sample-ops' }).closest('li') as HTMLElement;
  expect((within(ops).getByRole('button', { name: 'Delete sample-ops' }) as HTMLButtonElement).disabled).toBe(true);
  expect(within(ops).getByText(/has 3 members; owns agent sample-billing-bot; has 1 rule/)).toBeTruthy();
});

test('creating a group applies the same name rule and clears when done', () => {
  const onCreate = vi.fn();
  mount(<GroupsScreen {...groupsProps({ onCreate })} />);
  const form = screen.getByRole('form', { name: 'Add a group' });
  type('Group name', '-bad');
  fireEvent.submit(form);
  expect(onCreate).not.toHaveBeenCalled();
  type('Group name', 'sample-new');
  fireEvent.submit(form);
  expect(onCreate).toHaveBeenCalledExactlyOnceWith({ name: 'sample-new' });
});

// ───────────────────────── agents ─────────────────────────

test('an agent shows its owner as accountability only and never offers to issue or reveal a token', () => {
  const { container } = mount(<AgentsScreen {...agentsProps()} />);
  const ci = row('sample-ci-runner');
  expect(ci.getByText(/Accountability only/)).toBeTruthy();
  expect(ci.getByText('1 token usable now', { exact: false })).toBeTruthy();
  const link = ci.getByRole('link');
  expect(link.getAttribute('href')).toBe('/agents?agent=a-ci');
  expect(link.textContent).toBe('Manage tokens for sample-ci-runner');
  expect(screen.queryByRole('button', { name: /issue|rotate|reveal|copy/i })).toBeNull();
  expect(container.querySelector('[class*="secret"]')).toBeNull();
});

test('creating an agent needs a name and exactly one owner; nothing is sent until both are valid', () => {
  const onCreate = vi.fn();
  mount(<AgentsScreen {...agentsProps({ onCreate })} />);
  const form = screen.getByRole('form', { name: 'Add an agent' });
  fireEvent.submit(form);
  expect(onCreate).not.toHaveBeenCalled();
  type('Agent name', 'sample-new-bot');
  fireEvent.submit(form);
  expect(onCreate).not.toHaveBeenCalled();
  expect(within(form).getByText('Choose the owning user.')).toBeTruthy();
});

test('the owner is a user XOR a group: the payload carries exactly one owner, and switching kind changes which list is offered', () => {
  const onCreate = vi.fn();
  mount(<AgentsScreen {...agentsProps({ onCreate })} />);
  const form = screen.getByRole('form', { name: 'Add an agent' });
  type('Agent name', 'sample-new-bot');
  const owners = within(form).getByLabelText('Owning user') as HTMLSelectElement;
  expect(Array.from(owners.querySelectorAll('option'), (option) => option.textContent)).toEqual(['Choose a user', 'sample-admin', 'sample-sam']);
  fireEvent.click(within(form).getByRole('radio', { name: /A group/ }));
  const groupsSelect = within(form).getByLabelText('Owning group') as HTMLSelectElement;
  expect(Array.from(groupsSelect.querySelectorAll('option'), (option) => option.textContent)).toEqual(['Choose a group', 'sample-ops']);
  fireEvent.change(groupsSelect, { target: { value: 'g-ops' } });
  fireEvent.submit(form);
  expect(onCreate).toHaveBeenCalledExactlyOnceWith({ name: 'sample-new-bot', owner: { kind: 'group', id: 'g-ops' } });
});

test('disabled owners are never offered, and the page says owning an agent gives no access', () => {
  mount(<AgentsScreen {...agentsProps()} />);
  const form = screen.getByRole('form', { name: 'Add an agent' });
  expect(within(form).queryByRole('option', { name: /sample-robin/ })).toBeNull();
  expect(within(form).queryByRole('option', { name: /sample-contractors/ })).toBeNull();
  expect(within(form).getByText(/Owning it gives neither the owner nor the agent any access/)).toBeTruthy();
});

test('when no user is active the group owner is preselected so the form is never stuck on an empty choice', () => {
  mount(<AgentsScreen {...agentsProps({ load: { kind: 'ready', data: { agents: [], owners: { users: [{ id: 'u-robin', name: 'sample-robin', state: 'disabled' }], groups: agents.owners.groups } } } })} />);
  const form = screen.getByRole('form', { name: 'Add an agent' });
  expect((within(form).getByRole('radio', { name: /A group/ }) as HTMLInputElement).checked).toBe(true);
  expect(within(form).getByLabelText('Owning group')).toBeTruthy();
});

test('changing an owner says only accountability changes, excludes the current owner, and sends one owner', () => {
  const onTransferOwner = vi.fn();
  const onCancel = vi.fn();
  mount(<AgentsScreen {...agentsProps({ pending: { action: 'transfer', id: 'a-ci' }, onTransferOwner, onCancel })} />);
  const form = screen.getByRole('form', { name: 'Change the owner of sample-ci-runner' });
  expect(form.textContent).toContain('Only who is accountable changes');
  expect(form.textContent).toContain('keeps exactly the access it has now');
  const select = within(form).getByLabelText('Owning user') as HTMLSelectElement;
  expect(Array.from(select.querySelectorAll('option'), (option) => option.textContent)).toEqual(['Choose a user', 'sample-admin']);
  fireEvent.submit(form);
  expect(onTransferOwner).not.toHaveBeenCalled();
  fireEvent.change(select, { target: { value: 'u-admin' } });
  fireEvent.submit(form);
  expect(onTransferOwner).toHaveBeenCalledExactlyOnceWith({ agentId: 'a-ci', owner: { kind: 'user', id: 'u-admin' } });
  fireEvent.keyDown(form, { key: 'Escape' });
  expect(onCancel).toHaveBeenCalledTimes(1);
  expect(document.activeElement?.id).toBe('agent-a-ci-transfer');
});

test('disabling an agent says its tokens are revoked for good and that rules naming it grant nothing', () => {
  mount(<AgentsScreen {...agentsProps({ pending: { action: 'disable', id: 'a-ci' } })} />);
  const group = screen.getByRole('group', { name: 'Disable sample-ci-runner?' });
  expect(group.textContent).toContain('Every token for sample-ci-runner is revoked for good');
  expect(group.textContent).toContain('grant nothing');
});

test('a disabled agent offers Enable only when the backend supports it', () => {
  mount(<AgentsScreen {...agentsProps({ actions: ['disable'] })} />);
  expect(row('sample-retired').queryByRole('button', { name: 'Enable sample-retired' })).toBeNull();
  cleanup();
  mount(<AgentsScreen {...agentsProps()} />);
  expect(row('sample-retired').getByRole('button', { name: 'Enable sample-retired' })).toBeTruthy();
});

// ───────────────────────── structure, both themes, no leakage ─────────────────────────

const SCREENS: ReadonlyArray<readonly [string, () => ReactElement]> = [
  ['users', () => <UsersScreen {...usersProps({ pending: { action: 'disable', id: 'u-sam' } })} />],
  ['groups', () => <GroupsScreen {...groupsProps({ pending: { action: 'remove_member', id: 'g-ops', kind: 'user', memberId: 'u-sam' } })} />],
  ['agents', () => <AgentsScreen {...agentsProps({ pending: { action: 'transfer', id: 'a-ci' } })} />],
];

for (const theme of ['light', 'dark'] as const) {
  for (const [name, screenElement] of SCREENS) {
    test(`${name} (${theme}): one h1, no skipped heading level, every control named, ids unique, no inline style`, () => {
      const { container } = mount(screenElement(), theme);
      expect(document.documentElement.dataset.theme).toBe(theme);
      const levels = Array.from(container.querySelectorAll('h1, h2, h3, h4'), (heading) => Number(heading.tagName.slice(1)));
      expect(levels.filter((level) => level === 1)).toHaveLength(1);
      levels.forEach((level, index) => {
        if (index > 0) expect(level - (levels[index - 1] ?? 0), `heading ${index}`).toBeLessThanOrEqual(1);
      });
      for (const input of container.querySelectorAll<HTMLInputElement | HTMLSelectElement>('input, select')) {
        expect((input.labels?.length ?? 0) > 0 || input.hasAttribute('aria-label'), `unlabelled ${input.tagName} ${input.name}`).toBe(true);
      }
      for (const button of container.querySelectorAll('button')) {
        expect((button.textContent ?? '').trim() !== '' || button.hasAttribute('aria-label'), 'nameless button').toBe(true);
      }
      const ids = Array.from(container.querySelectorAll('[id]'), (element) => element.id);
      expect(ids.filter((id, index) => ids.indexOf(id) !== index)).toEqual([]);
      expect(container.querySelectorAll('[style]')).toHaveLength(0);
    });
  }
}

test('row action buttons are told apart by name: no two Disable or Delete buttons read the same', () => {
  mount(<UsersScreen {...usersProps()} />);
  for (const verb of ['Disable', 'Enable', 'Delete']) {
    const names = screen.queryAllByRole('button').map((button) => button.getAttribute('aria-label') ?? '').filter((label) => label.startsWith(`${verb} `));
    expect(names.length, verb).toBeGreaterThan(0);
    expect(new Set(names).size, verb).toBe(names.length);
  }
});

test('rendering the management screens reads and writes no storage, makes no request and has no password field', () => {
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  for (const [, screenElement] of SCREENS) {
    const { container, unmount } = mount(screenElement());
    expect(container.querySelector('input[type="password"]')).toBeNull();
    unmount();
  }
  expect(setItem).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(document.cookie).toBe('');
  vi.unstubAllGlobals();
});
