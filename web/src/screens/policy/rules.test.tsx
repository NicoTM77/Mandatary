import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { inventory, rules, rulesData, rulesDataEmpty, rulesDataUnverified } from '../../gallery/policyFixtures';
import { ThemeProvider } from '../../theme';
import type { RulesScreenProps } from './contract';
import { RulesScreen, needsAttention, ruleConsequence } from './rules';
import { EMPTY_SELECTOR, selectorKey } from './selector';

afterEach(cleanup);

// jsdom has no layout and no scrollIntoView. Every real browser does, and the editor calls it after a failed submit.
beforeEach(() => {
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, writable: true, value: () => undefined });
});

const noop = () => undefined;

const props = (patch: Partial<RulesScreenProps> = {}): RulesScreenProps => ({
  load: { kind: 'ready', data: rulesData },
  mutation: { kind: 'idle' },
  editor: { kind: 'closed' },
  pending: null,
  preview: { kind: 'idle' },
  onRetry: noop,
  onNew: noop,
  onEdit: noop,
  onCloseEditor: noop,
  onSubmit: noop,
  onPreview: noop,
  onAsk: noop,
  onCancel: noop,
  onConfirm: noop,
  ...patch,
});

function mount(ui: ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

function rule(id: string) {
  const found = rules.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`fixture ${id}`);
  return found;
}

function rowOf(sentence: string | RegExp) {
  const item = screen.getByRole('heading', { level: 3, name: sentence }).closest('li');
  if (!item) throw new Error(`no row for ${String(sentence)}`);
  return within(item);
}

function type(label: string | RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

// ───────────────────────── page-level states ─────────────────────────

test('the rules page says a rule is the only thing that grants access, and that the default is refusal', () => {
  mount(<RulesScreen {...props()} />);
  expect(screen.getByRole('heading', { level: 1, name: 'Rules' })).toBeTruthy();
  expect(screen.getByText('Managing access isn’t the same as having it')).toBeTruthy();
  expect(screen.getByText(/With no matching Allow, every request is refused/)).toBeTruthy();
});

test('the decision order is available, names Deny-over-Allow, and says the administrator role and ownership allow nothing', () => {
  mount(<RulesScreen {...props()} />);
  const summary = screen.getByText('How Mandatary decides a request');
  const details = summary.closest('details') as HTMLDetailsElement;
  expect(details.open).toBe(false);
  expect(details.textContent).toContain('If any Deny matches');
  expect(details.textContent).toContain('The administrator role and owning an agent are not in this list: neither allows anything');
});

test('loading, failure and denial of the rules page show no rules, no form and no Add button', () => {
  for (const kind of ['loading', 'failed', 'denied'] as const) {
    const { unmount } = mount(<RulesScreen {...props({ load: { kind } })} />);
    expect(screen.queryByRole('button', { name: 'Add a rule' }), kind).toBeNull();
    expect(screen.queryByRole('form'), kind).toBeNull();
    expect(screen.queryByRole('listitem'), kind).toBeNull();
    unmount();
  }
  mount(<RulesScreen {...props({ load: { kind: 'denied' } })} />);
  expect(screen.getByRole('alert').textContent).toContain('Only the policy administrator, signed in with a second factor');
});

test('no rules yet is explained as default deny and offers the first rule', () => {
  const onNew = vi.fn();
  mount(<RulesScreen {...props({ load: { kind: 'ready', data: rulesDataEmpty }, onNew })} />);
  expect(screen.getByText(/every container request is refused. That includes the policy administrator’s own/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Add the first rule' }));
  expect(onNew).toHaveBeenCalledTimes(1);
});

test('when Mandatary cannot verify itself the page says every operation is refused and no status is presented as a match', () => {
  mount(<RulesScreen {...props({ load: { kind: 'ready', data: rulesDataUnverified } })} />);
  expect(screen.getByRole('alert').textContent).toContain('Mandatary can’t verify its own container');
  expect(screen.getByRole('alert').textContent).toContain('every container operation on this endpoint is refused, whatever the rules say');
  expect(screen.queryByText(/Matches \d+ container/)).toBeNull();
  expect(screen.getAllByText('Target status unknown').length).toBe(rulesDataUnverified.rules.length);
});

// ───────────────────────── explicit grants and denials ─────────────────────────

test('every rule reads as one sentence, and Allow and Deny are told apart by word and icon, not colour', () => {
  mount(<RulesScreen {...props()} />);
  expect(screen.getByRole('heading', { level: 3, name: 'Allow agent sample-ci-runner to read logs of sample-edge-proxy' })).toBeTruthy();
  const deny = rowOf('Deny group sample-contractors from stopping containers matching sample-db*');
  expect(deny.getByText('Deny')).toBeTruthy();
  expect(deny.queryByText('Allow')).toBeNull();
  const denyBadge = deny.getByText('Deny').closest('span') as HTMLElement;
  expect(denyBadge.querySelector('svg')).not.toBeNull();
});

test('a rule shows its identity checks and limits, or says the name alone decides', () => {
  mount(<RulesScreen {...props()} />);
  const guarded = rowOf('Allow agent sample-ci-runner to read logs of sample-edge-proxy');
  expect(guarded.getByText('Compose project sample-shop')).toBeTruthy();
  expect(guarded.getByText('Compose service edge')).toBeTruthy();
  expect(guarded.getByText('at most 500 log lines per request')).toBeTruthy();
  expect(rowOf('Deny group sample-contractors from stopping containers matching sample-db*').getByText('No identity checks: the name alone decides.')).toBeTruthy();
  expect(rowOf('Allow user sample-sam to inspect the configuration of sample-edge-proxy').getByText(/Container ID a1a1a1a1a1a1…/)).toBeTruthy();
});

test('an Allow that reaches a pattern of containers with no identity check is flagged on its row', () => {
  mount(<RulesScreen {...props()} />);
  expect(rowOf('Allow group sample-ops to start containers matching sample-*').getByText('Pattern, no identity check')).toBeTruthy();
  expect(rowOf('Allow group sample-ops to view the status of containers matching sample-*').queryByText('Pattern, no identity check')).toBeNull();
});

test('the administrator is shown on their own rule, so a rule is visibly the only thing that grants the account access', () => {
  mount(<RulesScreen {...props()} />);
  expect(rowOf('Allow user sample-admin to view the status of sample-edge-proxy').getByText('Policy administrator')).toBeTruthy();
});

// ───────────────────────── missing targets stay visible ─────────────────────────

test('a rule whose container is gone is kept and flagged as inactive, with what that means for an Allow', () => {
  mount(<RulesScreen {...props()} />);
  const gone = rowOf('Allow agent sample-billing-bot to read logs of sample-old-worker');
  expect(gone.getByText('Inactive · target missing')).toBeTruthy();
  expect(gone.getByText(/this grants nothing and requests for it are refused/)).toBeTruthy();
  expect(gone.getByText(/keeps the rule rather than deleting it/)).toBeTruthy();
});

test('a missing target for a Deny says it blocks nothing yet but will if a match appears', () => {
  const data = { ...rulesData, rules: [{ ...rule('r4'), target: { kind: 'missing' as const } }] };
  mount(<RulesScreen {...props({ load: { kind: 'ready', data } })} />);
  expect(screen.getByText(/this blocks nothing yet/)).toBeTruthy();
});

test('the page summarises missing targets and filters to the rules that need attention', () => {
  mount(<RulesScreen {...props()} />);
  expect(screen.getByText('1 rule points at a container that doesn’t exist')).toBeTruthy();
  expect(screen.getByRole('status', { name: '' }).textContent).toBeDefined();
  fireEvent.click(screen.getByRole('button', { name: 'Show rules that need attention' }));
  const shown = screen.getAllByRole('heading', { level: 3 }).map((heading) => heading.textContent);
  expect(shown).toEqual([
    'Allow agent sample-billing-bot to read logs of sample-old-worker',
    'Allow user sample-sam to inspect the configuration of sample-edge-proxy',
    'Allow user sample-restored to start sample-db',
  ]);
  expect(screen.getByText('Showing 3 of 9')).toBeTruthy();
  expect((screen.getByLabelText(/Needs attention only/) as HTMLInputElement).checked).toBe(true);
});

test('needsAttention is true for missing, unknown, disabled and waiting rules and false for an active rule that matches', () => {
  expect(rules.filter(needsAttention).map((candidate) => candidate.id)).toEqual(['r5', 'r6', 'r8']);
});

test('filters narrow by decision and subject kind, report the count, and can be cleared', () => {
  mount(<RulesScreen {...props()} />);
  fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'deny' } });
  expect(screen.getByText('Showing 1 of 9')).toBeTruthy();
  fireEvent.change(screen.getByLabelText('For'), { target: { value: 'user' } });
  expect(screen.getByText('No rules match these filters')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
  expect(screen.getByText('Showing 9 of 9')).toBeTruthy();
});

// ───────────────────────── rule states and lifecycle ─────────────────────────

test('a disabled rule offers Enable, an active one Disable, and a restored one only Delete (it cannot be edited into force)', () => {
  mount(<RulesScreen {...props()} />);
  const disabled = rowOf('Allow user sample-sam to inspect the configuration of sample-edge-proxy');
  expect(disabled.getByText('Disabled')).toBeTruthy();
  expect(disabled.getByRole('button', { name: /^Enable:/ })).toBeTruthy();
  expect(disabled.queryByRole('button', { name: /^Disable:/ })).toBeNull();
  const restored = rowOf('Allow user sample-restored to start sample-db');
  expect(restored.getByText('Waiting for approval', { selector: 'span' })).toBeTruthy();
  expect(restored.getByText(/grants and blocks nothing until it is approved explicitly/)).toBeTruthy();
  expect(restored.queryByRole('button', { name: /^Edit:/ })).toBeNull();
  expect(restored.queryByRole('button', { name: /^Disable:/ })).toBeNull();
  expect(restored.queryByRole('button', { name: /^Enable:/ })).toBeNull();
  expect(restored.getByRole('button', { name: /^Delete:/ })).toBeTruthy();
});

test('row buttons carry the whole rule sentence so each is distinguishable by name', () => {
  const onAsk = vi.fn();
  const onEdit = vi.fn();
  mount(<RulesScreen {...props({ onAsk, onEdit })} />);
  const names = screen.getAllByRole('button', { name: /^Delete:/ }).map((button) => button.getAttribute('aria-label'));
  expect(new Set(names).size).toBe(names.length);
  fireEvent.click(screen.getByRole('button', { name: 'Edit: Allow agent sample-ci-runner to read logs of sample-edge-proxy' }));
  expect(onEdit).toHaveBeenCalledExactlyOnceWith('r1');
  fireEvent.click(screen.getByRole('button', { name: 'Delete: Allow agent sample-ci-runner to read logs of sample-edge-proxy' }));
  expect(onAsk).toHaveBeenCalledExactlyOnceWith('delete', 'r1');
});

test('the consequence of each lifecycle action says whether it loosens or tightens access', () => {
  const allow = rule('r1');
  const deny = rule('r4');
  expect(ruleConsequence(allow, 'disable')).toMatchObject({ loosens: false });
  expect(ruleConsequence(allow, 'delete')).toMatchObject({ loosens: false });
  expect(ruleConsequence(allow, 'enable')).toMatchObject({ loosens: true });
  expect(ruleConsequence(deny, 'enable')).toMatchObject({ loosens: false });
  expect(ruleConsequence(deny, 'disable')).toMatchObject({ loosens: true });
  expect(ruleConsequence(deny, 'delete')).toMatchObject({ loosens: true });
  expect(ruleConsequence(allow, 'disable').text).toContain('streams that are open now');
  expect(ruleConsequence(deny, 'delete').text).toContain('becomes possible again');
});

test('deleting a Deny is a warning (it loosens access), deleting an Allow is danger (it ends access); both name the rule', () => {
  const sentence = 'Deny group sample-contractors from stopping containers matching sample-db*';
  const { unmount } = mount(<RulesScreen {...props({ pending: { action: 'delete', id: 'r4' } })} />);
  const warn = screen.getByRole('group', { name: `Delete “${sentence}”?` });
  expect(warn.className).toContain('border-warn');
  expect(warn.textContent).toContain('This permanently removes the rule.');
  expect(warn.textContent).toContain('anything an Allow rule permits becomes possible again');
  unmount();
  mount(<RulesScreen {...props({ pending: { action: 'disable', id: 'r1' } })} />);
  const danger = screen.getByRole('group', { name: 'Disable “Allow agent sample-ci-runner to read logs of sample-edge-proxy”?' });
  expect(danger.className).toContain('border-danger');
  expect(danger.textContent).toContain('This access ends straight away, including streams that are open now');
});

test('confirming and cancelling report once, and Escape returns focus to the button that opened the confirmation', () => {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  mount(<RulesScreen {...props({ pending: { action: 'delete', id: 'r1' }, onConfirm, onCancel })} />);
  const group = screen.getByRole('group', { name: /^Delete “Allow agent sample-ci-runner/ });
  fireEvent.click(within(group).getByRole('button', { name: 'Delete rule' }));
  expect(onConfirm).toHaveBeenCalledTimes(1);
  fireEvent.keyDown(group, { key: 'Escape' });
  expect(onCancel).toHaveBeenCalledTimes(1);
  expect(document.activeElement?.id).toBe('rule-r1-delete');
});

test('an outcome that could not be confirmed appears on the rule it was about and offers a reload', () => {
  const onRetry = vi.fn();
  mount(<RulesScreen {...props({ mutation: { kind: 'rejected', reason: 'outcome_unknown', target: 'r3' }, onRetry })} />);
  const row = rowOf('Allow agent sample-ci-runner to restart sample-edge-proxy');
  expect(row.getByText('Mandatary couldn’t confirm the result')).toBeTruthy();
  fireEvent.click(row.getByRole('button', { name: 'Reload the list' }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

// ───────────────────────── editor: create ─────────────────────────

function openEditor(patch: Partial<RulesScreenProps> = {}) {
  return mount(<RulesScreen {...props({ editor: { kind: 'create' }, ...patch })} />);
}

test('while the editor is open the Add button is gone and the form is named', () => {
  openEditor();
  expect(screen.queryByRole('button', { name: 'Add a rule' })).toBeNull();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  expect(form.getAttribute('method')).toBe('post');
  expect(form.hasAttribute('action')).toBe(false);
});

test('submitting a blank rule explains every missing part inline, focuses the first and sends nothing', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  expect(fireEvent.submit(form)).toBe(false);
  expect(within(form).getByText('Choose the agent this rule is for.')).toBeTruthy();
  expect(within(form).getByText('Choose at least one operation.')).toBeTruthy();
  expect(within(form).getByText('Enter the container name.')).toBeTruthy();
  expect(document.activeElement).toBe(within(form).getByLabelText('Agent'));
  expect(onSubmit).not.toHaveBeenCalled();
});

test('focus moves to the first problem only AFTER the error text is on the page, so the browser scrolls against the final layout', () => {
  // Focusing first and inserting the messages afterwards makes the form grow after the browser has already chosen its scroll position.
  // Focusing against the finished layout keeps the focused field where the browser put it.
  const seen: Array<{ target: string | null; messagesPresent: boolean; invalid: number }> = [];
  const original = HTMLElement.prototype.focus;
  HTMLElement.prototype.focus = function focusSpy(this: HTMLElement, options?: FocusOptions) {
    seen.push({ target: this.getAttribute('name'), messagesPresent: document.body.textContent?.includes('Choose at least one operation.') ?? false, invalid: document.querySelectorAll('[aria-invalid="true"]').length });
    original.call(this, options);
  };
  try {
    openEditor();
    seen.length = 0;
    fireEvent.submit(screen.getByRole('form', { name: 'Add a rule' }));
  } finally {
    HTMLElement.prototype.focus = original;
  }
  const first = seen.find((entry) => entry.target === 'subject');
  expect(first).toBeDefined();
  expect(first?.messagesPresent).toBe(true);
  expect(first?.invalid).toBeGreaterThanOrEqual(2);
});

test('the first problem is centred in the window rather than left wherever the browser happens to scroll, so the sticky header cannot cover it', () => {
  // Engines disagree about where a focused field ends up (WebKit left it under the 64px header in the browser run); an explicit
  // instant, centred scroll after focusing makes the position the same everywhere.
  const scroll = vi.fn();
  const focusOptions: Array<FocusOptions | undefined> = [];
  const originalFocus = HTMLElement.prototype.focus;
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, writable: true, value: scroll });
  HTMLElement.prototype.focus = function focusSpy(this: HTMLElement, options?: FocusOptions) {
    focusOptions.push(options);
    originalFocus.call(this, options);
  };
  try {
    openEditor();
    focusOptions.length = 0;
    fireEvent.submit(screen.getByRole('form', { name: 'Add a rule' }));
  } finally {
    HTMLElement.prototype.focus = originalFocus;
  }
  expect(scroll).toHaveBeenCalledExactlyOnceWith({ block: 'center', inline: 'nearest', behavior: 'instant' });
  expect(focusOptions.at(-1)).toEqual({ preventScroll: true });
  expect(document.activeElement?.getAttribute('name')).toBe('subject');
});

test('only the six approved operations are offered, and the state-changing ones are marked', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  const boxes = within(form).getAllByRole('checkbox').filter((box) => (box.getAttribute('name') ?? '').startsWith('operations'));
  expect(boxes).toHaveLength(6);
  expect(within(form).getAllByText('Changes the container')).toHaveLength(3);
  expect(within(form).queryByLabelText(/exec|shell|raw/i)).toBeNull();
});

test('the whole draft is sent once, at submit: subject, effect, one entry per operation, normalised selector, only applicable caps', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  fireEvent.click(within(form).getByLabelText(/^Read logs/));
  fireEvent.click(within(form).getByLabelText(/^Restart/));
  type('Container name', '  sample-edge-proxy ');
  type('Compose project', 'sample-shop');
  type(/Most log lines/, '500');
  type(/Longest stop timeout/, '30');
  expect(within(form).getByText('This adds 2 rules')).toBeTruthy();
  expect(within(form).getByText('Allow agent sample-ci-runner to read logs of sample-edge-proxy')).toBeTruthy();
  expect(within(form).getByText('Allow agent sample-ci-runner to restart sample-edge-proxy')).toBeTruthy();
  fireEvent.click(within(form).getByRole('button', { name: 'Add 2 rules' }));
  expect(onSubmit).toHaveBeenCalledExactlyOnceWith(
    {
      subject: { kind: 'agent', id: 'a-ci' },
      effect: 'allow',
      operations: ['container:logs', 'container:restart'],
      selector: { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy', composeProject: 'sample-shop' },
      caps: { logTailMax: 500, stopTimeoutMax: 30 },
      acknowledgedBroad: false,
    },
    null,
  );
});

test('a ceiling is offered only for operations that accept it, and is dropped when its operation is unticked', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.click(within(form).getByLabelText(/^Start\s*Changes/));
  expect(within(form).queryByLabelText(/Most log lines/)).toBeNull();
  expect(within(form).queryByLabelText(/Longest stop timeout/)).toBeNull();
  fireEvent.click(within(form).getByLabelText(/^Read logs/));
  type(/Most log lines/, '200');
  fireEvent.click(within(form).getByLabelText(/^Read logs/));
  expect(within(form).queryByLabelText(/Most log lines/)).toBeNull();
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  type('Container name', 'sample-db');
  fireEvent.submit(form);
  expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({ operations: ['container:start'], caps: { logTailMax: null, stopTimeoutMax: null } });
});

test('a ceiling outside the range the evaluator accepts is refused on its field', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  fireEvent.click(within(form).getByLabelText(/^Stop/));
  type('Container name', 'sample-db');
  type(/Longest stop timeout/, '301');
  fireEvent.submit(form);
  expect(within(form).getByText('Use a whole number from 1 to 300.')).toBeTruthy();
  expect(document.activeElement).toBe(within(form).getByLabelText(/Longest stop timeout/));
  expect(onSubmit).not.toHaveBeenCalled();
});

test('an exact name that contains pattern characters is refused until it is marked as a pattern', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  fireEvent.click(within(form).getByLabelText(/^View status/));
  type('Container name', 'sample-*');
  fireEvent.submit(form);
  expect(within(form).getByText(/This looks like a pattern/)).toBeTruthy();
  fireEvent.click(within(form).getByLabelText(/^Match as a pattern/));
  fireEvent.submit(form);
  expect(onSubmit).toHaveBeenCalledTimes(1);
});

test('an invalid identity check opens the disclosure that holds it and focuses it', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  fireEvent.click(within(form).getByLabelText(/^View status/));
  type('Container name', 'sample-edge-proxy');
  const details = within(form).getByText('Identity checks (recommended)').closest('details') as HTMLDetailsElement;
  expect(details.open).toBe(false);
  fireEvent.change(within(form).getByLabelText(/Pin to one container ID/), { target: { value: 'abc' } });
  fireEvent.submit(form);
  expect(details.open).toBe(true);
  expect(document.activeElement).toBe(within(form).getByLabelText(/Pin to one container ID/));
  expect(within(form).getByText('Use exactly 64 hexadecimal characters.')).toBeTruthy();
});

// ───────────────────────── editor: guardrails ─────────────────────────

test('a broad Allow shows the guardrail summary and cannot be saved until the person ticks that they mean it', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  fireEvent.click(within(form).getByLabelText(/^Start\s*Changes/));
  type('Container name', '*');
  fireEvent.click(within(form).getByLabelText(/^Match as a pattern/));
  expect(within(form).getByText('Broad: every container on this endpoint')).toBeTruthy();
  expect(within(form).getByText(/Mandatary itself and its peer containers are never reachable/)).toBeTruthy();
  fireEvent.submit(form);
  expect(within(form).getByText('Tick the box to confirm you mean this.')).toBeTruthy();
  expect(onSubmit).not.toHaveBeenCalled();
  fireEvent.click(within(form).getByLabelText(/I understand this allows changing every container/));
  fireEvent.submit(form);
  expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({ acknowledgedBroad: true, selector: { containerName: '*', nameIsPattern: true } });
});

test('the same broad pattern as a Deny needs no acknowledgement: blocking more is not a risk to confirm', () => {
  const onSubmit = vi.fn();
  openEditor({ onSubmit });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Agent'), { target: { value: 'a-ci' } });
  fireEvent.click(within(form).getByLabelText(/^Start\s*Changes/));
  fireEvent.click(within(form).getByRole('radio', { name: /^Deny/ }));
  type('Container name', '*');
  fireEvent.click(within(form).getByLabelText(/^Match as a pattern/));
  expect(within(form).getByText('Blocks every container on this endpoint')).toBeTruthy();
  expect(within(form).queryByLabelText(/I understand/)).toBeNull();
  fireEvent.submit(form);
  expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({ effect: 'deny', acknowledgedBroad: false });
});

test('a name-only selector warns that a different image under that name would match', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  type('Container name', 'sample-edge-proxy');
  expect(within(form).getByText('Name only')).toBeTruthy();
  expect(within(form).getByText(/A different image started under this name would match too/)).toBeTruthy();
  type('Compose project', 'sample-shop');
  expect(within(form).getByText('Guarded: the name plus identity checks')).toBeTruthy();
});

test('starting from a running container fills its name and Compose labels, and opens the identity checks', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.change(within(form).getByLabelText('Start from a running container'), { target: { value: 'sample-edge-proxy' } });
  expect((within(form).getByLabelText('Container name') as HTMLInputElement).value).toBe('sample-edge-proxy');
  expect((within(form).getByLabelText('Compose project') as HTMLInputElement).value).toBe('sample-shop');
  expect((within(form).getByLabelText('Compose service') as HTMLInputElement).value).toBe('edge');
  expect((within(form).getByText('Identity checks (recommended)').closest('details') as HTMLDetailsElement).open).toBe(true);
});

test('a disclosure the person opened stays open when a field inside it is emptied again', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  const details = within(form).getByText('Identity checks (recommended)').closest('details') as HTMLDetailsElement;
  details.open = true;
  fireEvent(details, new Event('toggle'));
  type('Compose project', 'p');
  type('Compose project', '');
  expect(details.open).toBe(true);
});

test('the policy administrator is offered like anyone else, labelled, with a note that the role grants nothing', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.click(within(form).getByRole('radio', { name: /A user/ }));
  expect(within(form).getByRole('option', { name: 'sample-admin (policy administrator)' })).toBeTruthy();
  fireEvent.change(within(form).getByLabelText('User'), { target: { value: 'u-admin' } });
  expect(within(form).getByText('This is the policy administrator')).toBeTruthy();
  expect(within(form).getByText(/allows no container operation. This rule would be the only thing that gives this account any/)).toBeTruthy();
});

test('a disabled account stays visible in the picker but cannot be chosen', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  fireEvent.click(within(form).getByRole('radio', { name: /A user/ }));
  const option = within(form).getByRole('option', { name: 'sample-robin (disabled)' }) as HTMLOptionElement;
  expect(option.disabled).toBe(true);
});

test('the endpoint is stated, fixed, and Mandatary itself is said to be untargetable', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  expect(within(form).getByText(/Local \(Docker socket on this host\)/)).toBeTruthy();
  expect(within(form).getByText(/a rule can never reach another/)).toBeTruthy();
  expect(within(form).getByText(/Mandatary and its peer containers are never listed and can’t be targeted/)).toBeTruthy();
  expect(within(form).queryByLabelText(/endpoint/i)).toBeNull();
});

// ───────────────────────── editor: preview ─────────────────────────

test('the preview cannot be requested for an empty or invalid selector, and says why', () => {
  openEditor();
  const form = screen.getByRole('form', { name: 'Add a rule' });
  const check = within(form).getByRole('button', { name: 'Check matches' }) as HTMLButtonElement;
  expect(check.disabled).toBe(true);
  expect(within(form).getByText(/Enter a valid container name to check/)).toBeTruthy();
  type('Container name', 'sample-edge-proxy');
  expect(check.disabled).toBe(false);
});

test('checking sends the normalised selector once; a result for that selector is listed; editing the selector marks it stale and hides it', () => {
  const onPreview = vi.fn();
  const { rerender } = openEditor({ onPreview });
  const form = screen.getByRole('form', { name: 'Add a rule' });
  type('Container name', ' sample-edge-proxy ');
  fireEvent.click(within(form).getByRole('button', { name: 'Check matches' }));
  const checked = { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy' };
  expect(onPreview).toHaveBeenCalledExactlyOnceWith(checked);
  rerender(
    <ThemeProvider>
      <RulesScreen {...props({ editor: { kind: 'create' }, onPreview, preview: { kind: 'ready', forKey: selectorKey(checked), matches: inventory.slice(0, 1) } })} />
    </ThemeProvider>,
  );
  // The typed draft survived the re-render: the container can refresh props (or open a step-up) without costing the administrator their work.
  expect((screen.getByLabelText('Container name') as HTMLInputElement).value).toBe(' sample-edge-proxy ');
  expect(screen.getByText('1 container matches right now.')).toBeTruthy();
  expect(screen.getByText(/registry\.example\.invalid\/sample\/edge:1\.4 · a1a1a1a1a1a1/)).toBeTruthy();
  type('Container name', 'sample-billing-worker');
  expect(screen.getByText(/The selector changed since the last check/)).toBeTruthy();
  expect(screen.queryByText('1 container matches right now.')).toBeNull();
});

test('an empty preview says the rule can still be saved and will show as inactive; an unavailable one says it cannot be checked', () => {
  const { rerender } = openEditor({ preview: { kind: 'ready', forKey: selectorKey({ ...EMPTY_SELECTOR, containerName: '' }), matches: [] } });
  type('Container name', 'x');
  rerender(
    <ThemeProvider>
      <RulesScreen {...props({ editor: { kind: 'create' }, preview: { kind: 'ready', forKey: selectorKey({ ...EMPTY_SELECTOR, containerName: 'x' }), matches: [] } })} />
    </ThemeProvider>,
  );
  expect(screen.getByText('No container matches yet')).toBeTruthy();
  expect(screen.getByText(/show as Inactive · target missing/)).toBeTruthy();
  rerender(
    <ThemeProvider>
      <RulesScreen {...props({ editor: { kind: 'create' }, preview: { kind: 'unavailable' } })} />
    </ThemeProvider>,
  );
  expect(screen.getByText('Matches can’t be checked right now')).toBeTruthy();
});

test('while checking, the button announces progress and stays focusable', () => {
  openEditor({ preview: { kind: 'checking' } });
  const busy = screen.getByRole('button', { name: 'Checking…' });
  expect(busy.getAttribute('aria-busy')).toBe('true');
  expect((busy as HTMLButtonElement).disabled).toBe(false);
});

// ───────────────────────── editor: edit ─────────────────────────

test('editing fixes the subject and operation, prefills the rest, and reports the rule id', () => {
  const onSubmit = vi.fn();
  mount(<RulesScreen {...props({ editor: { kind: 'edit', id: 'r1' }, onSubmit })} />);
  const form = screen.getByRole('form', { name: 'Edit rule' });
  expect(within(form).getByText('sample-ci-runner')).toBeTruthy();
  expect(within(form).queryByRole('checkbox', { name: /^Read logs/ })).toBeNull();
  expect(within(form).queryByLabelText('Agent')).toBeNull();
  expect((within(form).getByLabelText('Container name') as HTMLInputElement).value).toBe('sample-edge-proxy');
  expect((within(form).getByLabelText(/Most log lines/) as HTMLInputElement).value).toBe('500');
  expect((within(form).getByLabelText('Compose project') as HTMLInputElement).value).toBe('sample-shop');
  type(/Most log lines/, '250');
  fireEvent.click(within(form).getByRole('button', { name: 'Save changes' }));
  expect(onSubmit).toHaveBeenCalledExactlyOnceWith(
    {
      subject: { kind: 'agent', id: 'a-ci' },
      effect: 'allow',
      operations: ['container:logs'],
      selector: { ...EMPTY_SELECTOR, containerName: 'sample-edge-proxy', composeProject: 'sample-shop', composeService: 'edge' },
      caps: { logTailMax: 250, stopTimeoutMax: null },
      acknowledgedBroad: false,
    },
    'r1',
  );
});

test('editing a broad Allow still needs the acknowledgement', () => {
  const onSubmit = vi.fn();
  mount(<RulesScreen {...props({ editor: { kind: 'edit', id: 'r9' }, onSubmit })} />);
  const form = screen.getByRole('form', { name: 'Edit rule' });
  fireEvent.submit(form);
  expect(within(form).getByText('Tick the box to confirm you mean this.')).toBeTruthy();
  expect(onSubmit).not.toHaveBeenCalled();
});

test('editing a rule that no longer exists says so instead of opening an empty form', () => {
  const onCloseEditor = vi.fn();
  mount(<RulesScreen {...props({ editor: { kind: 'edit', id: 'gone' }, onCloseEditor })} />);
  expect(screen.queryByRole('form', { name: 'Edit rule' })).toBeNull();
  expect(screen.getByText('That rule no longer exists')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  expect(onCloseEditor).toHaveBeenCalledTimes(1);
});

test('saving shows progress without dropping focus or sending twice; a refusal appears inside the form', () => {
  const onSubmit = vi.fn();
  const { rerender } = mount(<RulesScreen {...props({ editor: { kind: 'edit', id: 'r1' }, mutation: { kind: 'working', target: 'editor' }, onSubmit })} />);
  const save = screen.getByRole('button', { name: 'Saving…' });
  expect(save.getAttribute('aria-busy')).toBe('true');
  fireEvent.click(save);
  expect(onSubmit).not.toHaveBeenCalled();
  expect((screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true);
  rerender(
    <ThemeProvider>
      <RulesScreen {...props({ editor: { kind: 'edit', id: 'r1' }, mutation: { kind: 'rejected', reason: 'denied', target: 'editor' } })} />
    </ThemeProvider>,
  );
  expect(within(screen.getByRole('form', { name: 'Edit rule' })).getByRole('alert').textContent).toContain('That change wasn’t allowed');
});

test('cancelling the editor reports it once', () => {
  const onCloseEditor = vi.fn();
  openEditor({ onCloseEditor });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(onCloseEditor).toHaveBeenCalledTimes(1);
});

// ───────────────────────── structure, both themes, no leakage ─────────────────────────

const VARIANTS: ReadonlyArray<readonly [string, Partial<RulesScreenProps>]> = [
  ['list', {}],
  ['create editor', { editor: { kind: 'create' } }],
  ['edit editor with preview', { editor: { kind: 'edit', id: 'r1' }, preview: { kind: 'ready', forKey: selectorKey(rule('r1').selector), matches: inventory.slice(0, 1) } }],
  ['confirmation', { pending: { action: 'delete', id: 'r4' } }],
];

for (const theme of ['light', 'dark'] as const) {
  for (const [name, patch] of VARIANTS) {
    test(`rules ${name} (${theme}): one h1, no skipped heading, every control named, ids unique, no inline style, no password field`, () => {
      const { container } = mount(<RulesScreen {...props(patch)} />, theme);
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
      expect(container.querySelector('input[type="password"]')).toBeNull();
    });
  }
}

test('hostile container names and subjects render as text only', () => {
  const hostile = { ...rule('r1'), subject: { ...rule('r1').subject, name: '<script>alert(1)</script>' }, selector: { ...rule('r1').selector, containerName: '<img src=x onerror=alert(1)>' } };
  const { container } = mount(<RulesScreen {...props({ load: { kind: 'ready', data: { ...rulesData, rules: [hostile] } } })} />);
  expect(container.querySelector('img')).toBeNull();
  expect(container.querySelector('script')).toBeNull();
  expect(screen.getByRole('heading', { level: 3 }).textContent).toContain('<script>alert(1)</script>');
});

test('rendering and driving the rules screen touches no storage and makes no request', () => {
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  openEditor();
  fireEvent.click(screen.getByLabelText(/^Read logs/));
  type('Container name', 'sample-db');
  expect(setItem).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(document.cookie).toBe('');
  vi.unstubAllGlobals();
});
