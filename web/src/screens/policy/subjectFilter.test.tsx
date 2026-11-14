import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { rules, rulesData } from '../../gallery/policyFixtures';
import { ThemeProvider } from '../../theme';
import type { RuleRow, RulesScreenProps, SubjectRef } from './contract';
import { RulesScreen } from './rules';
import { RULES_PATH, parseSubjectHash, rulesHrefFor } from './subjectFilter';

/**
 * P1.18.4 P117-note-rule-link: the "View rules" link of the identity pages filters the Rules page by a subject's kind and IMMUTABLE id, never by
 * display name. The link is a same-origin path with an allowlisted fragment: no new request, no new authorization surface.
 */

afterEach(cleanup);
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

function mount(ui: React.ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

test('the link is a same-origin path with an allowlisted fragment that names the kind and the immutable id', () => {
  expect(rulesHrefFor({ kind: 'agent', id: 'a-ci' })).toBe('/policy#subject=agent:a-ci');
  expect(RULES_PATH).toBe('/policy');
  const href = rulesHrefFor({ kind: 'group', id: '3f2a9c10-aaaa-bbbb-cccc-0123456789ab' });
  expect(new URL(href, 'https://example.invalid').origin).toBe('https://example.invalid');
  expect(parseSubjectHash(new URL(href, 'https://example.invalid').hash)).toEqual({ kind: 'group', id: '3f2a9c10-aaaa-bbbb-cccc-0123456789ab' });
});

test('only an exact allowlisted fragment is a filter; everything else is ignored, never partly interpreted', () => {
  const bad = ['', '#', '#subject=', '#subject=user:', '#subject=role:u1', '#subject=user:..', '#subject=user:.', '#subject=user:a b', '#subject=user:a/b', '#subject=user:<script>', '#subject=user:u1&x=1', '#Subject=user:u1', '#subject=user:u1;', `#subject=user:${'x'.repeat(129)}`, '#subject=user:u1#subject=user:u2', 'subject=user:u1'];
  for (const hash of bad) expect(parseSubjectHash(hash), hash).toBeNull();
  expect(parseSubjectHash('#subject=user:u1')).toEqual({ kind: 'user', id: 'u1' });
  expect(parseSubjectHash(`#subject=agent:${'x'.repeat(128)}`)).not.toBeNull();
});

const ruleFor = (id: string, subject: RuleRow['subject']): RuleRow => ({ ...(rules[0] as RuleRow), id, subject });

test('the Rules page shows only the rules that name that kind and id, matching by id even when two accounts share a display name', () => {
  const twinA: RuleRow = ruleFor('r-a', { kind: 'user', id: 'u-a', name: 'sample-twin', state: 'active' });
  const twinB: RuleRow = ruleFor('r-b', { kind: 'user', id: 'u-b', name: 'sample-twin', state: 'active' });
  const sameIdOtherKind: RuleRow = ruleFor('r-g', { kind: 'group', id: 'u-a', name: 'sample-twin', state: 'active' });
  const data = { ...rulesData, rules: [twinA, twinB, sameIdOtherKind, ...rules] };
  const filter: SubjectRef = { kind: 'user', id: 'u-a' };
  mount(<ReviewHarness data={data} filter={filter} />);
  const items = screen.getAllByRole('listitem').filter((li) => li.querySelector('[data-rule]') || li.textContent?.includes('sample-twin'));
  // exactly the one rule for user u-a: not the same-named user u-b, not the group that happens to share the id
  expect(screen.getByRole('status').textContent).toContain('Showing 1 of');
  expect(items.some((li) => li.textContent?.includes('sample-twin'))).toBe(true);
  const banner = screen.getByText('Showing only the rules that name user sample-twin').closest('div') as HTMLElement;
  expect(banner.textContent).toContain('Matched by the account’s ID, not its name');
  expect(screen.queryByText(/sample-billing-worker/)).toBeNull(); // the fixture rules of other subjects are gone
});

function ReviewHarness({ data, filter, onClear }: { data: RulesScreenProps['load'] extends infer L ? (L extends { kind: 'ready'; data: infer D } ? D : never) : never; filter: SubjectRef | null; onClear?: () => void }) {
  return <RulesScreen {...props({ load: { kind: 'ready', data }, subjectFilter: filter, ...(onClear ? { onClearSubjectFilter: onClear } : {}) })} />;
}

test('a subject with no rules says so and offers the full list; "Show all rules" calls back and no filter means every rule', () => {
  const onClear = vi.fn();
  mount(<ReviewHarness data={rulesData} filter={{ kind: 'user', id: 'nobody' }} onClear={onClear} />);
  expect(screen.getByText('No rules match these filters')).toBeTruthy();
  expect(screen.getByRole('status').textContent).toContain('Showing 0 of');
  fireEvent.click(screen.getByRole('button', { name: 'Show all rules' }));
  expect(onClear).toHaveBeenCalledTimes(1);
  cleanup();
  mount(<ReviewHarness data={rulesData} filter={null} />);
  expect(screen.getByRole('status').textContent).toBe(`Showing ${rulesData.rules.length} of ${rulesData.rules.length}`);
  expect(screen.queryByRole('button', { name: 'Show all rules' })).toBeNull();
});

test('the subject filter combines with the Allow/Deny and attention filters instead of replacing them', () => {
  const agent = (rules[0] as RuleRow).subject;
  const data = { ...rulesData, rules: [ruleFor('x1', agent), { ...ruleFor('x2', agent), effect: 'deny' as const }, ruleFor('x3', { ...agent, id: 'another', name: agent.name })] };
  mount(<ReviewHarness data={data} filter={{ kind: agent.kind, id: agent.id }} />);
  expect(screen.getByRole('status').textContent).toBe('Showing 2 of 3');
  fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'deny' } });
  expect(screen.getByRole('status').textContent).toBe('Showing 1 of 3');
  const region = within(screen.getByRole('status').closest('div') as HTMLElement);
  expect(region.getByRole('status')).toBeTruthy();
});
