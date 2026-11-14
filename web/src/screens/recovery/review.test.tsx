import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { manifest, manifestApproved, manifestClean, manifestItems, sampleDigest } from '../../gallery/recoveryFixtures';
import { ThemeProvider } from '../../theme';
import { MAX_APPROVALS, type ApprovalState, type ManifestData, type ManifestRow, type ReviewScreenProps } from './contract';
import { ReviewScreen } from './review';

afterEach(cleanup);

const props = (patch: Partial<ReviewScreenProps> = {}): ReviewScreenProps => ({
  load: { kind: 'ready', data: manifest },
  approval: { kind: 'idle' },
  credentialsHref: (id) => `/agents?agent=${id}`,
  onRetry: () => undefined,
  onApprove: () => undefined,
  ...patch,
});

function mount(ui: ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

const box = (name: string) => screen.getByRole('checkbox', { name }) as HTMLInputElement;
const approveButton = () => screen.getByRole('button', { name: /^Approve (\d+ selected…|selected…)$/ }) as HTMLButtonElement;
/** The row of one record by its stable kind and id (the page tags every row with it). Names can repeat across rows; ids cannot. */
const record = (kind: string, id: string) => {
  const item = document.querySelector(`li[data-record="${kind}:${id}"]`) as HTMLElement | null;
  if (!item) throw new Error(`no row for ${kind}:${id}`);
  return within(item);
};
const digestOf = (kind: string, id: string) => sampleDigest(kind, id);

/** Mounts mid-request and delivers the answer, which is the order every real outcome arrives in. */
function answer(to: ApprovalState, extra: Partial<ReviewScreenProps> = {}) {
  const view = mount(<ReviewScreen {...props({ approval: { kind: 'working' }, ...extra })} />);
  view.rerender(
    <ThemeProvider initial="light">
      <ReviewScreen {...props({ approval: to, ...extra })} />
    </ThemeProvider>,
  );
  return view;
}

// ───────────────────────── the page around the list ─────────────────────────

test('loading is a polite status with nothing that could approve anything', () => {
  mount(<ReviewScreen {...props({ load: { kind: 'loading' } })} />);
  expect(screen.getByRole('status').textContent).toContain('Loading restored records…');
  expect(screen.queryByRole('button')).toBeNull();
  expect(screen.queryByRole('checkbox')).toBeNull();
});

test('a failed load is an error with a retry, never an empty list', () => {
  const onRetry = vi.fn();
  mount(<ReviewScreen {...props({ load: { kind: 'failed' }, onRetry })} />);
  expect(screen.getByRole('alert').textContent).toContain('Couldn’t load the restored records');
  expect(screen.queryByText('Nothing is waiting for approval')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

test('denied shows the one refusal and no record', () => {
  mount(<ReviewScreen {...props({ load: { kind: 'denied' } })} />);
  expect(screen.getByRole('alert').textContent).toContain('Policy administration isn’t available to this session');
  expect(screen.queryByRole('checkbox')).toBeNull();
  expect(screen.queryByText('sample-restored')).toBeNull();
});

test('no restore: an explanation, not an error, and nothing to approve', () => {
  mount(<ReviewScreen {...props({ load: { kind: 'no_restore' } })} />);
  expect(screen.getByRole('heading', { name: 'No restore to review' })).toBeTruthy();
  expect(screen.getByText(/Nothing has been restored on this installation/)).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.queryByRole('checkbox')).toBeNull();
});

test('ready: nothing is active until approved, approval grants no credential, and the restore is summarised', () => {
  mount(<ReviewScreen {...props()} />);
  expect(screen.getByRole('heading', { level: 1, name: 'Review restored access' })).toBeTruthy();
  expect(screen.getByText('Nothing listed here is active until you approve it')).toBeTruthy();
  expect(screen.getByText(/never restores a sign-in method or an agent token/)).toBeTruthy();
  const text = document.body.textContent ?? '';
  expect(text).toContain('sample-backup-0001');
  expect(text).toContain('(full backup)');
  expect(text).toContain('12 waiting for approval, 2 approved');
  expect(text).toContain('3 sign-in method records, 2 agent token records, kept switched off for reference. They can’t be switched back on.');
});

test('a clean backup says no credentials existed, and an unverified origin is stated', () => {
  mount(<ReviewScreen {...props({ load: { kind: 'ready', data: manifestClean } })} />);
  const text = document.body.textContent ?? '';
  expect(text).toContain('None. The file was a clean backup.');
  expect(text).toContain('restored after it was acknowledged');
});

// ───────────────────────── explicit, per-item approval ─────────────────────────

test('there is no select-all, no approve-everything, and nothing is ticked by default', () => {
  mount(<ReviewScreen {...props()} />);
  const boxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
  expect(boxes.length).toBeGreaterThan(5);
  expect(boxes.every((b) => !b.checked)).toBe(true);
  expect(screen.queryByRole('checkbox', { name: /^(select|approve) (all|everything)/i })).toBeNull();
  expect(screen.queryByRole('button', { name: /approve all|select all|approve everything/i })).toBeNull();
  expect(approveButton().disabled).toBe(true);
  expect(screen.getByRole('status', { name: '' }).textContent).toContain('Nothing selected');
});

test('only records the service marks approvable have a checkbox; the rest say why in fixed words', () => {
  mount(<ReviewScreen {...props()} />);
  const approvable = manifestItems.filter((item) => item.decision === 'pending' && item.approvable);
  expect(screen.getAllByRole('checkbox')).toHaveLength(approvable.length);
  const role = record('role', 'r-admin');
  expect(role.queryByRole('checkbox')).toBeNull();
  expect(role.getByText(/This installation has one administrator, and the host recovery sets who it is/)).toBeTruthy();
  const address = record('address', 'addr-1');
  expect(address.queryByRole('checkbox')).toBeNull();
  expect(address.getByText(/verified again by the person it belongs to/)).toBeTruthy();
  expect(screen.getByText('Not approved here')).toBeTruthy();
});

test('approved records have no checkbox and are labelled Approved', () => {
  mount(<ReviewScreen {...props()} />);
  const approved = record('user', 'u-sam');
  expect(approved.queryByRole('checkbox')).toBeNull();
  expect(approved.getByText('Approved')).toBeTruthy();
});

test('ticking records updates a polite count and names the button; Clear selection empties it', () => {
  mount(<ReviewScreen {...props()} />);
  fireEvent.click(box('User sample-restored'));
  fireEvent.click(box('Group sample-ops'));
  expect(screen.getByRole('status', { name: '' }).textContent).toContain('2 records selected.');
  expect(approveButton().textContent).toBe('Approve 2 selected…');
  expect(approveButton().disabled).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Clear selection' }));
  expect(box('User sample-restored').checked).toBe(false);
  expect(approveButton().disabled).toBe(true);
});

test('confirmation names every selected record, says all-or-nothing, and sends nothing until confirmed', () => {
  const onApprove = vi.fn();
  mount(<ReviewScreen {...props({ onApprove })} />);
  fireEvent.click(box('User sample-restored'));
  fireEvent.click(box('Group sample-ops'));
  fireEvent.click(approveButton());
  const group = screen.getByRole('group', { name: 'Approve 2 records?' });
  expect(document.activeElement).toBe(group);
  const list = within(group).getByRole('list', { name: 'Records to approve' });
  expect(list.textContent).toContain('User sample-restored');
  expect(list.textContent).toContain('Group sample-ops');
  expect(group.textContent).toContain('all-or-nothing');
  expect(group.textContent).toContain('never restores a sign-in method or an agent token');
  expect(onApprove).not.toHaveBeenCalled();
  fireEvent.click(within(group).getByRole('button', { name: 'Approve 2 records' }));
  expect(onApprove).toHaveBeenCalledTimes(1);
  // Manifest order, not click order: the service orders dependencies itself.
  expect(onApprove).toHaveBeenCalledWith([
    { kind: 'user', id: 'u-restored', digest: digestOf('user', 'u-restored') },
    { kind: 'group', id: 'g-ops', digest: digestOf('group', 'g-ops') },
  ]);
});

test('what is sent is only kind, id and the reviewed digest: no label, state, comparison, detail or other field', () => {
  const onApprove = vi.fn();
  mount(<ReviewScreen {...props({ onApprove })} />);
  fireEvent.click(screen.getByRole('checkbox', { name: /^Rule Deny agent sample-ci-runner \(ID a-ci\) from stopping/ }));
  fireEvent.click(approveButton());
  fireEvent.click(within(screen.getByRole('group', { name: 'Approve 1 record?' })).getByRole('button', { name: 'Approve 1 record' }));
  const [sent] = onApprove.mock.calls[0] as [Array<Record<string, unknown>>];
  expect(Object.keys(sent[0] ?? {}).sort()).toEqual(['digest', 'id', 'kind']);
});

test('Escape closes the confirmation and returns focus to the button that opened it; the selection is kept', () => {
  mount(<ReviewScreen {...props()} />);
  fireEvent.click(box('Group sample-ops'));
  fireEvent.click(approveButton());
  fireEvent.keyDown(screen.getByRole('group', { name: 'Approve 1 record?' }), { key: 'Escape' });
  expect(screen.queryByRole('group', { name: /^Approve/ })).toBeNull();
  expect(document.activeElement).toBe(approveButton());
  expect(box('Group sample-ops').checked).toBe(true);
});

test('while approving: the confirm button is busy but focusable and a repeat press sends nothing', () => {
  const onApprove = vi.fn();
  mount(<ReviewScreen {...props({ onApprove, approval: { kind: 'working' }, initial: { selected: [{ kind: 'group', id: 'g-ops' }], confirming: true } })} />);
  const button = screen.getByRole('button', { name: 'Approving…' });
  expect(button.getAttribute('aria-busy')).toBe('true');
  expect(button.hasAttribute('disabled')).toBe(false);
  fireEvent.click(button);
  expect(onApprove).not.toHaveBeenCalled();
});

test('more than the service accepts per request cannot be sent, and the page says so', () => {
  const many: ManifestRow[] = Array.from({ length: MAX_APPROVALS + 1 }, (_, index) => ({ ...(manifestItems[5] as ManifestRow), kind: 'group', id: `g-${index}`, label: `sample-group-${index}`, comparison: { kind: 'none' } }));
  const data: ManifestData = { ...manifest, items: many };
  mount(<ReviewScreen {...props({ load: { kind: 'ready', data }, initial: { selected: many.map(({ kind, id }) => ({ kind, id })) } })} />);
  expect(screen.getByRole('status', { name: '' }).textContent).toContain(`Select at most ${MAX_APPROVALS} at a time.`);
  expect(approveButton().disabled).toBe(true);
});

// ───────────────────────── imported against applied ─────────────────────────

test('a differing second-factor setting is shown side by side with the difference written out', () => {
  mount(<ReviewScreen {...props()} />);
  const user = record('user', 'u-restored');
  const terms = user.getAllByRole('term').map((t) => t.textContent);
  expect(terms).toEqual(['In the file', 'Applied when approved']);
  expect(user.getByText('Second factor optional')).toBeTruthy();
  expect(user.getByText('Second factor required')).toBeTruthy();
  expect(user.getByText(/These differ\. Approving applies the setting on the right, not the one in the file\./)).toBeTruthy();
});

test('an identical setting shows both sides and no warning', () => {
  mount(<ReviewScreen {...props()} />);
  const user = record('user', 'u-risky');
  expect(user.getAllByText('Second factor required')).toHaveLength(2);
  expect(user.queryByText(/These differ/)).toBeNull();
});

test('a kept local Deny is explained: an Allow from the file never replaces it', () => {
  mount(<ReviewScreen {...props()} />);
  const rule = record('policy', 'p-stop');
  expect(rule.getByText(/A Deny rule with this id already existed here and was kept\. An Allow from the file never replaces it\./)).toBeTruthy();
  const plain = record('policy', 'p-logs');
  expect(plain.queryByText(/already existed here/)).toBeNull();
});

test('a record with no comparison in the service gets none: no invented imported/effective values', () => {
  mount(<ReviewScreen {...props()} />);
  for (const [kind, id] of [['endpoint', 'ep-local'], ['group', 'g-ops'], ['agent', 'a-ci']] as const) expect(record(kind, id).queryByRole('term'), id).toBeNull();
});

test('an approved record no longer shows a comparison', () => {
  mount(<ReviewScreen {...props({ load: { kind: 'ready', data: { ...manifest, items: [{ ...(manifestItems[1] as ManifestRow), decision: 'approved' }] } } })} />);
  expect(screen.queryByText('Applied when approved')).toBeNull();
});

// ───────────────────────── provenance of each record ─────────────────────────

test('a record kept from before the restore says it was not in the file, and that a restore never deletes', () => {
  mount(<ReviewScreen {...props()} />);
  const kept = record('user', 'u-local-only');
  expect(kept.getByText('Not in the file')).toBeTruthy();
  expect(kept.getByText(/It was here before the restore and has been switched off\. A restore never deletes anything\./)).toBeTruthy();
});

test('a record the service marks compromised stays visible with its reason but has no checkbox and is not part of any selection', () => {
  mount(<ReviewScreen {...props()} />);
  const risky = record('user', 'u-risky');
  expect(risky.getByText('Marked compromised in the file')).toBeTruthy();
  expect(risky.queryByRole('checkbox')).toBeNull();
  expect(risky.getByText(/Marked compromised, so it can’t be approved\. Mandatary also refuses any attempt to approve it\./)).toBeTruthy();
  expect(screen.queryByRole('checkbox', { name: /sample-risky/ })).toBeNull();
  expect(screen.getByText('Not approved here')).toBeTruthy();
});

test('source state is shown only when unusual, and always as reference that grants nothing', () => {
  mount(<ReviewScreen {...props()} />);
  expect(record('user', 'u-risky').getByText(/In the file it was disabled\. That is for reference only and grants nothing\./)).toBeTruthy();
  expect(record('user', 'u-restored').queryByText(/In the file it was/)).toBeNull();
});

test('credential follow-ups: a pending user or agent is told nothing is restored; an approved agent links to Agent tokens', () => {
  mount(<ReviewScreen {...props()} />);
  expect(record('user', 'u-restored').getByText('Approving doesn’t bring back a sign-in method.')).toBeTruthy();
  expect(record('agent', 'a-ci').getByText(/Approving doesn’t bring back its tokens/)).toBeTruthy();
  const approved = record('agent', 'a-billing');
  expect(approved.getByText(/Approved\. It has no token\./)).toBeTruthy();
  expect(approved.getByRole('link', { name: 'Agent tokens page for sample-billing-bot' }).getAttribute('href')).toBe('/agents?agent=a-billing');
  expect(record('user', 'u-sam').getByText('Approved. It has no sign-in method yet; none is restored.')).toBeTruthy();
});

test('"See details" appears only when the container supplies a destination, and names its record', () => {
  const { unmount } = mount(<ReviewScreen {...props()} />);
  expect(screen.queryByRole('link', { name: /See details/ })).toBeNull();
  unmount();
  mount(<ReviewScreen {...props({ inspectHref: (kind, id) => (kind === 'role' ? undefined : `/x/${kind}/${id}`) })} />);
  expect(screen.getByRole('link', { name: 'See details of User sample-restored' }).getAttribute('href')).toBe('/x/user/u-restored');
  expect(within(screen.getByText('administrator role of sample-admin').closest('li') as HTMLElement).queryByRole('link')).toBeNull();
});

test('when everything approvable is approved only what the service never approves here is left, with no approve button, and the follow-ups remain', () => {
  mount(<ReviewScreen {...props({ load: { kind: 'ready', data: manifestApproved } })} />);
  expect(screen.queryByText('Nothing is waiting for approval')).toBeNull();
  expect(screen.getByText('Not approved here')).toBeTruthy();
  expect(screen.queryByRole('checkbox')).toBeNull();
  expect(screen.queryByRole('button', { name: /^Approve/ })).toBeNull();
  expect(screen.getByRole('link', { name: 'Agent tokens page for sample-ci-runner' })).toBeTruthy();
});

test('when nothing at all is pending the waiting panel says so', () => {
  const approved = manifestApproved.items.filter((item) => item.approvable);
  mount(<ReviewScreen {...props({ load: { kind: 'ready', data: { ...manifestApproved, items: approved } } })} />);
  expect(screen.getByText('Nothing is waiting for approval')).toBeTruthy();
});

// ───────────────────────── the answer ─────────────────────────

test('approved: says how many, that nothing credential-like came back, takes focus and empties the selection', () => {
  const view = mount(<ReviewScreen {...props({ initial: { selected: [{ kind: 'group', id: 'g-ops' }] } })} />);
  expect(box('Group sample-ops').checked).toBe(true);
  view.rerender(
    <ThemeProvider initial="light">
      <ReviewScreen {...props({ approval: { kind: 'done', count: 3 } })} />
    </ThemeProvider>,
  );
  const alert = screen.getAllByRole('status').find((node) => node.textContent?.includes('Approved 3 records'));
  expect(alert?.textContent).toContain('never restores a sign-in method or an agent token');
  expect((screen.getByRole('checkbox', { name: 'Group sample-ops' }) as HTMLInputElement).checked).toBe(false);
});

test('approved: focus lands on the result and the confirmation is gone', () => {
  answer({ kind: 'done', count: 1 }, { initial: { selected: [{ kind: 'group', id: 'g-ops' }], confirming: true } });
  const alert = screen.getAllByRole('status').find((node) => node.textContent?.includes('Approved 1 record'));
  expect(document.activeElement).toBe(alert);
  expect(screen.queryByRole('group', { name: /^Approve/ })).toBeNull();
});

test('a conflict names each refused record and why, says nothing was approved, keeps the selection and marks the rows', () => {
  answer(
    {
      kind: 'conflict',
      failures: [
        { kind: 'user_membership', id: 'u-restored:g-ops', reason: 'subject_not_active' },
        { kind: 'agent', id: 'a-ci', reason: 'owner_not_active' },
        { kind: 'user', id: 'u-risky', reason: 'compromised' },
      ],
    },
    { initial: { selected: [{ kind: 'user_membership', id: 'u-restored:g-ops' }, { kind: 'agent', id: 'a-ci' }, { kind: 'user', id: 'u-risky' }], confirming: true } },
  );
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('Nothing was approved');
  expect(alert.textContent).toContain('all-or-nothing');
  expect(alert.textContent).toContain('3 records couldn’t be');
  expect(alert.textContent).toContain('Group member (user) sample-restored in sample-ops.');
  expect(alert.textContent).toContain('The user, group or agent it belongs to isn’t approved yet');
  expect(alert.textContent).toContain('Its owner isn’t approved yet');
  expect(alert.textContent).toContain('It is marked compromised, so it can’t be approved.');
  expect(document.activeElement).toBe(alert);
  expect(screen.queryByRole('group', { name: /^Approve/ })).toBeNull();
  expect(box('Agent sample-ci-runner').checked).toBe(true);
  expect(record('agent', 'a-ci').getByText(/Not approved\. Its owner isn’t approved yet/)).toBeTruthy();
  expect(alert.textContent).not.toContain('u-restored');
});

test('a refusal code the page does not know is shown as a plain refusal, never as raw text', () => {
  answer({ kind: 'conflict', failures: [{ kind: 'group', id: 'g-ops', reason: 'other' }] });
  expect(screen.getByRole('alert').textContent).toContain('Mandatary refused it.');
});

const REJECTIONS: ReadonlyArray<readonly [Extract<ApprovalState, { kind: 'rejected' }>['reason'], string]> = [
  ['denied', 'That wasn’t allowed'],
  ['invalid', 'That request couldn’t be read'],
  ['rate_limited', 'Too many attempts'],
  ['still_quarantined', 'Mandatary is still in restore quarantine'],
  ['outcome_unknown', 'Mandatary couldn’t confirm the result'],
];

for (const [reason, title] of REJECTIONS) {
  test(`rejected (${reason}): titled, focused, and honest about what is known`, () => {
    answer({ kind: 'rejected', reason }, { initial: { selected: [{ kind: 'group', id: 'g-ops' }], confirming: true } });
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(title);
    expect(document.activeElement).toBe(alert);
    if (reason === 'outcome_unknown') {
      expect(alert.textContent).toContain('may have been approved');
      expect(alert.textContent).not.toContain('Nothing was approved');
    } else {
      expect(alert.textContent).toContain('Nothing was approved');
    }
  });
}

test('an unknown outcome offers a reload of the list and nothing that would repeat the approval', () => {
  const onRetry = vi.fn();
  answer({ kind: 'rejected', reason: 'outcome_unknown' }, { onRetry });
  fireEvent.click(screen.getByRole('button', { name: 'Reload the list' }));
  expect(onRetry).toHaveBeenCalledTimes(1);
});

// ───────────────────────── both themes ─────────────────────────

test.each(['light', 'dark'] as const)('%s theme: every review state renders with no inline style and every control named', (theme) => {
  const states: ReviewScreenProps[] = [props(), props({ approval: { kind: 'conflict', failures: [{ kind: 'group', id: 'g-ops', reason: 'other' }] } }), props({ initial: { selected: [{ kind: 'group', id: 'g-ops' }], confirming: true } }), props({ load: { kind: 'no_restore' } })];
  for (const state of states) {
    const { container, unmount } = mount(<ReviewScreen {...state} />, theme);
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(container.querySelector('[style]')).toBeNull();
    for (const control of container.querySelectorAll<HTMLInputElement>('input')) expect((control.labels?.length ?? 0) > 0, theme).toBe(true);
    for (const button of container.querySelectorAll('button')) expect((button.textContent ?? '').trim()).not.toBe('');
    unmount();
  }
});
