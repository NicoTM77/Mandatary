import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { reportClean, reportFull, sampleFile } from '../../gallery/recoveryFixtures';
import { ThemeProvider } from '../../theme';
import { MAX_ARCHIVE_BYTES, RESTORE_PHRASE, type RestoreEnded, type RestoreFormState, type RestoreRejection, type RestoreScreenProps } from './contract';
import { RestoreEndedPage, RestoreEndedView, RestoreScreen } from './restore';

afterEach(cleanup);

const props = (patch: Partial<RestoreScreenProps> = {}): RestoreScreenProps => ({ state: { kind: 'idle' }, onRestore: () => undefined, ...patch });

function mount(ui: ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

function choose(file: File) {
  fireEvent.change(screen.getByLabelText('Backup file'), { target: { files: [file] } });
}

const OPEN = 'Restore from this file…';
const confirmGroup = () => screen.getByRole('group', { name: /^Restore from / });
const phraseField = () => screen.getByLabelText(`Type ${RESTORE_PHRASE} to confirm`) as HTMLInputElement;

// ───────────────────────── before a file is chosen ─────────────────────────

test('before any file: the consequences are on the page, in words, and nothing can be sent', () => {
  mount(<RestoreScreen {...props()} />);
  expect(screen.getByRole('heading', { level: 1, name: 'Restore from a backup' })).toBeTruthy();
  const text = document.body.textContent ?? '';
  for (const phrase of [
    'A backup is a snapshot, not a rollback',
    'Everyone is signed out, including you.',
    'restore quarantine',
    'Nothing from the file is active.',
    'Nothing is deleted.',
    'A Deny rule already here is never replaced by an Allow from the file',
    'a weaker second-factor setting from the file never takes effect',
    'No sign-in method or agent token comes back.',
    'Only the server can end quarantine.',
    'No page in a browser can',
    'Then you approve, item by item.',
  ]) {
    expect(text, phrase).toContain(phrase);
  }
  expect(screen.queryByRole('group', { name: /^Restore from / })).toBeNull();
});

test('the page says there is no preview and what is checked on the server, instead of offering one', () => {
  mount(<RestoreScreen {...props()} />);
  expect(screen.getByText(/can’t preview it/)).toBeTruthy();
  expect(screen.getByText(/format, version, integrity and consistency/)).toBeTruthy();
  expect(screen.getByText(/changes nothing and doesn’t start quarantine/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: /preview/i })).toBeNull();
});

test('pressing Restore with no file explains why, puts focus on the file field and opens nothing', () => {
  const onRestore = vi.fn();
  mount(<RestoreScreen {...props({ onRestore })} />);
  fireEvent.click(screen.getByRole('button', { name: OPEN }));
  const input = screen.getByLabelText('Backup file');
  expect(screen.getByText('Choose a backup file.')).toBeTruthy();
  expect(input.getAttribute('aria-invalid')).toBe('true');
  expect(document.activeElement).toBe(input);
  expect(screen.queryByRole('group', { name: /^Restore from / })).toBeNull();
  expect(onRestore).not.toHaveBeenCalled();
});

test('an empty file and a file over the size limit are explained before any request, and open nothing', () => {
  mount(<RestoreScreen {...props()} />);
  choose(new File([], 'sample-empty.json'));
  fireEvent.click(screen.getByRole('button', { name: OPEN }));
  expect(screen.getByText('That file is empty.')).toBeTruthy();
  const big = new File(['x'], 'sample-big.json');
  Object.defineProperty(big, 'size', { value: MAX_ARCHIVE_BYTES + 1 });
  choose(big);
  fireEvent.click(screen.getByRole('button', { name: OPEN }));
  expect(screen.getByText(/Mandatary refuses anything over 16 MiB/)).toBeTruthy();
  expect(screen.queryByRole('group', { name: /^Restore from / })).toBeNull();
});

test('a chosen file shows only its name and size, never anything from inside it', () => {
  mount(<RestoreScreen {...props()} />);
  choose(sampleFile('sample-backup-0001-clean.json', 2048));
  expect(screen.getByText('sample-backup-0001-clean.json')).toBeTruthy();
  expect(screen.getByText('2 KiB')).toBeTruthy();
  expect(document.body.textContent).not.toContain('xxxxxxxx');
});

// ───────────────────────── the typed confirmation ─────────────────────────

test('opening the confirmation names the file, restates the consequence, and puts focus on the group', () => {
  mount(<RestoreScreen {...props({ initial: { file: sampleFile('sample-a.json') } })} />);
  fireEvent.click(screen.getByRole('button', { name: OPEN }));
  const group = within(confirmGroup());
  expect(confirmGroup().getAttribute('aria-label')).toBe('Restore from sample-a.json?');
  expect(group.getByText(/signs everyone out, including you/)).toBeTruthy();
  expect(group.getByText(/closes sign-in until the host recovery is run/)).toBeTruthy();
  expect(document.activeElement).toBe(confirmGroup());
  // The acknowledgement is not offered until the service asks for it.
  expect(screen.queryByRole('checkbox')).toBeNull();
});

test('a wrong or lower-case phrase sends nothing, explains itself and returns focus to the field', () => {
  const onRestore = vi.fn();
  mount(<RestoreScreen {...props({ onRestore, initial: { file: sampleFile(), confirming: true } })} />);
  for (const wrong of ['', 'restore', 'RESTOR', 'YES']) {
    fireEvent.change(phraseField(), { target: { value: wrong } });
    fireEvent.click(screen.getByRole('button', { name: 'Restore this backup' }));
    expect(screen.getByText(`Type ${RESTORE_PHRASE} in capital letters to continue.`)).toBeTruthy();
    expect(phraseField().getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(phraseField());
  }
  expect(onRestore).not.toHaveBeenCalled();
});

test('the exact phrase sends the file and no acknowledgement; the confirm button is the only thing that does', () => {
  const onRestore = vi.fn();
  const file = sampleFile('sample-b.json');
  mount(<RestoreScreen {...props({ onRestore, initial: { file, confirming: true } })} />);
  fireEvent.change(phraseField(), { target: { value: RESTORE_PHRASE } });
  expect(onRestore).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Restore this backup' }));
  expect(onRestore).toHaveBeenCalledTimes(1);
  expect(onRestore).toHaveBeenCalledWith({ file, acknowledgeUnauthenticatedProvenance: false });
});

test('Enter in the phrase field confirms, exactly like the button', () => {
  const onRestore = vi.fn();
  mount(<RestoreScreen {...props({ onRestore, initial: { file: sampleFile(), confirming: true } })} />);
  fireEvent.change(phraseField(), { target: { value: RESTORE_PHRASE } });
  fireEvent.keyDown(phraseField(), { key: 'Enter' });
  expect(onRestore).toHaveBeenCalledTimes(1);
});

test('Escape cancels, closes the confirmation and returns focus to the button that opened it', () => {
  mount(<RestoreScreen {...props({ initial: { file: sampleFile() } })} />);
  fireEvent.click(screen.getByRole('button', { name: OPEN }));
  fireEvent.keyDown(confirmGroup(), { key: 'Escape' });
  expect(screen.queryByRole('group', { name: /^Restore from / })).toBeNull();
  expect(document.activeElement).toBe(screen.getByRole('button', { name: OPEN }));
});

test('Cancel is labelled Cancel, and choosing a different file closes the confirmation so the phrase is typed again', () => {
  mount(<RestoreScreen {...props({ initial: { file: sampleFile('sample-a.json'), confirming: true } })} />);
  expect(screen.getByRole('button', { name: 'Cancel' })).toBeTruthy();
  fireEvent.change(phraseField(), { target: { value: RESTORE_PHRASE } });
  choose(sampleFile('sample-other.json'));
  expect(screen.queryByRole('group', { name: /^Restore from / })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: OPEN }));
  expect(confirmGroup().getAttribute('aria-label')).toBe('Restore from sample-other.json?');
  expect(phraseField().value).toBe('');
});

// ───────────────────────── in progress ─────────────────────────

test('while restoring: progress is announced, the button stays focusable and busy, repeats send nothing, Escape and Cancel are ignored', () => {
  const onRestore = vi.fn();
  mount(<RestoreScreen {...props({ onRestore, state: { kind: 'working' }, initial: { file: sampleFile(), confirming: true } })} />);
  expect(screen.getByRole('status').textContent).toContain('Restoring. This can take a minute. Don’t close this page, go back or reload it.');
  const confirm = screen.getByRole('button', { name: 'Restoring…' });
  expect(confirm.getAttribute('aria-busy')).toBe('true');
  expect(confirm.hasAttribute('disabled')).toBe(false);
  fireEvent.change(phraseField(), { target: { value: RESTORE_PHRASE } });
  fireEvent.click(confirm);
  expect(onRestore).not.toHaveBeenCalled();
  expect(phraseField().readOnly).toBe(true);
  fireEvent.keyDown(confirmGroup(), { key: 'Escape' });
  expect(confirmGroup()).toBeTruthy();
  expect((screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByLabelText('Backup file') as HTMLInputElement).disabled).toBe(true);
});

// ───────────────────────── provenance acknowledgement ─────────────────────────

/** Mounts the screen mid-request, then delivers the answer, which is the order every real outcome arrives in. */
function answer(to: RestoreFormState, initial: RestoreScreenProps['initial'], onRestore: RestoreScreenProps['onRestore'] = () => undefined) {
  const view = mount(<RestoreScreen {...props({ state: { kind: 'working' }, initial, onRestore })} />);
  view.rerender(
    <ThemeProvider initial="light">
      <RestoreScreen {...props({ state: to, initial, onRestore })} />
    </ThemeProvider>,
  );
  return view;
}

test('an unverifiable origin: the answer says nothing changed, moves focus to it, and the confirmation gains the checkbox', () => {
  answer({ kind: 'needs_acknowledgement' }, { file: sampleFile(), confirming: true });
  const alert = screen.getByRole('status', { name: '' });
  expect(alert.textContent).toContain('This file’s origin can’t be verified');
  expect(alert.textContent).toContain('Nothing was changed');
  expect(document.activeElement).toBe(alert);
  const box = within(confirmGroup()).getByRole('checkbox', { name: /origin can’t be verified/ }) as HTMLInputElement;
  expect(box.checked).toBe(false);
});

test('confirming without the checkbox is refused locally; ticking it sends acknowledgeUnauthenticatedProvenance true', () => {
  const onRestore = vi.fn();
  const file = sampleFile();
  mount(<RestoreScreen {...props({ onRestore, state: { kind: 'needs_acknowledgement' }, initial: { file, confirming: true } })} />);
  fireEvent.change(phraseField(), { target: { value: RESTORE_PHRASE } });
  fireEvent.click(screen.getByRole('button', { name: 'Restore this backup' }));
  expect(screen.getByText(/Tick the box to continue/)).toBeTruthy();
  expect(document.activeElement).toBe(screen.getByRole('checkbox'));
  expect(onRestore).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Restore this backup' }));
  expect(onRestore).toHaveBeenCalledWith({ file, acknowledgeUnauthenticatedProvenance: true });
});

test('the acknowledgement is never pre-set and a wrong phrase still blocks it', () => {
  const onRestore = vi.fn();
  mount(<RestoreScreen {...props({ onRestore, state: { kind: 'needs_acknowledgement' }, initial: { file: sampleFile(), confirming: true } })} />);
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Restore this backup' }));
  expect(screen.getByText(`Type ${RESTORE_PHRASE} in capital letters to continue.`)).toBeTruthy();
  expect(onRestore).not.toHaveBeenCalled();
});

// ───────────────────────── refusals ─────────────────────────

const REJECTIONS: ReadonlyArray<readonly [RestoreRejection, string]> = [
  ['archive_malformed', 'That isn’t a readable Mandatary backup'],
  ['archive_unsupported_version', 'This backup was made by an incompatible version'],
  ['archive_integrity_failed', 'The file failed its integrity check'],
  ['archive_inconsistent', 'The file’s contents don’t add up'],
  ['invalid_request', 'That request couldn’t be read'],
  ['denied', 'Restore wasn’t allowed'],
  ['rate_limited', 'Too many attempts'],
  ['unavailable', 'Mandatary couldn’t start the restore'],
];

for (const [reason, title] of REJECTIONS) {
  test(`refused (${reason}): says nothing was changed, takes focus, closes the confirmation and keeps the file for another try`, () => {
    answer({ kind: 'rejected', reason }, { file: sampleFile('sample-keep.json'), confirming: true });
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(title);
    expect(alert.textContent).toContain('Nothing was changed');
    expect(document.activeElement).toBe(alert);
    expect(screen.queryByRole('group', { name: /^Restore from / })).toBeNull();
    expect(screen.getByText('sample-keep.json')).toBeTruthy();
    expect(screen.getByRole('button', { name: OPEN })).toBeTruthy();
  });
}

test('the integrity refusal covers both a tampered file and a full backup from another key, without claiming to know which', () => {
  mount(<RestoreScreen {...props({ state: { kind: 'rejected', reason: 'archive_integrity_failed' }, initial: { file: sampleFile() } })} />);
  const text = screen.getByRole('alert').textContent ?? '';
  expect(text).toContain('altered or damaged');
  expect(text).toContain('full backup from an installation with a different key');
  expect(text).toContain('can’t tell which');
  expect(text).toContain('export a clean backup');
});

test('a refusal never claims the installation is in quarantine, and a rejected state is not a terminal one', () => {
  for (const [reason] of REJECTIONS) {
    const { unmount } = mount(<RestoreScreen {...props({ state: { kind: 'rejected', reason } })} />);
    const alertText = screen.getByRole('alert').textContent ?? '';
    expect(alertText, reason).not.toMatch(/quarantine/i);
    unmount();
  }
});

// ───────────────────────── after the request ─────────────────────────

const complete = (overrides: Partial<Extract<RestoreEnded, { kind: 'complete' }>> = {}): RestoreEnded => ({ kind: 'complete', report: reportFull, authorizerNotified: true, ...overrides });

test('complete: the first thing read says sign-in is closed and nothing is active; focus is on it', () => {
  mount(<RestoreEndedPage ended={complete()} />);
  expect(screen.getByRole('heading', { level: 1, name: 'Restore complete' })).toBeTruthy();
  const alert = screen.getByRole('status');
  expect(alert.textContent).toContain('Sign-in is closed until the host recovery is done');
  expect(alert.textContent).toContain('You and everyone else were signed out');
  expect(alert.textContent).toContain('Nothing from the file is active yet');
  expect(document.activeElement).toBe(alert);
});

test('complete: the report is counts only, credentials are said to stay off, and the excluded scope is named', () => {
  mount(<RestoreEndedView ended={complete()} />);
  const text = document.body.textContent ?? '';
  expect(text).toContain('3 users');
  expect(text).toContain('2 rules');
  expect(text).toContain('1 user, 1 rule');
  expect(text).toContain('3 sign-in method records, 2 agent token records, kept switched off for reference. They can’t be switched back on.');
  expect(text).toContain('usage statistics');
  expect(text).toContain('Verified with this installation’s key.');
});

test('complete (clean, unverified origin): says no credentials were in the file and that the origin was acknowledged', () => {
  mount(<RestoreEndedView ended={complete({ report: reportClean })} />);
  const text = document.body.textContent ?? '';
  expect(text).toContain('None. This was a clean backup.');
  expect(text).toContain('restored after you acknowledged that');
});

test('complete: next steps are an ordered list that ends with credential reissue and explicit approval', () => {
  mount(<RestoreEndedView ended={complete()} />);
  const steps = within(screen.getByRole('list')).getAllByRole('listitem').map((item) => item.textContent ?? '');
  expect(steps).toHaveLength(4);
  expect(steps[0]).toContain('Run the host recovery on the server. A browser can’t do this.');
  expect(steps[1]).toContain('Sign in as the administrator.');
  expect(steps[2]).toContain('approve each record you still want, by name');
  expect(steps[3]).toContain('Set up sign-in methods and agent tokens again');
});

test('complete: an authorizer that was not told is explained calmly; one that was told produces no such note', () => {
  const { unmount } = mount(<RestoreEndedView ended={complete({ authorizerNotified: false })} />);
  expect(screen.getByText('Access decisions may take a moment to catch up')).toBeTruthy();
  expect(document.body.textContent).toContain('Quarantine is already in force');
  unmount();
  mount(<RestoreEndedView ended={complete({ authorizerNotified: true })} />);
  expect(screen.queryByText('Access decisions may take a moment to catch up')).toBeNull();
});

test('the runbook link appears only when the container supplies one; nothing is invented', () => {
  const { unmount } = mount(<RestoreEndedView ended={complete()} />);
  expect(screen.queryByRole('link', { name: 'Open the operator runbook' })).toBeNull();
  unmount();
  mount(<RestoreEndedView ended={complete()} runbookHref="/docs/runbook" />);
  expect(screen.getByRole('link', { name: 'Open the operator runbook' }).getAttribute('href')).toBe('/docs/runbook');
});

test('did not finish: says nothing was imported yet sign-in is closed, and that repeating the same file is safe', () => {
  mount(<RestoreEndedView ended={{ kind: 'incomplete', cause: 'failed' }} />);
  expect(screen.getByRole('heading', { level: 1, name: 'The restore didn’t finish' })).toBeTruthy();
  const alert = screen.getByRole('alert');
  expect(alert.textContent).toContain('Sign-in is closed, and nothing was imported');
  expect(alert.textContent).toContain('everyone was signed out and sign-in is closed');
  expect(document.activeElement).toBe(alert);
  expect(document.body.textContent).toContain('Restore the same file again if you still want it. That is safe');
});

test('did not finish, superseded: names the competing restore and sends the person to see what it imported first', () => {
  mount(<RestoreEndedView ended={{ kind: 'incomplete', cause: 'superseded' }} />);
  expect(screen.getByRole('alert').textContent).toContain('Another restore ran at the same moment and took precedence');
  expect(document.body.textContent).toContain('see what the other restore imported before you restore again');
});

test('answer lost: does not say "nothing changed", tells the person how to find out, offers only a reload', () => {
  const onReload = vi.fn();
  mount(<RestoreEndedView ended={{ kind: 'unconfirmed' }} onReload={onReload} />);
  const text = document.body.textContent ?? '';
  expect(screen.getByRole('heading', { level: 1, name: 'Mandatary couldn’t confirm what happened' })).toBeTruthy();
  expect(screen.getByRole('status').textContent).toContain('Don’t start another restore yet');
  expect(text).toContain('may have run or not run at all');
  expect(text).toContain('If you are still signed in, the restore did not start');
  expect(text).toContain('If you are signed out, or sign-in is closed, the restore did start');
  // The alert the person lands on makes no claim either way; the only "nothing changed" is the conditional one the person can check for themselves.
  expect(screen.getByRole('status').textContent).not.toMatch(/nothing/i);
  expect(text.match(/nothing was changed/gi)).toHaveLength(1);
  expect(text).not.toMatch(/nothing was (applied|imported)\b/i);
  fireEvent.click(screen.getByRole('button', { name: 'Reload this page' }));
  expect(onReload).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('link', { name: 'Go to the sign-in page' })).toBeNull();
});

test('no terminal restore page offers a retry: the next step is on the host, or a reload', () => {
  const all: RestoreEnded[] = [complete(), { kind: 'incomplete', cause: 'failed' }, { kind: 'incomplete', cause: 'superseded' }, { kind: 'unconfirmed' }];
  for (const ended of all) {
    const { unmount } = mount(<RestoreEndedView ended={ended} />);
    expect(screen.queryByRole('button', { name: /try again|retry|restore (again|now)/i }), ended.kind).toBeNull();
    expect(screen.queryByRole('form')).toBeNull();
    expect(screen.queryByLabelText('Backup file')).toBeNull();
    unmount();
  }
});

test('the terminal page is a pre-session frame: no account strip, no navigation, a sign-in link that defaults to /login', () => {
  mount(<RestoreEndedPage ended={complete()} />);
  expect(screen.queryByRole('navigation', { name: 'Primary' })).toBeNull();
  expect(screen.queryByText('Sign out')).toBeNull();
  expect(screen.getByRole('link', { name: 'Go to the sign-in page' }).getAttribute('href')).toBe('/login');
  expect(screen.getAllByRole('main')).toHaveLength(1);
});

// ───────────────────────── both themes ─────────────────────────

const STATES: RestoreFormState[] = [{ kind: 'idle' }, { kind: 'working' }, { kind: 'needs_acknowledgement' }, { kind: 'rejected', reason: 'archive_integrity_failed' }];

test.each(['light', 'dark'] as const)('%s theme: every form state renders without an inline style, and every control has a name', (theme) => {
  for (const state of STATES) {
    const { container, unmount } = mount(<RestoreScreen {...props({ state, initial: { file: sampleFile(), confirming: true } })} />, theme);
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(container.querySelector('[style]')).toBeNull();
    for (const control of container.querySelectorAll<HTMLInputElement>('input')) expect((control.labels?.length ?? 0) > 0 || control.hasAttribute('aria-label'), `${theme} ${state.kind}`).toBe(true);
    for (const button of container.querySelectorAll('button')) expect((button.textContent ?? '').trim()).not.toBe('');
    unmount();
  }
});
