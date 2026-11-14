import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { ThemeProvider } from '../../theme';
import type { ExportReason, ExportScreenProps } from './contract';
import { ExportScreen } from './export';

afterEach(cleanup);

const props = (patch: Partial<ExportScreenProps> = {}): ExportScreenProps => ({ state: { kind: 'idle' }, onExport: () => undefined, ...patch });

function mount(ui: ReactElement, theme: 'light' | 'dark' = 'light') {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}

test('the page says what a backup is not before anything is chosen: not a rollback, no revocation history', () => {
  mount(<ExportScreen {...props()} />);
  expect(screen.getByRole('heading', { level: 1, name: 'Export a backup' })).toBeTruthy();
  expect(screen.getByText('A backup is a snapshot, not a rollback')).toBeTruthy();
  expect(screen.getByText(/does not record what was revoked or when/)).toBeTruthy();
  expect(screen.getByText(/Neither type brings a sign-in method or an agent token back to life/)).toBeTruthy();
});

test('clean is the default, the button names the choice, and submitting sends exactly that mode', () => {
  const onExport = vi.fn();
  mount(<ExportScreen {...props({ onExport })} />);
  expect((screen.getByRole('radio', { name: /Clean backup/ }) as HTMLInputElement).checked).toBe(true);
  expect(screen.queryByText('A full backup holds credential material')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Export clean backup' }));
  expect(onExport).toHaveBeenCalledTimes(1);
  expect(onExport).toHaveBeenCalledWith('clean');
});

test('choosing full shows the credential-material warning, renames the button and sends full', () => {
  const onExport = vi.fn();
  mount(<ExportScreen {...props({ onExport })} />);
  fireEvent.click(screen.getByRole('radio', { name: /Full backup/ }));
  expect(screen.getByText('A full backup holds credential material')).toBeTruthy();
  expect(screen.getByText(/only an installation with this installation’s key can restore it/i)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Export full backup' }));
  expect(onExport).toHaveBeenCalledWith('full');
});

test('what each type holds is stated in text, including that neither restores a credential to working order', () => {
  mount(<ExportScreen {...props()} />);
  const text = document.body.textContent ?? '';
  for (const phrase of ['Both types hold', 'Neither type holds', 'Only a full backup holds', 'never switches them on', 'installation key']) expect(text, phrase).toContain(phrase);
});

test('while working: the button is busy but stays focusable, a repeat press sends nothing and the choice is locked', () => {
  const onExport = vi.fn();
  mount(<ExportScreen {...props({ onExport, state: { kind: 'working', mode: 'clean' } })} />);
  const button = screen.getByRole('button', { name: 'Creating the backup…' });
  expect(button.getAttribute('aria-busy')).toBe('true');
  expect(button.hasAttribute('disabled')).toBe(false);
  fireEvent.click(button);
  fireEvent.submit(screen.getByRole('form', { name: 'Export a backup' }));
  expect(onExport).not.toHaveBeenCalled();
  for (const radio of screen.getAllByRole('radio')) expect((radio as HTMLInputElement).disabled).toBe(true);
});

test('done: names the file and the backup id, says nothing changed, and moves focus to the result', () => {
  mount(<ExportScreen {...props({ state: { kind: 'done', mode: 'full', backupId: 'sample-backup-0002', fileName: 'mandatary-backup-sample-backup-0002-full.json' } })} />);
  const alert = screen.getByRole('status');
  expect(alert.textContent).toContain('Backup file created');
  expect(alert.textContent).toContain('mandatary-backup-sample-backup-0002-full.json');
  expect(alert.textContent).toContain('sample-backup-0002');
  expect(alert.textContent).toContain('Nothing in this installation changed');
  expect(alert.textContent).toContain('only administrators can read it');
  expect(document.activeElement).toBe(alert);
});

test('a clean result does not claim the file holds credentials, and still says to store it with care', () => {
  mount(<ExportScreen {...props({ state: { kind: 'done', mode: 'clean', backupId: 'sample-backup-0001', fileName: 'f.json' } })} />);
  const text = screen.getByRole('status').textContent ?? '';
  expect(text).toContain('holds no sign-in or token records');
  expect(text).toContain('store it with care');
});

const REASONS: ReadonlyArray<readonly [ExportReason, string]> = [
  ['denied', 'Export wasn’t allowed'],
  ['invalid_request', 'That request couldn’t be read'],
  ['rate_limited', 'Too many attempts'],
  ['unavailable', 'Mandatary couldn’t create the backup'],
];

for (const [reason, title] of REASONS) {
  test(`rejected (${reason}): an alert that says nothing was exported, with focus on it, and the form still usable`, () => {
    mount(<ExportScreen {...props({ state: { kind: 'rejected', reason } })} />);
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(title);
    expect(alert.textContent).toContain('Nothing was exported');
    expect(document.activeElement).toBe(alert);
    expect((screen.getByRole('button', { name: /Export clean backup/ }) as HTMLButtonElement).disabled).toBe(false);
  });
}

test.each(['light', 'dark'] as const)('%s theme: renders under the theme with no inline style', (theme) => {
  const { container } = mount(<ExportScreen {...props({ state: { kind: 'rejected', reason: 'unavailable' } })} />, theme);
  expect(document.documentElement.dataset.theme).toBe(theme);
  expect(container.querySelector('[style]')).toBeNull();
});
