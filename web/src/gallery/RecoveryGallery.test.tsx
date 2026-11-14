import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { RECOVERY_NAV } from '../screens/recovery/nav';
import { ThemeProvider } from '../theme';
import Gallery from './Gallery';
import { manifest, manifestItems, reportFull } from './recoveryFixtures';

afterEach(cleanup);

function mount(view: string, theme?: 'light' | 'dark') {
  return render(
    <ThemeProvider {...(theme ? { initial: theme } : {})}>
      <Gallery view={view} />
    </ThemeProvider>,
  );
}

/**
 * Document-wide invariants over every synthetic P1.18 state at once. Like the P1.16 and P1.17 gallery tests these stand in for an automated
 * accessibility scan (none is approved) and assert the static CSP constraints; they are structural checks, not a conformance claim.
 */

test('every specimen is labelled as synthetic so no illustrated state can be mistaken for shipped behaviour', () => {
  const { container } = mount('recovery');
  const figures = container.querySelectorAll('figure');
  expect(figures.length).toBeGreaterThanOrEqual(33);
  for (const figure of figures) expect(figure.querySelector('figcaption')?.textContent, figure.textContent?.slice(0, 40)).toContain('Synthetic');
});

test('every specimen carries a unique flow id, and the groups cover export, restore, the terminal pages and review', () => {
  const { container } = mount('recovery');
  const flows = Array.from(container.querySelectorAll('figure figcaption span.font-mono'), (node) => node.textContent ?? '');
  expect(new Set(flows).size).toBe(flows.length);
  for (const prefix of ['X-', 'S-', 'T-', 'V-']) expect(flows.some((flow) => flow.startsWith(prefix)), prefix).toBe(true);
});

test('the gallery obeys the static CSP: no inline style attributes, images, scripts or remote and data: URLs (both themes)', () => {
  for (const theme of ['light', 'dark'] as const) {
    const { container, unmount } = mount('recovery', theme);
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(container.querySelectorAll('[style]')).toHaveLength(0);
    expect(container.querySelectorAll('img, picture, video, audio, iframe, object, embed, link, script')).toHaveLength(0);
    for (const element of container.querySelectorAll('[href], [src], [action], [formaction]')) {
      for (const name of ['href', 'src', 'action', 'formaction']) {
        const value = element.getAttribute(name);
        if (value === null) continue;
        expect(value, `${theme} ${name} on <${element.tagName.toLowerCase()}>`).not.toMatch(/^(https?:|data:|javascript:|blob:)/i);
      }
    }
    unmount();
  }
});

test('every input has an accessible name and every button has text (both themes)', () => {
  for (const theme of ['light', 'dark'] as const) {
    const { container, unmount } = mount('recovery', theme);
    for (const input of container.querySelectorAll<HTMLInputElement | HTMLSelectElement>('input:not([aria-hidden="true"]), select')) {
      const named = (input.labels?.length ?? 0) > 0 || input.hasAttribute('aria-label') || input.hasAttribute('aria-labelledby');
      expect(named, `${theme}: unlabelled <${input.tagName.toLowerCase()} name="${input.name}">`).toBe(true);
    }
    for (const button of container.querySelectorAll('button')) expect((button.textContent ?? '').trim() !== '' || button.hasAttribute('aria-label'), `${theme}: nameless button`).toBe(true);
    unmount();
  }
});

test('no id repeats inside a specimen, and no form submits natively', () => {
  const { container } = mount('recovery');
  for (const figure of container.querySelectorAll('figure')) {
    const local = Array.from(figure.querySelectorAll('[id]'), (element) => element.id);
    expect(local.filter((id, index) => local.indexOf(id) !== index), figure.querySelector('figcaption')?.textContent ?? '').toEqual([]);
  }
  for (const form of container.querySelectorAll('form')) {
    expect(form.getAttribute('method')).toBe('post');
    expect(form.hasAttribute('action')).toBe(false);
  }
});

test('headings never skip a level inside any specimen', () => {
  const { container } = mount('recovery');
  for (const figure of container.querySelectorAll('figure')) {
    const levels = Array.from(figure.querySelectorAll('h1, h2, h3, h4'), (heading) => Number(heading.tagName.slice(1)));
    levels.forEach((level, index) => {
      if (index > 0) expect(level - (levels[index - 1] ?? 0), figure.querySelector('figcaption')?.textContent ?? '').toBeLessThanOrEqual(1);
    });
  }
});

test('synthetic fixtures are unmistakably fake: every name is "sample-", ids are labels, and nothing looks like a credential, an address or an archive', () => {
  for (const row of manifestItems) {
    if (row.kind === 'policy' || row.kind === 'role' || row.kind === 'address') continue;
    expect(row.label, row.id).toMatch(/^(sample-|ALLOW )/);
  }
  const everything = JSON.stringify({ manifest, reportFull });
  expect(everything).not.toMatch(/mdt_|token":|password|secret|hmac|integrity_hmac|content_digest|ciphertext|verifier/i);
  expect(everything).not.toMatch(/@\w+\.\w+/);
  expect(everything).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  expect(manifest.backupId).toMatch(/^sample-/);
});

test('the gallery states every approved restore outcome with its own words', () => {
  const { container } = mount('recovery');
  const text = container.textContent ?? '';
  for (const phrase of [
    'Restore complete',
    'The restore didn’t finish',
    'Another restore ran at the same moment and took precedence',
    'Mandatary couldn’t confirm what happened',
    'This file’s origin can’t be verified',
    'The file failed its integrity check',
    'That isn’t a readable Mandatary backup',
    'This backup was made by an incompatible version',
    'The file’s contents don’t add up',
    'Restore wasn’t allowed',
    'Mandatary couldn’t start the restore',
    'Nothing was approved',
    'Mandatary couldn’t confirm the result',
    'Mandatary is still in restore quarantine',
    'No restore to review',
    'Not approved here',
    'A full backup holds credential material',
    'Access decisions may take a moment to catch up',
  ]) {
    expect(text, phrase).toContain(phrase);
  }
});

test('no specimen implies a rollback or a trustworthy revocation history, and none offers an approve-everything action', () => {
  const { container } = mount('recovery');
  const text = container.textContent ?? '';
  expect(text).not.toMatch(/roll(ed)? ?back to|point in time|restore point|revocation history|undo the restore|everything is back/i);
  expect(text).toContain('A backup is a snapshot, not a rollback');
  expect(screen.queryByRole('button', { name: /approve all|select all|approve everything/i })).toBeNull();
});

test('rendering the gallery and switching theme touches no storage, cookie or network', () => {
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  mount('recovery');
  fireEvent.click(screen.getAllByRole('button', { name: 'Use dark theme' })[0] as HTMLElement);
  expect(setItem).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(document.cookie).toBe('');
  expect(localStorage.length + sessionStorage.length).toBe(0);
  vi.unstubAllGlobals();
});

test('the shell views have one main landmark, a skip link first, the assurance label and a Recovery group with the three destinations', () => {
  for (const [view, current] of [
    ['recovery-shell', 'Export backup'],
    ['recovery-shell-restore', 'Restore from backup'],
    ['recovery-shell-review', 'Review restored access'],
  ] as const) {
    const { container, unmount } = mount(view);
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expect(container.querySelector<HTMLElement>('a[href], button, input')?.textContent).toBe('Skip to main content');
    expect(screen.getByText('Multi-factor verified')).toBeTruthy();
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(nav.textContent).toContain('Recovery');
    for (const item of RECOVERY_NAV) expect(nav.textContent, `${view} ${item.label}`).toContain(item.label);
    expect(nav.querySelector('[aria-current="page"]')?.textContent, view).toBe(current);
    const labels = Array.from(nav.querySelectorAll('a'), (link) => link.textContent);
    expect(new Set(labels).size).toBe(labels.length);
    unmount();
  }
});

test('the other galleries are unchanged and separate from this one', () => {
  expect(mount('').container.textContent).toContain('Authentication screens: synthetic state gallery');
  cleanup();
  expect(mount('policy').container.textContent).toContain('Policy management screens: synthetic state gallery');
  cleanup();
  expect(mount('recovery').container.textContent).toContain('Export, restore and reapproval screens: synthetic state gallery');
});

test('a single specimen can be shown alone inside the shell (one main, one h1); a terminal page shows alone in its own pre-session frame; an unknown id falls back to the full gallery', () => {
  const only = mount('recovery-only-S-b');
  expect(screen.getAllByRole('main')).toHaveLength(1);
  expect(only.container.querySelectorAll('h1')).toHaveLength(1);
  expect(screen.getByRole('form', { name: 'Restore from a backup' })).toBeTruthy();
  expect(screen.getByText(/Synthetic S-b: File chosen, typed confirmation open/)).toBeTruthy();
  only.unmount();
  const page = mount('recovery-only-T-a');
  expect(screen.getAllByRole('main')).toHaveLength(1);
  expect(page.container.querySelectorAll('h1')).toHaveLength(1);
  expect(screen.queryByRole('navigation', { name: 'Primary' })).toBeNull();
  expect(screen.getByRole('heading', { level: 1, name: 'Restore complete' })).toBeTruthy();
  page.unmount();
  const fallback = mount('recovery-only-nope');
  expect(fallback.container.textContent).toContain('Export, restore and reapproval screens: synthetic state gallery');
});
