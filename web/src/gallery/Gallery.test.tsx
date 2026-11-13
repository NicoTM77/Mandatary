import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { ThemeProvider } from '../theme';
import Gallery from './Gallery';
import { SYNTHETIC } from './fixtures';

afterEach(cleanup);

function mount(view: string) {
  return render(
    <ThemeProvider>
      <Gallery view={view} />
    </ThemeProvider>,
  );
}

/**
 * Document-wide invariants over every synthetic state at once. These stand in for an automated
 * accessibility scan (no scanner dependency is approved yet): they catch the structural defects such
 * scanners find first, and they assert the CSP constraints of the static handler.
 */

test('every specimen is labelled as synthetic so no illustrated state can be mistaken for shipped behaviour', () => {
  const { container } = mount('');
  const figures = container.querySelectorAll('figure');
  expect(figures.length).toBeGreaterThanOrEqual(70);
  for (const figure of figures) {
    expect(figure.querySelector('figcaption')?.textContent, figure.textContent?.slice(0, 40)).toContain('Synthetic');
  }
  expect(screen.getByText('Everything on this page is an illustration')).toBeTruthy();
});

test('every input has an accessible name, every button has text, and ids are unique (both themes)', () => {
  for (const theme of ['light', 'dark'] as const) {
    const { container, unmount } = render(
      <ThemeProvider initial={theme}>
        <Gallery view="" />
      </ThemeProvider>,
    );
    expect(document.documentElement.dataset.theme).toBe(theme);
    for (const input of container.querySelectorAll<HTMLInputElement>('input:not([aria-hidden="true"])')) {
      const named = (input.labels?.length ?? 0) > 0 || input.hasAttribute('aria-label') || input.hasAttribute('aria-labelledby');
      expect(named, `${theme}: unlabelled <input name="${input.name}">`).toBe(true);
    }
    for (const button of container.querySelectorAll('button')) {
      expect((button.textContent ?? '').trim() !== '' || button.hasAttribute('aria-label'), `${theme}: nameless button`).toBe(true);
    }
    const ids = Array.from(container.querySelectorAll('[id]'), (element) => element.id);
    const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
    expect(duplicates, `${theme}: duplicate ids`).toEqual([]);
    unmount();
  }
});

test('the gallery obeys the static CSP: no inline style attributes, no images, no remote or data: URLs', () => {
  const { container } = mount('');
  expect(container.querySelectorAll('[style]')).toHaveLength(0);
  expect(container.querySelectorAll('img, picture, video, audio, iframe, object, embed, link, script')).toHaveLength(0);
  for (const element of container.querySelectorAll('[href], [src], [action], [formaction]')) {
    for (const name of ['href', 'src', 'action', 'formaction']) {
      const value = element.getAttribute(name);
      if (value === null) continue;
      expect(value, `${name} on <${element.tagName.toLowerCase()}>`).not.toMatch(/^(https?:|data:|javascript:)/i);
    }
  }
});

test('headings never skip a level downward-to-upward in the page outline beyond one step', () => {
  const { container } = mount('');
  const levels = Array.from(container.querySelectorAll('h1, h2, h3, h4, h5, h6'), (heading) => Number(heading.tagName.slice(1)));
  expect(levels[0]).toBe(1);
  levels.forEach((level, index) => {
    if (index > 0) expect(level - (levels[index - 1] ?? 0), `heading ${index}`).toBeLessThanOrEqual(1);
  });
});

test('synthetic fixtures are unmistakably fake and not shaped like real secrets', () => {
  const values = [SYNTHETIC.seed, SYNTHETIC.token, ...SYNTHETIC.recoveryCodes];
  for (const value of values) {
    expect(value).toMatch(/SYNTHETIC/);
  }
  // Real agent tokens are 43 base62 characters after the prefix; real TOTP seeds are base32 with no punctuation.
  expect(SYNTHETIC.token).not.toMatch(/^mdt_[0-9A-Za-z]{43}$/);
  expect(SYNTHETIC.seed).not.toMatch(/^[A-Z2-7]{26,}$/);
});

test('rendering the gallery touches no storage, cookie, network or navigation', () => {
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  mount('');
  fireEvent.click(screen.getAllByRole('button', { name: 'Use dark theme' })[0] as HTMLElement);
  expect(setItem).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(document.cookie).toBe('');
  expect(localStorage.length + sessionStorage.length).toBe(0);
  vi.unstubAllGlobals();
});

test('the shell view has exactly one main landmark, a skip link first, and the assurance label', () => {
  const { container } = mount('shell');
  expect(screen.getAllByRole('main')).toHaveLength(1);
  const first = container.querySelector<HTMLElement>('a[href], button, input');
  expect(first?.textContent).toBe('Skip to main content');
  expect(screen.getByText('Multi-factor verified')).toBeTruthy();
  expect(screen.getByRole('navigation', { name: 'Primary' })).toBeTruthy();
});

test('the theme toggle switches the whole gallery between light and dark', () => {
  mount('');
  const toggle = screen.getAllByRole('button', { name: /Use (dark|light) theme/ })[0] as HTMLElement;
  const before = document.documentElement.dataset.theme;
  fireEvent.click(toggle);
  expect(document.documentElement.dataset.theme).not.toBe(before);
});
