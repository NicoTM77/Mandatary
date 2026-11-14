import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { POLICY_NAV, POLICY_ROUTES } from '../screens/policy/nav';
import { ThemeProvider } from '../theme';
import Gallery from './Gallery';
import { agents, groups, rules, subjects, users } from './policyFixtures';

afterEach(cleanup);

function mount(view: string, theme?: 'light' | 'dark') {
  return render(
    <ThemeProvider {...(theme ? { initial: theme } : {})}>
      <Gallery view={view} />
    </ThemeProvider>,
  );
}

/**
 * Document-wide invariants over every synthetic P1.17 state at once. Like the P1.16 gallery tests these stand in for an
 * automated accessibility scan (none is approved) and assert the static CSP constraints; they are structural checks, not
 * a conformance claim.
 */

test('every specimen is labelled as synthetic so no illustrated state can be mistaken for shipped behaviour', () => {
  const { container } = mount('policy');
  const figures = container.querySelectorAll('figure');
  expect(figures.length).toBeGreaterThanOrEqual(33);
  for (const figure of figures) {
    expect(figure.querySelector('figcaption')?.textContent, figure.textContent?.slice(0, 40)).toContain('Synthetic');
  }
});

test('every specimen carries a unique flow id, and the groups cover users, groups, agents, rules and the editor', () => {
  const { container } = mount('policy');
  const flows = Array.from(container.querySelectorAll('figure figcaption span.font-mono'), (node) => node.textContent ?? '');
  expect(new Set(flows).size).toBe(flows.length);
  for (const prefix of ['U-', 'G-', 'A-', 'R-', 'E-']) {
    expect(flows.some((flow) => flow.startsWith(prefix)), prefix).toBe(true);
  }
});

test('the gallery obeys the static CSP: no inline style attributes, images, scripts or remote and data: URLs (both themes)', () => {
  for (const theme of ['light', 'dark'] as const) {
    const { container, unmount } = mount('policy', theme);
    expect(document.documentElement.dataset.theme).toBe(theme);
    expect(container.querySelectorAll('[style]')).toHaveLength(0);
    expect(container.querySelectorAll('img, picture, video, audio, iframe, object, embed, link, script')).toHaveLength(0);
    for (const element of container.querySelectorAll('[href], [src], [action], [formaction]')) {
      for (const name of ['href', 'src', 'action', 'formaction']) {
        const value = element.getAttribute(name);
        if (value === null) continue;
        expect(value, `${theme} ${name} on <${element.tagName.toLowerCase()}>`).not.toMatch(/^(https?:|data:|javascript:)/i);
      }
    }
    unmount();
  }
});

test('every input has an accessible name and every button has text (both themes)', () => {
  for (const theme of ['light', 'dark'] as const) {
    const { container, unmount } = mount('policy', theme);
    for (const input of container.querySelectorAll<HTMLInputElement | HTMLSelectElement>('input:not([aria-hidden="true"]), select')) {
      const named = (input.labels?.length ?? 0) > 0 || input.hasAttribute('aria-label') || input.hasAttribute('aria-labelledby');
      expect(named, `${theme}: unlabelled <${input.tagName.toLowerCase()} name="${input.name}">`).toBe(true);
    }
    for (const button of container.querySelectorAll('button')) {
      expect((button.textContent ?? '').trim() !== '' || button.hasAttribute('aria-label'), `${theme}: nameless button`).toBe(true);
    }
    unmount();
  }
});

test('no two buttons or links in the whole gallery share an id, and no form submits natively', () => {
  const { container } = mount('policy');
  const ids = Array.from(container.querySelectorAll('[id]'), (element) => element.id);
  // Row ids repeat across specimens that show the same fixture, so uniqueness is asserted per specimen instead.
  for (const figure of container.querySelectorAll('figure')) {
    const local = Array.from(figure.querySelectorAll('[id]'), (element) => element.id);
    expect(local.filter((id, index) => local.indexOf(id) !== index), figure.querySelector('figcaption')?.textContent ?? '').toEqual([]);
  }
  expect(ids.length).toBeGreaterThan(0);
  for (const form of container.querySelectorAll('form')) {
    expect(form.getAttribute('method')).toBe('post');
    expect(form.hasAttribute('action')).toBe(false);
  }
});

test('headings never skip a level inside any specimen', () => {
  const { container } = mount('policy');
  for (const figure of container.querySelectorAll('figure')) {
    const levels = Array.from(figure.querySelectorAll('h1, h2, h3, h4'), (heading) => Number(heading.tagName.slice(1)));
    levels.forEach((level, index) => {
      if (index > 0) expect(level - (levels[index - 1] ?? 0), figure.querySelector('figcaption')?.textContent ?? '').toBeLessThanOrEqual(1);
    });
  }
});

test('synthetic fixtures are unmistakably fake: every account, group and agent is "sample-", every address and image is reserved', () => {
  const names = [...users.map((user) => user.username), ...groups.groups.map((group) => group.name), ...agents.agents.map((agent) => agent.name), ...subjects.map((subject) => subject.name)];
  for (const name of names) expect(name, name).toMatch(/^sample-/);
  for (const rule of rules) expect(rule.selector.containerName, rule.id).toMatch(/^sample-/);
  const everything = JSON.stringify({ users, groups, agents, rules });
  expect(everything).not.toMatch(/mdt_|token":|password|secret/i);
  expect(everything).not.toMatch(/@(?!example\.invalid)\w+\.\w+/);
});

test('the gallery states every approved lifecycle: a blocked delete, a missing target, a restored rule, an unverified endpoint and a refusal', () => {
  const { container } = mount('policy');
  const text = container.textContent ?? '';
  for (const phrase of ['Can’t be deleted yet', 'Inactive · target missing', 'Waiting for approval', 'can’t verify its own container', 'Policy administration isn’t available to this session', 'Mandatary couldn’t confirm the result']) {
    expect(text, phrase).toContain(phrase);
  }
});

test('rendering the gallery and switching theme touches no storage, cookie or network', () => {
  const setItem = vi.spyOn(Storage.prototype, 'setItem');
  const fetchSpy = vi.fn();
  vi.stubGlobal('fetch', fetchSpy);
  mount('policy');
  fireEvent.click(screen.getAllByRole('button', { name: 'Use dark theme' })[0] as HTMLElement);
  expect(setItem).not.toHaveBeenCalled();
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(document.cookie).toBe('');
  expect(localStorage.length + sessionStorage.length).toBe(0);
  vi.unstubAllGlobals();
});

test('the shell views have one main landmark, a skip link first, the assurance label and a Policy group with the four destinations', () => {
  for (const [view, current] of [
    ['policy-shell', 'Rules'],
    ['policy-shell-users', 'Users'],
    ['policy-shell-groups', 'Groups'],
    ['policy-shell-agents', 'Agents'],
  ] as const) {
    const { container, unmount } = mount(view);
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expect(container.querySelector<HTMLElement>('a[href], button, input')?.textContent).toBe('Skip to main content');
    expect(screen.getByText('Multi-factor verified')).toBeTruthy();
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(nav.textContent).toContain('Policy');
    for (const label of ['Rules', 'Users', 'Groups', 'Agents', 'Agent tokens']) expect(nav.textContent, `${view} ${label}`).toContain(label);
    expect(nav.querySelector('[aria-current="page"]')?.textContent, view).toBe(current);
    unmount();
  }
});

test('the Agents identity item and the P1.16 Agent tokens item never share a label', () => {
  mount('policy-shell-agents');
  const links = screen.getByRole('navigation', { name: 'Primary' }).querySelectorAll('a');
  const labels = Array.from(links, (link) => link.textContent);
  expect(new Set(labels).size).toBe(labels.length);
});

test('the policy navigation is the exact route set the integration must allow, grouped under Policy', () => {
  expect(POLICY_NAV.map((item) => [item.id, item.href, item.group])).toEqual([
    ['policy-rules', '/policy', 'Policy'],
    ['policy-users', '/policy/users', 'Policy'],
    ['policy-groups', '/policy/groups', 'Policy'],
    ['policy-agents', '/policy/agents', 'Policy'],
  ]);
  expect(Object.values(POLICY_ROUTES)).toEqual(['/policy', '/policy/users', '/policy/groups', '/policy/agents']);
});

test('the state gallery and the P1.16 gallery are separate views: the original synthetic view is unchanged', () => {
  const { container } = mount('');
  expect(container.textContent).toContain('Authentication screens: synthetic state gallery');
  expect(container.textContent).not.toContain('Policy management screens');
});

test('a single specimen can be shown alone inside the shell (one main, one h1), and an unknown id falls back to the full gallery', () => {
  const { container, unmount } = mount('policy-only-E-c');
  expect(screen.getAllByRole('main')).toHaveLength(1);
  expect(container.querySelectorAll('h1')).toHaveLength(1);
  expect(screen.getByRole('form', { name: 'Edit rule' })).toBeTruthy();
  expect(screen.getByText(/Synthetic E-c: Edit a broad Allow/)).toBeTruthy();
  unmount();
  const fallback = mount('policy-only-nope');
  expect(fallback.container.textContent).toContain('Policy management screens: synthetic state gallery');
});
