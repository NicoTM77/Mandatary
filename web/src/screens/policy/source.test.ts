import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';

/**
 * Source-level rules for the P1.17 screens, asserted rather than reviewed: both themes come from semantic tokens (so a screen cannot look right in
 * one theme only), the static CSP forbids inline styles, and nothing here may reach the network, storage or the console. These read the files, so a
 * future edit that breaks a rule fails here instead of in a reviewer's screenshot.
 */
const RAW = import.meta.glob(['./*.ts', './*.tsx', '!./*.test.ts', '!./*.test.tsx', '../../ui/Choice.tsx', '../../ui/ConfirmPanel.tsx', '../../ui/Disclosure.tsx'], { query: '?raw', import: 'default', eager: true });

function sources(): Array<[string, string]> {
  return Object.entries(RAW).map(([name, text]) => [name.replace(/^(\.\.\/)*\.?\/?/, '').replace(/^ui\//, 'src/ui/').replace(/^(?!src\/)/, 'src/screens/policy/'), String(text)]);
}

test('the sources under test are found (the assertions below must not pass vacuously)', () => {
  const names = sources().map(([name]) => name);
  for (const expected of ['src/screens/policy/rules.tsx', 'src/screens/policy/ruleEditor.tsx', 'src/screens/policy/users.tsx', 'src/screens/policy/groups.tsx', 'src/screens/policy/agentIdentity.tsx', 'src/screens/policy/contract.ts', 'src/ui/Choice.tsx', 'src/ui/ConfirmPanel.tsx', 'src/ui/Disclosure.tsx']) {
    expect(names, expected).toContain(expected);
  }
  expect(names.some((name) => name.includes('.test.'))).toBe(false);
});

test('both themes: no dark: variant, no raw colour and no inline style in any management screen or new primitive', () => {
  for (const [name, text] of sources()) {
    expect(text, `${name}: dark: variant`).not.toMatch(/\bdark:/);
    expect(text, `${name}: raw hex colour`).not.toMatch(/#[0-9a-fA-F]{3,8}\b(?![\w-])/);
    expect(text, `${name}: rgb()/hsl()`).not.toMatch(/\b(rgb|hsl)a?\(/);
    expect(text, `${name}: inline style attribute`).not.toMatch(/\sstyle=\{/);
  }
});

test('the sticky header never covers a focused control: the page reserves space for it when scrolling to focus', () => {
  // Read from disk (vitest runs from web/): its CSS pipeline returns an empty string for a ?raw import, as theme-contrast.test.ts notes.
  const css = readFileSync('src/style.css', 'utf8');
  expect(css.length).toBeGreaterThan(1000);
  const match = /html\s*\{[^}]*scroll-padding-top:\s*([\d.]+)rem/.exec(css);
  expect(match, 'html { scroll-padding-top } is missing').not.toBeNull();
  // The tallest header is the phone layout, 91.5px = 5.72rem at 16px: the reserved space must clear it.
  expect(Number(match?.[1])).toBeGreaterThanOrEqual(5.75);
});

test('nothing in the screens fetches, stores, logs or injects HTML', () => {
  for (const [name, text] of sources()) {
    expect(text, `${name}: fetch`).not.toMatch(/\bfetch\s*\(/);
    expect(text, `${name}: XMLHttpRequest/WebSocket/EventSource`).not.toMatch(/\b(XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/);
    expect(text, `${name}: web storage or cookies`).not.toMatch(/\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie/);
    expect(text, `${name}: console`).not.toMatch(/\bconsole\./);
    expect(text, `${name}: raw HTML`).not.toMatch(/dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML/);
    expect(text, `${name}: eval`).not.toMatch(/\beval\(|new Function\(/);
  }
});

test('no screen holds a secret: the contract has no token, password or code field', () => {
  const contract = sources().find(([name]) => name === 'src/screens/policy/contract.ts')?.[1] ?? '';
  expect(contract.length).toBeGreaterThan(1000);
  // The header comment names these words to say they are absent; strip comments before looking for fields.
  const code = contract.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  expect(code).not.toMatch(/\b(token|password|secret|recoveryCode|seed|bearer)\b/i);
});

test('every confirmation in the screens goes through ConfirmPanel, so keyboard and focus behaviour is defined once', () => {
  for (const [name, text] of sources()) {
    if (!name.includes('/screens/policy/') || !name.endsWith('.tsx')) continue;
    expect(text, `${name}: a hand-rolled confirmation group`).not.toMatch(/role="group"[^>]*aria-label=\{`(Confirm|Remove|Delete|Disable)/);
  }
});
