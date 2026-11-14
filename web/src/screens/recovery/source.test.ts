import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';
import { RECOVERY_NAV, RECOVERY_ROUTES } from './nav';
import { POLICY_NAV } from '../policy/nav';

/**
 * Source-level rules for the P1.18 screens, asserted rather than reviewed (same idea as ../policy/source.test.ts): both themes come from semantic
 * tokens, the static CSP forbids inline styles, nothing here may reach the network, storage or the console, and the boundaries of this contribution
 * (no cryptography, no file parsing, no authorization, no transaction control) are checked by looking for the APIs that would cross them.
 */
const RAW = import.meta.glob(['./*.ts', './*.tsx', '!./*.test.ts', '!./*.test.tsx'], { query: '?raw', import: 'default', eager: true });

function sources(): Array<[string, string]> {
  return Object.entries(RAW).map(([name, text]) => [`src/screens/recovery/${name.replace(/^\.\//, '')}`, String(text)]);
}

const strip = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

test('the sources under test are found (the assertions below must not pass vacuously)', () => {
  const names = sources().map(([name]) => name);
  for (const expected of ['contract.ts', 'export.tsx', 'restore.tsx', 'review.tsx', 'shared.tsx', 'nav.ts', 'outcomes.ts']) expect(names, expected).toContain(`src/screens/recovery/${expected}`);
  expect(names.some((name) => name.includes('.test.'))).toBe(false);
});

test('both themes: no dark: variant, no raw colour and no inline style in any recovery screen', () => {
  for (const [name, text] of sources()) {
    expect(text, `${name}: dark: variant`).not.toMatch(/\bdark:/);
    expect(text, `${name}: raw hex colour`).not.toMatch(/#[0-9a-fA-F]{3,8}\b(?![\w-])/);
    expect(text, `${name}: rgb()/hsl()`).not.toMatch(/\b(rgb|hsl)a?\(/);
    expect(text, `${name}: inline style attribute`).not.toMatch(/\sstyle=\{/);
  }
});

test('nothing in the screens fetches, stores, logs or injects HTML', () => {
  for (const [name, text] of sources()) {
    const code = strip(text);
    expect(code, `${name}: fetch`).not.toMatch(/\bfetch\s*\(/);
    expect(code, `${name}: XMLHttpRequest/WebSocket/EventSource`).not.toMatch(/\b(XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/);
    expect(code, `${name}: web storage or cookies`).not.toMatch(/\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie/);
    expect(code, `${name}: console`).not.toMatch(/\bconsole\./);
    expect(code, `${name}: raw HTML`).not.toMatch(/dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML/);
    expect(code, `${name}: eval`).not.toMatch(/\beval\(|new Function\(/);
  }
});

test('boundary: no cryptography, no reading or parsing of a file, no object-URL download and no navigation in the screens', () => {
  for (const [name, text] of sources()) {
    const code = strip(text);
    expect(code, `${name}: cryptography`).not.toMatch(/\bcrypto\b|\bsubtle\b|\bHMAC\b|\bsha-?\d+\b|\bTextEncoder\b|\bbtoa\b|\batob\b/i);
    expect(code, `${name}: reading a file`).not.toMatch(/\bFileReader\b|\.text\(\)|\.arrayBuffer\(\)|\.stream\(\)|\.slice\(\s*0/);
    expect(code, `${name}: parsing`).not.toMatch(/JSON\.parse|JSON\.stringify/);
    expect(code, `${name}: download or navigation`).not.toMatch(/createObjectURL|\blocation\b|\.assign\(|\.replace\(\s*['"`]\//);
  }
});

test('no screen holds a secret: the contract has no token, password, key, archive-content or credential-value field', () => {
  const contract = sources().find(([name]) => name.endsWith('/contract.ts'))?.[1] ?? '';
  expect(contract.length).toBeGreaterThan(2000);
  const code = strip(contract);
  expect(code).not.toMatch(/\b(token|password|secret|recoveryCode|seed|bearer|verifier|ciphertext|hmac|archive)\b\s*[?:]/i);
  // The only File in the contract is the browser's own handle; there is no string that could be an archive.
  expect(code.match(/\bFile\b/g)).toHaveLength(2);
});

test('the contract names no state, generation or quarantine VALUE the screens could be asked to decide with', () => {
  const code = strip(sources().find(([name]) => name.endsWith('/contract.ts'))?.[1] ?? '');
  expect(code).not.toMatch(/\b(generation|restore_generation|restoreGeneration|quarantined)\b/);
});

test('every confirmation goes through ConfirmPanel, so keyboard and focus behaviour is defined once', () => {
  for (const [name, text] of sources()) {
    if (!name.endsWith('restore.tsx') && !name.endsWith('review.tsx')) continue;
    expect(text, `${name}: ConfirmPanel`).toMatch(/<ConfirmPanel\b/);
    expect(text, `${name}: a hand-rolled confirmation group`).not.toMatch(/role="group"[^>]*aria-label=\{`(Confirm|Restore|Approve)/);
  }
});

test('the screens never read a record\'s source_state to decide anything: it is displayed, never compared except to hide the unremarkable "active"', () => {
  const review = sources().find(([name]) => name.endsWith('/review.tsx'))?.[1] ?? '';
  const uses = review.match(/sourceState/g) ?? [];
  expect(uses.length).toBeGreaterThan(0);
  for (const line of review.split('\n').filter((candidate) => candidate.includes('sourceState'))) {
    expect(line, line.trim()).not.toMatch(/\b(approvable|selectable|decision|disabled)\b/);
  }
});

test('the recovery routes are exact, distinct from the P1.16 /recovery sign-in and the policy routes, and grouped under Recovery', () => {
  expect(RECOVERY_NAV.map((item) => [item.id, item.href, item.group])).toEqual([
    ['backup-export', '/backup', 'Recovery'],
    ['backup-restore', '/restore', 'Recovery'],
    ['backup-review', '/restore/review', 'Recovery'],
  ]);
  expect(Object.values(RECOVERY_ROUTES)).toEqual(['/backup', '/restore', '/restore/review']);
  const taken = new Set(['/', '/setup', '/login', '/security', '/recovery', '/agents', ...POLICY_NAV.map((item) => item.href)]);
  for (const route of Object.values(RECOVERY_ROUTES)) expect(taken.has(route), route).toBe(false);
  const labels = [...POLICY_NAV, ...RECOVERY_NAV].map((item) => item.label);
  expect(new Set(labels).size).toBe(labels.length);
});

test('the sticky header never covers a focused control: the page reserves space for it when scrolling to focus', () => {
  const css = readFileSync('src/style.css', 'utf8');
  const match = /html\s*\{[^}]*scroll-padding-top:\s*([\d.]+)rem/.exec(css);
  expect(match, 'html { scroll-padding-top } is missing').not.toBeNull();
  expect(Number(match?.[1])).toBeGreaterThanOrEqual(5.75);
});
