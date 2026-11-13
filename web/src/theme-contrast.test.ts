import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';

// Read from disk (vitest runs from web/): its CSS pipeline returns an empty string for a ?raw import.
const css = readFileSync('src/style.css', 'utf8');

/**
 * WCAG 2.2 contrast regression for BOTH themes, computed from the real token values in style.css.
 * Editing a colour that drops any pair below its threshold fails here, so a theme cannot silently
 * become unreadable. Thresholds: 4.5:1 normal text (1.4.3), 3:1 control boundaries and focus ring (1.4.11).
 */

function block(selector: RegExp): Map<string, string> {
  const match = selector.exec(css);
  if (!match?.[1]) throw new Error(`token block not found: ${selector}`);
  const tokens = new Map<string, string>();
  for (const [, name, value] of match[1].matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
    if (name && value) tokens.set(name, value);
  }
  return tokens;
}

function channel(hex: string, offset: number): number {
  const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
  return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  return 0.2126 * channel(hex, 1) + 0.7152 * channel(hex, 3) + 0.0722 * channel(hex, 5);
}

function ratio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return ((hi ?? 0) + 0.05) / ((lo ?? 0) + 0.05);
}

const themes = new Map<'light' | 'dark', Map<string, string>>([
  ['light', block(/:root,\s*\[data-theme='light'\]\s*\{([^}]*)\}/)],
  ['dark', block(/\[data-theme='dark'\]\s*\{([^}]*)\}/)],
]);

/** [foreground token, background token, minimum ratio, where it is used] */
const PAIRS: ReadonlyArray<readonly [string, string, number, string]> = [
  ['fg', 'bg', 7, 'body text on page'],
  ['fg', 'surface', 7, 'body text in panels'],
  ['fg', 'sunken', 7, 'text on nav hover / read-only inputs'],
  ['muted', 'surface', 4.5, 'secondary text in panels'],
  ['muted', 'bg', 4.5, 'secondary text on page'],
  ['muted', 'sunken', 4.5, 'secondary text on sunken'],
  ['subtle', 'surface', 4.5, 'placeholders, group labels'],
  ['subtle', 'bg', 4.5, 'group labels on page'],
  ['accent-fg', 'accent', 4.5, 'primary button label'],
  ['accent-fg', 'accent-hover', 4.5, 'primary button label on hover'],
  ['accent-text', 'accent-soft', 4.5, 'current nav item, info badge'],
  ['accent', 'surface', 4.5, 'accent used as text/link on surface'],
  ['accent-text', 'surface', 4.5, 'quiet button / link text'],
  ['danger', 'surface', 4.5, 'inline error, danger button'],
  ['danger', 'danger-soft', 4.5, 'danger alert and badge'],
  ['fg', 'danger-soft', 7, 'danger alert body'],
  ['warn', 'warn-soft', 4.5, 'warning alert, reveal-once panel and badge'],
  ['fg', 'warn-soft', 7, 'warning alert body'],
  ['success', 'success-soft', 4.5, 'success alert and badge'],
  ['success', 'surface', 4.5, 'success text on surface'],
  ['fg', 'accent-soft', 7, 'info alert body'],
  ['line-strong', 'surface', 3, 'input and secondary-button boundaries'],
  ['line-strong', 'bg', 3, 'control boundaries on the page'],
  ['focus', 'surface', 3, 'focus ring on panels'],
  ['focus', 'bg', 3, 'focus ring on the page'],
  ['focus', 'sunken', 3, 'focus ring on sunken areas'],
];

test.each(['light', 'dark'] as const)('%s theme defines every token the pairs use', (theme) => {
  const tokens = themes.get(theme) ?? new Map<string, string>();
  for (const [fg, bg] of PAIRS) {
    expect(tokens.has(fg), `${theme}: --${fg}`).toBe(true);
    expect(tokens.has(bg), `${theme}: --${bg}`).toBe(true);
  }
});

for (const theme of ['light', 'dark'] as const) {
  for (const [fg, bg, minimum, use] of PAIRS) {
    test(`${theme}: ${fg} on ${bg} is at least ${minimum}:1 (${use})`, () => {
      const tokens = themes.get(theme) ?? new Map<string, string>();
      const foreground = tokens.get(fg);
      const background = tokens.get(bg);
      expect(foreground && background).toBeTruthy();
      expect(ratio(foreground as string, background as string)).toBeGreaterThanOrEqual(minimum);
    });
  }
}

test('the stylesheet never relies on web fonts or data:/remote URLs (the static CSP forbids them)', () => {
  expect(css).not.toMatch(/@font-face/);
  expect(css).not.toMatch(/url\(\s*['"]?data:/);
  expect(css).not.toMatch(/url\(\s*['"]?https?:/);
});

test('both themes declare their colour-scheme so native controls and scrollbars follow the theme', () => {
  expect(css).toMatch(/\[data-theme='light'\]\s*\{\s*color-scheme: light;/);
  expect(css).toMatch(/\[data-theme='dark'\]\s*\{\s*color-scheme: dark;/);
});
