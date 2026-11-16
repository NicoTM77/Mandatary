import { readFileSync } from 'node:fs';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { ThemeProvider } from '../theme';
import { AdminShell, BrandIcon, BrandLockup, CenteredFrame } from '.';
import { ICON_PATHS } from './BrandMark';

afterEach(cleanup);

// Read from disk (vitest runs from web/). The approved artwork is versioned in web/brand/ and is the source of truth.
const css = readFileSync('src/style.css', 'utf8');
const themeSpec = readFileSync('brand/THEME.md', 'utf8');
const SOURCES = {
  'dark icon': readFileSync('brand/mandatary-icon.svg', 'utf8'),
  'light icon': readFileSync('brand/mandatary-icon-light.svg', 'utf8'),
  'dark logo': readFileSync('brand/mandatary-logo.svg', 'utf8'),
  'light logo': readFileSync('brand/mandatary-logo-light.svg', 'utf8'),
} as const;

function tokens(theme: 'light' | 'dark'): Map<string, string> {
  const selector = theme === 'dark' ? /\[data-theme='dark'\]\s*\{([^}]*)\}/ : /:root,\s*\[data-theme='light'\]\s*\{([^}]*)\}/;
  const block = selector.exec(css)?.[1] ?? '';
  return new Map(Array.from(block.matchAll(/--(brand-[a-z]+):\s*(#[0-9a-fA-F]{6})\s*;/g), ([, name, value]) => [name ?? '', (value ?? '').toLowerCase()]));
}

/** The fill of the <path> carrying exactly this path data, in an approved SVG. */
function fillOf(svg: string, d: string): string | undefined {
  for (const [, attributes] of svg.matchAll(/<path\s+([^>]*?)\/>/g)) {
    if (attributes?.includes(`d="${d}"`)) return /fill="(#[0-9a-fA-F]{6})"/.exec(attributes)?.[1]?.toLowerCase();
  }
  return undefined;
}

/** The fill of the live <text> element with exactly this content, in an approved full logo. */
function textFill(svg: string, content: string): string | undefined {
  for (const [, attributes, body] of svg.matchAll(/<text\s+([^>]*)>([^<]*)<\/text>/g)) {
    if (body === content) return /fill="(#[0-9a-fA-F]{6})"/.exec(attributes ?? '')?.[1]?.toLowerCase();
  }
  return undefined;
}

/** The colours THEME.md approves, by element, parsed from its table. */
function approved(theme: 'light' | 'dark'): Map<string, string> {
  const result = new Map<string, string>();
  for (const [, element, dark, light] of themeSpec.matchAll(/^\|\s*([A-Za-z ]+?)\s*\|\s*[A-Za-z ]+`(#[0-9A-Fa-f]{6})`\s*\|\s*[A-Za-z ]+`(#[0-9A-Fa-f]{6})`/gm)) {
    result.set(element ?? '', ((theme === 'dark' ? dark : light) ?? '').toLowerCase());
  }
  return result;
}

// ───────────────────────── artwork fidelity ─────────────────────────

test.each(Object.entries(SOURCES))('the component geometry is the approved %s artwork, verbatim', (_name, svg) => {
  for (const d of Object.values(ICON_PATHS)) expect(svg, d).toContain(`d="${d}"`);
});

test.each(['light', 'dark'] as const)('%s: the brand tokens are exactly the colours approved in THEME.md and used by the approved SVGs', (theme) => {
  const token = tokens(theme);
  const spec = approved(theme);
  expect([...spec.keys()].sort()).toEqual(['Gateway', 'Lower pillars', 'M symbol', 'Tagline', 'Wordmark']);
  expect(token.get('brand-mark')).toBe(spec.get('M symbol'));
  expect(token.get('brand-gateway')).toBe(spec.get('Gateway'));
  expect(token.get('brand-pillar')).toBe(spec.get('Lower pillars'));
  expect(token.get('brand-wordmark')).toBe(spec.get('Wordmark'));

  const icon = theme === 'dark' ? SOURCES['dark icon'] : SOURCES['light icon'];
  const logo = theme === 'dark' ? SOURCES['dark logo'] : SOURCES['light logo'];
  for (const svg of [icon, logo]) {
    expect(fillOf(svg, ICON_PATHS.m)).toBe(token.get('brand-mark'));
    expect(fillOf(svg, ICON_PATHS.gateway)).toBe(token.get('brand-gateway'));
    expect(fillOf(svg, ICON_PATHS.pillarLeft)).toBe(token.get('brand-pillar'));
    expect(fillOf(svg, ICON_PATHS.pillarRight)).toBe(token.get('brand-pillar'));
  }
  expect(textFill(logo, 'mandatary')).toBe(spec.get('Wordmark'));
  expect(textFill(logo, 'Authority by design.')).toBe(spec.get('Tagline'));
});

test.each(Object.entries(SOURCES))('the approved %s is inert: no script, event handler, external reference, style, image or foreignObject', (_name, svg) => {
  expect(svg).not.toMatch(/<script|<foreignObject|<style|<image|<use|<a[\s>]|<iframe|<object|<embed/i);
  expect(svg).not.toMatch(/\son[a-z]+\s*=/i);
  expect(svg).not.toMatch(/(?:href|src)\s*=|url\(|@import|javascript:|data:/i);
  expect(svg).not.toMatch(/<!(?:DOCTYPE|ENTITY)/i);
  // Only the SVG namespace is declared.
  expect(svg).not.toContain('xmlns:');
  expect(Array.from(svg.matchAll(/xmlns="([^"]+)"/g), (match) => match[1])).toEqual(['http://www.w3.org/2000/svg']);
});

test('the approved full logos keep live text in a font the application does not ship, which is why they are source assets only', () => {
  for (const svg of [SOURCES['dark logo'], SOURCES['light logo']]) expect(svg).toMatch(/<text[^>]*font-family="Manrope, Inter, Arial, sans-serif"/);
  expect(css).not.toMatch(/@font-face/);
});

// ───────────────────────── component ─────────────────────────

test('the icon is decorative: hidden from assistive technology, unfocusable, no title or description', () => {
  const { container } = render(<BrandIcon />);
  const svg = container.querySelector('svg');
  expect(svg?.getAttribute('aria-hidden')).toBe('true');
  expect(svg?.getAttribute('focusable')).toBe('false');
  expect(svg?.querySelector('title, desc')).toBeNull();
  expect(svg?.getAttribute('role')).toBeNull();
  // Colours come from the theme tokens through classes: no inline style (CSP style-src 'self'), no hard-coded fill.
  expect(svg?.outerHTML).not.toMatch(/style=|fill="/);
  expect(Array.from(svg?.querySelectorAll('path') ?? [], (path) => path.getAttribute('class'))).toEqual(['fill-brand-gateway', 'fill-brand-pillar', 'fill-brand-pillar', 'fill-brand-mark']);
});

test('the lockup names the product once, in lowercase, without the tagline', () => {
  const { container } = render(<BrandLockup />);
  expect(screen.getAllByText('mandatary')).toHaveLength(1);
  expect(container.textContent).toBe('mandatary');
  expect(container.textContent).not.toMatch(/authority by design/i);
  expect(container.querySelector('a, button, h1, h2, nav, [role]')).toBeNull();
});

test('the signed-in shell and the pre-session frame each show the lockup exactly once, outside main', () => {
  const { unmount } = render(
    <ThemeProvider>
      <AdminShell nav={[{ id: 'a', label: 'Overview', href: '#a' }]} currentId="a">
        <h1>Page</h1>
      </AdminShell>
    </ThemeProvider>,
  );
  expect(screen.getAllByText('mandatary')).toHaveLength(1);
  expect(screen.getByRole('main').textContent).not.toContain('mandatary');
  unmount();
  render(
    <ThemeProvider>
      <CenteredFrame>
        <h1>Sign in</h1>
      </CenteredFrame>
    </ThemeProvider>,
  );
  expect(screen.getAllByText('mandatary')).toHaveLength(1);
  expect(screen.getByRole('main').textContent).not.toContain('mandatary');
});

test('the pre-session lockup drops to the glyph on very narrow screens but keeps the word as its accessible name; the shell row never hides it', () => {
  const frame = render(<BrandLockup size="frame" />);
  const frameWord = screen.getByText('mandatary');
  expect(frameWord.className).toContain('max-[350px]:sr-only');
  expect(frameWord.textContent).toBe('mandatary');
  frame.unmount();
  render(<BrandLockup size="header" />);
  expect(screen.getByText('mandatary').className).not.toContain('sr-only');
});
