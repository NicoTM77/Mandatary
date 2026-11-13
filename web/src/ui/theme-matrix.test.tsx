import { readFileSync } from 'node:fs';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { ThemeProvider } from '../theme';
import { Alert, Button, EmptyState, Skeleton } from '.';

/**
 * Theme matrix (UX §3): every new primitive renders under BOTH themes via semantic tokens only.
 * Contrast values themselves are covered by theme-contrast.test.ts; this file checks that the
 * primitives cannot bypass the token system (no raw colours, no inline styles).
 */

afterEach(cleanup);

const THEMES = ['light', 'dark'] as const;

function renderBoth(theme: 'light' | 'dark') {
  return render(
    <ThemeProvider initial={theme}>
      <Skeleton label="addresses" />
      <EmptyState title="No addresses yet" description="Add one to receive notices." action={{ label: 'Add address', onClick: () => {} }} />
      <Alert tone="danger" title="Couldn’t load addresses">
        Try again.
      </Alert>
      <Button variant="secondary">Cancel</Button>
    </ThemeProvider>,
  );
}

test.each(THEMES)('%s theme is applied to <html> and the primitives still render with the same accessible structure', (theme) => {
  const { container } = renderBoth(theme);
  expect(document.documentElement.dataset.theme).toBe(theme);
  expect(screen.getByRole('status').textContent).toContain('Loading addresses…');
  expect(screen.getByRole('heading', { level: 2, name: 'No addresses yet' })).toBeTruthy();
  expect(screen.getByRole('alert').textContent).toContain('Couldn’t load addresses');
  expect(container.querySelectorAll('button')).toHaveLength(2);
});

test.each(THEMES)('%s theme: nothing rendered carries an inline style, so colour can only come from tokens', (theme) => {
  const { container } = renderBoth(theme);
  expect(container.querySelector('[style]')).toBeNull();
});

test('primitive sources use no raw colour literals and no inline style props', () => {
  const sources = [readFileSync('src/ui/Skeleton.tsx', 'utf8'), readFileSync('src/ui/EmptyState.tsx', 'utf8')];
  for (const source of sources) {
    expect(source).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(source).not.toMatch(/\brgba?\(|\bhsla?\(/);
    expect(source).not.toMatch(/\bstyle=\{/);
    expect(source).not.toMatch(/\bbg-\[|\btext-\[#|\bborder-\[#/);
  }
});

test('every colour utility used by the primitives is a semantic token defined in style.css', () => {
  const css = readFileSync('src/style.css', 'utf8');
  const tokens = new Set(Array.from(css.matchAll(/--color-([a-z-]+):/g), (match) => match[1]));
  // Non-colour utilities that share the text-/bg-/border- prefixes.
  const NON_COLOUR = new Set(['xs', 'sm', 'base', 'lg', 'xl', '2xl', 'left', 'center', 'right', 'wrap', 'none', 'px', 'py', 'pulse', 'dashed']);
  const used = new Set<string>();
  const sources = [readFileSync('src/ui/Skeleton.tsx', 'utf8'), readFileSync('src/ui/EmptyState.tsx', 'utf8')];
  for (const source of sources) {
    for (const match of source.matchAll(/\b(?:text|bg|border)-([a-z][a-z-]*)\b/g)) {
      if (match[1] && !NON_COLOUR.has(match[1])) used.add(match[1]);
    }
  }
  expect(used.size).toBeGreaterThan(0);
  for (const name of used) {
    expect(tokens.has(name), `colour token "${name}" is not defined in style.css`).toBe(true);
  }
});
