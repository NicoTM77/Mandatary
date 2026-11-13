import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type Theme = 'light' | 'dark';

interface ThemeValue {
  theme: Theme;
  /** Explicit user choice for this page view only. Nothing is written to storage. */
  setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeValue | null>(null);

const DARK_QUERY = '(prefers-color-scheme: dark)';

function systemPrefersDark(): boolean {
  return typeof globalThis.matchMedia === 'function' && globalThis.matchMedia(DARK_QUERY).matches;
}

/**
 * Theme contract (P1.16.1, decision D-THEME-1): the first paint follows the operating
 * system (`prefers-color-scheme`); the toggle overrides it in memory for the life of the
 * page. No localStorage/sessionStorage/cookie is used, so the "no web storage" leakage
 * invariant stays trivially checkable. The trade-off is that a reload returns to the
 * system theme; a persisted preference needs a separate, reviewed decision.
 *
 * The chosen theme is applied as data-theme on <html> so scrollbars, form controls and
 * overscroll follow it (color-scheme is declared per theme in style.css).
 */
export function ThemeProvider({ children, initial }: { children: ReactNode; initial?: Theme }) {
  const [system, setSystem] = useState<Theme>(() => (systemPrefersDark() ? 'dark' : 'light'));
  const [override, setOverride] = useState<Theme | null>(initial ?? null);
  const theme = override ?? system;

  useEffect(() => {
    if (typeof globalThis.matchMedia !== 'function') return;
    const query = globalThis.matchMedia(DARK_QUERY);
    const onChange = (event: MediaQueryListEvent) => setSystem(event.matches ? 'dark' : 'light');
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    return () => {
      delete root.dataset.theme;
    };
  }, [theme]);

  const setTheme = useCallback((next: Theme) => setOverride(next), []);
  const value = useMemo(() => ({ theme, setTheme }), [theme, setTheme]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeValue {
  const value = useContext(ThemeContext);
  if (!value) throw new Error('useTheme must be used inside ThemeProvider');
  return value;
}
