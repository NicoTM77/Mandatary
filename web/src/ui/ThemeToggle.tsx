import { useTheme } from '../theme';
import { Icon } from './Icon';

/**
 * Toggle between light and dark for this page view. The accessible name states the action
 * ("Use dark theme"); no aria-pressed, because the name already changes with the state.
 */
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <button
      type="button"
      onClick={() => setTheme(next)}
      className="inline-flex min-h-11 items-center gap-2 rounded-control border border-line-strong bg-surface px-3 text-sm font-medium text-fg transition-colors duration-150 hover:bg-sunken"
    >
      <Icon name={next === 'dark' ? 'moon' : 'sun'} />
      <span>Use {next} theme</span>
    </button>
  );
}
