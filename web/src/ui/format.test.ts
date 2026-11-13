import { describe, expect, test } from 'vitest';
import { formatDate, formatMinutes } from './format';

describe('formatMinutes', () => {
  test('uses the singular only for exactly one minute', () => {
    expect(formatMinutes(1)).toBe('1 minute');
    expect(formatMinutes(0)).toBe('0 minutes');
    expect(formatMinutes(24)).toBe('24 minutes');
  });

  test('truncates fractions and clamps negatives so it never overstates time left', () => {
    expect(formatMinutes(2.7)).toBe('2 minutes');
    expect(formatMinutes(-3)).toBe('0 minutes');
    expect(formatMinutes(Number.NaN)).toBe('0 minutes');
  });
});

describe('formatDate', () => {
  // 2026-11-13 12:00 UTC, passed with an explicit time zone so the result is host-independent.
  const NOON_UTC = Math.floor(Date.UTC(2026, 10, 13, 12, 0, 0) / 1000);

  test('formats a Unix-seconds instant with the given locale and time zone', () => {
    const text = formatDate(NOON_UTC, 'en-US', 'UTC');
    expect(text).toContain('Nov 13, 2026');
    // Intl may use a narrow no-break space before PM; \s matches it.
    expect(text).toMatch(/12:00\s?PM/);
  });

  test('a different locale changes the rendering, so no format is hardcoded', () => {
    const english = formatDate(NOON_UTC, 'en-US', 'UTC');
    const german = formatDate(NOON_UTC, 'de-DE', 'UTC');
    expect(german).not.toBe(english);
    expect(german).toContain('2026');
  });

  test('a non-finite timestamp renders as nothing instead of "Invalid Date"', () => {
    expect(formatDate(Number.NaN, 'en-US', 'UTC')).toBe('');
  });
});
