import { describe, expect, test } from 'vitest';
import { deriveSetupClock } from './clock';

// Fixed "now" so every case is deterministic; the clock never reads Date.now itself.
const NOW = Date.UTC(2026, 10, 13, 12, 0, 0);
const MINUTE = 60_000;
/** The server sends the deadline in whole Unix seconds. */
const at = (msFromNow: number) => Math.floor((NOW + msFromNow) / 1000);

describe('deriveSetupClock', () => {
  test('more than five minutes left is active and reports whole minutes (rounded up)', () => {
    expect(deriveSetupClock(at(30 * MINUTE), NOW)).toEqual({ kind: 'active', minutesLeft: 30 });
    expect(deriveSetupClock(at(5 * MINUTE + 1000), NOW)).toEqual({ kind: 'active', minutesLeft: 6 });
  });

  test('exactly five minutes left, and anything under it, is expiring', () => {
    expect(deriveSetupClock(at(5 * MINUTE), NOW)).toEqual({ kind: 'expiring', minutesLeft: 5 });
    expect(deriveSetupClock(at(4 * MINUTE + 59_000), NOW)).toEqual({ kind: 'expiring', minutesLeft: 5 });
    expect(deriveSetupClock(at(1000), NOW)).toEqual({ kind: 'expiring', minutesLeft: 1 });
  });

  test('a deadline that has arrived or passed is expired, never a negative count', () => {
    expect(deriveSetupClock(at(0), NOW)).toEqual({ kind: 'expired' });
    expect(deriveSetupClock(at(-MINUTE), NOW)).toEqual({ kind: 'expired' });
  });

  test('a non-finite deadline fails closed to expired', () => {
    expect(deriveSetupClock(Number.NaN, NOW)).toEqual({ kind: 'expired' });
    expect(deriveSetupClock(Number.POSITIVE_INFINITY, NOW)).toEqual({ kind: 'expired' });
  });
});
