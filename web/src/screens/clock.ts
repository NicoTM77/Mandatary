import type { SetupClock } from './contract';

const MINUTE_MS = 60_000;
const EXPIRING_WINDOW_MS = 5 * MINUTE_MS;

/**
 * Presentational setup clock (P1.16.2, UX §9). Pure: the caller supplies `nowMs`, so the result is
 * deterministic and tests need no timers.
 *
 * `expiresAtUnix` is the server's absolute deadline in Unix seconds. This is display only: the server
 * enforces expiry, and the container owns the timer. A non-finite input fails closed to `expired`.
 * Within five minutes of the deadline the clock is `expiring`; at or after it, `expired`.
 */
export function deriveSetupClock(expiresAtUnix: number, nowMs: number): SetupClock {
  if (!Number.isFinite(expiresAtUnix) || !Number.isFinite(nowMs)) return { kind: 'expired' };
  const remainingMs = expiresAtUnix * 1000 - nowMs;
  if (remainingMs <= 0) return { kind: 'expired' };
  const minutesLeft = Math.ceil(remainingMs / MINUTE_MS);
  return remainingMs <= EXPIRING_WINDOW_MS ? { kind: 'expiring', minutesLeft } : { kind: 'active', minutesLeft };
}
