/**
 * Pure presentation helpers (P1.16.2). Every format comes from Intl so locale changes apply;
 * nothing here is hardcoded English layout beyond the default locale.
 */

/**
 * Formats a Unix-seconds instant as a medium date and short time. Returns '' for an instant the
 * Date object cannot represent, so the UI never shows "Invalid Date". `timeZone` is optional;
 * pass it when a deterministic rendering is needed (tests do).
 */
export function formatDate(unixSeconds: number, locale?: string | string[], timeZone?: string): string {
  const date = new Date(unixSeconds * 1000);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(date);
}

/**
 * "1 minute", "24 minutes". The count is truncated (never rounded up) and clamped at zero, so a
 * caller cannot overstate remaining time. Use `deriveSetupClock` for rounding a deadline.
 */
export function formatMinutes(count: number, locale: string = 'en-US'): string {
  const whole = Number.isFinite(count) ? Math.max(0, Math.trunc(count)) : 0;
  const unit = new Intl.PluralRules(locale).select(whole) === 'one' ? 'minute' : 'minutes';
  return `${new Intl.NumberFormat(locale).format(whole)} ${unit}`;
}
