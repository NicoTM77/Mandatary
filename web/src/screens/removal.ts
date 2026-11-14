import type { SecurityKeyRow, TotpFactorRow } from './contract';

/**
 * What removing one sign-in method does to the account's OWN ability to sign in (P1.18.4 AUTH-08-L4). Presentation only: the server alone decides
 * whether a removal is allowed (it refuses the last method an account is required to keep), applies the conservative assurance rule (a method that
 * was disabled protectively after failed codes stays unusable and is never revived by removing another) and ends every session when it succeeds.
 * Nothing here lowers that floor. It only tells the person, BEFORE they confirm, the consequence the page can already see in their own inventory.
 * It reads only this account's rows; no other account's factor state is involved.
 */
export interface RemovalConsequence {
  /** After this removal the account has no working authenticator app or security key left. */
  lastWorking: boolean;
  /** The method being removed is itself one that works today. A disabled one gives nothing up. */
  targetWorks: boolean;
  /** Authenticator apps of this account that are disabled after too many failed codes (never usable while disabled). */
  disabledApps: number;
  /** Other working methods that remain after the removal. */
  otherWorking: number;
}

export function removalConsequence(totp: readonly TotpFactorRow[], keys: readonly SecurityKeyRow[], target: { kind: 'totp' | 'webauthn'; id: string }): RemovalConsequence {
  const workingApps = totp.filter((row) => row.status === 'active');
  const targetWorks = target.kind === 'totp' ? workingApps.some((row) => row.id === target.id) : keys.some((row) => row.id === target.id);
  const otherApps = workingApps.filter((row) => !(target.kind === 'totp' && row.id === target.id)).length;
  const otherKeys = keys.filter((row) => !(target.kind === 'webauthn' && row.id === target.id)).length;
  const otherWorking = otherApps + otherKeys;
  const disabledApps = totp.filter((row) => row.status === 'disabled' && !(target.kind === 'totp' && row.id === target.id)).length;
  return { lastWorking: otherWorking === 0, targetWorks, disabledApps, otherWorking };
}

/** The exact consequence sentence. `remaining` is the count of unused saved recovery codes (the inventory shows a count, never a code). */
export function removalWarning(consequence: RemovalConsequence, remaining: number): { title: string; body: string } | null {
  if (!consequence.lastWorking) return null;
  if (!consequence.targetWorks) return null;
  const sibling = consequence.disabledApps > 0 ? `Your other authenticator ${consequence.disabledApps === 1 ? 'app is' : 'apps are'} disabled after too many failed codes, so ${consequence.disabledApps === 1 ? 'it doesn’t' : 'they don’t'} count, and removing this one doesn’t bring ${consequence.disabledApps === 1 ? 'it' : 'them'} back. ` : '';
  const codes =
    remaining > 0
      ? `After this you can get back in only with a saved recovery code. You have ${remaining} unused ${remaining === 1 ? 'code' : 'codes'}.`
      : 'After this you can get back in only with a saved recovery code, and you have none left, so you would be locked out until whoever runs this server does the host recovery.';
  return { title: 'This is your last working second factor', body: `${sibling}${codes} Everyone signed in as you is signed out when it is removed.` };
}
