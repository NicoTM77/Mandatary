import type { AddressRow, CredentialRow, ManagedAddress, SecurityKeyRow, TotpFactorRow } from '../screens/contract';
import type { NavItem } from '../ui';

/**
 * Synthetic data for the design gallery and presentational tests ONLY.
 *
 * Every value is deliberately unmistakable as fake and deliberately NOT in the shape of a real
 * secret: the "seed" is not valid base32, the "token" does not match the agent-token canonical
 * format, the "codes" are not 128-bit encodings. Addresses use the reserved example.invalid domain.
 * No fixture here may ever be replaced with a real credential, and secret scanners must stay quiet.
 */
export const SYNTHETIC = {
  username: 'sample-admin',
  passwordGuidance: 'This password appears in a list of commonly used passwords. Choose something less predictable.',
  seed: 'SYNTHETIC-KEY-NOT-REAL-0000',
  token: 'mdt_SYNTHETIC_NOT_A_REAL_TOKEN_0000',
  recoveryCodes: Array.from({ length: 10 }, (_, index) => `SYNTHETIC-CODE-${String(index + 1).padStart(2, '0')}-NOT-REAL`),

  setupAddressesMixed: [
    { id: 'a1', address: 'owner@example.invalid', confirmed: true, proof: { kind: 'idle' } },
    { id: 'a2', address: 'backup@example.invalid', confirmed: false, proof: { kind: 'sent' } },
  ] satisfies AddressRow[],
  setupAddressesErrors: [
    { id: 'a1', address: 'owner@example.invalid', confirmed: false, proof: { kind: 'error', reason: 'wrong_code' } },
    { id: 'a2', address: 'backup@example.invalid', confirmed: false, proof: { kind: 'sending' } },
  ] satisfies AddressRow[],

  totp: [{ id: 't1', label: 'Authenticator app', addedOn: '3 Nov 2026', status: 'active' }] satisfies TotpFactorRow[],
  totpDisabled: [{ id: 't1', label: 'Authenticator app', addedOn: '3 Nov 2026', status: 'disabled' }] satisfies TotpFactorRow[],
  keys: [{ id: 'k1', name: 'Desk key', addedOn: '9 Nov 2026' }] satisfies SecurityKeyRow[],

  managedAddresses: [
    { id: 'm1', address: 'owner@example.invalid', status: 'confirmed' },
    { id: 'm2', address: 'backup@example.invalid', status: 'confirmed' },
  ] satisfies ManagedAddress[],
  managedOne: [{ id: 'm1', address: 'owner@example.invalid', status: 'confirmed' }] satisfies ManagedAddress[],
  managedPending: [
    { id: 'm1', address: 'owner@example.invalid', status: 'confirmed' },
    { id: 'm2', address: 'backup@example.invalid', status: 'confirmed' },
    { id: 'm3', address: 'new@example.invalid', status: 'unconfirmed' },
    { id: 'm4', address: 'fourth@example.invalid', status: 'confirmed' },
  ] satisfies ManagedAddress[],

  credentials: [{ id: 'c1', displayId: 'mdt_a1b2…', status: 'active', expiresOn: '11 Feb 2027' }] satisfies CredentialRow[],
  credentialsRotating: [
    { id: 'c2', displayId: 'mdt_c3d4…', status: 'active', expiresOn: '11 Feb 2027' },
    { id: 'c1', displayId: 'mdt_a1b2…', status: 'rotating_out', expiresOn: '11 Feb 2027', overlapEndsOn: 'today 15:30' },
  ] satisfies CredentialRow[],
};

/** Navigation for the P1.16 shell view. P1.17/P1.18 add their own groups; nothing is listed before it exists. */
export const NAV: readonly NavItem[] = [
  { id: 'security', label: 'Account security', href: '?synthetic=shell', icon: 'shield', group: 'Account' },
  { id: 'methods', label: 'Sign-in methods', href: '?synthetic=shell', icon: 'key', group: 'Account' },
  { id: 'recovery', label: 'Recovery codes', href: '?synthetic=shell', icon: 'list', group: 'Account' },
  { id: 'addresses', label: 'Notification addresses', href: '?synthetic=shell', icon: 'mail', group: 'Account' },
];
