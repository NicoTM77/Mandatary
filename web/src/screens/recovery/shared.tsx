import type { ReactNode } from 'react';
import { Alert, Icon, type IconName } from '../../ui';
import type { BackupMode, ManifestKind } from './contract';

/**
 * Wording shared by the three P1.18 screens. One vocabulary, so the same thing is never called two names on two pages:
 *   restore quarantine : the installation state a restore leaves; sign-in is closed, nothing imported is active
 *   switched off       : an imported (or retained) record that grants nothing yet
 *   approve            : the explicit, per-item act that makes one switched-off record effective
 *   host recovery      : the step, run on the server, that ends quarantine; no browser page can do it
 */

export const MODE_NAME: Record<BackupMode, string> = { full: 'Full backup', clean: 'Clean backup' };

/** Singular label of a manifest kind, as a person would say it. */
export const KIND_LABEL: Record<ManifestKind, string> = {
  endpoint: 'Endpoint',
  user: 'User',
  group: 'Group',
  agent: 'Agent',
  user_membership: 'Group member (user)',
  agent_membership: 'Group member (agent)',
  policy: 'Rule',
  role: 'Administrator role',
  address: 'Notification address',
};

const COUNT_NOUN = new Map<string, readonly [one: string, many: string]>([
  ['endpoint', ['endpoint', 'endpoints']],
  ['user', ['user', 'users']],
  ['group', ['group', 'groups']],
  ['agent', ['agent', 'agents']],
  ['user_membership', ['user membership', 'user memberships']],
  ['agent_membership', ['agent membership', 'agent memberships']],
  ['policy', ['rule', 'rules']],
  ['role', ['administrator role', 'administrator roles']],
  ['address', ['notification address', 'notification addresses']],
  ['authenticators', ['sign-in method record', 'sign-in method records']],
  ['agent_credentials', ['agent token record', 'agent token records']],
]);

/** "2 users, 1 group". Only kinds the service defines are shown: an unknown key is dropped rather than displayed. Zero counts are omitted. */
export function countsSentence(counts: Readonly<Record<string, number>>): string {
  const parts: string[] = [];
  // A Map (not bracket access) keeps the lookup free of object-injection patterns.
  const given = new Map<string, number>(Object.entries(counts));
  for (const [key, [one, many]] of COUNT_NOUN) {
    const value = given.get(key);
    if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) parts.push(`${value} ${value === 1 ? one : many}`);
  }
  return parts.join(', ');
}

const EXCLUDED = new Map<string, string>([
  ['sessions', 'sign-in sessions'],
  ['rate_limit_state', 'rate-limit counters'],
  ['usage_statistics', 'usage statistics'],
  ['setup_and_recovery_state', 'setup and recovery state'],
  ['security_notices', 'security notices'],
  ['control_generations_and_quarantine', 'the quarantine state itself'],
  ['master_key_and_installation_binding', 'the installation key and its binding'],
]);

/** Plain names for the scope codes the service lists as neither read nor written; unknown codes are dropped. */
export function excludedNames(codes: readonly string[]): string[] {
  const names: string[] = [];
  for (const code of codes) {
    const name = EXCLUDED.get(code);
    if (name !== undefined) names.push(name);
  }
  return names;
}

/**
 * The statement every P1.18 page repeats where it matters: a backup is a snapshot of settings, not a point you can roll back to, and it
 * does not record what was revoked or when. Not collapsible: it is the assumption people bring that these screens must correct.
 */
export function SnapshotNote({ children }: { children?: ReactNode }) {
  return (
    <Alert tone="info" role="none" title="A backup is a snapshot, not a rollback">
      It lists who and what is configured at the moment it is made. Restoring it does not undo later changes, and the file does not record what was revoked or when. Anything it brings back arrives switched off until you approve it by name.
      {children ? <> {children}</> : null}
    </Alert>
  );
}

/** One line of a consequence list: an icon, a short bold lead, then the plain explanation. The icon is decoration; the words carry the meaning. */
export function Consequence({ icon, lead, children }: { icon: IconName; lead: string; children: ReactNode }) {
  return (
    <li className="flex gap-3 py-3 first:pt-0 last:pb-0">
      <Icon name={icon} className="mt-0.5 size-5 text-muted" />
      <p className="min-w-0 text-sm leading-relaxed">
        <span className="font-semibold">{lead}</span> {children}
      </p>
    </li>
  );
}

/** A file or backup id: identifiers are not words, so they are set apart, never translated, and may wrap anywhere. */
export function Ident({ children }: { children: string }) {
  return (
    <code translate="no" className="rounded bg-sunken px-1.5 py-0.5 font-mono text-[0.85em] break-all">
      {children}
    </code>
  );
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1024) return `${bytes} bytes`;
  const trim = (value: number) => value.toFixed(1).replace(/\.0$/, '');
  if (bytes < 1024 * 1024) return `${trim(bytes / 1024)} KiB`;
  return `${trim(bytes / (1024 * 1024))} MiB`;
}
