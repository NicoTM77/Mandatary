import type { NavItem } from '../../ui';

/**
 * Document routes the recovery screens expect (P1.18.2). Like every P1.16/P1.17 route they are EXACT paths served by an allowlist in
 * web/assets.go (D-ROUTE-1): there is no wildcard fallback, so each one must be added there on purpose (P1.18.3 owns that). `/recovery`
 * already belongs to the P1.16 recovery-code sign-in, which is why these live under `/backup` and `/restore`.
 */
export const RECOVERY_ROUTES = {
  export: '/backup',
  restore: '/restore',
  review: '/restore/review',
} as const;

export type RecoveryPageId = 'backup-export' | 'backup-restore' | 'backup-review';

/**
 * The "Recovery" group of the admin shell. A container adds these items ONLY for a session whose view says it is the administrator (as
 * P1.16 does for Agent tokens and P1.17 for Policy). That is a convenience: the server refuses every one of these routes' API calls for anyone
 * else, so hiding the links protects nothing and showing them to the wrong person exposes nothing.
 *
 * The labels are the page titles' verbs, so a person who read "Review restored access" in a restore result finds exactly that in the menu.
 */
export const RECOVERY_NAV: readonly NavItem[] = [
  { id: 'backup-export', label: 'Export backup', href: RECOVERY_ROUTES.export, icon: 'download', group: 'Recovery' },
  { id: 'backup-restore', label: 'Restore from backup', href: RECOVERY_ROUTES.restore, icon: 'upload', group: 'Recovery' },
  { id: 'backup-review', label: 'Review restored access', href: RECOVERY_ROUTES.review, icon: 'list', group: 'Recovery' },
];
