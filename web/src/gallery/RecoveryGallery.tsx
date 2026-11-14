import type { ReactNode } from 'react';
import type { ExportScreenProps, ItemRef, RestoreScreenProps, ReviewScreenProps } from '../screens/recovery/contract';
import { ExportScreen } from '../screens/recovery/export';
import { RECOVERY_NAV } from '../screens/recovery/nav';
import { RestoreEndedPage, RestoreEndedView, RestoreScreen } from '../screens/recovery/restore';
import { ReviewScreen } from '../screens/recovery/review';
import { AdminShell, AutoFocusContext, SyntheticBadge, ThemeToggle, type NavItem } from '../ui';
import { manifest, manifestApproved, manifestClean, reportClean, reportFull, sampleFile } from './recoveryFixtures';

const noop = () => undefined;

const exportBase: ExportScreenProps = { state: { kind: 'idle' }, onExport: noop };
const restoreBase: RestoreScreenProps = { state: { kind: 'idle' }, onRestore: noop };
const reviewBase: ReviewScreenProps = { load: { kind: 'ready', data: manifest }, approval: { kind: 'idle' }, inspectHref: () => '#g-review', credentialsHref: () => '#g-review', onRetry: noop, onApprove: noop };

const chosen = { file: sampleFile(), confirming: true } as const;
const selection: readonly ItemRef[] = [
  { kind: 'user', id: 'u-restored' },
  { kind: 'group', id: 'g-ops' },
  { kind: 'user_membership', id: 'u-restored:g-ops' },
  { kind: 'policy', id: 'p-logs' },
];

type Group = 'g-export' | 'g-restore' | 'g-ended' | 'g-review';

interface Specimen {
  flow: string;
  name: string;
  group: Group;
  /** `page`: the specimen is a whole pre-session page (the terminal restore pages); `shell`: a screen that lives inside the admin shell. */
  frame: 'shell' | 'page';
  node: ReactNode;
  page?: ReactNode;
}

const ended = (flow: string, name: string, props: Parameters<typeof RestoreEndedView>[0]): Specimen => ({ flow, name, group: 'g-ended', frame: 'page', node: <RestoreEndedView {...props} />, page: <RestoreEndedPage {...props} /> });

const SPECIMENS: readonly Specimen[] = [
  { flow: 'X-a', group: 'g-export', frame: 'shell', name: 'Choose a type: clean is the default', node: <ExportScreen {...exportBase} /> },
  { flow: 'X-b', group: 'g-export', frame: 'shell', name: 'Full selected: credential material warning', node: <ExportScreen {...exportBase} initialMode="full" /> },
  { flow: 'X-c', group: 'g-export', frame: 'shell', name: 'Creating the backup', node: <ExportScreen {...exportBase} initialMode="full" state={{ kind: 'working', mode: 'full' }} /> },
  { flow: 'X-d', group: 'g-export', frame: 'shell', name: 'Done: clean', node: <ExportScreen {...exportBase} state={{ kind: 'done', mode: 'clean', backupId: 'sample-backup-0001', fileName: 'mandatary-backup-sample-backup-0001-clean.json' }} /> },
  { flow: 'X-e', group: 'g-export', frame: 'shell', name: 'Done: full', node: <ExportScreen {...exportBase} initialMode="full" state={{ kind: 'done', mode: 'full', backupId: 'sample-backup-0002', fileName: 'mandatary-backup-sample-backup-0002-full.json' }} /> },
  { flow: 'X-f', group: 'g-export', frame: 'shell', name: 'Refused: not allowed', node: <ExportScreen {...exportBase} state={{ kind: 'rejected', reason: 'denied' }} /> },
  { flow: 'X-g', group: 'g-export', frame: 'shell', name: 'Unavailable: nothing exported, safe to retry', node: <ExportScreen {...exportBase} state={{ kind: 'rejected', reason: 'unavailable' }} /> },

  { flow: 'S-a', group: 'g-restore', frame: 'shell', name: 'Before a file is chosen', node: <RestoreScreen {...restoreBase} /> },
  { flow: 'S-b', group: 'g-restore', frame: 'shell', name: 'File chosen, typed confirmation open', node: <RestoreScreen {...restoreBase} initial={chosen} /> },
  { flow: 'S-c', group: 'g-restore', frame: 'shell', name: 'Restoring: progress and no repeat', node: <RestoreScreen {...restoreBase} initial={chosen} state={{ kind: 'working' }} /> },
  { flow: 'S-d', group: 'g-restore', frame: 'shell', name: 'Origin can’t be verified: acknowledgement asked for', node: <RestoreScreen {...restoreBase} initial={chosen} state={{ kind: 'needs_acknowledgement' }} /> },
  { flow: 'S-e', group: 'g-restore', frame: 'shell', name: 'Refused: integrity check failed (tamper or other key)', node: <RestoreScreen {...restoreBase} initial={{ file: sampleFile() }} state={{ kind: 'rejected', reason: 'archive_integrity_failed' }} /> },
  { flow: 'S-f', group: 'g-restore', frame: 'shell', name: 'Refused: not a readable backup', node: <RestoreScreen {...restoreBase} initial={{ file: sampleFile() }} state={{ kind: 'rejected', reason: 'archive_malformed' }} /> },
  { flow: 'S-g', group: 'g-restore', frame: 'shell', name: 'Refused: incompatible version', node: <RestoreScreen {...restoreBase} initial={{ file: sampleFile() }} state={{ kind: 'rejected', reason: 'archive_unsupported_version' }} /> },
  { flow: 'S-h', group: 'g-restore', frame: 'shell', name: 'Refused: contents inconsistent', node: <RestoreScreen {...restoreBase} initial={{ file: sampleFile() }} state={{ kind: 'rejected', reason: 'archive_inconsistent' }} /> },
  { flow: 'S-i', group: 'g-restore', frame: 'shell', name: 'Refused: not allowed', node: <RestoreScreen {...restoreBase} initial={{ file: sampleFile() }} state={{ kind: 'rejected', reason: 'denied' }} /> },
  { flow: 'S-j', group: 'g-restore', frame: 'shell', name: 'Could not start: nothing changed, safe to retry', node: <RestoreScreen {...restoreBase} initial={{ file: sampleFile() }} state={{ kind: 'rejected', reason: 'unavailable' }} /> },

  ended('T-a', 'Complete: full backup, origin verified', { ended: { kind: 'complete', report: reportFull, authorizerNotified: true }, runbookHref: '#g-ended' }),
  ended('T-b', 'Complete: clean backup of unverified origin, access service not told', { ended: { kind: 'complete', report: reportClean, authorizerNotified: false } }),
  ended('T-c', 'Did not finish: nothing imported, quarantine in force', { ended: { kind: 'incomplete', cause: 'failed' }, runbookHref: '#g-ended' }),
  ended('T-d', 'Did not finish: another restore took precedence', { ended: { kind: 'incomplete', cause: 'superseded' } }),
  ended('T-e', 'Answer lost: may or may not have started', { ended: { kind: 'unconfirmed' }, onReload: noop }),

  { flow: 'V-a', group: 'g-review', frame: 'shell', name: 'Ready: waiting, approved, kept, blocked, and imported against applied', node: <ReviewScreen {...reviewBase} /> },
  { flow: 'V-b', group: 'g-review', frame: 'shell', name: 'Four records selected, confirmation open', node: <ReviewScreen {...reviewBase} initial={{ selected: selection, confirming: true }} /> },
  { flow: 'V-c', group: 'g-review', frame: 'shell', name: 'Approving', node: <ReviewScreen {...reviewBase} initial={{ selected: selection, confirming: true }} approval={{ kind: 'working' }} /> },
  { flow: 'V-d', group: 'g-review', frame: 'shell', name: 'Approved: no credential restored', node: <ReviewScreen {...reviewBase} approval={{ kind: 'done', count: 4 }} /> },
  {
    flow: 'V-e',
    group: 'g-review',
    frame: 'shell',
    name: 'Nothing approved: each refusal named, selection kept',
    node: (
      <ReviewScreen
        {...reviewBase}
        initial={{ selected: [{ kind: 'user_membership', id: 'u-restored:g-ops' }, { kind: 'agent', id: 'a-ci' }, { kind: 'user', id: 'u-risky' }] }}
        approval={{
          kind: 'conflict',
          failures: [
            { kind: 'user_membership', id: 'u-restored:g-ops', reason: 'subject_not_active' },
            { kind: 'agent', id: 'a-ci', reason: 'owner_not_active' },
            { kind: 'user', id: 'u-risky', reason: 'compromised' },
          ],
        }}
      />
    ),
  },
  { flow: 'V-f', group: 'g-review', frame: 'shell', name: 'Result could not be confirmed', node: <ReviewScreen {...reviewBase} approval={{ kind: 'rejected', reason: 'outcome_unknown' }} /> },
  { flow: 'V-g', group: 'g-review', frame: 'shell', name: 'Everything approvable approved: follow-ups remain', node: <ReviewScreen {...reviewBase} load={{ kind: 'ready', data: manifestApproved }} /> },
  { flow: 'V-h', group: 'g-review', frame: 'shell', name: 'Clean backup, origin acknowledged: no credentials existed', node: <ReviewScreen {...reviewBase} load={{ kind: 'ready', data: manifestClean }} /> },
  { flow: 'V-i', group: 'g-review', frame: 'shell', name: 'Still in quarantine', node: <ReviewScreen {...reviewBase} approval={{ kind: 'rejected', reason: 'still_quarantined' }} /> },
  { flow: 'V-j', group: 'g-review', frame: 'shell', name: 'No restore on this installation', node: <ReviewScreen {...reviewBase} load={{ kind: 'no_restore' }} /> },
  { flow: 'V-k', group: 'g-review', frame: 'shell', name: 'Loading', node: <ReviewScreen {...reviewBase} load={{ kind: 'loading' }} /> },
  { flow: 'V-l', group: 'g-review', frame: 'shell', name: 'Load failed (never an empty list)', node: <ReviewScreen {...reviewBase} load={{ kind: 'failed' }} /> },
  { flow: 'V-m', group: 'g-review', frame: 'shell', name: 'Not the policy administrator', node: <ReviewScreen {...reviewBase} load={{ kind: 'denied' }} /> },
];

const GROUPS: ReadonlyArray<readonly [Group, string, string]> = [
  ['g-export', 'Export', 'X · clean or full, with what each holds and what neither does'],
  ['g-restore', 'Restore', 'S · consequences first, then a file, then a typed confirmation; every refusal changes nothing'],
  ['g-ended', 'After a restore', 'T · pre-session pages: the session is gone, the next step is on the host'],
  ['g-review', 'Review restored access', 'V · approve named records one by one; imported against applied only where the service exposes it'],
];

const NAV_FOR_GROUP: Record<Group, string> = { 'g-export': 'backup-export', 'g-restore': 'backup-restore', 'g-ended': 'backup-restore', 'g-review': 'backup-review' };

function SpecimenFigure({ specimen }: { specimen: Specimen }) {
  return (
    <figure className="min-w-0">
      <figcaption className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        <span className="rounded bg-sunken px-1.5 py-0.5 font-mono text-xs text-muted">{specimen.flow}</span>
        <span className="font-semibold">{specimen.name}</span>
        <SyntheticBadge />
      </figcaption>
      <div className="rounded-panel border border-dashed border-line-strong bg-bg p-3 sm:p-4">{specimen.node}</div>
    </figure>
  );
}

const SHELL_VIEWS = new Map<string, { id: string; node: ReactNode }>([
  ['recovery-shell', { id: 'backup-export', node: <ExportScreen {...exportBase} /> }],
  ['recovery-shell-restore', { id: 'backup-restore', node: <RestoreScreen {...restoreBase} /> }],
  ['recovery-shell-review', { id: 'backup-review', node: <ReviewScreen {...reviewBase} /> }],
]);

const SHELL_HREF = new Map<string, string>([
  ['backup-export', '?synthetic=recovery-shell'],
  ['backup-restore', '?synthetic=recovery-shell-restore'],
  ['backup-review', '?synthetic=recovery-shell-review'],
]);

const SHELL_NAV: readonly NavItem[] = [
  { id: 'overview', label: 'Overview', href: '?synthetic=recovery-shell' },
  { id: 'security', label: 'Account security', href: '?synthetic=recovery-shell', group: 'Account', icon: 'shield' },
  { id: 'agent-tokens', label: 'Agent tokens', href: '?synthetic=recovery-shell', group: 'Account', icon: 'key' },
  ...RECOVERY_NAV.map((item) => ({ ...item, href: SHELL_HREF.get(item.id) ?? '?synthetic=recovery-shell' })),
];

const ONLY_PREFIX = 'recovery-only-';
const ACCOUNT = { username: 'sample-admin', assurance: 'aal2' } as const;

/**
 * Entry for `?synthetic=recovery` (every state), `?synthetic=recovery-only-<flow>` (one state alone, in the shell or, for the pre-session pages, in
 * their own frame) and `?synthetic=recovery-shell[-restore|-review]` (the admin shell with the Recovery group).
 */
export default function RecoveryGallery({ view }: { view: string }) {
  const shell = SHELL_VIEWS.get(view);
  const only = view.startsWith(ONLY_PREFIX) ? SPECIMENS.find((specimen) => specimen.flow === view.slice(ONLY_PREFIX.length)) : undefined;
  return <AutoFocusContext.Provider value={false}>{shell ? <ShellView id={shell.id}>{shell.node}</ShellView> : only ? <OnlyView specimen={only} /> : <StateGallery />}</AutoFocusContext.Provider>;
}

function ShellView({ id, children }: { id: string; children: ReactNode }) {
  return (
    <AdminShell nav={SHELL_NAV} currentId={id} account={{ ...ACCOUNT, freshnessNote: 'Verified 4 minutes ago' }} onSignOut={noop}>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <SyntheticBadge>Synthetic shell view: nothing here is connected</SyntheticBadge>
        <a href="?synthetic=recovery" className="text-sm font-medium text-accent-text underline underline-offset-2">
          Back to state gallery
        </a>
      </div>
      {children}
    </AdminShell>
  );
}

function OnlyView({ specimen }: { specimen: Specimen }) {
  if (specimen.frame === 'page') return <>{specimen.page}</>;
  return (
    <AdminShell nav={SHELL_NAV} currentId={NAV_FOR_GROUP[specimen.group]} account={ACCOUNT} onSignOut={noop}>
      <div className="mb-4">
        <SyntheticBadge>{`Synthetic ${specimen.flow}: ${specimen.name}`}</SyntheticBadge>
      </div>
      {specimen.node}
    </AdminShell>
  );
}

function StateGallery() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight">Export, restore and reapproval screens: synthetic state gallery</h1>
            <p className="text-sm text-muted">P1.18.2 design baseline. Fixtures only: no server, no archive, no real accounts, no working recovery.</p>
          </div>
          <ThemeToggle />
        </div>
      </header>
      <div className="mx-auto max-w-5xl gap-8 px-4 py-6 sm:px-6 lg:grid lg:max-w-7xl lg:grid-cols-[13rem_minmax(0,1fr)]">
        <nav aria-label="Screens" className="mb-6 lg:sticky lg:top-4 lg:mb-0 lg:self-start">
          <ul className="flex flex-wrap gap-1.5 lg:block lg:space-y-0.5">
            {GROUPS.map(([id, title]) => (
              <li key={id}>
                <a href={`#${id}`} className="block rounded-control px-2.5 py-1.5 text-sm text-fg hover:bg-sunken lg:min-h-9">
                  {title}
                </a>
              </li>
            ))}
            <li>
              <a href="?synthetic=recovery-shell" className="block rounded-control px-2.5 py-1.5 text-sm font-medium text-accent-text hover:bg-accent-soft">
                Admin shell view
              </a>
            </li>
          </ul>
        </nav>
        <main id="main-content" tabIndex={-1} className="min-w-0 space-y-14 outline-none">
          <h2 className="sr-only">Specimens</h2>
          {GROUPS.map(([id, title, note]) => (
            <section key={id} id={id} aria-labelledby={`${id}-h`} className="scroll-mt-24 space-y-4">
              <div>
                <h2 id={`${id}-h`} className="text-xl font-semibold">
                  {title}
                </h2>
                <p className="text-sm text-muted">{note}</p>
              </div>
              <div className="space-y-8">
                {SPECIMENS.filter((specimen) => specimen.group === id).map((specimen) => (
                  <SpecimenFigure key={specimen.flow} specimen={specimen} />
                ))}
              </div>
            </section>
          ))}
        </main>
      </div>
    </div>
  );
}
