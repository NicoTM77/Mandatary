import { useId, useRef, useState, type ReactNode } from 'react';
import { Alert, Button, CenteredFrame, CheckboxField, ConfirmPanel, Icon, PageHeader, Panel, TextField } from '../../ui';
import { Fact, Facts } from '../policy/shared';
import { RejectionAlert, commonRejection, useFocusWhen, type Rejection } from '../shared';
import { MAX_ARCHIVE_BYTES, RESTORE_PHRASE, type RestoreEnded, type RestoreEndedProps, type RestoreRejection, type RestoreScreenProps } from './contract';
import { Consequence, Ident, MODE_NAME, SnapshotNote, countsSentence, excludedNames, formatBytes } from './shared';

// ───────────────────────── restore form ─────────────────────────

/** Everything here happened before the installation changed; each says so. The service never reflects which check failed, so neither do these. */
function rejection(reason: RestoreRejection): Rejection {
  switch (reason) {
    case 'archive_malformed':
      return { title: 'That isn’t a readable Mandatary backup', body: 'The file may be damaged, cut short, larger than 16 MiB, or not a backup at all. Nothing was changed. Choose a different file, or export a fresh one.' };
    case 'archive_unsupported_version':
      return { title: 'This backup was made by an incompatible version', body: 'Mandatary can’t read the format or database version in this file. Nothing was changed. Use a backup exported by a version this Mandatary supports.' };
    case 'archive_integrity_failed':
      return {
        title: 'The file failed its integrity check',
        body: 'It may have been altered or damaged since it was exported, or it is a full backup from an installation with a different key. Mandatary can’t tell which. Nothing was changed. Don’t edit backup files; to move to a new installation, export a clean backup from the old one.',
      };
    case 'archive_inconsistent':
      return { title: 'The file’s contents don’t add up', body: 'Its records contradict each other, for example a rule that names a user the file doesn’t contain, so Mandatary refuses it even though its integrity check passed. Nothing was changed. Export a fresh backup from the source installation.' };
    case 'invalid_request':
      return { title: 'That request couldn’t be read', body: 'Reload the page, choose the file again and retry. Nothing was changed.' };
    case 'denied':
      return { title: 'Restore wasn’t allowed', body: 'Only the administrator, signed in with a recent second factor, can restore a backup. Nothing was changed.' };
    case 'rate_limited':
      return { ...commonRejection('rate_limited'), body: 'Wait a minute, then try again. Nothing was changed.' };
    case 'unavailable':
      return { title: 'Mandatary couldn’t start the restore', body: 'Nothing was changed. Try again in a moment; if it keeps happening, check the server log.' };
  }
}

function UnverifiedOrigin() {
  const ref = useFocusWhen(true);
  return (
    <Alert ref={ref} tone="warning" title="This file’s origin can’t be verified">
      It is a clean backup that this installation’s key can’t check, so Mandatary can’t tell whether it came from the installation you think, or was changed on the way. Nothing was changed. If you are sure of where it came from, confirm below and
      restore it again; everything in it still arrives switched off. If not, cancel.
    </Alert>
  );
}

interface ConfirmProps {
  fileName: string;
  needsAcknowledgement: boolean;
  busy: boolean;
  returnFocusId: string;
  onCancel: () => void;
  onConfirm: (acknowledge: boolean) => void;
}

/**
 * The typed confirmation. Same anatomy and keyboard behaviour as ConfirmPanel (focus lands on the group, Escape cancels and returns focus
 * to the button that opened it, the confirm button stays focusable while busy); the added field is the phrase the service also requires.
 * Enter in the field confirms. A wrong phrase is explained inline and focus returns to the field: the request is never sent.
 */
function RestoreConfirm({ fileName, needsAcknowledgement, busy, returnFocusId, onCancel, onConfirm }: ConfirmProps) {
  const phrase = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const [phraseError, setPhraseError] = useState<string | undefined>();
  const [ackError, setAckError] = useState<string | undefined>();
  const [acknowledged, setAcknowledged] = useState(false);

  const confirm = () => {
    if ((phrase.current?.value ?? '').trim() !== RESTORE_PHRASE) {
      setPhraseError(`Type ${RESTORE_PHRASE} in capital letters to continue.`);
      phrase.current?.focus();
      return;
    }
    setPhraseError(undefined);
    if (needsAcknowledgement && !acknowledged) {
      setAckError('Tick the box to continue, or cancel and use a file you can verify.');
      box.current?.querySelector<HTMLInputElement>('input[type="checkbox"]')?.focus();
      return;
    }
    setAckError(undefined);
    onConfirm(needsAcknowledgement && acknowledged);
  };

  return (
    <ConfirmPanel title={`Restore from ${fileName}?`} confirmLabel="Restore this backup" cancelLabel="Cancel" busyLabel="Restoring…" tone="danger" busy={busy} onConfirm={confirm} onCancel={onCancel} returnFocusId={returnFocusId}>
      <div ref={box} className="space-y-3">
        <p>
          This signs everyone out, including you, and closes sign-in until the host recovery is run. Nothing restored is active until you approve it. It can’t be undone from this page.
        </p>
        {needsAcknowledgement ? (
          <CheckboxField
            label="I understand this file’s origin can’t be verified."
            hint="Only restore a file you trust. It could have been changed, or made by a different installation."
            checked={acknowledged}
            onChange={setAcknowledged}
            disabled={busy}
            {...(ackError ? { error: ackError } : {})}
          />
        ) : null}
        <TextField
          ref={phrase}
          name="confirm"
          label={`Type ${RESTORE_PHRASE} to confirm`}
          hint="Capital letters, exactly as shown."
          autoComplete="off"
          autoCapitalize="characters"
          autoCorrect="off"
          spellCheck={false}
          mono
          readOnly={busy}
          className="max-w-xs"
          {...(phraseError ? { error: phraseError } : {})}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              confirm();
            }
          }}
        />
        {busy ? (
          <p role="status" className="flex items-center gap-2 text-sm font-medium">
            <Icon name="spinner" className="size-4" />
            Restoring. This can take a minute. Don’t close this page, go back or reload it.
          </p>
        ) : null}
      </div>
    </ConfirmPanel>
  );
}

/** What a restore does, in the order a person needs it. Always on screen before a file is chosen: it is the point of the page. */
function WhatARestoreDoes() {
  return (
    <Panel title="What a restore does" description="Read this before you choose a file. It all happens at once.">
      <ul className="divide-y divide-line">
        <Consequence icon="logout" lead="Everyone is signed out, including you.">
          The installation enters restore quarantine and sign-in stays closed.
        </Consequence>
        <Consequence icon="ban" lead="Nothing from the file is active.">
          Users, groups, agents, group memberships, rules and the endpoint are stored switched off. Records already here that the file doesn’t mention are kept, switched off too. Nothing is deleted.
        </Consequence>
        <Consequence icon="shield" lead="Stricter local settings win.">
          A Deny rule already here is never replaced by an Allow from the file, and a weaker second-factor setting from the file never takes effect.
        </Consequence>
        <Consequence icon="key" lead="No sign-in method or agent token comes back.">
          Every agent token that works today is revoked for good. People set up their sign-in methods again and agents get new tokens.
        </Consequence>
        <Consequence icon="lock" lead="Only the server can end quarantine.">
          Someone with access to the host runs the host recovery. No page in a browser can, and the administrator can’t sign back in until it is done.
        </Consequence>
        <Consequence icon="check" lead="Then you approve, item by item.">
          After the host recovery, sign in and open Review restored access. Each record becomes effective only when you approve it by name.
        </Consequence>
      </ul>
    </Panel>
  );
}

/**
 * Restore from a backup file (P1.18.2). The flow is: read what a restore does, choose a file, open the confirmation, type the phrase,
 * restore. There is no preview of the file, because the service has none (a preview would be a second, unreviewed way to read an archive);
 * the page says so and says what Mandatary checks before it changes anything.
 *
 * The screen holds the file handle and the confirmation's open/closed state, nothing secret. It never reads the file. A request that could
 * not start, or was refused before any change, comes back as `rejected` or `needs_acknowledgement` and leaves the form as it was; every
 * outcome after which the session may be gone is a `RestoreEnded`, shown by a different component.
 */
export function RestoreScreen({ state, onRestore, initial }: RestoreScreenProps) {
  const inputId = useId();
  const hintId = `${inputId}-hint`;
  const errorId = `${inputId}-error`;
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(initial?.file ?? null);
  const [fileError, setFileError] = useState<string | undefined>();
  const [confirming, setConfirming] = useState(initial?.confirming ?? false);
  const [lastKind, setLastKind] = useState(state.kind);
  const working = state.kind === 'working';
  const triggerId = `${inputId}-open`;

  // Adjusting state while rendering (not in an effect): once a request has been refused the confirmation closes, so the refusal is what the
  // person lands on, and opening it again means typing the phrase again. A `needs_acknowledgement` answer keeps it open.
  if (state.kind !== lastKind) {
    setLastKind(state.kind);
    if (state.kind === 'rejected') setConfirming(false);
  }

  const open = () => {
    let problem: string | undefined;
    if (file === null) problem = 'Choose a backup file.';
    else if (file.size === 0) problem = 'That file is empty.';
    else if (file.size > MAX_ARCHIVE_BYTES) problem = `That file is ${formatBytes(file.size)}. Mandatary refuses anything over ${formatBytes(MAX_ARCHIVE_BYTES)}.`;
    setFileError(problem);
    if (problem) {
      input.current?.focus();
      return;
    }
    setConfirming(true);
  };

  const describedBy = [hintId, fileError ? errorId : null].filter(Boolean).join(' ');
  return (
    <div className="space-y-6">
      <PageHeader title="Restore from a backup" description="Load a backup file into this installation. This is a recovery step, not an undo." />
      <SnapshotNote />
      <WhatARestoreDoes />
      <Panel title="Choose the file" description="A backup you exported from Mandatary. Mandatary can’t preview it: it checks the format, version, integrity and consistency on the server before anything changes, and a file that fails changes nothing and doesn’t start quarantine.">
        <form
          method="post"
          noValidate
          aria-label="Restore from a backup"
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (!confirming && !working) open();
          }}
        >
          <div>
            <label htmlFor={inputId} className="mb-1.5 block text-sm font-medium text-fg">
              Backup file
            </label>
            <input
              ref={input}
              id={inputId}
              type="file"
              name="archive"
              accept=".json,application/json"
              aria-describedby={describedBy}
              aria-invalid={fileError ? true : undefined}
              disabled={working}
              onChange={(event) => {
                setFile(event.currentTarget.files?.[0] ?? null);
                setFileError(undefined);
                setConfirming(false);
              }}
              className={`min-h-11 w-full rounded-control border bg-surface px-3 py-2 text-base text-fg file:mr-3 file:min-h-9 file:rounded-control file:border-0 file:bg-accent-soft file:px-3 file:font-medium file:text-accent-text disabled:opacity-60 ${fileError ? 'border-danger' : 'border-line-strong'}`}
            />
            <p id={hintId} className="mt-1.5 text-sm text-muted">
              A .json file of up to {formatBytes(MAX_ARCHIVE_BYTES)}. Nothing is uploaded until you confirm.
            </p>
            {fileError ? (
              <p id={errorId} className="mt-1.5 flex items-start gap-1.5 text-sm font-medium text-danger">
                <Icon name="error" className="mt-0.5 size-4" />
                <span>{fileError}</span>
              </p>
            ) : null}
          </div>
          {file !== null && fileError === undefined ? (
            <Facts>
              <Fact label="Chosen file">
                <Ident>{file.name}</Ident>
              </Fact>
              <Fact label="Size">{formatBytes(file.size)}</Fact>
            </Facts>
          ) : null}
          {state.kind === 'rejected' ? <RejectionAlert rejection={rejection(state.reason)} active /> : null}
          {/* The opening button stays on the page while the confirmation is open: Escape and Cancel return focus to it, so it has to exist. Pressing it again changes nothing. */}
          <div className="space-y-1.5">
            <Button id={triggerId} type="submit" variant="danger" icon="upload" aria-expanded={confirming}>
              Restore from this file…
            </Button>
            {confirming ? null : <p className="text-sm text-muted">Restoring needs a recent multi-factor verification. If it has been a while you will be asked to verify first, then confirm again.</p>}
          </div>
          {confirming && file !== null ? (
            <div className="space-y-3">
              {state.kind === 'needs_acknowledgement' ? <UnverifiedOrigin /> : null}
              <RestoreConfirm
                fileName={file.name}
                needsAcknowledgement={state.kind === 'needs_acknowledgement'}
                busy={working}
                returnFocusId={triggerId}
                onCancel={() => setConfirming(false)}
                onConfirm={(acknowledge) => onRestore({ file, acknowledgeUnauthenticatedProvenance: acknowledge })}
              />
            </div>
          ) : null}
        </form>
      </Panel>
    </div>
  );
}

// ───────────────────────── after the request ─────────────────────────

function NextSteps({ children }: { children: ReactNode }) {
  return <ol className="list-decimal space-y-2 pl-5 text-sm leading-relaxed marker:font-semibold">{children}</ol>;
}

function Report({ ended }: { ended: Extract<RestoreEnded, { kind: 'complete' }> }) {
  const { report } = ended;
  const imported = countsSentence(report.imported);
  const retained = countsSentence(report.retainedLocal);
  const credentials = countsSentence(report.inactiveCredentials);
  const excluded = excludedNames(report.excluded);
  return (
    <Panel title="What was restored" description="Counts only. Every record below is switched off.">
      <Facts>
        <Fact label="Backup">
          <Ident>{report.backupId}</Ident> ({MODE_NAME[report.mode].toLowerCase()})
        </Fact>
        <Fact label="Origin">{report.provenance === 'authenticated' ? 'Verified with this installation’s key.' : 'Not verifiable with this installation’s key; restored after you acknowledged that.'}</Fact>
        <Fact label="Imported, switched off">{imported || 'Nothing'}</Fact>
        <Fact label="Already here, kept switched off">{retained || 'None'}</Fact>
        <Fact label="Credentials">
          {report.credentialsStripped ? 'None. This was a clean backup.' : credentials ? `${credentials}, kept switched off for reference. They can’t be switched back on.` : 'None were in the file.'}
        </Fact>
        {excluded.length > 0 ? <Fact label="Not read or changed">{excluded.join(', ')}</Fact> : null}
      </Facts>
    </Panel>
  );
}

function Complete({ ended, runbookHref }: { ended: Extract<RestoreEnded, { kind: 'complete' }>; runbookHref?: string }) {
  const ref = useFocusWhen(true);
  return (
    <>
      <PageHeader title="Restore complete" description="Mandatary is now in restore quarantine." />
      <Alert ref={ref} tone="warning" title="Sign-in is closed until the host recovery is done">
        You and everyone else were signed out. Nothing from the file is active yet.
      </Alert>
      {ended.authorizerNotified ? null : (
        <Alert tone="info" role="none" title="Access decisions may take a moment to catch up">
          Mandatary couldn’t tell its access-decision service straight away. Quarantine is already in force; any decision it had cached lapses at its next refresh.
        </Alert>
      )}
      <Report ended={ended} />
      <Panel title="What to do next">
        <NextSteps>
          <HostRecoveryStep {...(runbookHref ? { runbookHref } : {})} />
          <li>Sign in as the administrator.</li>
          <li>Open Review restored access and approve each record you still want, by name.</li>
          <li>Set up sign-in methods and agent tokens again. Approving a record never restores either.</li>
        </NextSteps>
      </Panel>
    </>
  );
}

/** The first step after any restore that reached quarantine. Shared so the two outcomes cannot drift apart. */
function HostRecoveryStep({ runbookHref }: { runbookHref?: string }) {
  return (
    <li>
      Run the host recovery on the server. A browser can’t do this.
      {runbookHref ? (
        <>
          {' '}
          <a href={runbookHref} className="font-medium text-accent-text underline underline-offset-2">
            Open the operator runbook
          </a>
          .
        </>
      ) : null}
    </li>
  );
}

function Incomplete({ ended, runbookHref }: { ended: Extract<RestoreEnded, { kind: 'incomplete' }>; runbookHref?: string }) {
  const ref = useFocusWhen(true);
  return (
    <>
      <PageHeader title="The restore didn’t finish" description="Nothing from the file was applied, but Mandatary is in restore quarantine." />
      <Alert ref={ref} tone="danger" title="Sign-in is closed, and nothing was imported">
        {ended.cause === 'superseded' ? 'Another restore ran at the same moment and took precedence, so this one applied nothing.' : 'Something failed while the file was being imported, so none of it was kept.'} The first step had already happened: everyone was
        signed out and sign-in is closed.
      </Alert>
      <Panel title="What to do next">
        <NextSteps>
          <HostRecoveryStep {...(runbookHref ? { runbookHref } : {})} />
          <li>Sign in as the administrator.</li>
          <li>{ended.cause === 'superseded' ? 'Open Review restored access to see what the other restore imported before you restore again.' : 'Restore the same file again if you still want it. That is safe: a failed restore never leaves part of a file behind.'}</li>
        </NextSteps>
      </Panel>
    </>
  );
}

function Unconfirmed({ onReload }: { onReload?: () => void }) {
  const ref = useFocusWhen(true);
  return (
    <>
      <PageHeader title="Mandatary couldn’t confirm what happened" description="The restore may have started." />
      <Alert ref={ref} tone="warning" title="Don’t start another restore yet">
        The connection broke or timed out before an answer arrived, so the restore may have run or not run at all. Your session may already have ended.
      </Alert>
      <Panel title="Find out where things stand">
        <NextSteps>
          <li>Reload this page.</li>
          <li>If you are still signed in, the restore did not start. Nothing was changed and you can try again.</li>
          <li>If you are signed out, or sign-in is closed, the restore did start: the installation is in restore quarantine and needs the host recovery.</li>
        </NextSteps>
        {onReload ? (
          <Button icon="upload" variant="secondary" onClick={onReload}>
            Reload this page
          </Button>
        ) : null}
      </Panel>
    </>
  );
}

/**
 * The page after a restore request that closed, or may have closed, the session (P1.18.2). It is NOT rendered inside the signed-in shell: the
 * session is gone, so the shell's account strip, navigation and 401 handling would all be wrong. There is no retry button on any outcome; the next
 * step is always on the host, or, when the answer was lost, a reload to find out.
 */
export function RestoreEndedView({ ended, runbookHref, signInHref = '/login', onReload }: RestoreEndedProps) {
  return (
    <div className="space-y-5">
      {ended.kind === 'complete' ? <Complete ended={ended} {...(runbookHref ? { runbookHref } : {})} /> : ended.kind === 'incomplete' ? <Incomplete ended={ended} {...(runbookHref ? { runbookHref } : {})} /> : <Unconfirmed {...(onReload ? { onReload } : {})} />}
      {ended.kind === 'unconfirmed' ? null : (
        <p className="text-sm">
          <a href={signInHref} className="font-medium text-accent-text underline underline-offset-2">
            Go to the sign-in page
          </a>
          . Sign-in stays closed until the host recovery is done.
        </p>
      )}
    </div>
  );
}

/** `RestoreEndedView` in the pre-session frame, for the container to render in place of the shell. */
export function RestoreEndedPage(props: RestoreEndedProps) {
  return (
    <CenteredFrame width="max-w-xl">
      <RestoreEndedView {...props} />
    </CenteredFrame>
  );
}
