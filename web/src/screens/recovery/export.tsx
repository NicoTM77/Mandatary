import { useState } from 'react';
import { Alert, Button, PageHeader, Panel, RadioGroup } from '../../ui';
import { RejectionAlert, useFocusWhen, type Rejection } from '../shared';
import { Fact, Facts } from '../policy/shared';
import type { BackupMode, ExportReason, ExportScreenProps, ExportState } from './contract';
import { Ident, MODE_NAME, SnapshotNote } from './shared';

function rejection(reason: ExportReason): Rejection {
  switch (reason) {
    case 'denied':
      return { title: 'Export wasn’t allowed', body: 'Only the administrator, signed in with a recent second factor, can export a backup. Nothing was exported.' };
    case 'invalid_request':
      return { title: 'That request couldn’t be read', body: 'Reload the page and try again. Nothing was exported.' };
    case 'rate_limited':
      return { title: 'Too many attempts', body: 'Wait a minute, then try again. Nothing was exported.' };
    case 'unavailable':
      return { title: 'Mandatary couldn’t create the backup', body: 'Nothing was exported and nothing was changed. Try again in a moment; if it keeps happening, check the server log.' };
  }
}

function Outcome({ state }: { state: ExportState }) {
  const done = state.kind === 'done';
  const ref = useFocusWhen(done);
  if (state.kind === 'rejected') return <RejectionAlert rejection={rejection(state.reason)} active />;
  if (state.kind !== 'done') return null;
  return (
    <Alert ref={ref} tone="success" title="Backup file created">
      <p>
        Your browser was given <Ident>{state.fileName}</Ident>. Check where it saves downloads. Nothing in this installation changed.
      </p>
      <p className="mt-1">
        Backup ID <Ident>{state.backupId}</Ident> ({MODE_NAME[state.mode].toLowerCase()}).{' '}
        {state.mode === 'full' ? 'It holds sealed sign-in and token records, so store it where only administrators can read it.' : 'It holds no sign-in or token records, but it still lists everyone with access, so store it with care.'}
      </p>
    </Alert>
  );
}

/**
 * Export a backup (P1.18.2). One decision: clean or full. The page's job is to make the difference, and what neither type does,
 * unmistakable BEFORE the file exists: the choice is made with its consequence written beside it, the button names the choice, and the
 * result says what the person now holds. It is a stateless function of `state`; the container performs the request (a class
 * `backup-export` step-up gate, CSRF, the download) and the page never sees the file.
 */
export function ExportScreen({ state, onExport, initialMode = 'clean' }: ExportScreenProps) {
  const [mode, setMode] = useState<BackupMode>(initialMode);
  const working = state.kind === 'working';
  return (
    <div className="space-y-6">
      <PageHeader title="Export a backup" description="Save this installation’s access settings to a file you can restore later, here or on a new installation." />
      <SnapshotNote />
      <Panel title="Choose the type of backup" description="Neither type brings a sign-in method or an agent token back to life. After a restore those are set up and issued again.">
        <form
          method="post"
          noValidate
          aria-label="Export a backup"
          className="space-y-5"
          onSubmit={(event) => {
            event.preventDefault();
            if (!working) onExport(mode);
          }}
        >
          <RadioGroup
            name="mode"
            legend="Backup type"
            value={mode}
            onChange={(value) => setMode(value === 'full' ? 'full' : 'clean')}
            options={[
              { value: 'clean', label: 'Clean backup', hint: 'Settings only: no sign-in or token records. Can be restored on this installation or on a new one with a different key.', disabled: working },
              { value: 'full', label: 'Full backup', hint: 'Adds sealed sign-in and token records. Only an installation with this installation’s key can restore it, and the records come back switched off.', disabled: working },
            ]}
          />
          {mode === 'full' ? (
            <Alert tone="warning" role="none" title="A full backup holds credential material">
              The sign-in and token records are sealed with this installation’s key, which is not in the file. Treat the file as a secret anyway: keep it where only administrators can read it.
            </Alert>
          ) : null}
          <Facts>
            <Fact label="Both types hold">Users, groups and agents; who belongs to which group; the administrator role; access rules and the container selectors they use; notification addresses; this installation’s endpoint name.</Fact>
            <Fact label="Neither type holds">Sign-in sessions, usage statistics, setup and recovery state, security notices, or the installation key.</Fact>
            <Fact label="Only a full backup holds">Sign-in method records (passwords, authenticator apps, security keys) and agent token records, sealed. Restoring keeps them for reference and never switches them on.</Fact>
          </Facts>
          <Outcome state={state} />
          <div className="space-y-1.5">
            <Button type="submit" icon="download" busy={working} busyLabel="Creating the backup…">
              {`Export ${mode} backup`}
            </Button>
            <p className="text-sm text-muted">Exporting needs a recent multi-factor verification. If it has been a while you will be asked to verify first, then press Export again.</p>
          </div>
        </form>
      </Panel>
    </div>
  );
}
