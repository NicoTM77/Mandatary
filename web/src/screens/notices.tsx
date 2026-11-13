import { Alert, Badge, Button, CodeField, Panel, TextField } from '../ui';
import type { AddressManagementProps, ManagedAddress, NoticeHealthProps } from './contract';
import { Command, RejectionAlert, commonRejection, useRequiredForm, type Rejection } from './shared';

function addressRejection(reason: 'wrong_code' | 'denied' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  switch (reason) {
    case 'wrong_code':
      return { title: 'That code didn’t match', body: 'Check the latest email and try again, or go back and send a new code.' };
    case 'denied':
      return { title: 'The change wasn’t made', body: 'The address can’t be used, or you need to verify again first. Nothing was changed.' };
    default:
      return commonRejection(reason);
  }
}

function AddAddressForm({ state, onSubmitAddress, onSubmitProof, onCancelAdd }: Pick<AddressManagementProps, 'state' | 'onSubmitAddress' | 'onSubmitProof' | 'onCancelAdd'>) {
  const adding = state.kind === 'adding' ? state : null;
  const busy = adding?.busy === true;
  const addressForm = useRequiredForm([['address', 'an email address']], (data) => onSubmitAddress({ address: String(data.get('address')).trim() }), { rejected: adding?.error !== undefined });
  const proofForm = useRequiredForm([['code', 'the code from the email']], (data) => onSubmitProof({ code: String(data.get('code')).replace(/[\s-]/g, '') }), { rejected: adding?.error !== undefined, clearOnReject: ['code'] });
  if (!adding) return null;
  return (
    <div className="rounded-control border border-line-strong bg-sunken p-4">
      {adding.error ? <RejectionAlert rejection={addressRejection(adding.error)} active /> : null}
      {adding.step === 'enter' ? (
        <form {...addressForm.formProps} aria-label="Add notification address" className="mt-0 space-y-3">
          <TextField name="address" label="Email address" type="email" autoComplete="email" autoCapitalize="none" spellCheck={false} required error={addressForm.errorFor('address')} readOnly={busy} className={adding.error ? 'mt-3' : ''} />
          <div className="flex flex-wrap gap-2">
            <Button type="submit" busy={busy} busyLabel="Sending code…">
              Send confirmation code
            </Button>
            <Button variant="quiet" onClick={onCancelAdd} disabled={busy}>
              Cancel
            </Button>
          </div>
        </form>
      ) : (
        <form {...proofForm.formProps} aria-label="Confirm notification address" className="space-y-3">
          <p className={adding.error ? 'mt-3' : ''}>
            We sent a code to <strong className="break-all">{adding.pendingAddress}</strong>. The address isn’t used until you confirm it.
          </p>
          <CodeField kind="mailed-proof" name="code" label="Code from the email" required error={proofForm.errorFor('code')} readOnly={busy} />
          <div className="flex flex-wrap gap-2">
            <Button type="submit" busy={busy} busyLabel="Confirming…">
              Confirm address
            </Button>
            <Button variant="quiet" onClick={onCancelAdd} disabled={busy}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

export function AddressManagement({ addresses, maxAddresses, state, mailConfigured, onStartAdd, onSubmitAddress, onSubmitProof, onCancelAdd, onAskRemove, onCancelRemove, onConfirmRemove }: AddressManagementProps) {
  const confirmed = addresses.filter((row) => row.status === 'confirmed');
  const atLimit = addresses.length >= maxAddresses;
  // The last confirmed address can never be removed: security notices need at least one live destination.
  const removable = (row: ManagedAddress) => row.status === 'unconfirmed' || confirmed.length > 1;
  return (
    <Panel title="Notification addresses" description="Security notices (new sign-in methods, recovery, removals) are sent to every confirmed address. Keep at least two so a lost mailbox doesn’t hide a warning.">
      {!mailConfigured ? (
        <Alert tone="warning" role="none" title="Email isn’t configured">
          New addresses can’t be confirmed until the mail relay is set up. Existing addresses are unchanged.
        </Alert>
      ) : null}
      {state.kind === 'rejected' ? <RejectionAlert rejection={addressRejection(state.reason)} active /> : null}
      {confirmed.length === 1 ? (
        <Alert tone="info" role="none" title="You have one confirmed address">
          Add a second so notices still reach you if this mailbox is unavailable.
        </Alert>
      ) : null}
      <ul className="divide-y divide-line">
        {addresses.map((row) => (
          <li key={row.id} className="py-3 first:pt-0">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="min-w-0 break-all font-medium">{row.address}</p>
              <div className="flex items-center gap-2">
                {row.status === 'confirmed' ? (
                  <Badge tone="success" icon="check">
                    Confirmed
                  </Badge>
                ) : (
                  <Badge tone="warning" icon="clock">
                    Not confirmed
                  </Badge>
                )}
                <Button variant="danger" disabled={!removable(row)} onClick={() => onAskRemove(row.id)} aria-label={`Remove ${row.address}`}>
                  Remove
                </Button>
              </div>
            </div>
            {!removable(row) ? <p className="mt-1 text-sm text-muted">This is your only confirmed address, so it can’t be removed. Add and confirm another first.</p> : null}
            {state.kind === 'confirming_removal' && state.id === row.id ? (
              <div role="group" aria-label={`Confirm removing ${row.address}`} className="mt-3 rounded-control border border-danger bg-danger-soft p-3.5">
                <p className="font-medium text-danger">Remove {row.address}?</p>
                <p className="mt-1 text-sm">It will stop receiving security notices. We’ll email your remaining addresses about this change.</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button variant="danger" busy={state.busy === true} busyLabel="Removing…" onClick={onConfirmRemove}>
                    Remove address
                  </Button>
                  <Button variant="secondary" onClick={onCancelRemove} disabled={state.busy === true}>
                    Keep it
                  </Button>
                </div>
              </div>
            ) : null}
          </li>
        ))}
      </ul>
      {state.kind === 'adding' ? (
        <AddAddressForm state={state} onSubmitAddress={onSubmitAddress} onSubmitProof={onSubmitProof} onCancelAdd={onCancelAdd} />
      ) : (
        <div>
          <Button variant="secondary" icon="plus" onClick={onStartAdd} disabled={atLimit || !mailConfigured}>
            Add address
          </Button>
          {atLimit ? <p className="mt-2 text-sm text-muted">You’ve reached the maximum of {maxAddresses} addresses.</p> : null}
        </div>
      )}
    </Panel>
  );
}

/**
 * Security-notice delivery health. Aggregate counts only: no recipients, no SMTP diagnostics. An
 * unreadable status is "unknown", never "healthy". A non-zero `protective` count is the most serious
 * state because a security change happened that no notice could be recorded for.
 */
export function NoticeHealth({ health, onRetry, retrying = false }: NoticeHealthProps) {
  const { pending, failed, bounced, quarantined, protective, unknown } = health;
  const retry = onRetry ? (
    <Button variant="secondary" busy={retrying} busyLabel="Retrying…" onClick={onRetry}>
      Retry failed notices
    </Button>
  ) : undefined;
  if (unknown) {
    return (
      <Alert tone="warning" title="Notice delivery status is unknown">
        Mandatary couldn’t read the delivery status, so it can’t say notices are being delivered. Check the server log.
      </Alert>
    );
  }
  if (protective > 0) {
    return (
      <Alert tone="danger" title={`${protective} security ${protective === 1 ? 'change has' : 'changes have'} no recorded notice`}>
        A sign-in method was removed or reported compromised, and the notice for it could not be stored. The change itself took effect. An operator needs to investigate and tell the account owners by another channel. Check the
        server log.
      </Alert>
    );
  }
  if (failed + bounced + quarantined > 0) {
    return (
      <Alert tone="warning" title="Some security notices weren’t delivered" actions={failed > 0 ? retry : undefined}>
        <ul className="list-inside list-disc tabular-nums">
          {failed > 0 ? <li>{failed} failed after repeated attempts</li> : null}
          {bounced > 0 ? <li>{bounced} bounced by the receiving mail server</li> : null}
          {quarantined > 0 ? <li>{quarantined} held back after an incident</li> : null}
          {pending > 0 ? <li>{pending} still waiting to be sent</li> : null}
        </ul>
        <p className="mt-1.5">Check the mail relay settings and the addresses above. Retrying re-sends to the same recipients.</p>
      </Alert>
    );
  }
  if (pending > 0) {
    return (
      <Alert tone="info" title={`${pending} security ${pending === 1 ? 'notice is' : 'notices are'} waiting to be sent`}>
        This is normal for a moment after a change. If it stays this way, check the mail relay (<Command>MANDATARY_SMTP_RELAY</Command>).
      </Alert>
    );
  }
  return (
    <Alert tone="success" title="Security notices are being delivered" role="none">
      No failed, bounced or waiting notices.
    </Alert>
  );
}
