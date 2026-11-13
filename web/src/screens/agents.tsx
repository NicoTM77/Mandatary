import { Badge, Button, Panel, SecretReveal } from '../ui';
import type { AgentCredentialsProps, CredentialRow } from './contract';
import { RejectionAlert, commonRejection, type Rejection } from './shared';

function credentialBadge(row: CredentialRow) {
  switch (row.status) {
    case 'active':
      return (
        <Badge tone="success" icon="check">
          Active
        </Badge>
      );
    case 'rotating_out':
      return (
        <Badge tone="warning" icon="clock">
          Stops working {row.overlapEndsOn}
        </Badge>
      );
    case 'revoked':
      return <Badge tone="neutral">Revoked</Badge>;
    case 'expired':
      return <Badge tone="neutral">Expired</Badge>;
  }
}

function rejection(reason: 'step_up_required' | 'denied' | 'conflict' | 'rate_limited' | 'unavailable' | 'invalid_request'): Rejection {
  switch (reason) {
    case 'step_up_required':
      return { title: 'Verify again to continue', body: 'Agent credentials need a recent multi-factor verification. Nothing was created or changed.' };
    case 'conflict':
      return { title: 'The agent already has two live tokens', body: 'Revoke one, or wait for the rotation window to end, then try again.' };
    case 'denied':
      return { title: 'That wasn’t allowed', body: 'The agent may be disabled or no longer exist. Reload the list.' };
    default:
      return commonRejection(reason);
  }
}

/**
 * Agent credential list with reveal-once issue/rotate. The list only ever shows non-secret metadata
 * (short display id, status, dates). The token exists in the DOM only inside <SecretReveal>.
 */
export function AgentCredentials({ agentName, credentials, state, onIssue, onRotate, onAskRevoke, onCancelRevoke, onConfirmRevoke, onHidden, synthetic }: AgentCredentialsProps) {
  const live = credentials.filter((row) => row.status === 'active' || row.status === 'rotating_out');
  const working = state.kind === 'working';
  return (
    <div className="space-y-5">
      {state.kind === 'reveal' ? (
        <SecretReveal
          heading={`New token for ${agentName}`}
          synthetic={synthetic}
          value={state.token}
          copyLabel="Copy token"
          intro={
            <>
              Give it to the agent as a bearer token for the REST API and MCP server.{' '}
              {state.expiresOn ? <>It expires on {state.expiresOn}.</> : <>It does not expire; revoke it when it is no longer needed.</>}
              {state.rotatedOutDisplayId ? <> The previous token ({state.rotatedOutDisplayId}) keeps working only until the overlap window below ends.</> : null}
            </>
          }
          acknowledge={{ confirmLabel: 'I have copied this token to where the agent will read it.', doneLabel: 'Hide the token', onDone: onHidden }}
        />
      ) : null}
      <Panel
        title={`Credentials for ${agentName}`}
        description="Tokens identify an agent to the API and MCP server. Only a hash is stored, so a token can’t be shown again."
        headerActions={
          live.length === 0 ? (
            <Button icon="key" busy={working} busyLabel="Creating…" onClick={onIssue} disabled={state.kind === 'reveal'}>
              Issue token
            </Button>
          ) : (
            <Button variant="secondary" icon="key" busy={working} busyLabel="Rotating…" onClick={onRotate} disabled={state.kind === 'reveal'}>
              Rotate token
            </Button>
          )
        }
      >
        {state.kind === 'rejected' ? <RejectionAlert rejection={rejection(state.reason)} active /> : null}
        {credentials.length === 0 ? (
          <p className="text-muted">No tokens yet. Issue one so this agent can call the API.</p>
        ) : (
          <ul className="divide-y divide-line">
            {credentials.map((row) => (
              <li key={row.id} className="py-3 first:pt-0 last:pb-0">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-mono text-[0.9rem]" translate="no">
                      {row.displayId}
                    </p>
                    <p className="text-sm text-muted">{row.expiresOn ? `Expires ${row.expiresOn}` : 'No expiry'}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {credentialBadge(row)}
                    {row.status === 'active' || row.status === 'rotating_out' ? (
                      <Button variant="danger" aria-label={`Revoke ${row.displayId}`} onClick={() => onAskRevoke(row.id)}>
                        Revoke
                      </Button>
                    ) : null}
                  </div>
                </div>
                {state.kind === 'confirming_revoke' && state.id === row.id ? (
                  <div role="group" aria-label={`Confirm revoking ${row.displayId}`} className="mt-3 rounded-control border border-danger bg-danger-soft p-3.5">
                    <p className="font-medium text-danger">Revoke {row.displayId}?</p>
                    <p className="mt-1 text-sm">The agent using it is cut off immediately, including any stream it has open. This can’t be undone.</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Button variant="danger" onClick={onConfirmRevoke}>
                        Revoke token
                      </Button>
                      <Button variant="secondary" onClick={onCancelRevoke}>
                        Keep it
                      </Button>
                    </div>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
