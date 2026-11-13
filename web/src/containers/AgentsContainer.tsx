import { useEffect, useMemo, useState } from 'react';
import type { AccountApi } from '../api/account';
import { AgentsApi, type AgentMeta, type CredentialMeta } from '../api/security';
import type { AgentCredentialState, CredentialRow } from '../screens/contract';
import { AgentCredentials } from '../screens/agents';
import { formatDate } from '../ui/format';
import { Alert, Button, EmptyState, PageHeader, Skeleton } from '../ui';
import type { Navigate } from './LoginContainer';
import { failureReason, outcomeOf } from './outcome';
import { SignedIn, type SignedInContext } from './SignedIn';
import { StepUpGate, useStepUp } from './StepUpGate';
import { SecurityApi } from '../api/security';

/**
 * Agent credentials (P1.16.4, P1.10 routes): issue, rotate and revoke bearer tokens with REVEAL-ONCE.
 * The list is non-secret metadata only. The token exists in the DOM only inside the one SecretReveal that
 * `state.token` feeds, and is dropped when the person hides it, when a step-up replaces the session, and
 * when the page unloads (it is never in the URL, storage, history, a title or the console). A rotation
 * that fails or is refused shows no token: nothing was created.
 *
 * Whether the viewer may administer agents is the server's decision (an administrator holding fresh
 * AAL2 evidence); the page shows the refusal and nothing else.
 */

function rowOf(credential: CredentialMeta): CredentialRow {
  const base = { id: credential.id, displayId: credential.displayId, expiresOn: credential.expiresAt === null ? null : formatDate(credential.expiresAt) };
  switch (credential.status) {
    case 'active':
      return { ...base, status: 'active' };
    case 'overlapping':
      return { ...base, status: 'rotating_out', ...(credential.overlapUntil === null ? {} : { overlapEndsOn: formatDate(credential.overlapUntil) }) };
    case 'expired':
      return { ...base, status: 'expired' };
    default:
      // rotated_out, revoked, quarantined and stale are all "no longer accepted".
      return { ...base, status: 'revoked' };
  }
}

export function AgentsContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="agents">
      {(context) => <AgentsPage {...context} />}
    </SignedIn>
  );
}

type Load = { kind: 'loading' } | { kind: 'ready'; agents: AgentMeta[] } | { kind: 'forbidden' } | { kind: 'failed' };

function AgentsPage({ api, view, navigate, refresh }: SignedInContext) {
  const agentsApi = useMemo(() => new AgentsApi(api), [api]);
  const sec = useMemo(() => new SecurityApi(api), [api]);
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [selected, setSelected] = useState('');
  const [state, setState] = useState<AgentCredentialState>({ kind: 'idle' });

  function reload() {
    void agentsApi.list().then((result) => {
      if (result.ok) {
        setLoad({ kind: 'ready', agents: result.data });
        setSelected((current) => (result.data.some((agent) => agent.id === current) ? current : (result.data[0]?.id ?? '')));
      } else if (result.status === 401) navigate('/login');
      else if (result.status === 403) setLoad({ kind: 'forbidden' });
      else setLoad({ kind: 'failed' });
    });
  }

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- load once per mount
  }, []);

  // A step-up replaces the session: a revealed token belongs to the previous one and is dropped.
  const stepUp = useStepUp(sec, view, refresh, () => setState({ kind: 'idle' }));

  if (load.kind === 'loading') {
    return (
      <div className="space-y-4">
        <PageHeader title="Agents" description="Credentials for the agents that call the REST API and MCP server." />
        <Skeleton label="agents" lines={3} />
      </div>
    );
  }
  if (load.kind === 'forbidden' || load.kind === 'failed') {
    return (
      <div className="space-y-4">
        <PageHeader title="Agents" description="Credentials for the agents that call the REST API and MCP server." />
        {load.kind === 'forbidden' ? (
          <Alert tone="warning" role="alert" title="Agent administration isn’t available to this session">
            Only an administrator signed in with a second factor can manage agent credentials. Nothing is shown here.
          </Alert>
        ) : (
          <Alert
            tone="danger"
            title="Couldn’t load agents"
            actions={
              <Button
                onClick={() => {
                  setLoad({ kind: 'loading' });
                  reload();
                }}
              >
                Try again
              </Button>
            }
          >
            Nothing was changed. Try again in a moment.
          </Alert>
        )}
      </div>
    );
  }

  const agent = load.agents.find((candidate) => candidate.id === selected);
  if (!agent) {
    return (
      <div className="space-y-4">
        <PageHeader title="Agents" description="Credentials for the agents that call the REST API and MCP server." />
        <EmptyState title="No agents yet" description="Agents are created by an administrator. Once one exists, you can issue it a token here." />
      </div>
    );
  }

  const failed = (result: Parameters<typeof outcomeOf>[0], action: string) => {
    const outcome = outcomeOf(result);
    switch (outcome.kind) {
      case 'ended':
        navigate('/login');
        return;
      case 'step_up':
        stepUp.show(action);
        setState({ kind: 'idle' });
        return;
      case 'assurance_unavailable':
        stepUp.show(action, true);
        setState({ kind: 'idle' });
        return;
      default:
        setState({ kind: 'rejected', reason: result.status === 409 ? 'conflict' : failureReason(outcome) });
    }
  };

  const issueOrRotate = (rotate: boolean) => {
    const action = rotate ? 'Rotate an agent token' : 'Issue an agent token';
    setState({ kind: 'working' });
    void (rotate ? agentsApi.rotate(agent.id) : agentsApi.issue(agent.id)).then((result) => {
      if (!result.ok) {
        failed(result, action);
        return;
      }
      setState({
        kind: 'reveal',
        token: result.data.token,
        expiresOn: result.data.credential.expiresAt === null ? null : formatDate(result.data.credential.expiresAt),
        ...(result.data.rotatedOut[0] ? { rotatedOutDisplayId: result.data.rotatedOut[0].displayId } : {}),
      });
      reload();
    });
  };

  return (
    <div className="space-y-5">
      <PageHeader title="Agents" description="Credentials for the agents that call the REST API and MCP server." />
      <StepUpGate controls={stepUp} view={view} />
      {load.agents.length > 1 ? (
        <label className="block">
          <span className="mb-1 block text-sm font-medium">Agent</span>
          <select
            className="min-h-11 w-full max-w-sm rounded-control border border-line-strong bg-surface px-3 text-base"
            value={selected}
            disabled={state.kind === 'reveal'}
            onChange={(event) => {
              setSelected(event.target.value);
              setState({ kind: 'idle' });
            }}
          >
            {load.agents.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.name}
              </option>
            ))}
          </select>
        </label>
      ) : null}
      <AgentCredentials
        agentName={agent.name}
        credentials={agent.credentials.map(rowOf)}
        state={state}
        onIssue={() => issueOrRotate(false)}
        onRotate={() => issueOrRotate(true)}
        onAskRevoke={(id) => setState({ kind: 'confirming_revoke', id })}
        onCancelRevoke={() => setState({ kind: 'idle' })}
        onConfirmRevoke={() => {
          if (state.kind !== 'confirming_revoke') return;
          setState({ kind: 'working' });
          void agentsApi.revoke(agent.id, state.id).then((result) => {
            if (result.ok) {
              setState({ kind: 'idle' });
              reload();
            } else failed(result, 'Revoke an agent token');
          });
        }}
        onHidden={() => {
          setState({ kind: 'idle' }); // the token leaves the page here and cannot be fetched again
          reload();
        }}
      />
    </div>
  );
}
