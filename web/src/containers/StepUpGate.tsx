import { useState } from 'react';
import type { SessionView, StepUpMethodName } from '../api/account';
import type { SecurityApi } from '../api/security';
import { getCredential } from '../api/webauthn';
import type { StepUpMethod, StepUpState } from '../screens/contract';
import { StepUpPanel } from '../screens/login';
import { commonReason } from '../api/http';

/**
 * Step-up (docs/ui §7.4, D-STEPUP-1). Step-up is a fresh sign-in that issues a SUCCESSOR session: the
 * cookie, the CSRF token and the freshness are all new and every ceremony begun under the old session is
 * gone. So the gate (1) lets the page discard its pending ceremonies when it opens, (2) re-reads the
 * session to adopt the rotated CSRF token, and (3) NEVER resends the blocked request: the panel says so
 * and the person repeats the action. The server decides which proofs it accepts (`stepUpMethods`); the
 * page offers only those and the service refuses everything else.
 */

const FRESH_MINUTES = 15;

export interface StepUpOpen {
  action: string;
  state: StepUpState;
  method: StepUpMethod;
}

export interface StepUpControls {
  open: StepUpOpen | null;
  /** Shows the panel for a blocked action. With no usable proof the panel says the account can't be verified. */
  show: (action: string, unavailable?: boolean) => void;
  dismiss: () => void;
  submitPassword: (values: { password: string }) => void;
  submitTotp: (values: { password: string; code: string; authenticatorId?: string }) => void;
  startKey: () => void;
  choose: (method: StepUpMethod) => void;
}

export function useStepUp(sec: SecurityApi, view: SessionView, refresh: () => Promise<boolean>, onOpen: () => void, onVerified?: () => void): StepUpControls {
  const [open, setOpen] = useState<StepUpOpen | null>(null);

  function show(action: string, unavailable = false) {
    onOpen(); // the page drops its pending ceremonies: they belong to the session being replaced
    const method: StepUpMethod = view.stepUpMethods[0] ?? 'password';
    setOpen({ action, method, state: unavailable || view.stepUpMethods.length === 0 ? { kind: 'unavailable' } : { kind: 'idle' } });
  }

  function patch(state: StepUpState) {
    setOpen((current) => (current === null ? current : { ...current, state }));
  }

  async function finish(result: Awaited<ReturnType<SecurityApi['stepUpPassword']>>) {
    if (result.ok) {
      // Adopt the successor session. The blocked request is deliberately NOT replayed.
      if (await refresh()) {
        patch({ kind: 'verified', validMinutes: FRESH_MINUTES });
        onVerified?.();
      }
      return;
    }
    if (result.status === 401) {
      patch({ kind: 'rejected', reason: 'denied' });
      await refresh(); // the session ended: SignedIn sends the person to sign in
      return;
    }
    if (result.status === 403) patch({ kind: 'rejected', reason: 'denied' });
    else patch({ kind: 'rejected', reason: commonReason(result.status) });
  }

  return {
    open,
    show,
    dismiss: () => setOpen(null),
    submitPassword: ({ password }) => {
      patch({ kind: 'submitting' });
      void sec.stepUpPassword(password).then(finish);
    },
    submitTotp: ({ password, code, authenticatorId }) => {
      patch({ kind: 'submitting' });
      void sec.stepUpTotp(password, code, authenticatorId).then(finish);
    },
    startKey: () => {
      patch({ kind: 'webauthn_waiting' });
      void (async () => {
        const begun = await sec.stepUpKeyBegin();
        if (!begun.ok) {
          await finish(begun);
          return;
        }
        const key = await getCredential(begun.data.options);
        if (!key.ok) {
          patch({ kind: 'rejected', reason: key.reason === 'webauthn_cancelled' ? 'webauthn_cancelled' : 'denied' });
          return;
        }
        await finish(await sec.stepUpKeyFinish(begun.data.id, key.response));
      })();
    },
    choose: (method) => setOpen((current) => (current === null ? current : { ...current, method, state: { kind: 'idle' } })),
  };
}

export function StepUpGate({ controls, view }: { controls: StepUpControls; view: SessionView }) {
  const { open } = controls;
  if (open === null) return null;
  const methods: readonly StepUpMethodName[] = view.stepUpMethods;
  return (
    <StepUpPanel
      method={open.method}
      actionLabel={open.action}
      state={open.state}
      username={view.username}
      totpFactors={view.totpFactors.map((factor, index) => ({ id: factor.id, label: `Authenticator app ${index + 1}` }))}
      methods={methods}
      onChooseMethod={controls.choose}
      onSubmitPassword={controls.submitPassword}
      onSubmitTotp={controls.submitTotp}
      onStartWebAuthn={controls.startKey}
      onDismiss={controls.dismiss}
    />
  );
}
