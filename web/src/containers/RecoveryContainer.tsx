import { useEffect, useRef, useState } from 'react';
import { RecoveryApi, type RecoveryStart } from '../api/security';
import { createCredential } from '../api/webauthn';
import type { RestrictedRecoveryState, TotpEnrollState, WebAuthnRegisterState } from '../screens/contract';
import { HostRecoveryHelp, RestrictedRecovery } from '../screens/factors';
import { CenteredFrame, Skeleton } from '../ui';
import { commonReason } from '../api/http';

/**
 * Restricted recovery (P1.16.4): a still-valid password plus ONE saved code yields a ten-minute
 * re-enrolment capability (the server's `__Host-` cookie) and one replacement saved code. It is never a
 * session. The page:
 *  - shows the replacement code ONCE, in the only state that holds it, and drops it when hidden;
 *  - shows the new authenticator's seed ONCE, likewise;
 *  - treats every refusal of the first step as one outcome (no account signal);
 *  - ends in "go to sign in": completing recovery issues no session and the page never claims one.
 */

const TICK_MS = 15_000;

type Stage = { kind: 'checking' } | { kind: 'form'; state: RestrictedRecoveryState } | { kind: 'capability'; start: RecoveryStart } | { kind: 'completed' };

function minutesLeft(expiresAt: number, nowMs: number): number {
  return Math.max(0, Math.floor((expiresAt * 1000 - nowMs) / 60_000));
}

export function RecoveryContainer({ api: injected }: { api?: RecoveryApi }) {
  const [api] = useState(() => injected ?? new RecoveryApi());
  const [stage, setStage] = useState<Stage>({ kind: 'checking' });
  const [totp, setTotp] = useState<TotpEnrollState>({ kind: 'not_started' });
  const [key, setKey] = useState<WebAuthnRegisterState>({ kind: 'idle' });
  const [replacement, setReplacement] = useState<string | undefined>(undefined);
  const [now, setNow] = useState(() => Date.now());
  const pending = useRef('');
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    // A capability may already be live (reload): resume it. The replacement code is never shown again.
    void api.state().then((result) => {
      if (!mounted.current) return;
      if (result.ok) {
        setReplacement(undefined);
        setStage({ kind: 'capability', start: result.data });
      } else setStage({ kind: 'form', state: { kind: 'idle' } });
    });
    return () => {
      mounted.current = false;
    };
  }, [api]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(timer);
  }, []);

  function start(values: { username: string; password: string; code: string }) {
    setStage({ kind: 'form', state: { kind: 'submitting' } });
    void api.start(values.username, values.password, values.code).then((result) => {
      if (!mounted.current) return;
      if (result.ok) {
        setReplacement(result.data.replacementCode);
        setNow(Date.now());
        setStage({ kind: 'capability', start: { expiresAt: result.data.expiresAt, methods: result.data.methods } });
        return;
      }
      // Unknown user, wrong password, wrong or used code and a throttle are ONE outcome.
      setStage({ kind: 'form', state: { kind: 'rejected', reason: result.status === 403 ? 'denied' : commonReason(result.status) } });
    });
  }

  function endCapability() {
    // The capability ended (ten minutes, or the server discarded it): start again from the form.
    api.forget();
    setTotp({ kind: 'not_started' });
    setKey({ kind: 'idle' });
    setReplacement(undefined);
    setStage({ kind: 'form', state: { kind: 'expired' } });
  }

  function beginTotp() {
    setTotp({ kind: 'starting' });
    void api.beginTotp().then((result) => {
      if (!mounted.current) return;
      if (result.ok) {
        pending.current = result.data.authenticatorId;
        setTotp({ kind: 'seed_shown', seed: result.data.seed });
      } else if (result.status === 401) endCapability();
      else setTotp({ kind: 'rejected', reason: 'unavailable', seed: '' });
    });
  }

  function confirmTotp(code: string) {
    const seed = totp.kind === 'seed_shown' || totp.kind === 'confirming' || totp.kind === 'rejected' ? totp.seed : '';
    if (seed === '') {
      setTotp({ kind: 'not_started' });
      return;
    }
    setTotp({ kind: 'confirming', seed });
    void api.confirmTotp(pending.current, code).then((result) => {
      if (!mounted.current) return;
      if (result.ok) {
        pending.current = '';
        setTotp({ kind: 'proven' }); // the seed leaves the page here
        api.forget();
        setStage({ kind: 'completed' });
      } else if (result.status === 401) endCapability();
      else setTotp({ kind: 'rejected', reason: result.status === 403 ? 'wrong_code' : commonReason(result.status), seed });
    });
  }

  function registerKey() {
    setKey({ kind: 'waiting' });
    void (async () => {
      const begun = await api.keyBegin();
      if (!mounted.current) return;
      if (!begun.ok) {
        if (begun.status === 401) endCapability();
        else setKey({ kind: 'rejected', reason: begun.status === 403 ? 'denied' : commonReason(begun.status) });
        return;
      }
      const created = await createCredential(begun.data.options);
      if (!created.ok) {
        setKey({ kind: 'rejected', reason: created.reason });
        return;
      }
      const finished = await api.keyFinish(begun.data.id, created.response);
      if (!mounted.current) return;
      if (finished.ok) {
        api.forget();
        setStage({ kind: 'completed' });
      } else if (finished.status === 401) endCapability();
      else setKey({ kind: 'rejected', reason: finished.status === 403 ? 'denied' : commonReason(finished.status) });
    })();
  }

  // The capability's deadline is the server's; reaching it only changes what is shown (the secrets with it:
  // an expired capability renders the form, so neither the replacement code nor a seed stays on screen).
  const shown: Stage = stage.kind === 'capability' && now >= stage.start.expiresAt * 1000 ? { kind: 'form', state: { kind: 'expired' } } : stage;

  let state: RestrictedRecoveryState;
  switch (shown.kind) {
    case 'form':
      state = shown.state;
      break;
    case 'completed':
      state = { kind: 'completed' };
      break;
    case 'capability':
      state = { kind: 'capability', minutesLeft: minutesLeft(shown.start.expiresAt, now), totp, methods: shown.start.methods, key, ...(replacement === undefined ? {} : { replacementCode: replacement }) };
      break;
    case 'checking':
      return (
        <CenteredFrame>
          <h1 className="sr-only">Recover access to Mandatary</h1>
          <Skeleton label="recovery" lines={3} />
        </CenteredFrame>
      );
  }
  return (
    <CenteredFrame>
      <h1 className="sr-only">Recover access to Mandatary</h1>
      <div className="space-y-5">
        <RestrictedRecovery
          state={state}
          onSubmit={start}
          onBeginTotp={beginTotp}
          onConfirmTotp={confirmTotp}
          onRegisterKey={shown.kind === 'capability' && shown.start.methods.includes('webauthn') ? registerKey : undefined}
          onReplacementHidden={() => setReplacement(undefined)}
          signInHref="/login"
        />
        {shown.kind === 'form' ? <HostRecoveryHelp /> : null}
      </div>
    </CenteredFrame>
  );
}
