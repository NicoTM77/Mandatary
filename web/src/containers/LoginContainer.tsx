import { useEffect, useRef, useState } from 'react';
import { AccountApi, type TotpChoice } from '../api/account';
import { commonReason } from '../api/http';
import { getCredential } from '../api/webauthn';
import type { LoginFactorState, LoginMethod, LoginState } from '../screens/contract';
import { LoginFactor, LoginPassword } from '../screens/login';
import { CenteredFrame } from '../ui';

/**
 * Login container (P1.16.3): password step, then the factor the SERVER listed, then a full-page
 * navigation to the application home. A full navigation (not a client-side route change) discards the
 * password field and every in-memory token with the page.
 *
 * Outcome handling is the only place an HTTP status is interpreted (docs/ui §6.2):
 *  - password step 401, and every refusal behind it, is ONE `denied` outcome (no account signal);
 *  - factor step 401 means the five-minute capability ended (cookie cleared by the server) → `expired`;
 *  - factor step 403 is a refused code (wrong, replayed, throttled and exhausted look identical);
 *  - `no-mfa` is offered only when the server listed it, and the server re-checks policy on the call.
 */

const PREAUTH_MS = 5 * 60 * 1000;

export type Navigate = (path: string) => void;
export const defaultNavigate: Navigate = (path) => globalThis.location.assign(path);

type Next = ReadonlyArray<'totp' | 'webauthn' | 'no-mfa'>;

export function LoginContainer({ api: injected, navigate = defaultNavigate }: { api?: AccountApi; navigate?: Navigate }) {
  const [api] = useState(() => injected ?? new AccountApi());
  const [step, setStep] = useState<'password' | 'factor'>('password');
  const [password, setPassword] = useState<LoginState>({ kind: 'idle' });
  const [factor, setFactor] = useState<LoginFactorState>({ kind: 'idle' });
  const [next, setNext] = useState<Next>([]);
  const [totpFactors, setTotpFactors] = useState<readonly TotpChoice[]>([]);
  const [method, setMethod] = useState<LoginMethod>('totp');
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // The capability lives five minutes on the server; this timer only changes what is displayed.
  useEffect(() => {
    if (step !== 'factor') return;
    const timer = setTimeout(() => setFactor({ kind: 'expired' }), PREAUTH_MS);
    return () => clearTimeout(timer);
  }, [step]);

  function restart() {
    api.forget();
    setNext([]);
    setPassword({ kind: 'idle' });
    setFactor({ kind: 'idle' });
    setStep('password');
  }

  function onPassword(values: { username: string; password: string }) {
    setPassword({ kind: 'submitting' });
    void api.login(values.username, values.password).then((result) => {
      if (!mounted.current) return;
      if (!result.ok) {
        if (result.status === 401) setPassword({ kind: 'rejected', reason: 'denied' });
        else setPassword({ kind: 'rejected', reason: commonReason(result.status) });
        return;
      }
      if (result.data.step === 'session') {
        navigate('/');
        return;
      }
      const offered = result.data.next;
      if (!offered.includes('totp') && !offered.includes('webauthn')) {
        // The server listed nothing this page understands: finish nothing, never guess.
        api.forget();
        setPassword({ kind: 'rejected', reason: 'unavailable' });
        return;
      }
      setNext(offered);
      setTotpFactors(result.data.totpFactors);
      setMethod(offered.includes('totp') ? 'totp' : 'webauthn');
      setFactor({ kind: 'idle' });
      setPassword({ kind: 'idle' });
      setStep('factor');
    });
  }

  function failFactor(status: number, refused: 'denied' | 'password_only_refused') {
    if (status === 401) setFactor({ kind: 'expired' });
    else if (status === 403) setFactor({ kind: 'rejected', reason: refused });
    else setFactor({ kind: 'rejected', reason: commonReason(status) });
  }

  function onTotp({ code, authenticatorId }: { code: string; authenticatorId?: string }) {
    setFactor({ kind: 'submitting' });
    void api.loginTotp(code, authenticatorId).then((result) => {
      if (!mounted.current) return;
      if (result.ok) navigate('/');
      else failFactor(result.status, 'denied');
    });
  }

  /** Security-key sign-in: the server issues the ceremony for THIS preauth and verifies the signed result (UV required). */
  function onWebAuthn() {
    setFactor({ kind: 'webauthn_waiting' });
    void (async () => {
      const begun = await api.loginKeyBegin();
      if (!mounted.current) return;
      if (!begun.ok) {
        // 404/409: this installation has no security-key service for this page; 401: the capability ended.
        if (begun.status === 404 || begun.status === 405) setFactor({ kind: 'rejected', reason: 'webauthn_unsupported' });
        else failFactor(begun.status, 'denied');
        return;
      }
      const key = await getCredential(begun.data.options);
      if (!mounted.current) return;
      if (!key.ok) {
        setFactor({ kind: 'rejected', reason: key.reason === 'insecure_context' ? 'webauthn_unsupported' : key.reason });
        return;
      }
      const finished = await api.loginKeyFinish(begun.data.id, key.response);
      if (!mounted.current) return;
      if (finished.ok) navigate('/');
      else failFactor(finished.status, 'denied');
    })();
  }

  function onPasswordOnly() {
    setFactor({ kind: 'submitting' });
    void api.loginNoMfa().then((result) => {
      if (!mounted.current) return;
      if (result.ok) navigate('/');
      else failFactor(result.status, 'password_only_refused');
    });
  }

  return (
    <CenteredFrame>
      <h1 className="sr-only">Sign in to Mandatary</h1>
      {step === 'password' ? (
        <LoginPassword state={password} onSubmit={onPassword} recoveryHref="/recovery" />
      ) : (
        <LoginFactor
          next={next}
          method={method}
          state={factor}
          totpFactors={totpFactors.map((candidate, index) => ({ id: candidate.id, label: `Authenticator app ${index + 1}` }))}
          onChooseMethod={(chosen) => {
            setMethod(chosen);
            setFactor({ kind: 'idle' });
          }}
          onSubmitTotp={onTotp}
          onStartWebAuthn={onWebAuthn}
          onContinuePasswordOnly={next.includes('no-mfa') ? onPasswordOnly : undefined}
          onRestart={restart}
        />
      )}
    </CenteredFrame>
  );
}
