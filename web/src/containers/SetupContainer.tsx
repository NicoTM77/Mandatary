import { useEffect, useRef, useState } from 'react';
import { commonReason } from '../api/http';
import { SetupApi, type SetupView } from '../api/setup';
import type { AccountFormState, AccountFormValues, AddressRow, ProofState, SetupClock, SetupCompleteProps, SetupPurpose, SetupExchangeState, TotpEnrollState } from '../screens/contract';
import { deriveSetupClock } from '../screens/clock';
import { SETUP_STEPS, SetupAccount, SetupAddresses, SetupClockNotice, SetupComplete, SetupExchange, TotpEnrollment } from '../screens/setup';
import { Alert, Button, CenteredFrame, Skeleton, Steps } from '../ui';

/**
 * Setup container (P1.16.3). Owns the setup session lifecycle: token exchange, the in-memory CSRF token
 * (inside SetupApi), the fixed deadline timer and every translation from an HTTP outcome to a
 * presentation state (docs/ui §6.1). The screens stay stateless.
 *
 * Secrets: the pasted token and the password are arguments of one API call and are not kept. The TOTP
 * seed lives ONLY in `totp` state while a screen shows it and is dropped when the code is proven, the
 * session ends or the deadline passes. Nothing is written to storage, the URL or the console.
 */

type Stage = { kind: 'loading' } | { kind: 'exchange'; state: SetupExchangeState } | { kind: 'wizard' } | { kind: 'ended' } | { kind: 'unsupported' };

type Step = 'account' | 'addresses' | 'totp' | 'complete';

const MAX_ADDRESSES = 4;
const TICK_MS = 15_000;

function stepFor(view: SetupView): Step {
  if (view.purpose === 'mfa_reset') {
    if (view.replacePassword && !view.accountStaged) return 'account';
    return view.totpProven ? 'complete' : 'totp';
  }
  if (!view.accountStaged) return 'account'; // initial_setup and restore_recovery both enrol a NEW account, address and authenticator
  if (!view.addresses.some((row) => row.confirmed)) return 'addresses';
  return view.totpProven ? 'complete' : 'totp';
}

function totpFor(view: SetupView): TotpEnrollState {
  if (view.totpProven) return { kind: 'proven' };
  // Begun in an earlier page view: the seed is never re-displayed.
  return view.totpBegun ? { kind: 'seed_lost' } : { kind: 'not_started' };
}

export function SetupContainer({ api: injected }: { api?: SetupApi }) {
  const [api] = useState(() => injected ?? new SetupApi());
  const [stage, setStage] = useState<Stage>({ kind: 'loading' });
  const [view, setView] = useState<SetupView | null>(null);
  const [step, setStep] = useState<Step>('account');
  const [account, setAccount] = useState<AccountFormState>({ kind: 'idle' });
  const [proofs, setProofs] = useState<ReadonlyMap<string, ProofState>>(new Map());
  const [totp, setTotp] = useState<TotpEnrollState>({ kind: 'not_started' });
  const [complete, setComplete] = useState<SetupCompleteProps['state']>({ kind: 'idle' });
  const [now, setNow] = useState(() => Date.now());
  const mounted = useRef(true);
  const deadline = useRef(Infinity); // ms; written by handlers, read by the timer
  // The purpose of the last accepted window: the closing screens outlive the view and must still speak for the right ceremony.
  const purposeRef = useRef<SetupPurpose>('initial_setup');

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Resume after a reload: the HttpOnly cookie, not this page, is what keeps the session.
  useEffect(() => {
    let cancelled = false;
    void api.session().then((result) => {
      if (cancelled) return;
      if (result.ok) enter(result.data);
      else if (result.status === 401) setStage({ kind: 'exchange', state: { kind: 'idle' } });
      else if (result.status === 404) setStage({ kind: 'exchange', state: { kind: 'closed' } });
      else setStage({ kind: 'exchange', state: { kind: 'rejected', reason: commonReason(result.status) } });
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per mount; `enter` only calls state setters
  }, [api]);

  useEffect(() => {
    const timer = setInterval(() => {
      const at = Date.now();
      setNow(at);
      // At the deadline everything secret held by this page is dropped; the server enforces it regardless.
      if (at >= deadline.current) setTotp((current) => (current.kind === 'seed_shown' || current.kind === 'confirming' || current.kind === 'rejected' ? { kind: 'seed_lost' } : current));
    }, TICK_MS);
    return () => clearInterval(timer);
  }, []);

  const clock: SetupClock | null = view ? deriveSetupClock(view.expiresAt, now) : null;
  const expired = clock?.kind === 'expired';

  /** Enters the wizard for a session view (first load, resume after reload, or after the exchange). */
  function enter(next: SetupView) {
    if (next.purpose !== 'initial_setup' && next.purpose !== 'mfa_reset' && next.purpose !== 'restore_recovery') {
      api.forget();
      setStage({ kind: 'unsupported' });
      return;
    }
    purposeRef.current = next.purpose;
    setView(next);
    deadline.current = next.expiresAt * 1000;
    setStep(stepFor(next));
    setTotp(totpFor(next));
    setStage({ kind: 'wizard' });
  }

  function endSession() {
    api.forget();
    setTotp({ kind: 'not_started' }); // drops any seed
    setView(null);
    setStage({ kind: 'ended' });
  }

  async function refresh(): Promise<void> {
    const result = await api.session();
    if (!mounted.current) return;
    if (result.ok) {
      setView(result.data);
      deadline.current = result.data.expiresAt * 1000;
    } else if (result.status === 401) {
      endSession();
    }
  }

  function onExchange({ token }: { token: string }) {
    setStage({ kind: 'exchange', state: { kind: 'submitting' } });
    void api.exchange(token).then((result) => {
      if (!mounted.current) return;
      if (result.ok) {
        enter(result.data);
        return;
      }
      // ONE message for a wrong, expired or replayed token: the server does not distinguish, so neither may the UI.
      if (result.status === 401) setStage({ kind: 'exchange', state: { kind: 'rejected', reason: 'invalid_token' } });
      else if (result.status === 404) setStage({ kind: 'exchange', state: { kind: 'closed' } });
      else setStage({ kind: 'exchange', state: { kind: 'rejected', reason: commonReason(result.status) } });
    });
  }

  function onAccount(values: AccountFormValues) {
    if (!view) return;
    setAccount({ kind: 'submitting' });
    const initial = view.purpose !== 'mfa_reset'; // a new account: first setup or the recovery administrator
    const request = initial ? api.account({ username: values.username, password: values.password, addresses: values.addresses }) : api.account({ password: values.password });
    void request.then(async (result) => {
      if (!mounted.current) return;
      if (result.ok) {
        setAccount({ kind: 'idle' });
        await refresh();
        setStep(initial ? 'addresses' : 'totp');
      } else if (result.status === 422 && result.code === 'password_rejected') {
        setAccount({ kind: 'rejected', reason: 'password_rejected', guidance: result.guidance ?? 'Choose a different password.' });
      } else if (result.status === 401) {
        endSession();
      } else if (result.status === 403 && result.code === 'denied') {
        setAccount({ kind: 'rejected', reason: 'denied' });
      } else {
        setAccount({ kind: 'rejected', reason: commonReason(result.status) });
      }
    });
  }

  function setProof(id: string, state: ProofState) {
    setProofs((current) => new Map(current).set(id, state));
  }

  function onSendProof(id: string) {
    setProof(id, { kind: 'sending' });
    void api.sendProof(id).then((result) => {
      if (!mounted.current) return;
      if (result.ok) setProof(id, { kind: 'sent' });
      else if (result.status === 401) endSession();
      // A refused send (resend interval, proof budget, unknown address) is one outcome: wait, then retry.
      else setProof(id, { kind: 'error', reason: result.status === 403 ? 'rate_limited' : commonReason(result.status) });
    });
  }

  function onConfirm(id: string, code: string) {
    setProof(id, { kind: 'confirming' });
    void api.confirmAddress(id, code).then(async (result) => {
      if (!mounted.current) return;
      if (result.ok) {
        setProof(id, { kind: 'idle' });
        await refresh();
      } else if (result.status === 401) {
        endSession();
      } else {
        // The server cannot say "wrong code" apart from any other denial; the copy covers both.
        setProof(id, { kind: 'error', reason: result.status === 403 ? 'wrong_code' : commonReason(result.status) });
      }
    });
  }

  function onBegin() {
    setTotp({ kind: 'starting' });
    void api.beginTotp().then((result) => {
      if (!mounted.current) return;
      if (result.ok) setTotp({ kind: 'seed_shown', seed: result.data.secret });
      else if (result.status === 401) endSession();
      // One enrolment per session: a refusal here means it was already begun and the seed cannot be shown again.
      else if (result.status === 403) setTotp({ kind: 'seed_lost' });
      else setTotp({ kind: 'not_started' });
    });
  }

  function onConfirmTotp(code: string) {
    setTotp((current) => (current.kind === 'seed_shown' || current.kind === 'rejected' ? { kind: 'confirming', seed: current.seed } : current));
    void api.confirmTotp(code).then(async (result) => {
      if (!mounted.current) return;
      if (result.ok) {
        setTotp({ kind: 'proven' }); // the seed leaves state here; the person continues from the confirmation
        await refresh();
      } else if (result.status === 401) {
        endSession();
      } else {
        setTotp((current) => (current.kind === 'confirming' ? { kind: 'rejected', reason: result.status === 403 ? 'wrong_code' : commonReason(result.status), seed: current.seed } : current));
      }
    });
  }

  function onComplete() {
    setComplete({ kind: 'submitting' });
    void api.complete().then((result) => {
      if (!mounted.current) return;
      if (result.ok) {
        api.forget(); // the server cleared the setup cookie; no session was issued
        setView(null);
        setComplete({ kind: 'done', username: result.data.username });
      } else if (result.status === 401) {
        endSession();
      } else {
        setComplete({ kind: 'rejected', reason: result.status === 403 ? 'denied' : commonReason(result.status) });
      }
    });
  }

  const frame = (children: React.ReactNode) => (
    <CenteredFrame width="max-w-xl">
      <h1 className="sr-only">{purposeRef.current === 'restore_recovery' ? 'Restore recovery' : 'First-time setup'}</h1>
      <div className="space-y-5">{children}</div>
    </CenteredFrame>
  );

  if (complete.kind === 'done') {
    return frame(<SetupComplete accountStaged confirmedAddressCount={0} totpProven state={complete} onComplete={() => undefined} signInHref="/login" purpose={purposeRef.current} />);
  }
  if (stage.kind === 'loading') return frame(<Skeleton label="setup" lines={3} />);
  if (stage.kind === 'exchange') return frame(<SetupExchange state={stage.state} onSubmit={onExchange} />);
  if (stage.kind === 'unsupported') {
    return frame(
      <Alert tone="info" role="none" title="This setup window can’t be used here">
        It was issued for a different purpose. Ask the host operator to check <code className="font-mono">mandatary setup status</code>.
      </Alert>,
    );
  }
  if (stage.kind === 'ended' || !view || !clock) {
    return frame(
      <>
        <SetupClockNotice clock={{ kind: 'expired' }} purpose={purposeRef.current} />
        <Button onClick={() => globalThis.location.reload()}>Enter a new token</Button>
      </>,
    );
  }
  if (expired) {
    return frame(
      <>
        <SetupClockNotice clock={clock} purpose={purposeRef.current} />
        <Button onClick={() => globalThis.location.reload()}>Enter a new token</Button>
      </>,
    );
  }

  const initial = view.purpose !== 'mfa_reset';
  const steps = initial ? SETUP_STEPS : SETUP_STEPS.filter((item) => item.id !== 'addresses' && (item.id !== 'account' || view.replacePassword));
  const rows: AddressRow[] = view.addresses.map((row) => ({ id: row.id, address: row.address, confirmed: row.confirmed, proof: proofs.get(row.id) ?? { kind: 'idle' } }));
  const confirmed = rows.filter((row) => row.confirmed).length;
  const current = step === 'complete' ? 'complete' : step;

  return frame(
    <>
      <Steps steps={steps} currentId={current} />
      <SetupClockNotice clock={clock} purpose={purposeRef.current} />
      {step === 'account' ? (
        <SetupAccount purpose={view.purpose === 'mfa_reset' ? 'mfa_reset' : view.purpose === 'restore_recovery' ? 'restore_recovery' : 'initial_setup'} targetUser={view.targetUser} replacePassword={view.replacePassword} mailConfigured={view.mailConfigured} maxAddresses={MAX_ADDRESSES} state={account} onSubmit={onAccount} />
      ) : null}
      {step === 'addresses' ? (
        <>
          <SetupAddresses addresses={rows} mailConfigured={view.mailConfigured} onSendProof={onSendProof} onConfirm={onConfirm} />
          <Button className="w-full" disabled={confirmed === 0} onClick={() => setStep('totp')}>
            Continue
          </Button>
        </>
      ) : null}
      {step === 'totp' ? (
        <>
          <TotpEnrollment state={totp} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={onBegin} onConfirm={onConfirmTotp} />
          {totp.kind === 'proven' ? (
            <Button className="w-full" onClick={() => setStep('complete')}>
              Continue
            </Button>
          ) : null}
        </>
      ) : null}
      {step === 'complete' ? <SetupComplete accountStaged={view.accountStaged || view.purpose === 'mfa_reset'} confirmedAddressCount={confirmed} totpProven={totp.kind === 'proven' || view.totpProven} state={complete} onComplete={onComplete} signInHref="/login" purpose={purposeRef.current} /> : null}
    </>,
  );
}
