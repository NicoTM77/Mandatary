import { useEffect, useMemo, useRef, useState } from 'react';
import type { AccountApi } from '../api/account';
import { commonReason, type ApiResult } from '../api/http';
import { SecurityApi, type Inventory } from '../api/security';
import { createCredential } from '../api/webauthn';
import type { AddressListState, ManagedAddress, NoticeHealthView, RecoveryCodesState, TotpEnrollState, WebAuthnRegisterState } from '../screens/contract';
import { AddressManagement, NoticeHealth } from '../screens/notices';
import { RecoveryCodes, SignInMethods } from '../screens/factors';
import { TotpEnrollment } from '../screens/setup';
import { formatDate } from '../ui/format';
import { Alert, Button, PageHeader, Skeleton } from '../ui';
import { WebAuthnRegister } from '../screens/factors';
import type { Navigate } from './LoginContainer';
import { outcomeOf, failureReason, type Outcome } from './outcome';
import { SignedIn, type SignedInContext } from './SignedIn';
import { StepUpGate, useStepUp } from './StepUpGate';

/**
 * Account security page (P1.16.4): notice health, sign-in methods (authenticator apps and security keys),
 * recovery codes and notification addresses, against the real services through the Browser boundary.
 *
 * Authority is the server's: every mutation is class-gated before the service runs (403 step_up_required →
 * the in-place step-up panel, 403 assurance_unavailable → the no-retry state). The page never decides what
 * is allowed; it hides nothing the server would allow and offers nothing it can know the server refuses.
 *
 * Secrets live ONLY in the state that shows them and are dropped the moment that state is left: the TOTP
 * seed (`totp.seed`) and the ten recovery codes (`codes.codes`). A step-up, a removal, a reload or a
 * session end discards them (a reload shows `seed_lost`-style absence, never the value).
 */

const TOTP_ALGORITHM_LABELS: Readonly<Record<string, string>> = { SHA256: 'SHA-256', SHA1: 'SHA-1' };

type Codes = { kind: 'idle' } | { kind: 'working' } | { kind: 'confirming' } | { kind: 'reveal'; codes: readonly string[] } | { kind: 'rejected'; reason: 'denied' | 'rate_limited' | 'unavailable' | 'invalid_request' };

type Banner = { tone: 'warning' | 'danger' | 'success'; title: string; body: string } | null;

function noticeView(inv: Inventory): NoticeHealthView {
  return { ...inv.notices };
}

export function SecurityContainer({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="security">
      {(context) => <SecurityPage {...context} />}
    </SignedIn>
  );
}

function SecurityPage({ api, view, navigate, refresh }: SignedInContext) {
  const sec = useMemo(() => new SecurityApi(api), [api]);
  const [inv, setInv] = useState<Inventory | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  // The server withholds the inventory from a session that lacks the authority to see it (password only).
  const [withheld, setWithheld] = useState(false);
  const [banner, setBanner] = useState<Banner>(null);
  const [gone, setGone] = useState<string | null>(null);

  const [totp, setTotp] = useState<TotpEnrollState>({ kind: 'not_started' });
  const [totpMeta, setTotpMeta] = useState({ id: '', algorithmLabel: 'SHA-256', digits: 6, period: 30 });
  const [removal, setRemoval] = useState<{ kind: 'totp' | 'webauthn'; id: string } | undefined>(undefined);
  const [removing, setRemoving] = useState(false);
  // AUTH-08-L4: the inventory is re-read when a removal is asked for, so the warning reflects the account's current methods and not a stale page.
  const [removalCheck, setRemovalCheck] = useState<'checking' | 'fresh' | 'failed'>('fresh');
  const removalAsk = useRef(0);
  const [key, setKey] = useState<WebAuthnRegisterState>({ kind: 'idle' });
  const [codes, setCodes] = useState<Codes>({ kind: 'idle' });
  const [addr, setAddr] = useState<AddressListState>({ kind: 'idle' });
  const pendingAddress = useRef({ id: '', address: '' });

  function load() {
    void sec.inventory().then((result) => {
      if (result.ok) {
        setInv(result.data);
        setLoadFailed(false);
        setWithheld(false);
      } else if (result.status === 401) navigate('/login');
      else if (result.status === 403) setWithheld(true);
      else setLoadFailed(true);
    });
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- load once per mount
  }, []);

  /** Drops every pending ceremony and every revealed secret: they belong to the session being replaced. */
  function discardCeremonies() {
    setTotpMeta((meta) => ({ ...meta, id: '' }));
    setTotp({ kind: 'not_started' });
    setKey({ kind: 'idle' });
    setCodes({ kind: 'idle' });
    setAddr({ kind: 'idle' });
    setRemoval(undefined);
    pendingAddress.current = { id: '', address: '' };
  }

  const stepUp = useStepUp(sec, view, refresh, discardCeremonies, load);

  /** Interprets a failed result shared by every action; returns the outcome only when the caller must show a form-level reason. */
  function route(action: string, outcome: Outcome): Outcome | null {
    switch (outcome.kind) {
      case 'ended':
        navigate('/login');
        return null;
      case 'step_up':
        stepUp.show(action);
        return null;
      case 'assurance_unavailable':
        stepUp.show(action, true);
        return null;
      default:
        return outcome;
    }
  }

  // ───────────── authenticator app ─────────────

  function addTotp() {
    setBanner(null);
    setTotp({ kind: 'starting' });
    void sec.beginTotp().then((result) => {
      if (result.ok) {
        setTotpMeta({ id: result.data.authenticatorId, algorithmLabel: TOTP_ALGORITHM_LABELS[result.data.algorithm] ?? result.data.algorithm, digits: result.data.digits, period: result.data.period });
        setTotp({ kind: 'seed_shown', seed: result.data.seed });
        return;
      }
      setTotp({ kind: 'not_started' });
      const rest = route('Add an authenticator app', outcomeOf(result));
      if (rest) setBanner({ tone: 'danger', title: 'The authenticator app wasn’t added', body: 'Nothing was changed. Verify again or try again in a moment.' });
    });
  }

  function confirmTotp(code: string) {
    const seed = totp.kind === 'seed_shown' || totp.kind === 'confirming' || totp.kind === 'rejected' ? totp.seed : '';
    if (seed === '') return;
    setTotp({ kind: 'confirming', seed });
    void sec.confirmTotp(totpMeta.id, code).then((result) => {
      if (result.ok) {
        setTotpMeta((meta) => ({ ...meta, id: '' }));
        setTotp({ kind: 'proven' }); // the seed leaves the page here
        load();
        return;
      }
      const rest = route('Add an authenticator app', outcomeOf(result));
      if (rest) setTotp({ kind: 'rejected', reason: rest.kind === 'common' ? rest.reason : 'wrong_code', seed });
    });
  }

  // ───────────── removal (authenticator app or security key) ─────────────

  function confirmRemoval() {
    if (!removal) return;
    setRemoving(true);
    const call: Promise<ApiResult<null>> = removal.kind === 'totp' ? sec.removeTotp(removal.id) : sec.removeKey(removal.id);
    void call.then((result) => {
      setRemoving(false);
      if (result.ok) {
        // The server ended EVERY session of the account in the same transaction.
        api.forget();
        setGone('removed');
        return;
      }
      const rest = route('Remove a sign-in method', outcomeOf(result));
      if (rest) {
        setRemoval(undefined);
        setBanner({
          tone: 'danger',
          title: 'The sign-in method wasn’t removed',
          body: rest.kind === 'denied' ? 'It may be the last second factor this account is required to keep, or it no longer exists. Nothing was changed.' : 'Nothing was changed. Try again in a moment.',
        });
      }
    });
  }

  // ───────────── security key ─────────────

  function addKey() {
    setBanner(null);
    setKey({ kind: 'waiting' });
    void (async () => {
      const begun = await sec.keyBegin();
      if (!begun.ok) {
        const rest = route('Add a security key', outcomeOf(begun));
        setKey(rest ? { kind: 'rejected', reason: rest.kind === 'common' ? rest.reason : 'denied' } : { kind: 'idle' });
        return;
      }
      const created = await createCredential(begun.data.options);
      if (!created.ok) {
        setKey({ kind: 'rejected', reason: created.reason });
        return;
      }
      const finished = await sec.keyFinish(begun.data.id, created.response);
      if (finished.ok) {
        setKey({ kind: 'registered' });
        load();
        return;
      }
      const rest = route('Add a security key', outcomeOf(finished));
      setKey(rest ? { kind: 'rejected', reason: rest.kind === 'common' ? rest.reason : 'denied' } : { kind: 'idle' });
    })();
  }

  // ───────────── recovery codes ─────────────

  function issueCodes() {
    setBanner(null);
    setCodes({ kind: 'working' });
    void sec.issueCodes().then((result) => {
      if (result.ok) {
        setCodes({ kind: 'reveal', codes: result.data });
        return;
      }
      const rest = route('Create recovery codes', outcomeOf(result));
      setCodes(rest ? { kind: 'rejected', reason: failureReason(rest) } : { kind: 'idle' });
    });
  }

  function hideCodes() {
    setCodes({ kind: 'idle' }); // the codes leave the page here and cannot be fetched again
    load();
  }

  // ───────────── notification addresses ─────────────

  function addressFailure(rest: Outcome): 'denied' | 'rate_limited' | 'unavailable' | 'invalid_request' {
    return failureReason(rest);
  }

  async function sendCode(id: string, address: string): Promise<boolean> {
    const result = await sec.sendAddressProof(id);
    if (result.ok) {
      pendingAddress.current = { id, address };
      setAddr({ kind: 'adding', step: 'proof', pendingAddress: address });
      return true;
    }
    const rest = route('Confirm a notification address', outcomeOf(result));
    if (rest) setAddr({ kind: 'rejected', reason: rest.kind === 'denied' ? 'denied' : addressFailure(rest) });
    return false;
  }

  function submitAddress({ address }: { address: string }) {
    setAddr({ kind: 'adding', step: 'enter', busy: true });
    void sec.addAddress(address).then(async (result) => {
      if (!result.ok) {
        const rest = route('Add a notification address', outcomeOf(result));
        setAddr(rest ? { kind: 'adding', step: 'enter', error: addressFailure(rest) } : { kind: 'idle' });
        return;
      }
      load();
      // The address is staged and unused until its proof is entered.
      await sendCode(result.data, address);
    });
  }

  function submitProof({ code }: { code: string }) {
    const { id, address } = pendingAddress.current;
    if (id === '') return;
    setAddr({ kind: 'adding', step: 'proof', pendingAddress: address, busy: true });
    void sec.confirmAddress(id, code).then((result) => {
      if (result.ok) {
        pendingAddress.current = { id: '', address: '' };
        setAddr({ kind: 'idle' });
        load();
        return;
      }
      const rest = route('Confirm a notification address', outcomeOf(result));
      // The server cannot tell a wrong code from any other refusal, and neither may the page.
      if (rest) setAddr({ kind: 'adding', step: 'proof', pendingAddress: address, error: rest.kind === 'denied' ? 'wrong_code' : addressFailure(rest) });
    });
  }

  function confirmAddressRemoval() {
    if (addr.kind !== 'confirming_removal') return;
    const id = addr.id;
    setAddr({ kind: 'confirming_removal', id, busy: true });
    void sec.removeAddress(id).then((result) => {
      if (result.ok) {
        setAddr({ kind: 'idle' });
        load();
        return;
      }
      const rest = route('Remove a notification address', outcomeOf(result));
      if (rest) setAddr({ kind: 'rejected', reason: addressFailure(rest) });
    });
  }

  // ───────────── render ─────────────

  if (gone !== null) {
    return (
      <div className="space-y-4">
        <PageHeader title="Account security" />
        <Alert tone="success" role="status" title="Sign-in method removed" actions={<Button onClick={() => navigate('/login')}>Sign in</Button>}>
          For your security every session for this account ended, including this one. Your other notification addresses were told. Sign in again with a method you still have.
        </Alert>
      </div>
    );
  }
  if (inv === null) {
    return (
      <div className="space-y-4">
        <PageHeader title="Account security" description="Sign-in methods, recovery codes and notification addresses." />
        <StepUpGate controls={stepUp} view={view} />
        {withheld ? (
          <Alert
            tone="warning"
            role="alert"
            title="This session can’t show your security settings"
            actions={
              stepUp.open === null ? (
                <Button onClick={() => stepUp.show('View your security settings', view.stepUpMethods.length === 0)}>Verify to continue</Button>
              ) : undefined
            }
          >
            You signed in with a password only. Verify with your second factor to see and change sign-in methods, recovery codes and notification addresses.
          </Alert>
        ) : loadFailed ? (
          <Alert
            tone="danger"
            title="Couldn’t load your security settings"
            actions={
              <Button
                onClick={() => {
                  setLoadFailed(false);
                  load();
                }}
              >
                Try again
              </Button>
            }
          >
            Nothing was changed. Try again in a moment.
          </Alert>
        ) : (
          <Skeleton label="your security settings" lines={4} />
        )}
      </div>
    );
  }

  const confirmedCount = inv.addresses.filter((row) => row.confirmed).length;
  const addresses: ManagedAddress[] = inv.addresses.map((row) => ({ id: row.id, address: row.address, status: row.confirmed ? 'confirmed' : 'unconfirmed' }));
  const codesState: RecoveryCodesState =
    codes.kind === 'idle' ? (inv.recoveryRemaining > 0 ? { kind: 'issued', remaining: inv.recoveryRemaining } : { kind: 'none' }) : codes.kind === 'confirming' ? { kind: 'confirming_regenerate', remaining: inv.recoveryRemaining } : codes;

  return (
    <div className="space-y-5">
      <PageHeader title="Account security" description="Sign-in methods, recovery codes and notification addresses. Changes need a recent verification." />
      {view.assurance === 'password-only' ? (
        <Alert tone="warning" role="none" title="This is a password-only session">
          Password-only sessions can’t change security settings. Sign out and sign in again with your second factor.
        </Alert>
      ) : null}
      <StepUpGate controls={stepUp} view={view} />
      {banner ? (
        <Alert tone={banner.tone} title={banner.title}>
          {banner.body}
        </Alert>
      ) : null}
      <NoticeHealth health={noticeView(inv)} />
      {totp.kind !== 'not_started' ? <TotpEnrollment state={totp} algorithmLabel={totpMeta.algorithmLabel} digits={totpMeta.digits} periodSeconds={totpMeta.period} onBegin={addTotp} onConfirm={confirmTotp} /> : null}
      {key.kind !== 'idle' ? <WebAuthnRegister state={key} onSubmit={addKey} /> : null}
      <SignInMethods
        totp={inv.totp.map((row, index) => ({ id: row.id, label: `Authenticator app ${index + 1}`, addedOn: formatDate(row.addedAt), status: row.status }))}
        keys={inv.keys.map((row, index) => ({ id: row.id, name: `Security key ${index + 1}`, addedOn: formatDate(row.addedAt) }))}
        maxKeys={inv.maxKeys}
        keysSupported={inv.webauthnAvailable}
        confirmingRemoval={removal}
        removing={removing}
        onAddTotp={addTotp}
        onAddKey={addKey}
        recoveryRemaining={inv.recoveryRemaining}
        removalCheck={removalCheck}
        onAskRemove={(kind, id) => {
          setBanner(null);
          setRemoval({ kind, id });
          setRemovalCheck('checking');
          const ticket = ++removalAsk.current;
          void sec.inventory().then((result) => {
            if (ticket !== removalAsk.current) return; // a newer ask or a cancel superseded this read
            if (result.ok) {
              setInv(result.data);
              const stillThere = kind === 'totp' ? result.data.totp.some((row) => row.id === id) : result.data.keys.some((row) => row.id === id);
              if (!stillThere) {
                // Stale page: the method is already gone. Nothing is removed and the person is told.
                setRemoval(undefined);
                setBanner({ tone: 'warning', title: 'That sign-in method is already gone', body: 'The list has been refreshed. Nothing was changed.' });
                return;
              }
              setRemovalCheck('fresh');
            } else if (result.status === 401) navigate('/login');
            else setRemovalCheck('failed');
          });
        }}
        onCancelRemove={() => {
          removalAsk.current++;
          setRemoval(undefined);
        }}
        onConfirmRemove={confirmRemoval}
      />
      <RecoveryCodes
        state={codesState}
        onIssue={issueCodes}
        onAskRegenerate={() => setCodes({ kind: 'confirming' })}
        onCancelRegenerate={() => setCodes({ kind: 'idle' })}
        onConfirmRegenerate={issueCodes}
        onHidden={hideCodes}
      />
      <AddressManagement
        addresses={addresses}
        maxAddresses={inv.maxAddresses}
        state={addr}
        mailConfigured
        onStartAdd={() => {
          setBanner(null);
          setAddr({ kind: 'adding', step: 'enter' });
        }}
        onSubmitAddress={submitAddress}
        onSubmitProof={submitProof}
        onCancelAdd={() => {
          pendingAddress.current = { id: '', address: '' };
          setAddr({ kind: 'idle' });
        }}
        onAskRemove={(id) => setAddr({ kind: 'confirming_removal', id })}
        onCancelRemove={() => setAddr({ kind: 'idle' })}
        onConfirmRemove={confirmAddressRemoval}
        onSendCode={(id) => {
          const row = inv.addresses.find((candidate) => candidate.id === id);
          if (row) void sendCode(id, row.address);
        }}
      />
      {confirmedCount === 0 ? (
        <Alert tone="danger" title="No confirmed notification address">
          Security notices have nowhere to go. Confirm an address above.
        </Alert>
      ) : null}
    </div>
  );
}

export { commonReason };
