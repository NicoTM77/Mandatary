import { useEffect, useRef, useState } from 'react';
import { AccountApi, type SessionView } from '../api/account';
import { formatDate } from '../ui/format';
import { AdminShell, Alert, Button, DetailRow, PageHeader, Panel, Skeleton, type NavItem } from '../ui';
import { defaultNavigate, type Navigate } from './LoginContainer';

/**
 * Signed-in home (P1.16.3). Everything shown comes from GET /api/v1/session (the server's own labels):
 * the page never computes, upgrades or stores an assurance. A 401 anywhere means the session ended
 * (idle, absolute, logout elsewhere, policy change) and is shown as such; a logout the server did not
 * confirm is never presented as done.
 */

const NAV: readonly NavItem[] = [{ id: 'overview', label: 'Overview', href: '/' }];
const TICK_MS = 30_000;

const METHOD_LABELS: ReadonlyMap<string, string> = new Map([
  ['password', 'Password'],
  ['totp', 'Authenticator app'],
  ['webauthn', 'Security key'],
  ['webauthn-uv', 'Security key with verification'],
]);

function methodText(methods: readonly string[]): string {
  return methods.map((method) => METHOD_LABELS.get(method) ?? 'Another method').join(' + ');
}

type Phase = { kind: 'loading' } | { kind: 'ready'; view: SessionView } | { kind: 'ended' } | { kind: 'error' };

export function SessionHome({ api: injected, navigate = defaultNavigate }: { api?: AccountApi; navigate?: Navigate }) {
  const [api] = useState(() => injected ?? new AccountApi());
  const [phase, setPhase] = useState<Phase>({ kind: 'loading' });
  const [signingOut, setSigningOut] = useState(false);
  const [signOutFailed, setSignOutFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const mounted = useRef(true);

  function fetchSession() {
    void api.session().then((result) => {
      if (!mounted.current) return;
      if (result.ok) setPhase({ kind: 'ready', view: result.data });
      else if (result.status === 401) navigate('/login');
      else setPhase({ kind: 'error' });
    });
  }

  function retry() {
    setPhase({ kind: 'loading' });
    fetchSession();
  }

  useEffect(() => {
    mounted.current = true;
    fetchSession();
    return () => {
      mounted.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- load once per mount
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(timer);
  }, []);

  // The absolute session deadline is fixed by the server; reaching it only changes what is shown.
  const overdue = phase.kind === 'ready' && now >= phase.view.expiresAt * 1000;

  function signOut() {
    setSigningOut(true);
    setSignOutFailed(false);
    void api.logout().then((result) => {
      if (!mounted.current) return;
      setSigningOut(false);
      if (result.ok || result.status === 401) {
        api.forget();
        navigate('/login');
      } else {
        // The server keeps the session when it cannot revoke it, so the page keeps showing it.
        setSignOutFailed(true);
      }
    });
  }

  if (phase.kind === 'loading') {
    return (
      <div className="mx-auto max-w-xl px-4 py-12">
        <h1 className="sr-only">Mandatary</h1>
        <Skeleton label="your session" lines={3} />
      </div>
    );
  }
  if (phase.kind === 'error') {
    return (
      <div className="mx-auto max-w-xl space-y-4 px-4 py-12">
        <h1 className="text-2xl font-semibold">Mandatary</h1>
        <Alert tone="danger" title="Couldn’t load your session" actions={<Button onClick={retry}>Try again</Button>}>
          Nothing was changed. Try again in a moment.
        </Alert>
      </div>
    );
  }
  if (phase.kind === 'ended' || overdue) {
    return (
      <div className="mx-auto max-w-xl space-y-4 px-4 py-12">
        <h1 className="text-2xl font-semibold">Mandatary</h1>
        <Alert tone="warning" role="alert" title="Your session ended" actions={<Button onClick={() => navigate('/login')}>Sign in again</Button>}>
          For your security, sessions end after a period of inactivity or at a fixed deadline. Nothing was changed.
        </Alert>
      </div>
    );
  }

  const { view } = phase;
  return (
    <AdminShell nav={NAV} currentId="overview" account={{ username: view.username, assurance: view.assurance }} onSignOut={signOut} signingOut={signingOut}>
      <PageHeader title="Overview" description="You are signed in." />
      <div className="space-y-5">
        {signOutFailed ? (
          <Alert tone="danger" title="Sign-out wasn’t completed" actions={<Button onClick={signOut}>Try again</Button>}>
            You are still signed in. Try again; if it keeps failing, close this browser window and check the server log.
          </Alert>
        ) : null}
        {view.assurance === 'password-only' ? (
          <Alert tone="warning" role="none" title="This is a password-only session">
            Password-only sessions can’t change security settings or administer Mandatary. Sign out and sign in again with your second factor for full access.
          </Alert>
        ) : null}
        <Panel title="Your session">
          <dl className="divide-y divide-line">
            <DetailRow label="Verification">{view.assurance === 'aal2' ? 'Multi-factor verified' : 'Password only'}</DetailRow>
            <DetailRow label="Signed in with">{methodText(view.methods)}</DetailRow>
            <DetailRow label="Session ends">{formatDate(view.expiresAt)}</DetailRow>
          </dl>
          <p className="text-sm text-muted">Account security settings are not available in this build yet.</p>
        </Panel>
      </div>
    </AdminShell>
  );
}
