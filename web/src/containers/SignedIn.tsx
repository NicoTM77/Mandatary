import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AccountApi, type SessionView } from '../api/account';
import { AdminShell, Alert, Button, Skeleton, type NavItem } from '../ui';
import { defaultNavigate, type Navigate } from './LoginContainer';

/**
 * The signed-in frame shared by every account page (P1.16.3 home, P1.16.4 security and agents).
 * Everything shown about the session comes from GET /api/v1/session (the server's own labels): the page
 * never computes, upgrades or stores an assurance. A 401 anywhere means the session ended (idle,
 * absolute, logout elsewhere, a removed factor, policy change) and is shown as such; a logout the server
 * did not confirm is never presented as done.
 */

export type PageId = 'overview' | 'security' | 'agents';

const TICK_MS = 30_000;

/** Only destinations that exist are listed. The Agents link is shown to administrators, and the server enforces regardless. */
export function navFor(view: SessionView | null): readonly NavItem[] {
  const items: NavItem[] = [
    { id: 'overview', label: 'Overview', href: '/' },
    { id: 'security', label: 'Account security', href: '/security' },
  ];
  if (view?.administrator) items.push({ id: 'agents', label: 'Agents', href: '/agents' });
  return items;
}

export interface SignedInContext {
  api: AccountApi;
  view: SessionView;
  navigate: Navigate;
  /** Re-reads the session (after a step-up the cookie, CSRF token and freshness are new). Resolves true when the session is still live. */
  refresh: () => Promise<boolean>;
}

type Phase = { kind: 'loading' } | { kind: 'ready'; view: SessionView } | { kind: 'ended' } | { kind: 'error' };

export function SignedIn({ api: injected, navigate = defaultNavigate, current, children }: { api?: AccountApi; navigate?: Navigate; current: PageId; children: (context: SignedInContext) => ReactNode }) {
  const [api] = useState(() => injected ?? new AccountApi());
  const [phase, setPhase] = useState<Phase>({ kind: 'loading' });
  const [signingOut, setSigningOut] = useState(false);
  const [signOutFailed, setSignOutFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const mounted = useRef(true);

  /** Re-reads the session; resolves true while it is live. */
  function refresh(): Promise<boolean> {
    return api.session().then((result) => {
      if (result.ok) {
        setPhase({ kind: 'ready', view: result.data });
        return true;
      }
      if (result.status === 401) navigate('/login');
      else setPhase({ kind: 'error' });
      return false;
    });
  }

  useEffect(() => {
    mounted.current = true;
    void refresh();
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
        <Alert
          tone="danger"
          title="Couldn’t load your session"
          actions={
            <Button
              onClick={() => {
                setPhase({ kind: 'loading' });
                void refresh();
              }}
            >
              Try again
            </Button>
          }
        >
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
    <AdminShell nav={navFor(view)} currentId={current} account={{ username: view.username, assurance: view.assurance }} onSignOut={signOut} signingOut={signingOut}>
      {signOutFailed ? (
        <div className="mb-5">
          <Alert
            tone="danger"
            title="Sign-out wasn’t completed"
            actions={<Button onClick={signOut}>Try again</Button>}
          >
            You are still signed in. Try again; if it keeps failing, close this browser window and check the server log.
          </Alert>
        </div>
      ) : null}
      {children({ api, view, navigate, refresh })}
    </AdminShell>
  );
}
