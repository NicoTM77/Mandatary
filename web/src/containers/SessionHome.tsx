import type { AccountApi } from '../api/account';
import { formatDate } from '../ui/format';
import { Alert, DetailRow, PageHeader, Panel } from '../ui';
import type { Navigate } from './LoginContainer';
import { SignedIn } from './SignedIn';

/**
 * Signed-in home (P1.16.3). The frame, session loading, expiry and sign-out live in SignedIn; this page
 * only shows the server's own labels and points at the account-security page.
 */

const METHOD_LABELS: ReadonlyMap<string, string> = new Map([
  ['password', 'Password'],
  ['totp', 'Authenticator app'],
  ['webauthn', 'Security key'],
  ['webauthn-uv', 'Security key with verification'],
]);

function methodText(methods: readonly string[]): string {
  return methods.map((method) => METHOD_LABELS.get(method) ?? 'Another method').join(' + ');
}

export function SessionHome({ api, navigate }: { api?: AccountApi; navigate?: Navigate }) {
  return (
    <SignedIn api={api} navigate={navigate} current="overview">
      {({ view }) => (
        <>
          <PageHeader title="Overview" description="You are signed in." />
          <div className="space-y-5">
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
              <p className="text-sm text-muted">
                Manage your sign-in methods, recovery codes and notification addresses under{' '}
                <a href="/security" className="font-medium text-accent-text underline underline-offset-2">
                  Account security
                </a>
                .
              </p>
            </Panel>
          </div>
        </>
      )}
    </SignedIn>
  );
}
