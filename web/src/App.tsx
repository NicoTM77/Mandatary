import { lazy, Suspense } from 'react';
import { AgentsContainer } from './containers/AgentsContainer';
import { GroupsContainer, PolicyAgentsContainer, RulesContainer, UsersContainer } from './containers/PolicyContainers';
import { LoginContainer } from './containers/LoginContainer';
import { RecoveryContainer } from './containers/RecoveryContainer';
import { ExportContainer, RestoreContainer, ReviewContainer } from './containers/RecoveryContainers';
import { SecurityContainer } from './containers/SecurityContainer';
import { SessionHome } from './containers/SessionHome';
import { SetupContainer } from './containers/SetupContainer';
import { ThemeProvider } from './theme';
import { Alert, CenteredFrame } from './ui';

// The synthetic state gallery is a design-review tool, not product surface. It is imported only
// when Vite's DEV flag is true, so the production bundle contains neither the gallery nor its
// fixtures (asserted in the handoff by grepping the built assets).
const Gallery = import.meta.env.DEV ? lazy(() => import('./gallery/Gallery')) : null;

function galleryView(): string | null {
  if (Gallery === null) return null;
  return new URLSearchParams(globalThis.location?.search ?? '').get('synthetic');
}

export type AppRoute = 'home' | 'setup' | 'login' | 'security' | 'recovery' | 'agents' | 'policy-rules' | 'policy-users' | 'policy-groups' | 'policy-agents' | 'backup-export' | 'backup-restore' | 'backup-review' | 'unknown';

/**
 * The server serves this shell only at the exact document routes `/`, `/setup` and `/login` (D-ROUTE-1);
 * the path picks the view. There is no client-side router: moving between views is a full page
 * navigation, which discards every in-memory token and field with the old page.
 */
export function routeFor(pathname: string): AppRoute {
  switch (pathname) {
    case '/':
      return 'home';
    case '/setup':
      return 'setup';
    case '/login':
      return 'login';
    case '/security':
      return 'security';
    case '/recovery':
      return 'recovery';
    case '/agents':
      return 'agents';
    case '/policy':
      return 'policy-rules';
    case '/policy/users':
      return 'policy-users';
    case '/policy/groups':
      return 'policy-groups';
    case '/policy/agents':
      return 'policy-agents';
    case '/backup':
      return 'backup-export';
    case '/restore':
      return 'backup-restore';
    case '/restore/review':
      return 'backup-review';
    default:
      return 'unknown';
  }
}

function View({ path }: { path: string }) {
  switch (routeFor(path)) {
    case 'setup':
      return <SetupContainer />;
    case 'login':
      return <LoginContainer />;
    case 'home':
      return <SessionHome />;
    case 'security':
      return <SecurityContainer />;
    case 'recovery':
      return <RecoveryContainer />;
    case 'agents':
      return <AgentsContainer />;
    case 'policy-rules':
      return <RulesContainer />;
    case 'policy-users':
      return <UsersContainer />;
    case 'policy-groups':
      return <GroupsContainer />;
    case 'policy-agents':
      return <PolicyAgentsContainer />;
    case 'backup-export':
      return <ExportContainer />;
    case 'backup-restore':
      return <RestoreContainer />;
    case 'backup-review':
      return <ReviewContainer />;
    case 'unknown':
      return (
        <CenteredFrame>
          <h1 className="sr-only">Mandatary</h1>
          <Alert tone="info" role="none" title="Nothing is here">
            This address isn’t part of Mandatary.{' '}
            <a href="/login" className="font-medium text-accent-text underline underline-offset-2">
              Go to sign in
            </a>
            .
          </Alert>
        </CenteredFrame>
      );
  }
}

export function App({ path = globalThis.location?.pathname ?? '/' }: { path?: string }) {
  const view = galleryView();
  return (
    <ThemeProvider>
      {view !== null && Gallery ? (
        <Suspense fallback={null}>
          <Gallery view={view} />
        </Suspense>
      ) : (
        <View path={path} />
      )}
    </ThemeProvider>
  );
}
