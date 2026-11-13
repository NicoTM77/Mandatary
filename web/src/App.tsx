import { lazy, Suspense } from 'react';
import { ThemeProvider } from './theme';
import { ThemeToggle } from './ui';

// The synthetic state gallery is a design-review tool, not product surface. It is imported only
// when Vite's DEV flag is true, so the production bundle contains neither the gallery nor its
// fixtures (asserted in the handoff by grepping the built assets).
const Gallery = import.meta.env.DEV ? lazy(() => import('./gallery/Gallery')) : null;

function galleryView(): string | null {
  if (Gallery === null) return null;
  return new URLSearchParams(globalThis.location?.search ?? '').get('synthetic');
}

function Skeleton() {
  return (
    <div className="min-h-screen px-4 py-12 sm:px-8">
      <main id="main-content" className="mx-auto max-w-2xl space-y-6">
        <h1 className="text-4xl font-semibold tracking-tight">Mandatary</h1>
        <p>Development skeleton — authentication and container operations are not available.</p>
        <p className="text-muted">This build serves embedded static assets only. It does not connect to Docker or store credentials.</p>
        <ThemeToggle />
      </main>
    </div>
  );
}

export function App() {
  const view = galleryView();
  return (
    <ThemeProvider>
      {view !== null && Gallery ? (
        <Suspense fallback={null}>
          <Gallery view={view} />
        </Suspense>
      ) : (
        <Skeleton />
      )}
    </ThemeProvider>
  );
}
