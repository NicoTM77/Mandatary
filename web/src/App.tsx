import { useState } from 'react';

export function App() {
  const [dark, setDark] = useState(false);
  return (
    <main data-theme={dark ? 'dark' : 'light'}>
      <div className="mx-auto max-w-2xl space-y-6">
        <h1 className="text-4xl font-semibold">Mandatary</h1>
        <p>Development skeleton — authentication and container operations are not available.</p>
        <p>This build serves embedded static assets only. It does not connect to Docker or store credentials.</p>
        <button type="button" aria-pressed={dark} onClick={() => setDark(!dark)}>
          Use {dark ? 'light' : 'dark'} theme
        </button>
      </div>
    </main>
  );
}
