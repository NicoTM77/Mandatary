import type { ReactNode } from 'react';

export interface PanelProps {
  title?: ReactNode;
  description?: ReactNode;
  /** Right-aligned header controls (badges, a secondary action). */
  headerActions?: ReactNode;
  /** Heading level so the panel fits the page outline (the page title is the h1). Default 2. */
  headingLevel?: 2 | 3;
  children?: ReactNode;
  className?: string;
}

/** A stable, opaque surface for forms and dense information. Never translucent: forms are read, not glanced at. */
export function Panel({ title, description, headerActions, headingLevel = 2, children, className = '' }: PanelProps) {
  const Heading = headingLevel === 2 ? 'h2' : 'h3';
  return (
    <section className={`rounded-panel border border-line bg-surface shadow-panel ${className}`}>
      {title || headerActions ? (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4 sm:px-6">
          <div className="min-w-0">
            {title ? <Heading className="text-lg font-semibold leading-snug">{title}</Heading> : null}
            {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
          </div>
          {headerActions ? <div className="flex items-center gap-2">{headerActions}</div> : null}
        </header>
      ) : null}
      <div className="space-y-5 px-5 py-5 sm:px-6">{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold leading-tight tracking-tight sm:text-[1.75rem]">{title}</h1>
        {description ? <p className="mt-1.5 max-w-prose text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** Row of a read-only key/value list (non-secret metadata). */
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 py-2.5 sm:flex-row sm:items-baseline sm:gap-6">
      <dt className="text-sm text-muted sm:w-44 sm:shrink-0">{label}</dt>
      <dd className="min-w-0 break-words text-fg">{children}</dd>
    </div>
  );
}
