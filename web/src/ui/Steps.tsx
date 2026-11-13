import { Icon } from './Icon';

export interface StepItem {
  id: string;
  label: string;
}

/**
 * Progress through an ordered ceremony (setup). Position is announced as text
 * ("Step 2 of 5: Account"), never inferred from colour; the current step carries aria-current.
 * Below the sm breakpoint only the current label is shown so the row never wraps or scrolls.
 */
export function Steps({ steps, currentId, label = 'Progress' }: { steps: readonly StepItem[]; currentId: string; label?: string }) {
  const index = Math.max(0, steps.findIndex((step) => step.id === currentId));
  return (
    <div>
      <p className="mb-2 text-sm font-medium text-muted">
        Step {index + 1} of {steps.length}
      </p>
      <ol aria-label={label} className="flex flex-wrap gap-x-1 gap-y-1.5">
        {steps.map((step, position) => {
          const done = position < index;
          const current = position === index;
          return (
            <li key={step.id} aria-current={current ? 'step' : undefined} className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-sm ${current ? 'border-accent bg-accent-soft font-semibold text-accent-text' : done ? 'border-transparent text-success' : 'border-line text-muted'} ${current ? '' : 'max-sm:hidden'}`}>
              {done ? <Icon name="check" className="size-4" /> : <span aria-hidden="true" className="tabular-nums">{position + 1}</span>}
              <span>{step.label}</span>
              {done ? <span className="sr-only">(done)</span> : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
