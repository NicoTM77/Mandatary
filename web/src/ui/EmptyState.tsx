import type { ReactNode } from 'react';
import { Button, type ButtonVariant } from './Button';
import type { IconName } from './Icon';

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
  /** Defaults to primary: an empty state usually offers the one action that fills it. */
  variant?: ButtonVariant;
  icon?: IconName;
}

export interface EmptyStateProps {
  title: string;
  /** Plain explanation of why there is nothing here and what it is for. */
  description?: ReactNode;
  /** Rendered as a native Button; omit when there is no next step. */
  action?: EmptyStateAction;
  /** Heading level so the empty state fits the page outline. Default 2. */
  headingLevel?: 2 | 3;
  className?: string;
}

/**
 * "Nothing here yet" state (UX §9). Text and a native Button only: no illustration image, so it
 * stays inside the static CSP and reads the same in both themes.
 */
export function EmptyState({ title, description, action, headingLevel = 2, className = '' }: EmptyStateProps) {
  const Heading = headingLevel === 2 ? 'h2' : 'h3';
  return (
    <div className={`flex flex-col items-start gap-3 rounded-panel border border-dashed border-line-strong bg-sunken px-5 py-6 sm:px-6 ${className}`}>
      <Heading className="text-base font-semibold leading-snug text-fg">{title}</Heading>
      {description ? <p className="max-w-prose text-sm text-muted">{description}</p> : null}
      {action ? (
        <Button variant={action.variant ?? 'primary'} icon={action.icon} onClick={action.onClick}>
          {action.label}
        </Button>
      ) : null}
    </div>
  );
}
