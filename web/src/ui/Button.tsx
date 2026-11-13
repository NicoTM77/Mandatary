import type { ButtonHTMLAttributes, MouseEvent, ReactNode, Ref } from 'react';
import { Icon, type IconName } from './Icon';

export type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'danger';

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  variant?: ButtonVariant;
  /**
   * Request in flight. The button keeps focus and stays in the tab order (aria-disabled, not
   * disabled) so a keyboard user is not dropped to <body>; repeat activation is ignored.
   */
  busy?: boolean;
  /** Visible label while busy; end with an ellipsis, e.g. "Signing in…". */
  busyLabel?: string;
  icon?: IconName;
  children: ReactNode;
  ref?: Ref<HTMLButtonElement>;
}

function variantClasses(variant: ButtonVariant): string {
  switch (variant) {
    case 'primary':
      return 'bg-accent text-accent-fg hover:bg-accent-hover border border-transparent';
    case 'secondary':
      return 'bg-surface text-fg border border-line-strong hover:bg-sunken';
    case 'quiet':
      return 'bg-transparent text-accent-text border border-transparent hover:bg-accent-soft';
    case 'danger':
      return 'bg-surface text-danger border border-danger hover:bg-danger-soft';
  }
}

export function Button({ variant = 'primary', busy = false, busyLabel = 'Working…', icon, children, className = '', onClick, type = 'button', disabled, ref, ...rest }: ButtonProps) {
  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    if (busy) {
      // Also stops a busy type="submit" button from submitting the form a second time.
      event.preventDefault();
      return;
    }
    onClick?.(event);
  };
  return (
    <button
      {...rest}
      ref={ref}
      type={type}
      disabled={disabled}
      aria-busy={busy || undefined}
      aria-disabled={busy || undefined}
      onClick={handleClick}
      className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-control px-4 text-base font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-55 aria-disabled:cursor-progress ${variantClasses(variant)} ${className}`}
    >
      {busy ? <Icon name="spinner" /> : icon ? <Icon name={icon} /> : null}
      <span>{busy ? busyLabel : children}</span>
    </button>
  );
}
