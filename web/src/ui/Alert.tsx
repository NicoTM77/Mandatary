import type { ReactNode, Ref } from 'react';
import { Icon, type IconName } from './Icon';

export type Tone = 'info' | 'success' | 'warning' | 'danger';

function toneIcon(tone: Tone): IconName {
  switch (tone) {
    case 'success':
      return 'check';
    case 'warning':
      return 'alert';
    case 'danger':
      return 'error';
    case 'info':
      return 'info';
  }
}

function toneClasses(tone: Tone): { box: string; accent: string } {
  switch (tone) {
    case 'success':
      return { box: 'border-success bg-success-soft', accent: 'text-success' };
    case 'warning':
      return { box: 'border-warn bg-warn-soft', accent: 'text-warn' };
    case 'danger':
      return { box: 'border-danger bg-danger-soft', accent: 'text-danger' };
    case 'info':
      return { box: 'border-accent bg-accent-soft', accent: 'text-accent-text' };
  }
}

export interface AlertProps {
  tone: Tone;
  title?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  /**
   * Live-region behaviour. Default: danger → alert (assertive, form failures), others → status
   * (polite). Use 'none' for content that is already on screen at load and must not be re-announced.
   */
  role?: 'alert' | 'status' | 'none';
  className?: string;
  /** Alerts are focusable by script (tabIndex -1) so a failed submit can move focus to the summary. */
  ref?: Ref<HTMLDivElement>;
}

/** Banner for outcomes. Tone is always paired with an icon and a text title/body (never colour alone). */
export function Alert({ tone, title, children, actions, role, className = '', ref }: AlertProps) {
  const effective = role ?? (tone === 'danger' ? 'alert' : 'status');
  const { box, accent } = toneClasses(tone);
  return (
    <div ref={ref} tabIndex={-1} role={effective === 'none' ? undefined : effective} className={`flex gap-3 rounded-control border p-3.5 text-fg ${box} ${className}`}>
      <Icon name={toneIcon(tone)} className={`mt-0.5 size-5 ${accent}`} />
      <div className="min-w-0 flex-1 space-y-1">
        {title ? <p className={`font-semibold ${accent}`}>{title}</p> : null}
        {children ? <div className="text-sm leading-relaxed">{children}</div> : null}
        {actions ? <div className="flex flex-wrap gap-2 pt-1.5">{actions}</div> : null}
      </div>
    </div>
  );
}

export type BadgeTone = Tone | 'neutral';

function badgeClasses(tone: BadgeTone): string {
  switch (tone) {
    case 'neutral':
      return 'bg-sunken text-muted border-line';
    case 'info':
      return 'bg-accent-soft text-accent-text border-transparent';
    case 'success':
      return 'bg-success-soft text-success border-transparent';
    case 'warning':
      return 'bg-warn-soft text-warn border-transparent';
    case 'danger':
      return 'bg-danger-soft text-danger border-transparent';
  }
}

export function Badge({ tone = 'neutral', icon, children }: { tone?: BadgeTone; icon?: IconName; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${badgeClasses(tone)}`}>
      {icon ? <Icon name={icon} className="size-3.5" /> : null}
      {children}
    </span>
  );
}

/**
 * Marks a screen/state whose backing service or route does not exist yet, or a fixture that is
 * only an illustration. It must stay visible in the gallery so no synthetic state reads as shipped.
 */
export function SyntheticBadge({ children = 'Synthetic' }: { children?: ReactNode }) {
  return (
    <Badge tone="warning" icon="alert">
      {children}
    </Badge>
  );
}
