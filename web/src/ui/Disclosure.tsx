import { useState, type ReactNode } from 'react';
import { Icon } from './Icon';

/**
 * A native <details>/<summary> disclosure with a visible chevron (the browser's own marker is lost once the summary is a flex row).
 * Native keyboard behaviour is kept: Tab to the summary, Enter or Space toggles. The chevron turns when open; reduced motion removes
 * the turn through the global rule in style.css.
 *
 * `open` only ever OPENS it (for example when a field inside gains a value): it never closes a disclosure the person opened
 * themselves, so a panel does not shut under the cursor while they type in it.
 */
export function Disclosure({ summary, open, children, framed = true, className = '' }: { summary: ReactNode; open?: boolean; children: ReactNode; framed?: boolean; className?: string }) {
  const [isOpen, setOpen] = useState(open === true);
  // Adjusting state while rendering (not in an effect): when the `open` prop turns true, open once.
  const [wasOpen, setWasOpen] = useState(open === true);
  if ((open === true) !== wasOpen) {
    setWasOpen(open === true);
    if (open === true) setOpen(true);
  }
  return (
    <details open={isOpen} onToggle={(event) => setOpen(event.currentTarget.open)} className={`group ${framed ? 'rounded-control border border-line bg-sunken' : ''} ${className}`}>
      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 px-4 font-medium marker:content-none [&::-webkit-details-marker]:hidden">
        <Icon name="chevron" className="size-4 text-muted transition-transform duration-150 group-open:rotate-90" />
        {summary}
      </summary>
      <div className="border-t border-line px-4 py-4">{children}</div>
    </details>
  );
}
