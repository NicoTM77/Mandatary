import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { Alert, SyntheticBadge } from './Alert';
import { Button } from './Button';
import { useAutoFocus } from './focus';

export interface SecretAcknowledge {
  /** Sentence beside the checkbox, e.g. "I have stored this token somewhere safe." */
  confirmLabel: string;
  /** Button that removes the secret from the page, e.g. "Hide token". */
  doneLabel: string;
  /** Called once, after the secret has been removed from the DOM. The parent must drop its copy. */
  onDone: () => void;
}

export interface SecretRevealProps {
  /** What is being revealed, e.g. "Your agent token". Also the accessible name of the region. */
  heading: string;
  /** Plain-language consequences (expiry, rotation overlap). Never contains the secret. */
  intro?: ReactNode;
  /** One secret (agent token, TOTP key). Exactly one of `value` / `items` must be given. */
  value?: string;
  /** Several secrets shown together (recovery codes). */
  items?: readonly string[];
  /** Visual grouping of a single value, e.g. 4 for TOTP keys. Copy always uses the raw value. */
  groupEvery?: number;
  copyLabel?: string;
  /**
   * Two-step dismissal (checkbox, then button). Omit ONLY where the container removes the secret
   * itself on a defined event, e.g. a TOTP key that disappears when the first code is proven.
   */
  acknowledge?: SecretAcknowledge;
  /** Gallery fixtures only: labels the panel as an illustration. */
  synthetic?: boolean;
}

type CopyState = 'idle' | 'copied' | 'failed';

function group(value: string, size: number): string {
  if (size < 1) return value;
  const parts: string[] = [];
  for (let at = 0; at < value.length; at += size) parts.push(value.slice(at, at + size));
  return parts.join(' ');
}

/**
 * Reveal-once treatment (agent tokens, TOTP keys, recovery codes).
 *
 * Presentation contract, enforced here and asserted in SecretReveal.test.tsx:
 *  - The secret exists only as text content of one element. It is never placed in an attribute,
 *    id, class, data-*, aria-label, document.title, URL, history or any web storage, and is never
 *    announced through a live region (the live region only says "Copied").
 *  - Dismissal is two-step (acknowledge, then hide) so a stray click cannot destroy the only copy.
 *  - After "done" the secret node is REMOVED, not hidden with CSS, and the component renders a
 *    secret-free notice even if the parent forgets to unmount it.
 *  - Focus moves to the region on mount so a screen-reader user lands on the warning first.
 * This component performs no network, storage or cryptographic work; the container owns the value's
 * lifetime and must clear its own reference in `acknowledge.onDone` / on its own removal event.
 */
export function SecretReveal({ heading, intro, value, items, groupEvery, copyLabel = 'Copy', acknowledge, synthetic = false }: SecretRevealProps) {
  const headingId = useId();
  const statusId = useId();
  const region = useRef<HTMLElement>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [copy, setCopy] = useState<CopyState>('idle');

  const autoFocus = useAutoFocus();
  useEffect(() => {
    if (autoFocus) region.current?.focus();
  }, [autoFocus]);

  useEffect(() => {
    if (copy === 'idle') return;
    const timer = globalThis.setTimeout(() => setCopy('idle'), 4000);
    return () => globalThis.clearTimeout(timer);
  }, [copy]);

  if (hidden) {
    return (
      <Alert tone="info" title={`${heading} hidden`}>
        It can&rsquo;t be shown again. If you didn&rsquo;t save it, create a new one.
      </Alert>
    );
  }

  const copyToClipboard = () => {
    const clipboard = globalThis.navigator?.clipboard;
    if (!clipboard) {
      setCopy('failed');
      return;
    }
    const text = items ? items.join('\n') : (value ?? '');
    clipboard.writeText(text).then(
      () => setCopy('copied'),
      () => setCopy('failed'),
    );
  };

  const finish = () => {
    setHidden(true);
    acknowledge?.onDone();
  };

  return (
    <section ref={region} tabIndex={-1} aria-labelledby={headingId} className="rounded-panel border-2 border-dashed border-warn bg-warn-soft p-5 outline-none focus-visible:outline-2 sm:p-6">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id={headingId} className="text-lg font-semibold text-fg">
          {heading}
        </h2>
        {synthetic ? <SyntheticBadge>Synthetic value, not a real secret</SyntheticBadge> : null}
      </div>
      <p className="mt-2 font-medium text-warn">This is the only time it will be shown. Reloading or leaving this page removes it for good.</p>
      {intro ? <div className="mt-2 text-sm text-fg">{intro}</div> : null}

      <div translate="no" className="mt-4 rounded-control border border-line-strong bg-surface p-4 font-mono text-[0.95rem] leading-relaxed text-fg">
        {items ? (
          <ol className="grid list-decimal grid-cols-1 gap-x-8 gap-y-1.5 pl-6 sm:grid-cols-2">
            {items.map((item, position) => (
              // Index keys: secret values never become React keys.
              <li key={position} className="secret-select tabular-nums">
                {item}
              </li>
            ))}
          </ol>
        ) : (
          <p className="secret-select">{groupEvery ? group(value ?? '', groupEvery) : value}</p>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Button variant="secondary" icon="copy" onClick={copyToClipboard} aria-describedby={statusId}>
          {items ? (items.length === 1 ? 'Copy code' : 'Copy all codes') : copyLabel}
        </Button>
        {/* The status text never contains the secret. */}
        <p id={statusId} role="status" className={`text-sm ${copy === 'failed' ? 'font-medium text-danger' : 'text-success'}`}>
          {copy === 'copied' ? 'Copied to clipboard.' : copy === 'failed' ? 'Couldn’t copy automatically. Select the text above and copy it yourself.' : ''}
        </p>
      </div>

      {acknowledge ? (
        <div className="mt-5 border-t border-warn/40 pt-4">
          <label className="flex cursor-pointer items-start gap-3 text-fg">
            <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} className="mt-0.5 size-5 shrink-0 accent-accent" />
            <span>{acknowledge.confirmLabel}</span>
          </label>
          <div className="mt-3">
            <Button variant="primary" disabled={!acknowledged} onClick={finish}>
              {acknowledge.doneLabel}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
