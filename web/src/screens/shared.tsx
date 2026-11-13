import { useEffect, useLayoutEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Alert, useAutoFocus } from '../ui';

/** `[inputName, noun phrase used in "Enter …."]` */
export type RequiredField = readonly [name: string, description: string];

export interface RequiredFormOptions {
  /** True while the screen is in a rejected state: the named inputs are blanked (secrets never survive a failure). */
  rejected?: boolean;
  clearOnReject?: readonly string[];
  /** Inputs whose value must not be trimmed when checking for emptiness (passwords). */
  untrimmed?: readonly string[];
}

/**
 * Form wiring shared by every screen.
 *  - Always preventDefault + method="post": a credential can never reach a URL query string, and the
 *    static CSP (form-action 'none') would block a native submit anyway.
 *  - Reads values from UNCONTROLLED inputs through FormData once, at submit.
 *  - Empty required fields are reported inline, focus moves to the first one, and no request is made.
 *    This is convenience only; the server verdict is authoritative for everything else.
 */
export function useRequiredForm(required: readonly RequiredField[], onValues: (data: FormData) => void, options: RequiredFormOptions = {}) {
  const [missing, setMissing] = useState<readonly string[]>([]);
  const form = useRef<HTMLFormElement>(null);
  const { rejected = false, clearOnReject = [], untrimmed = [] } = options;
  const clearKey = clearOnReject.join(',');

  // A layout effect: the blanking lands in the same commit that shows the rejection, never a paint later.
  useLayoutEffect(() => {
    if (!rejected || !form.current || clearKey === '') return;
    for (const name of clearKey.split(',')) {
      const control = form.current.elements.namedItem(name);
      if (control instanceof HTMLInputElement) control.value = '';
    }
  }, [rejected, clearKey]);

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const empty = required.filter(([name]) => {
      const value = String(data.get(name) ?? '');
      return (untrimmed.includes(name) ? value : value.trim()) === '';
    });
    setMissing(empty.map(([name]) => name));
    const first = empty[0];
    if (first) {
      const control = event.currentTarget.elements.namedItem(first[0]);
      if (control instanceof HTMLElement) control.focus();
      return;
    }
    onValues(data);
  };

  return {
    formProps: { ref: form, method: 'post' as const, noValidate: true, onSubmit },
    errorFor: (name: string): string | undefined => {
      const match = required.find(([candidate]) => candidate === name);
      return match && missing.includes(name) ? `Enter ${match[1]}.` : undefined;
    },
  };
}

/** Moves focus to an alert when it appears, so keyboard and screen-reader users land on the outcome. */
export function useFocusWhen(active: boolean) {
  const ref = useRef<HTMLDivElement>(null);
  const autoFocus = useAutoFocus();
  useEffect(() => {
    if (active && autoFocus) ref.current?.focus();
  }, [active, autoFocus]);
  return ref;
}

export interface Rejection {
  title: string;
  body: ReactNode;
}

/** Copy for outcomes common to many forms. Specific screens add their own cases before falling back here. */
export function commonRejection(reason: 'rate_limited' | 'unavailable' | 'invalid_request' | 'denied'): Rejection {
  switch (reason) {
    case 'rate_limited':
      return { title: 'Too many attempts', body: 'Wait a minute, then try again. Your details were not saved.' };
    case 'unavailable':
      return { title: 'Mandatary couldn’t finish that', body: 'Nothing was changed. Try again in a moment; if it keeps happening, check the server log.' };
    case 'invalid_request':
      return { title: 'That request couldn’t be read', body: 'Reload the page and try again.' };
    case 'denied':
      return { title: 'That wasn’t accepted', body: 'Check what you entered and try again.' };
  }
}

export function RejectionAlert({ rejection, active, children }: { rejection: Rejection; active: boolean; children?: ReactNode }) {
  const ref = useFocusWhen(active);
  return (
    <Alert ref={ref} tone="danger" title={rejection.title} actions={children}>
      {rejection.body}
    </Alert>
  );
}

/** Operator command shown as copyable-by-selection text. Never contains a secret. */
export function Command({ children }: { children: string }) {
  return (
    <code translate="no" className="rounded bg-sunken px-1.5 py-0.5 font-mono text-[0.85em] break-words">
      {children}
    </code>
  );
}
