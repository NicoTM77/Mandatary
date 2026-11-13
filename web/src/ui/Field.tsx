import { useEffect, useId, useRef, useState, type InputHTMLAttributes, type ReactNode, type Ref } from 'react';
import { Icon } from './Icon';

export interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id' | 'aria-label' | 'aria-describedby'> {
  /** Always visible; placeholders are never the label. */
  label: string;
  hint?: ReactNode;
  /** Inline error. Presence sets aria-invalid and links the message through aria-describedby. */
  error?: string;
  /** Monospace + tabular figures for codes, tokens, usernames shown as identifiers. */
  mono?: boolean;
  /** Control rendered inside the input frame, e.g. the show/hide password button. */
  trailing?: ReactNode;
  ref?: Ref<HTMLInputElement>;
}

/**
 * Labelled input with hint and inline error. Inputs are meant to be UNCONTROLLED
 * (defaultValue + FormData on submit) for anything secret so that no React state or
 * devtools snapshot ever holds a password, code or token.
 */
export function TextField({ label, hint, error, mono = false, trailing, className = '', ref, ...input }: TextFieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(' ') || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-fg">
        {label}
      </label>
      <div className="relative">
        <input
          {...input}
          ref={ref}
          id={id}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={`min-h-11 w-full rounded-control border bg-surface px-3 text-base text-fg placeholder:text-subtle read-only:bg-sunken disabled:opacity-60 ${error ? 'border-danger' : 'border-line-strong'} ${mono ? 'font-mono tracking-wide' : ''} ${trailing ? 'pr-12' : ''}`}
        />
        {trailing ? <div className="absolute inset-y-0 right-1 flex items-center">{trailing}</div> : null}
      </div>
      {hint ? (
        <p id={hintId} className="mt-1.5 text-sm text-muted">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errorId} className="mt-1.5 flex items-start gap-1.5 text-sm font-medium text-danger">
          <Icon name="error" className="mt-0.5 size-4" />
          <span>{error}</span>
        </p>
      ) : null}
    </div>
  );
}

export interface PasswordFieldProps extends Omit<TextFieldProps, 'type' | 'trailing' | 'autoComplete' | 'mono'> {
  /** Required so password managers classify the form: sign-in vs choosing a new password. */
  autoComplete: 'current-password' | 'new-password';
}

/**
 * Password input: paste and managers are never blocked, there are no composition rules in
 * the UI (the server contract decides), and there is no "confirm password" box — a
 * show/hide toggle lets the person verify what they typed instead. The field is returned to
 * masked state whenever its form is submitted so a revealed value is not left on screen.
 */
export function PasswordField({ autoComplete, ...rest }: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);
  const wrapper = useRef<HTMLDivElement>(null);
  const controlId = useId();

  useEffect(() => {
    const form = wrapper.current?.closest('form');
    if (!form) return;
    const mask = () => setVisible(false);
    form.addEventListener('submit', mask);
    return () => form.removeEventListener('submit', mask);
  }, []);

  return (
    <div ref={wrapper}>
      <TextField
        {...rest}
        type={visible ? 'text' : 'password'}
        autoComplete={autoComplete}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        trailing={
          <button
            type="button"
            id={controlId}
            aria-pressed={visible}
            onClick={() => setVisible((value) => !value)}
            className="inline-flex size-10 items-center justify-center rounded-control text-muted hover:bg-sunken hover:text-fg"
          >
            <Icon name={visible ? 'eye-off' : 'eye'} />
            <span className="sr-only">Show password</span>
          </button>
        }
      />
    </div>
  );
}

export type CodeKind = 'totp' | 'mailed-proof' | 'saved-code' | 'setup-token';

type CodeAttributes = Pick<InputHTMLAttributes<HTMLInputElement>, 'inputMode' | 'autoComplete' | 'enterKeyHint'> & { extra?: Record<string, string> };

const NO_MANAGER = { 'data-1p-ignore': 'true', 'data-lpignore': 'true', 'data-bwignore': 'true' };

function codeAttributes(kind: CodeKind): CodeAttributes {
  switch (kind) {
    case 'totp':
      // Authenticator-app code: platform one-time-code fill and the numeric keypad.
      return { inputMode: 'numeric', autoComplete: 'one-time-code', enterKeyHint: 'go' };
    case 'mailed-proof':
      // Code mailed to a notification address.
      return { inputMode: 'text', autoComplete: 'one-time-code', enterKeyHint: 'go' };
    case 'saved-code':
      // Offline recovery code: never offered for autofill or saved by a manager.
      return { inputMode: 'text', autoComplete: 'off', enterKeyHint: 'go', extra: NO_MANAGER };
    case 'setup-token':
      // Host-terminal setup token: single use, pasted by hand, not a password to remember.
      return { inputMode: 'text', autoComplete: 'off', enterKeyHint: 'go', extra: NO_MANAGER };
  }
}

export interface CodeFieldProps extends Omit<TextFieldProps, 'type' | 'mono' | 'autoComplete' | 'inputMode' | 'maxLength' | 'pattern'> {
  kind: CodeKind;
}

/**
 * One-time-code style inputs. Deliberately NOT split into per-digit boxes and with NO maxLength
 * or pattern: one field keeps paste ("123 456"), SMS/app autofill and screen readers working. The
 * container strips spaces/hyphens before sending; the server verdict is authoritative.
 */
export function CodeField({ kind, ...rest }: CodeFieldProps) {
  const { extra, ...standard } = codeAttributes(kind);
  return <TextField {...rest} {...standard} {...extra} type="text" mono autoCapitalize="none" autoCorrect="off" spellCheck={false} />;
}
