import { useEffect, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { Button } from './Button';
import { useAutoFocus } from './focus';

export interface ConfirmPanelProps {
  /** Names the object and the action, e.g. "Remove Ada from contractors?". Also the accessible name of the group. */
  title: string;
  /** The consequence, in plain words: what stops, what starts, who is notified. */
  children: ReactNode;
  /** Names the object too: "Remove Ada", never "Yes". */
  confirmLabel: string;
  busyLabel?: string;
  cancelLabel?: string;
  busy?: boolean;
  /** `danger`: removes or revokes access. `warning`: a change that may LOOSEN access or that cannot be previewed. */
  tone?: 'danger' | 'warning';
  onConfirm: () => void;
  onCancel: () => void;
  /** DOM id of the control that opened the panel. Focus returns to it when the panel is cancelled. */
  returnFocusId?: string;
}

/**
 * Inline named confirmation (D-CONFIRM-1), lifted from the P1.16 screens so every destructive or
 * authority-changing action in P1.17/P1.18 looks and behaves the same. Not a modal: the page behind stays
 * reachable and nothing traps focus.
 *
 * Keyboard: focus moves to the group when it appears (so a screen-reader user hears its name and the
 * consequence first), Tab goes to "<confirm>" then "Keep it", Escape cancels and returns focus to the
 * control that opened it. The confirm button is never the focus target and is outlined, not filled.
 * While busy, Escape and "Keep it" are ignored and the confirm button keeps focus and says what is happening.
 */
export function ConfirmPanel({ title, children, confirmLabel, busyLabel = 'Working…', cancelLabel = 'Keep it', busy = false, tone = 'danger', onConfirm, onCancel, returnFocusId }: ConfirmPanelProps) {
  const ref = useRef<HTMLDivElement>(null);
  const autoFocus = useAutoFocus();

  useEffect(() => {
    if (autoFocus) ref.current?.focus();
  }, [autoFocus]);

  const cancel = () => {
    if (busy) return;
    onCancel();
    if (returnFocusId) document.getElementById(returnFocusId)?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.stopPropagation();
      cancel();
    }
  };

  const danger = tone === 'danger';
  return (
    <div
      ref={ref}
      role="group"
      aria-label={title}
      tabIndex={-1}
      onKeyDown={onKeyDown}
      className={`rounded-control border p-3.5 outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus ${danger ? 'border-danger bg-danger-soft' : 'border-warn bg-warn-soft'}`}
    >
      <p className={`font-medium ${danger ? 'text-danger' : 'text-warn'}`}>{title}</p>
      <div className="mt-1 text-sm">{children}</div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button variant={danger ? 'danger' : 'secondary'} busy={busy} busyLabel={busyLabel} onClick={onConfirm}>
          {confirmLabel}
        </Button>
        <Button variant="secondary" onClick={cancel} disabled={busy}>
          {cancelLabel}
        </Button>
      </div>
    </div>
  );
}
