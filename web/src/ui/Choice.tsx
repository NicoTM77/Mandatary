import { useId, type ReactNode, type Ref, type SelectHTMLAttributes } from 'react';
import { Icon } from './Icon';

/*
 * Choice controls for the management screens (P1.17.1): a labelled native <select>, a radio group and a
 * checkbox. All three are native elements with visible labels; none is a custom widget, so keyboard,
 * screen-reader and autofill behaviour is the browser's own (D-STACK-1: no new dependency).
 *
 * They are meant for NON-SECRET values (names, effects, operations). Secrets stay in the uncontrolled
 * TextField/PasswordField/CodeField primitives.
 */

// ───────────────────────── SelectField ─────────────────────────

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectGroup {
  label: string;
  options: readonly SelectOption[];
}

export interface SelectFieldProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'id' | 'aria-label' | 'aria-describedby' | 'children'> {
  label: string;
  hint?: ReactNode;
  error?: string;
  /** Flat options, or `groups` for <optgroup>s. */
  options?: readonly SelectOption[];
  groups?: readonly SelectGroup[];
  /** Renders a first, empty-valued option so "nothing chosen" is the empty string rather than the first real choice. */
  placeholder?: string;
  ref?: Ref<HTMLSelectElement>;
}

function Options({ options }: { options: readonly SelectOption[] }) {
  return options.map((option) => (
    <option key={option.value} value={option.value} disabled={option.disabled}>
      {option.label}
    </option>
  ));
}

/**
 * Labelled native select with hint and inline error (same anatomy as TextField). Disabled options stay
 * in the list with their reason written in the label, so a person can see why a choice is unavailable.
 */
export function SelectField({ label, hint, error, options, groups, placeholder, className = '', ref, ...select }: SelectFieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(' ') || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-fg">
        {label}
      </label>
      <select
        {...select}
        ref={ref}
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={`min-h-11 w-full rounded-control border bg-surface px-3 text-base text-fg disabled:opacity-60 ${error ? 'border-danger' : 'border-line-strong'}`}
      >
        {placeholder !== undefined ? <option value="">{placeholder}</option> : null}
        {options ? <Options options={options} /> : null}
        {groups?.map((group) => (
          <optgroup key={group.label} label={group.label}>
            <Options options={group.options} />
          </optgroup>
        ))}
      </select>
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

// ───────────────────────── RadioGroup ─────────────────────────

export interface RadioOption {
  value: string;
  label: string;
  /** Plain-language consequence of choosing this option; linked with aria-describedby. */
  hint?: ReactNode;
  disabled?: boolean;
}

export interface RadioGroupProps {
  name: string;
  legend: string;
  options: readonly RadioOption[];
  /** Controlled: pass `value`. Uncontrolled: pass `defaultValue`. */
  value?: string;
  defaultValue?: string;
  onChange?: (value: string) => void;
  hint?: ReactNode;
  error?: string;
  className?: string;
  /** Lay the options out side by side from the sm breakpoint up. Below it they always stack. Default: stacked. */
  columns?: 2 | 3;
}

/**
 * A fieldset of native radios. Each option is a bordered, 44 px-high choice with its consequence written
 * beside it; the selected option is marked by border, tint AND the native radio mark (never colour alone).
 * Arrow keys move between options and Tab leaves the group, exactly as native radios do.
 */
export function RadioGroup({ name, legend, options, value, defaultValue, onChange, hint, error, className = '', columns }: RadioGroupProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(' ') || undefined;
  return (
    <fieldset aria-describedby={describedBy} className={`min-w-0 ${className}`}>
      <legend className="mb-1.5 text-sm font-medium text-fg">{legend}</legend>
      <div className={`grid gap-2 ${columns === 3 ? 'sm:grid-cols-3' : columns === 2 ? 'sm:grid-cols-2' : ''}`}>
        {options.map((option) => {
          const optionId = `${id}-${option.value}`;
          const optionHint = `${optionId}-hint`;
          return (
            <label key={option.value} htmlFor={optionId} className={`flex min-h-11 items-start gap-3 rounded-control border border-line-strong bg-surface px-3 py-2.5 has-[:checked]:border-accent has-[:checked]:bg-accent-soft ${option.disabled ? 'opacity-60' : 'cursor-pointer'}`}>
              <input
                type="radio"
                id={optionId}
                name={name}
                value={option.value}
                disabled={option.disabled}
                aria-describedby={option.hint ? optionHint : undefined}
                {...(value !== undefined ? { checked: value === option.value } : { defaultChecked: defaultValue === option.value })}
                onChange={() => onChange?.(option.value)}
                className="mt-0.5 size-5 shrink-0 accent-accent"
              />
              <span className="min-w-0">
                <span className="block font-medium text-fg">{option.label}</span>
                {option.hint ? (
                  <span id={optionHint} className="block text-sm text-muted">
                    {option.hint}
                  </span>
                ) : null}
              </span>
            </label>
          );
        })}
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
    </fieldset>
  );
}

// ───────────────────────── CheckboxField ─────────────────────────

export interface CheckboxFieldProps {
  label: ReactNode;
  hint?: ReactNode;
  name?: string;
  checked?: boolean;
  defaultChecked?: boolean;
  disabled?: boolean;
  onChange?: (checked: boolean) => void;
  className?: string;
  /** Marks the box when its parent form is rejected for it being unticked. */
  error?: string;
}

/** A native checkbox with the whole label clickable (44 px high), an optional hint and inline error. */
export function CheckboxField({ label, hint, name, checked, defaultChecked, disabled, onChange, className = '', error }: CheckboxFieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(' ') || undefined;
  return (
    <div className={className}>
      <label htmlFor={id} className={`flex min-h-11 items-start gap-3 py-1.5 text-fg ${disabled ? 'opacity-60' : 'cursor-pointer'}`}>
        <input
          id={id}
          type="checkbox"
          name={name}
          disabled={disabled}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          {...(checked !== undefined ? { checked } : { defaultChecked })}
          onChange={(event) => onChange?.(event.target.checked)}
          className="mt-0.5 size-5 shrink-0 accent-accent"
        />
        <span className="min-w-0">
          {label}
          {hint ? (
            <span id={hintId} className="block text-sm text-muted">
              {hint}
            </span>
          ) : null}
        </span>
      </label>
      {error ? (
        <p id={errorId} className="ml-8 mt-1 flex items-start gap-1.5 text-sm font-medium text-danger">
          <Icon name="error" className="mt-0.5 size-4" />
          <span>{error}</span>
        </p>
      ) : null}
    </div>
  );
}
