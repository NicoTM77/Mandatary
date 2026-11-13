import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { AutoFocusContext, CheckboxField, ConfirmPanel, Disclosure, RadioGroup, SelectField } from '.';

afterEach(cleanup);

// ───────────────────────── SelectField ─────────────────────────

test('a select has a visible label, a hint and an error linked through aria-describedby, and is a native control', () => {
  render(<SelectField name="owner" label="Owner" hint="Pick one" error="Choose an owner." options={[{ value: 'a', label: 'Ada' }]} placeholder="Choose an owner" />);
  const select = screen.getByLabelText('Owner') as HTMLSelectElement;
  expect(select.tagName).toBe('SELECT');
  expect(select.getAttribute('aria-invalid')).toBe('true');
  const described = (select.getAttribute('aria-describedby') ?? '').split(' ').map((id) => document.getElementById(id)?.textContent);
  expect(described).toEqual(['Pick one', 'Choose an owner.']);
  expect(select.getAttribute('role')).toBeNull();
});

test('a placeholder is a real empty option that is selected first, so "nothing chosen" is submitted as the empty string', () => {
  render(<SelectField name="owner" label="Owner" options={[{ value: 'a', label: 'Ada' }]} placeholder="Choose an owner" />);
  const select = screen.getByLabelText('Owner') as HTMLSelectElement;
  expect(select.value).toBe('');
  expect(within(select).getAllByRole('option').map((option) => option.textContent)).toEqual(['Choose an owner', 'Ada']);
});

test('grouped options render as labelled optgroups and a disabled option stays visible with its reason in the label', () => {
  render(
    <SelectField
      name="member"
      label="Add a member"
      groups={[
        { label: 'Users', options: [{ value: 'user:1', label: 'ada' }] },
        { label: 'Agents', options: [{ value: 'agent:1', label: 'ci-runner (disabled)', disabled: true }] },
      ]}
    />,
  );
  const select = screen.getByLabelText('Add a member');
  expect(select.querySelectorAll('optgroup')).toHaveLength(2);
  expect(Array.from(select.querySelectorAll('optgroup'), (group) => group.label)).toEqual(['Users', 'Agents']);
  expect((within(select).getByRole('option', { name: 'ci-runner (disabled)' }) as HTMLOptionElement).disabled).toBe(true);
});

// ───────────────────────── RadioGroup ─────────────────────────

const effects = [
  { value: 'allow', label: 'Allow', hint: 'Lets the subject do this.' },
  { value: 'deny', label: 'Deny', hint: 'Always wins over an Allow.' },
] as const;

test('a radio group is a fieldset with a legend, native radios sharing one name, and a hint per option', () => {
  render(<RadioGroup name="effect" legend="Decision" options={effects} defaultValue="allow" />);
  const group = screen.getByRole('group', { name: 'Decision' });
  expect(group.tagName).toBe('FIELDSET');
  const radios = within(group).getAllByRole('radio') as HTMLInputElement[];
  expect(radios.map((radio) => radio.name)).toEqual(['effect', 'effect']);
  expect(radios.map((radio) => radio.checked)).toEqual([true, false]);
  const hint = document.getElementById(radios[1]?.getAttribute('aria-describedby') ?? '');
  expect(hint?.textContent).toBe('Always wins over an Allow.');
});

test('selecting a radio reports the value once; a group error is linked to the fieldset', () => {
  const onChange = vi.fn();
  render(<RadioGroup name="effect" legend="Decision" options={effects} error="Choose a decision." onChange={onChange} />);
  fireEvent.click(screen.getByRole('radio', { name: /Deny/ }));
  expect(onChange).toHaveBeenCalledExactlyOnceWith('deny');
  const group = screen.getByRole('group', { name: 'Decision' });
  expect(group.getAttribute('aria-invalid')).toBeNull();
  expect(document.getElementById(group.getAttribute('aria-describedby') ?? '')?.textContent).toBe('Choose a decision.');
});

test('a disabled radio option keeps its label and its reason visible', () => {
  render(<RadioGroup name="owner" legend="Owner" options={[{ value: 'user', label: 'A user' }, { value: 'group', label: 'A group', hint: 'There are no groups yet.', disabled: true }]} />);
  const radio = screen.getByRole('radio', { name: /A group/ }) as HTMLInputElement;
  expect(radio.disabled).toBe(true);
  expect(screen.getByText('There are no groups yet.')).toBeTruthy();
});

// ───────────────────────── CheckboxField ─────────────────────────

test('a checkbox is native, labelled, hinted, and reports the new state', () => {
  const onChange = vi.fn();
  render(<CheckboxField name="pattern" label="Match as a pattern" hint="Use * and ?" onChange={onChange} />);
  const box = screen.getByLabelText(/^Match as a pattern/) as HTMLInputElement;
  expect(box.type).toBe('checkbox');
  expect(document.getElementById(box.getAttribute('aria-describedby') ?? '')?.textContent).toBe('Use * and ?');
  // The hint sits inside the clickable label, so it is part of the control's visible name block and never detached from it.
  expect(box.closest('label')?.textContent).toContain('Use * and ?');
  fireEvent.click(box);
  expect(onChange).toHaveBeenCalledExactlyOnceWith(true);
});

// ───────────────────────── ConfirmPanel ─────────────────────────

function panel(props: Partial<Parameters<typeof ConfirmPanel>[0]> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <div>
      <button id="trigger" type="button">
        Remove
      </button>
      <ConfirmPanel title="Remove Ada?" confirmLabel="Remove Ada" onConfirm={onConfirm} onCancel={onCancel} returnFocusId="trigger" {...props}>
        She stops receiving access straight away.
      </ConfirmPanel>
    </div>,
  );
  return { onConfirm, onCancel };
}

test('a confirmation is a named group that states the consequence and offers a named confirm and "Keep it"', () => {
  panel();
  const group = screen.getByRole('group', { name: 'Remove Ada?' });
  expect(group.textContent).toContain('She stops receiving access straight away.');
  expect(within(group).getByRole('button', { name: 'Remove Ada' })).toBeTruthy();
  expect(within(group).getByRole('button', { name: 'Keep it' })).toBeTruthy();
});

test('focus moves to the confirmation when it appears, but not when auto-focus is off (the gallery)', () => {
  panel();
  expect(document.activeElement).toBe(screen.getByRole('group', { name: 'Remove Ada?' }));
  cleanup();
  render(
    <AutoFocusContext.Provider value={false}>
      <ConfirmPanel title="Remove Ada?" confirmLabel="Remove Ada" onConfirm={() => undefined} onCancel={() => undefined}>
        x
      </ConfirmPanel>
    </AutoFocusContext.Provider>,
  );
  expect(document.activeElement).toBe(document.body);
});

test('Escape cancels and returns focus to the control that opened it; Keep it does the same', () => {
  const { onCancel } = panel();
  fireEvent.keyDown(screen.getByRole('group', { name: 'Remove Ada?' }), { key: 'Escape' });
  expect(onCancel).toHaveBeenCalledTimes(1);
  expect(document.activeElement).toBe(document.getElementById('trigger'));
  fireEvent.click(screen.getByRole('button', { name: 'Keep it' }));
  expect(onCancel).toHaveBeenCalledTimes(2);
});

test('the confirm button is outlined danger, never the first control, and confirming calls once', () => {
  const { onConfirm } = panel();
  const buttons = within(screen.getByRole('group', { name: 'Remove Ada?' })).getAllByRole('button');
  expect(buttons.map((button) => button.textContent)).toEqual(['Remove Ada', 'Keep it']);
  fireEvent.click(buttons[0] as HTMLElement);
  expect(onConfirm).toHaveBeenCalledTimes(1);
  expect(document.activeElement).not.toBe(buttons[0]);
});

test('while busy, Escape and Keep it do nothing and the confirm button announces progress without losing focus', () => {
  const { onCancel, onConfirm } = panel({ busy: true, busyLabel: 'Removing…' });
  fireEvent.keyDown(screen.getByRole('group', { name: 'Remove Ada?' }), { key: 'Escape' });
  expect(onCancel).not.toHaveBeenCalled();
  const keep = screen.getByRole('button', { name: 'Keep it' }) as HTMLButtonElement;
  fireEvent.click(keep);
  expect(onCancel).not.toHaveBeenCalled();
  const confirm = screen.getByRole('button', { name: 'Removing…' });
  expect(confirm.getAttribute('aria-busy')).toBe('true');
  fireEvent.click(confirm);
  expect(onConfirm).not.toHaveBeenCalled();
});

test('a warning confirmation (for changes that loosen access) is not styled as destructive', () => {
  panel({ tone: 'warning' });
  const group = screen.getByRole('group', { name: 'Remove Ada?' });
  expect(group.className).toContain('border-warn');
  expect(group.className).not.toContain('border-danger');
});

// ───────────────────────── Disclosure ─────────────────────────

test('a disclosure is a native details with a visible summary; "open" only opens it and never shuts one the person opened', () => {
  const { rerender } = render(<Disclosure summary="Identity checks">body</Disclosure>);
  const details = screen.getByText('Identity checks').closest('details') as HTMLDetailsElement;
  expect(details.open).toBe(false);
  expect(details.querySelector('summary svg')).not.toBeNull();
  rerender(<Disclosure summary="Identity checks" open>body</Disclosure>);
  expect(details.open).toBe(true);
  rerender(<Disclosure summary="Identity checks" open={false}>body</Disclosure>);
  expect(details.open).toBe(true);
  details.open = false;
  fireEvent(details, new Event('toggle'));
  rerender(<Disclosure summary="Identity checks" open={false}>body</Disclosure>);
  expect(details.open).toBe(false);
});
