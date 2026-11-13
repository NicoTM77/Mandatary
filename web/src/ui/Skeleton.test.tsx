import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { Skeleton } from './Skeleton';

afterEach(cleanup);

function lines(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>('[data-skeleton-line]'));
}

test('announces a visible loading message as a polite busy status', () => {
  render(<Skeleton label="addresses" />);
  const status = screen.getByRole('status');
  expect(status.textContent).toContain('Loading addresses…');
  expect(status.getAttribute('aria-busy')).toBe('true');
  expect(screen.getByText('Loading addresses…')).toBeTruthy();
});

test('defaults to three placeholder lines and honours an explicit count', () => {
  const first = render(<Skeleton label="notices" />);
  expect(lines(first.container)).toHaveLength(3);
  first.unmount();

  const second = render(<Skeleton label="notices" lines={5} />);
  expect(lines(second.container)).toHaveLength(5);
});

test('line count is clamped to 1–10 so a bad value cannot blank or flood the layout', () => {
  const low = render(<Skeleton label="x" lines={0} />);
  expect(lines(low.container)).toHaveLength(1);
  low.unmount();

  const nan = render(<Skeleton label="x" lines={Number.NaN} />);
  expect(lines(nan.container)).toHaveLength(3);
  nan.unmount();

  const high = render(<Skeleton label="x" lines={50} />);
  expect(lines(high.container)).toHaveLength(10);
});

test('placeholder blocks are hidden from assistive technology and carry no focusable content', () => {
  const { container } = render(<Skeleton label="factors" lines={2} />);
  for (const line of lines(container)) {
    // The wrapper carries aria-hidden, which hides every block inside it from the accessibility tree.
    expect(line.closest('[aria-hidden="true"]')).not.toBeNull();
  }
  expect(container.querySelector('button, a, input, [tabindex]')).toBeNull();
});

test('shimmer is gated on the motion-safe variant; reduced motion gets static blocks', () => {
  const { container } = render(<Skeleton label="factors" />);
  for (const line of lines(container)) {
    expect(line.classList.contains('motion-safe:animate-pulse')).toBe(true);
    expect(line.classList.contains('animate-pulse')).toBe(false);
  }
});

test('placeholders have a fixed height and no inline style, so the layout cannot jump', () => {
  const { container } = render(<Skeleton label="factors" />);
  for (const line of lines(container)) {
    expect(line.hasAttribute('style')).toBe(false);
    expect(line.classList.contains('h-4')).toBe(true);
  }
});
