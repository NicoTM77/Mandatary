import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { EmptyState } from './EmptyState';

afterEach(cleanup);

test('the title is a heading at level 2 by default and follows headingLevel', () => {
  const { unmount } = render(<EmptyState title="No tokens yet" />);
  expect(screen.getByRole('heading', { level: 2, name: 'No tokens yet' })).toBeTruthy();
  unmount();

  render(<EmptyState title="No addresses" headingLevel={3} />);
  expect(screen.getByRole('heading', { level: 3, name: 'No addresses' })).toBeTruthy();
});

test('shows the explanation as text and renders no action when none is given', () => {
  render(<EmptyState title="No tokens yet" description="Issue one so this agent can call the API." />);
  expect(screen.getByText('Issue one so this agent can call the API.')).toBeTruthy();
  expect(screen.queryByRole('button')).toBeNull();
});

test('the action is a native button that fires once per click and defaults to type=button', () => {
  const onClick = vi.fn();
  render(<EmptyState title="No keys" action={{ label: 'Add a security key', onClick }} />);
  const button = screen.getByRole('button', { name: 'Add a security key' });
  expect(button.tagName).toBe('BUTTON');
  expect(button.getAttribute('type')).toBe('button');
  fireEvent.click(button);
  expect(onClick).toHaveBeenCalledTimes(1);
});

test('renders no images, so the empty state stays within the CSP and carries no illustration', () => {
  const { container } = render(<EmptyState title="Nothing here" description="Text only." action={{ label: 'Go', onClick: () => {} }} />);
  expect(container.querySelector('img, svg[role="img"], picture')).toBeNull();
  expect(container.querySelector('[style]')).toBeNull();
});
