import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, test } from 'vitest';
import { App } from './App';

afterEach(cleanup);

test('identifies the skeleton without offering unimplemented product controls', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: 'Mandatary' })).toBeTruthy();
  expect(screen.getByText(/authentication and container operations are not available/i)).toBeTruthy();
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(screen.queryByRole('link', { name: /login|containers|policy/i })).toBeNull();
});

test('switches between light and dark without storing credentials or fetching data', () => {
  const { container } = render(<App />);
  const button = screen.getByRole('button', { name: 'Use dark theme' });
  expect(container.querySelector('main')?.getAttribute('data-theme')).toBe('light');
  fireEvent.click(button);
  expect(container.querySelector('main')?.getAttribute('data-theme')).toBe('dark');
  fireEvent.click(screen.getByRole('button', { name: 'Use light theme' }));
  expect(container.querySelector('main')?.getAttribute('data-theme')).toBe('light');
  expect(localStorage.length).toBe(0);
});
