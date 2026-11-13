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
  render(<App />);
  // P1.16.1: the theme is now applied on <html> (scrollbars/controls follow it), not on <main>.
  const root = document.documentElement;
  const button = screen.getByRole('button', { name: 'Use dark theme' });
  expect(root.getAttribute('data-theme')).toBe('light');
  fireEvent.click(button);
  expect(root.getAttribute('data-theme')).toBe('dark');
  fireEvent.click(screen.getByRole('button', { name: 'Use light theme' }));
  expect(root.getAttribute('data-theme')).toBe('light');
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
});
