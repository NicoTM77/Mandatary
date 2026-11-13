import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { App, routeFor } from './App';

// Nothing here may reach a server: the real flows are covered against fake adapters in
// containers/containers.test.tsx and against the real services in the browser tests.
beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(new Response(JSON.stringify({ error: 'unauthenticated' }), { status: 401, headers: { 'Content-Type': 'application/json' } }))),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test('the path chooses the view, and only the three served document routes are views', () => {
  expect([routeFor('/'), routeFor('/setup'), routeFor('/login')]).toEqual(['home', 'setup', 'login']);
  for (const path of ['', '/setup/', '/login/', '/Setup', '/admin', '/setup/exchange', '//setup', '/index.html']) expect(routeFor(path)).toBe('unknown');
});

test('an unknown address is a dead end that links only to sign-in and offers no product controls', () => {
  render(<App path="/somewhere-else" />);
  expect(screen.getByRole('heading', { name: 'Mandatary' })).toBeTruthy();
  expect(screen.getByText('Nothing is here')).toBeTruthy();
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(screen.getAllByRole('link').map((link) => link.getAttribute('href'))).toEqual(['#main-content', '/login']);
});

test('the login view offers sign-in only', () => {
  render(<App path="/login" />);
  expect(screen.getByRole('form', { name: 'Sign in' })).toBeTruthy();
  expect(screen.queryByRole('link', { name: /containers|policy/i })).toBeNull();
});

test('switches between light and dark without storing credentials or fetching data', () => {
  render(<App path="/somewhere-else" />);
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
  expect(fetch).not.toHaveBeenCalled();
});
