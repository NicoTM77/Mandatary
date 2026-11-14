/**
 * Inline SVG icons. The CSP forbids data: and external images, so icons are DOM elements.
 * Every icon is decorative (aria-hidden): meaning is always carried by adjacent text,
 * never by an icon or colour alone (WCAG 1.4.1 / 1.1.1).
 */
const PATH_DATA = {
  check: 'M5 12.5l4.5 4.5L19 7.5',
  alert: 'M12 4l9 16H3L12 4zM12 10v4.5M12 17.5v.01',
  info: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 11v5M12 8v.01',
  error: 'M12 21a9 9 0 100-18 9 9 0 000 18zM9 9l6 6M15 9l-6 6',
  copy: 'M9 9h10v11H9zM5 15V4h10',
  eye: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12zM12 14.5a2.5 2.5 0 100-5 2.5 2.5 0 000 5z',
  'eye-off': 'M3 3l18 18M10.6 6a9.8 9.8 0 011.4-.5c6 0 9.5 6.5 9.5 6.5a16 16 0 01-2.9 3.7M6.6 7.6A16 16 0 002.5 12S6 18.5 12 18.5c1.5 0 2.8-.4 4-.9',
  key: 'M8 11.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7zM10.5 12.5L20 3M16 7l3 3M13.5 9.5l2 2',
  shield: 'M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6l8-3zM9 12l2.2 2.2L15.5 10',
  sun: 'M12 16a4 4 0 100-8 4 4 0 000 8zM12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4',
  moon: 'M20 14.5A8.5 8.5 0 019.5 4 8.5 8.5 0 1020 14.5z',
  menu: 'M4 7h16M4 12h16M4 17h16',
  mail: 'M3.5 6.5h17v11h-17zM4 7l8 6 8-6',
  phone: 'M8 3h8a1 1 0 011 1v16a1 1 0 01-1 1H8a1 1 0 01-1-1V4a1 1 0 011-1zM11 18h2',
  usb: 'M12 3v13M12 16a2 2 0 100 4 2 2 0 000-4zM12 9l4 3v3M12 12L8 9.5M16 15.5a1 1 0 100 2 1 1 0 000-2zM7 8h2v2H7z',
  clock: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3 2',
  lock: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 017 0v3',
  trash: 'M4 7h16M9 7V4h6v3M6.5 7l1 13h9l1-13M10 11v6M14 11v6',
  plus: 'M12 5v14M5 12h14',
  list: 'M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01',
  user: 'M12 12a4 4 0 100-8 4 4 0 000 8zM4.5 20a7.5 7.5 0 0115 0',
  logout: 'M10 4H5v16h5M15 8l4 4-4 4M19 12H9',
  ban: 'M12 21a9 9 0 100-18 9 9 0 000 18zM5.6 5.6l12.8 12.8',
  users: 'M9 11.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM2.5 20a6.5 6.5 0 0113 0M16 4.8a3.5 3.5 0 010 6.4M18 14a6.5 6.5 0 013.5 6',
  edit: 'M4 20l1-4L16.5 4.5a2 2 0 012.8 0l.2.2a2 2 0 010 2.8L8 19l-4 1zM14.5 6.5l3 3',
  box: 'M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3zM4 7.5l8 4.5 8-4.5M12 12v9',
  chevron: 'M9 6l6 6-6 6',
  download: 'M12 4v11M7.5 11l4.5 4.5 4.5-4.5M5 19.5h14',
  upload: 'M12 15V4M7.5 8L12 3.5 16.5 8M5 19.5h14',
  bot: 'M12 3v3M7 8h10a2 2 0 012 2v6a2 2 0 01-2 2H7a2 2 0 01-2-2v-6a2 2 0 012-2zM9.5 12.5v.01M14.5 12.5v.01M9 21h6',
} as const;

export type IconName = keyof typeof PATH_DATA | 'spinner';

// A Map (not bracket access) keeps the lookup free of object-injection patterns.
const PATHS = new Map<string, string>(Object.entries(PATH_DATA));

export function Icon({ name, className = 'size-5' }: { name: IconName; className?: string }) {
  if (name === 'spinner') {
    return (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false" className={`mdt-spin ${className}`}>
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2.5" />
        <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
      </svg>
    );
  }
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={`shrink-0 ${className}`}
    >
      <path d={PATHS.get(name)} />
    </svg>
  );
}
