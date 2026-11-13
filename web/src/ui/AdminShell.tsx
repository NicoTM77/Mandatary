import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { Badge } from './Alert';
import { Button } from './Button';
import { Icon, type IconName } from './Icon';
import { ThemeToggle } from './ThemeToggle';

export interface NavItem {
  id: string;
  label: string;
  /** Real document/route URL. Navigation is always an <a>, so middle-click and copy-link work. */
  href: string;
  icon?: IconName;
  /** Items with the same group render under one small heading (P1.16 "Account", P1.17 "Policy", P1.18 "Recovery"). */
  group?: string;
}

export interface AccountSummary {
  username: string;
  /** Server-derived label (GET session → assurance). The UI never computes or upgrades it. */
  assurance: 'password-only' | 'aal2';
  /** Pre-formatted by the container, e.g. "Recent verification valid for 11 more minutes". */
  freshnessNote?: string;
}

export interface AdminShellProps {
  nav: readonly NavItem[];
  currentId: string;
  /** Present once a session exists; absent on pre-session screens (setup/login render without the shell). */
  account?: AccountSummary;
  onSignOut?: () => void;
  signingOut?: boolean;
  children: ReactNode;
}

function groupItems(nav: readonly NavItem[]): Array<{ group: string | undefined; items: NavItem[] }> {
  const groups: Array<{ group: string | undefined; items: NavItem[] }> = [];
  for (const item of nav) {
    const last = groups.at(-1);
    if (last && last.group === item.group) last.items.push(item);
    else groups.push({ group: item.group, items: [item] });
  }
  return groups;
}

/**
 * Shared admin shell for P1.16–18: skip link, sidebar navigation (collapsing to a menu button
 * below the lg breakpoint), a session strip with the server-derived assurance label, theme toggle
 * and sign out. Landmarks: nav "Primary", main #main-content. It performs no routing, fetching or
 * authorisation; items the user may not use are simply not passed in (and the server enforces
 * regardless — hiding a link is never access control).
 */
export function AdminShell({ nav, currentId, account, onSignOut, signingOut = false, children }: AdminShellProps) {
  const [open, setOpen] = useState(false);
  const navId = useId();
  const toggle = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        toggle.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[15.5rem_minmax(0,1fr)]">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      <div className="border-b border-line bg-surface lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:border-r lg:border-b-0">
        <div className="flex h-14 items-center justify-between gap-3 px-4 lg:h-16">
          <p className="flex items-center gap-2 text-base font-semibold tracking-tight">
            <span className="grid size-8 place-items-center rounded-control bg-accent text-accent-fg">
              <Icon name="shield" className="size-5" />
            </span>
            Mandatary
          </p>
          <button
            ref={toggle}
            type="button"
            aria-expanded={open}
            aria-controls={navId}
            onClick={() => setOpen((value) => !value)}
            className="inline-flex min-h-11 items-center gap-2 rounded-control border border-line-strong px-3 text-sm font-medium hover:bg-sunken lg:hidden"
          >
            <Icon name="menu" />
            Menu
          </button>
        </div>
        <nav id={navId} aria-label="Primary" className={`${open ? 'block' : 'hidden'} px-3 pb-4 lg:block`}>
          {groupItems(nav).map(({ group, items }) => (
            <div key={group ?? 'ungrouped'} className="mt-3 first:mt-1">
              {group ? <p className="px-3 pb-1 text-xs font-semibold text-subtle">{group}</p> : null}
              <ul className="space-y-0.5">
                {items.map((item) => {
                  const current = item.id === currentId;
                  return (
                    <li key={item.id}>
                      <a
                        href={item.href}
                        aria-current={current ? 'page' : undefined}
                        onClick={() => setOpen(false)}
                        className={`flex min-h-11 items-center gap-2.5 rounded-control px-3 text-[0.9375rem] transition-colors duration-150 ${current ? 'bg-accent-soft font-semibold text-accent-text' : 'text-fg hover:bg-sunken'}`}
                      >
                        {item.icon ? <Icon name={item.icon} /> : null}
                        {item.label}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
      </div>

      <div className="min-w-0">
        <header className="sticky top-0 z-30 flex min-h-14 flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-line bg-surface/92 px-4 py-2 backdrop-blur-md sm:px-6 lg:h-16">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
            {account ? (
              <>
                <p className="flex items-center gap-1.5 truncate font-medium">
                  <Icon name="user" className="size-4 text-muted" />
                  <span className="truncate">{account.username}</span>
                </p>
                {account.assurance === 'aal2' ? (
                  <Badge tone="success" icon="shield">
                    Multi-factor verified
                  </Badge>
                ) : (
                  <Badge tone="warning" icon="alert">
                    Password only
                  </Badge>
                )}
                {account.freshnessNote ? <span className="text-sm text-muted">{account.freshnessNote}</span> : null}
              </>
            ) : (
              <p className="text-sm text-muted">Not signed in</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            {account && onSignOut ? (
              <Button variant="secondary" icon="logout" busy={signingOut} busyLabel="Signing out…" onClick={onSignOut}>
                Sign out
              </Button>
            ) : null}
          </div>
        </header>
        <main id="main-content" tabIndex={-1} className="mx-auto w-full max-w-5xl px-4 py-6 outline-none sm:px-6 sm:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}

/**
 * Centered single-column frame for pre-session screens (setup, login, recovery). No navigation:
 * there is nothing to navigate to before authentication.
 */
export function CenteredFrame({ children, width = 'max-w-md' }: { children: ReactNode; width?: 'max-w-md' | 'max-w-xl' }) {
  return (
    <div className="min-h-screen">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <div className="flex justify-end px-4 pt-4 sm:px-6">
        <ThemeToggle />
      </div>
      <main id="main-content" tabIndex={-1} className={`mx-auto w-full ${width} px-4 pb-16 pt-6 outline-none sm:pt-12`}>
        <p className="mb-6 flex items-center justify-center gap-2 text-lg font-semibold tracking-tight">
          <span className="grid size-9 place-items-center rounded-control bg-accent text-accent-fg">
            <Icon name="shield" className="size-5" />
          </span>
          Mandatary
        </p>
        {children}
      </main>
    </div>
  );
}
