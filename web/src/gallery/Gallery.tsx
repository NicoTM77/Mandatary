import type { ReactNode } from 'react';
import { AddressManagement, NoticeHealth } from '../screens/notices';
import { AgentCredentials } from '../screens/agents';
import { HostRecoveryHelp, RecoveryCodes, RestrictedRecovery, SignInMethods, WebAuthnRegister } from '../screens/factors';
import { LoginFactor, LoginPassword, StepUpPanel } from '../screens/login';
import { SETUP_STEPS, SetupAccount, SetupAddresses, SetupClockNotice, SetupComplete, SetupExchange, TotpEnrollment } from '../screens/setup';
import { AdminShell, Alert, AutoFocusContext, Panel, Steps, SyntheticBadge, ThemeToggle, type NavItem } from '../ui';
import { NAV, SYNTHETIC } from './fixtures';
import PolicyGallery from './PolicyGallery';
import RecoveryGallery from './RecoveryGallery';

const noop = () => undefined;

function Specimen({ flow, name, children, wide = false }: { flow: string; name: string; children: ReactNode; wide?: boolean }) {
  return (
    <figure className={`min-w-0 ${wide ? 'xl:col-span-2' : ''}`}>
      <figcaption className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        <span className="rounded bg-sunken px-1.5 py-0.5 font-mono text-xs text-muted">{flow}</span>
        <span className="font-semibold">{name}</span>
        <SyntheticBadge />
      </figcaption>
      <div className="rounded-panel border border-dashed border-line-strong bg-bg p-3 sm:p-4">{children}</div>
    </figure>
  );
}

function Group({ id, title, slice, note, children }: { id: string; title: string; slice: 1 | 2; note?: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="scroll-mt-24 space-y-4">
      <div>
        <h2 id={`${id}-h`} className="text-xl font-semibold">
          {title}
        </h2>
        <p className="text-sm text-muted">
          Slice {slice} · {slice === 1 ? 'setup and sign-in' : 'factors, recovery and step-up'}
          {note ? ` · ${note}` : ''}
        </p>
      </div>
      <div className="grid gap-6 xl:grid-cols-2">{children}</div>
    </section>
  );
}

const INDEX: ReadonlyArray<readonly [string, string]> = [
  ['g-setup-token', 'Setup · token'],
  ['g-setup-progress', 'Setup · progress and clock'],
  ['g-setup-account', 'Setup · account'],
  ['g-setup-addresses', 'Setup · addresses'],
  ['g-totp', 'Authenticator enrolment'],
  ['g-setup-finish', 'Setup · finish'],
  ['g-login', 'Sign in · password'],
  ['g-login-factor', 'Sign in · second factor'],
  ['g-stepup', 'Step-up'],
  ['g-methods', 'Sign-in methods'],
  ['g-webauthn', 'Register a security key'],
  ['g-recovery-codes', 'Recovery codes'],
  ['g-recovery', 'Recovery'],
  ['g-addresses', 'Notification addresses'],
  ['g-notices', 'Notice delivery health'],
  ['g-agent', 'Agent token'],
];

/** Entry used by App when Vite DEV is on and the URL has ?synthetic (states) or ?synthetic=shell. */
export default function GalleryRoot({ view }: { view: string }) {
  if (view.startsWith('policy')) return <PolicyGallery view={view} />;
  if (view.startsWith('recovery')) return <RecoveryGallery view={view} />;
  return view === 'shell' ? <ShellView /> : <StateGallery />;
}

const addr = { maxAddresses: 4, mailConfigured: true, onStartAdd: noop, onSubmitAddress: noop, onSubmitProof: noop, onCancelAdd: noop, onAskRemove: noop, onCancelRemove: noop, onConfirmRemove: noop };
const agent = { agentName: 'ci-runner', onIssue: noop, onRotate: noop, onAskRevoke: noop, onCancelRevoke: noop, onConfirmRevoke: noop, onHidden: noop };

function StateGallery() {
  const f = SYNTHETIC;
  const common = { onSubmit: noop };
  return (
    <AutoFocusContext.Provider value={false}>
      <div className="min-h-screen">
        <header className="border-b border-line bg-surface">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6">
            <div className="min-w-0">
              <h1 className="text-xl font-semibold tracking-tight">Authentication screens: synthetic state gallery</h1>
              <p className="text-sm text-muted">P1.16.1 design baseline. Fixtures only: no server, no real credentials, no working authentication.</p>
            </div>
            <ThemeToggle />
          </div>
        </header>
        <div className="mx-auto max-w-7xl gap-8 px-4 py-6 sm:px-6 lg:grid lg:grid-cols-[13rem_minmax(0,1fr)]">
          <nav aria-label="Screens" className="mb-6 lg:sticky lg:top-4 lg:mb-0 lg:self-start">
            <ul className="flex flex-wrap gap-1.5 lg:block lg:space-y-0.5">
              {INDEX.map(([id, label]) => (
                <li key={id}>
                  <a href={`#${id}`} className="block rounded-control px-2.5 py-1.5 text-sm text-fg hover:bg-sunken lg:min-h-9">
                    {label}
                  </a>
                </li>
              ))}
              <li>
                <a href="?synthetic=shell" className="block rounded-control px-2.5 py-1.5 text-sm font-medium text-accent-text hover:bg-accent-soft">
                  Admin shell view
                </a>
              </li>
            </ul>
          </nav>
          <main id="main-content" tabIndex={-1} className="min-w-0 space-y-12 outline-none">
            <Alert tone="warning" role="none" title="Everything on this page is an illustration">
              Each specimen shows a presentation state, not behaviour that exists. Setup and password/TOTP login have approved services; address management, notice repair and several recovery/WebAuthn routes
              do not have HTTP routes yet. See docs/ui/p1.16-authentication-ux-contract.md for what each state needs before it can be wired.
            </Alert>

            <Group id="g-setup-token" title="Setup · token" slice={1} note="F1">
              <Specimen flow="F1-a" name="Idle"><SetupExchange state={{ kind: 'idle' }} {...common} /></Specimen>
              <Specimen flow="F1-b" name="Submitting"><SetupExchange state={{ kind: 'submitting' }} {...common} /></Specimen>
              <Specimen flow="F1-c" name="Token rejected (wrong, expired or replayed: one message)"><SetupExchange state={{ kind: 'rejected', reason: 'invalid_token' }} {...common} /></Specimen>
              <Specimen flow="F1-d" name="Rate limited"><SetupExchange state={{ kind: 'rejected', reason: 'rate_limited' }} {...common} /></Specimen>
              <Specimen flow="F1-e" name="Setup closed (404)"><SetupExchange state={{ kind: 'closed' }} {...common} /></Specimen>
            </Group>

            <Group id="g-setup-progress" title="Setup · progress and clock" slice={1}>
              <Specimen flow="F1-f" name="Steps, 30 minutes left"><Panel><Steps steps={SETUP_STEPS} currentId="addresses" label="Setup progress" /><SetupClockNotice clock={{ kind: 'active', minutesLeft: 24 }} /></Panel></Specimen>
              <Specimen flow="F1-g" name="Expiring"><SetupClockNotice clock={{ kind: 'expiring', minutesLeft: 4 }} /></Specimen>
              <Specimen flow="F1-h" name="Expired"><SetupClockNotice clock={{ kind: 'expired' }} /></Specimen>
            </Group>

            <Group id="g-setup-account" title="Setup · account" slice={1} note="F1, F3 password manager and paste">
              <Specimen flow="F1-i" name="Initial administrator"><SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'idle' }} {...common} /></Specimen>
              <Specimen flow="F1-j" name="Password rejected (server guidance on the field)"><SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured maxAddresses={4} state={{ kind: 'rejected', reason: 'password_rejected', guidance: f.passwordGuidance }} {...common} /></Specimen>
              <Specimen flow="F1-k" name="Mail relay not configured (blocks)"><SetupAccount purpose="initial_setup" replacePassword={false} mailConfigured={false} maxAddresses={4} state={{ kind: 'idle' }} {...common} /></Specimen>
              <Specimen flow="F6-h" name="Emergency reset: replace password"><SetupAccount purpose="mfa_reset" targetUser={f.username} replacePassword mailConfigured maxAddresses={4} state={{ kind: 'idle' }} {...common} /></Specimen>
            </Group>

            <Group id="g-setup-addresses" title="Setup · addresses" slice={1} note="F1, F7">
              <Specimen flow="F1-l" name="Two addresses, one confirmed"><SetupAddresses addresses={f.setupAddressesMixed} mailConfigured onSendProof={noop} onConfirm={noop} /></Specimen>
              <Specimen flow="F1-m" name="Wrong code, sending, nothing confirmed"><SetupAddresses addresses={f.setupAddressesErrors} mailConfigured onSendProof={noop} onConfirm={noop} /></Specimen>
            </Group>

            <Group id="g-totp" title="Authenticator enrolment" slice={1} note="F1, F4 (the same component serves setup, account security and recovery)">
              <Specimen flow="F4-a" name="Not started"><TotpEnrollment state={{ kind: 'not_started' }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} /></Specimen>
              <Specimen flow="F4-b" name="Key shown once"><TotpEnrollment synthetic state={{ kind: 'seed_shown', seed: f.seed }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} /></Specimen>
              <Specimen flow="F4-c" name="Wrong code"><TotpEnrollment synthetic state={{ kind: 'rejected', reason: 'wrong_code', seed: f.seed }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} /></Specimen>
              <Specimen flow="F4-d" name="Key lost after reload"><TotpEnrollment state={{ kind: 'seed_lost' }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} onRestart={noop} /></Specimen>
              <Specimen flow="F4-e" name="Confirmed"><TotpEnrollment state={{ kind: 'proven' }} algorithmLabel="SHA-256" digits={6} periodSeconds={30} onBegin={noop} onConfirm={noop} /></Specimen>
            </Group>

            <Group id="g-setup-finish" title="Setup · finish" slice={1}>
              <Specimen flow="F1-n" name="Requirements missing"><SetupComplete accountStaged confirmedAddressCount={0} totpProven={false} state={{ kind: 'idle' }} onComplete={noop} signInHref="#" /></Specimen>
              <Specimen flow="F1-o" name="Ready"><SetupComplete accountStaged confirmedAddressCount={1} totpProven state={{ kind: 'idle' }} onComplete={noop} signInHref="#" /></Specimen>
              <Specimen flow="F1-p" name="Complete: no session issued"><SetupComplete accountStaged confirmedAddressCount={2} totpProven state={{ kind: 'done', username: f.username }} onComplete={noop} signInHref="#" /></Specimen>
            </Group>

            <Group id="g-login" title="Sign in · password" slice={1} note="F2, F3">
              <Specimen flow="F2-a" name="Idle"><LoginPassword state={{ kind: 'idle' }} recoveryHref="#g-recovery" {...common} /></Specimen>
              <Specimen flow="F2-b" name="Submitting"><LoginPassword state={{ kind: 'submitting' }} {...common} /></Specimen>
              <Specimen flow="F2-c" name="Denied (identical for every cause)"><LoginPassword state={{ kind: 'rejected', reason: 'denied' }} {...common} /></Specimen>
              <Specimen flow="F2-d" name="Rate limited"><LoginPassword state={{ kind: 'rejected', reason: 'rate_limited' }} {...common} /></Specimen>
              <Specimen flow="F2-e" name="No password-only session possible"><LoginPassword state={{ kind: 'rejected', reason: 'recovery_required' }} {...common} /></Specimen>
            </Group>

            <Group id="g-login-factor" title="Sign in · second factor" slice={1} note="F2">
              <Specimen flow="F2-f" name="Authenticator code, two methods"><LoginFactor next={['totp', 'webauthn']} method="totp" state={{ kind: 'idle' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} /></Specimen>
              <Specimen flow="F2-g" name="Code rejected"><LoginFactor next={['totp']} method="totp" state={{ kind: 'rejected', reason: 'denied' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} /></Specimen>
              <Specimen flow="F2-h" name="Waiting for security key"><LoginFactor next={['totp', 'webauthn']} method="webauthn" state={{ kind: 'webauthn_waiting' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} /></Specimen>
              <Specimen flow="F2-i" name="Security key cancelled"><LoginFactor next={['webauthn']} method="webauthn" state={{ kind: 'rejected', reason: 'webauthn_cancelled' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} /></Specimen>
              <Specimen flow="F2-j" name="Password-only offered (lower assurance)"><LoginFactor next={['totp', 'no-mfa']} method="totp" state={{ kind: 'idle' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onContinuePasswordOnly={noop} onRestart={noop} /></Specimen>
              <Specimen flow="F2-k" name="Preauth timed out"><LoginFactor next={['totp']} method="totp" state={{ kind: 'expired' }} onChooseMethod={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onRestart={noop} /></Specimen>
            </Group>

            <Group id="g-stepup" title="Step-up" slice={2} note="F9">
              <Specimen flow="F9-a" name="Password and code"><StepUpPanel method="totp" actionLabel="Add a security key" username={f.username} state={{ kind: 'idle' }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} /></Specimen>
              <Specimen flow="F9-b" name="Password only (account without a second factor)"><StepUpPanel method="password" actionLabel="Change your password" username={f.username} state={{ kind: 'idle' }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} /></Specimen>
              <Specimen flow="F9-c" name="Security key, waiting"><StepUpPanel method="webauthn" actionLabel="Remove a security key" username={f.username} state={{ kind: 'webauthn_waiting' }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} /></Specimen>
              <Specimen flow="F9-d" name="Verification failed"><StepUpPanel method="totp" actionLabel="Add a security key" username={f.username} state={{ kind: 'rejected', reason: 'denied' }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} /></Specimen>
              <Specimen flow="F9-e" name="No usable method (assurance unavailable)"><StepUpPanel method="totp" actionLabel="Add a security key" username={f.username} state={{ kind: 'unavailable' }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} /></Specimen>
              <Specimen flow="F9-f" name="Verified (request not replayed)"><StepUpPanel method="totp" actionLabel="Add a security key" username={f.username} state={{ kind: 'verified', validMinutes: 15 }} onSubmitPassword={noop} onSubmitTotp={noop} onStartWebAuthn={noop} onDismiss={noop} /></Specimen>
            </Group>

            <Group id="g-methods" title="Sign-in methods" slice={2} note="F4, F5">
              <Specimen flow="F5-a" name="One app, one key"><SignInMethods totp={f.totp} keys={f.keys} maxKeys={16} onAddTotp={noop} onAddKey={noop} onAskRemove={noop} onCancelRemove={noop} onConfirmRemove={noop} /></Specimen>
              <Specimen flow="F5-b" name="Confirm removal, disabled factor"><SignInMethods totp={f.totpDisabled} keys={f.keys} maxKeys={16} confirmingRemoval={{ kind: 'webauthn', id: f.keys[0]?.id ?? '' }} onAddTotp={noop} onAddKey={noop} onAskRemove={noop} onCancelRemove={noop} onConfirmRemove={noop} /></Specimen>
              <Specimen flow="F5-c" name="Empty, key limit reached"><SignInMethods totp={[]} keys={f.keys} maxKeys={1} onAddTotp={noop} onAddKey={noop} onAskRemove={noop} onCancelRemove={noop} onConfirmRemove={noop} /></Specimen>
            </Group>

            <Group id="g-webauthn" title="Register a security key" slice={2} note="F5">
              <Specimen flow="F5-d" name="Idle"><WebAuthnRegister state={{ kind: 'idle' }} {...common} /></Specimen>
              <Specimen flow="F5-e" name="Waiting for key"><WebAuthnRegister state={{ kind: 'waiting' }} {...common} /></Specimen>
              <Specimen flow="F5-f" name="Cancelled or timed out"><WebAuthnRegister state={{ kind: 'rejected', reason: 'webauthn_cancelled' }} {...common} /></Specimen>
              <Specimen flow="F5-g" name="Insecure context"><WebAuthnRegister state={{ kind: 'rejected', reason: 'insecure_context' }} {...common} /></Specimen>
              <Specimen flow="F5-h" name="Registered"><WebAuthnRegister state={{ kind: 'registered' }} {...common} /></Specimen>
            </Group>

            <Group id="g-recovery-codes" title="Recovery codes" slice={2} note="F6">
              <Specimen flow="F6-a" name="None issued"><RecoveryCodes state={{ kind: 'none' }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={noop} /></Specimen>
              <Specimen flow="F6-b" name="Revealed once"><RecoveryCodes synthetic state={{ kind: 'reveal', codes: f.recoveryCodes }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={noop} /></Specimen>
              <Specimen flow="F6-c" name="Issued, 7 unused"><RecoveryCodes state={{ kind: 'issued', remaining: 7 }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={noop} /></Specimen>
              <Specimen flow="F6-d" name="Confirm replacement"><RecoveryCodes state={{ kind: 'confirming_regenerate', remaining: 7 }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={noop} /></Specimen>
            </Group>

            <Group id="g-recovery" title="Recovery" slice={2} note="F6">
              <Specimen flow="F6-e" name="Saved code form"><RestrictedRecovery state={{ kind: 'idle' }} onSubmit={noop} onBeginTotp={noop} onConfirmTotp={noop} signInHref="#" /></Specimen>
              <Specimen flow="F6-f" name="Rejected"><RestrictedRecovery state={{ kind: 'rejected', reason: 'denied' }} onSubmit={noop} onBeginTotp={noop} onConfirmTotp={noop} signInHref="#" /></Specimen>
              <Specimen flow="F6-g" name="Code accepted: add a new authenticator"><RestrictedRecovery state={{ kind: 'capability', minutesLeft: 8, totp: { kind: 'seed_shown', seed: f.seed } }} onSubmit={noop} onBeginTotp={noop} onConfirmTotp={noop} signInHref="#" /></Specimen>
              <Specimen flow="F6-i" name="Completed"><RestrictedRecovery state={{ kind: 'completed' }} onSubmit={noop} onBeginTotp={noop} onConfirmTotp={noop} signInHref="#" /></Specimen>
              <Specimen flow="F6-j" name="Everything lost: host-local only"><HostRecoveryHelp /></Specimen>
            </Group>

            <Group id="g-addresses" title="Notification addresses" slice={2} note="F7 (no HTTP route exists yet)">
              <Specimen flow="F7-a" name="Two confirmed addresses"><AddressManagement {...addr} addresses={f.managedAddresses} state={{ kind: 'idle' }} /></Specimen>
              <Specimen flow="F7-b" name="Only one confirmed (cannot be removed)"><AddressManagement {...addr} addresses={f.managedOne} state={{ kind: 'idle' }} /></Specimen>
              <Specimen flow="F7-c" name="Add: enter address"><AddressManagement {...addr} addresses={f.managedAddresses} state={{ kind: 'adding', step: 'enter' }} /></Specimen>
              <Specimen flow="F7-d" name="Add: enter code, wrong code"><AddressManagement {...addr} addresses={f.managedAddresses} state={{ kind: 'adding', step: 'proof', pendingAddress: 'new@example.invalid', error: 'wrong_code' }} /></Specimen>
              <Specimen flow="F7-e" name="Confirm removal"><AddressManagement {...addr} addresses={f.managedAddresses} state={{ kind: 'confirming_removal', id: 'm2' }} /></Specimen>
              <Specimen flow="F7-f" name="Maximum reached, one unconfirmed"><AddressManagement {...addr} addresses={f.managedPending} state={{ kind: 'idle' }} /></Specimen>
              <Specimen flow="F7-g" name="Mail relay not configured"><AddressManagement {...addr} addresses={f.managedAddresses} state={{ kind: 'idle' }} mailConfigured={false} /></Specimen>
              <Specimen flow="F7-h" name="Needs fresh verification"><AddressManagement {...addr} addresses={f.managedAddresses} state={{ kind: 'rejected', reason: 'denied' }} /></Specimen>
            </Group>

            <Group id="g-notices" title="Notice delivery health" slice={2} note="F8 (aggregate counts only)">
              <Specimen flow="F8-a" name="Healthy"><NoticeHealth health={{ pending: 0, failed: 0, bounced: 0, quarantined: 0, protective: 0 }} /></Specimen>
              <Specimen flow="F8-b" name="Waiting to be sent"><NoticeHealth health={{ pending: 2, failed: 0, bounced: 0, quarantined: 0, protective: 0 }} /></Specimen>
              <Specimen flow="F8-c" name="Failed and bounced (retry offered)"><NoticeHealth health={{ pending: 1, failed: 2, bounced: 1, quarantined: 0, protective: 0 }} onRetry={noop} /></Specimen>
              <Specimen flow="F8-d" name="Security change without a recorded notice"><NoticeHealth health={{ pending: 0, failed: 0, bounced: 0, quarantined: 0, protective: 1 }} /></Specimen>
              <Specimen flow="F8-e" name="Status unreadable (never shown as healthy)"><NoticeHealth health={{ pending: 0, failed: 0, bounced: 0, quarantined: 0, protective: 0, unknown: true }} /></Specimen>
            </Group>

            <Group id="g-agent" title="Agent token" slice={2} note="F10 (P1.10 routes exist)">
              <Specimen flow="F10-a" name="One active token"><AgentCredentials {...agent} credentials={f.credentials} state={{ kind: 'idle' }} /></Specimen>
              <Specimen flow="F10-b" name="Issued: revealed once"><AgentCredentials {...agent} synthetic credentials={f.credentials} state={{ kind: 'reveal', token: f.token, expiresOn: '11 Feb 2027' }} /></Specimen>
              <Specimen flow="F10-c" name="Rotated: overlap window"><AgentCredentials {...agent} synthetic credentials={f.credentialsRotating} state={{ kind: 'reveal', token: f.token, expiresOn: '11 Feb 2027', rotatedOutDisplayId: 'mdt_a1b2…' }} /></Specimen>
              <Specimen flow="F10-d" name="Confirm revoke"><AgentCredentials {...agent} credentials={f.credentialsRotating} state={{ kind: 'confirming_revoke', id: 'c1' }} /></Specimen>
              <Specimen flow="F10-e" name="No tokens yet"><AgentCredentials {...agent} credentials={[]} state={{ kind: 'idle' }} /></Specimen>
              <Specimen flow="F10-f" name="Needs fresh verification"><AgentCredentials {...agent} credentials={f.credentials} state={{ kind: 'rejected', reason: 'step_up_required' }} /></Specimen>
            </Group>
          </main>
        </div>
      </div>
    </AutoFocusContext.Provider>
  );
}

/** Full-page admin shell with a composed Account security page, for layout and responsive review. */
function ShellView() {
  const f = SYNTHETIC;
  const nav: readonly NavItem[] = NAV;
  return (
    <AutoFocusContext.Provider value={false}>
      <AdminShell nav={nav} currentId="security" account={{ username: f.username, assurance: 'aal2', freshnessNote: 'Verified 4 minutes ago' }} onSignOut={noop}>
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <SyntheticBadge>Synthetic shell view: nothing here is connected</SyntheticBadge>
          <a href="?synthetic" className="text-sm font-medium text-accent-text underline underline-offset-2">
            Back to state gallery
          </a>
        </div>
        <div className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight">Account security</h1>
          <p className="mt-1.5 max-w-prose text-muted">Your sign-in methods, recovery options and where security notices are sent.</p>
        </div>
        <div className="space-y-6">
          <NoticeHealth health={{ pending: 0, failed: 2, bounced: 1, quarantined: 0, protective: 0 }} onRetry={noop} />
          <SignInMethods totp={f.totp} keys={f.keys} maxKeys={16} onAddTotp={noop} onAddKey={noop} onAskRemove={noop} onCancelRemove={noop} onConfirmRemove={noop} />
          <RecoveryCodes state={{ kind: 'issued', remaining: 7 }} onIssue={noop} onAskRegenerate={noop} onCancelRegenerate={noop} onConfirmRegenerate={noop} onHidden={noop} />
          <AddressManagement addresses={f.managedAddresses} maxAddresses={4} state={{ kind: 'idle' }} mailConfigured onStartAdd={noop} onSubmitAddress={noop} onSubmitProof={noop} onCancelAdd={noop} onAskRemove={noop} onCancelRemove={noop} onConfirmRemove={noop} />
        </div>
      </AdminShell>
    </AutoFocusContext.Provider>
  );
}
