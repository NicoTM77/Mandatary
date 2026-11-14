/**
 * Presentation contract for the P1.16 authentication screens (P1.16.1).
 *
 * Every screen is a STATELESS function of (`state`, data props, callbacks). Containers (written by
 * P1.16.3 / P1.16.4) own fetching, CSRF, cookies, timers, routing and every security decision, and
 * translate server outcomes into these presentation states using the mapping tables in
 * docs/ui/p1.16-authentication-ux-contract.md. Nothing here performs I/O.
 *
 * Reasons are PRESENTATION reasons, not API codes: the container maps e.g. HTTP 401 `invalid_token`
 * to `{ kind: 'rejected', reason: 'invalid_token' }`. A reason never carries server text except
 * `password_rejected.guidance`, which is a fixed server string that is rendered as TEXT (never HTML).
 *
 * Secrets: callbacks receive typed values once, at submit time, read from UNCONTROLLED inputs via
 * FormData. A screen never keeps a password, code or token in React state, and a rejected submit
 * clears secret inputs (the container re-renders with a fresh `key`).
 */

export type Phase = { kind: 'idle' } | { kind: 'submitting' };

/** Failure reasons shared by every network-backed form. */
export type CommonReason = 'rate_limited' | 'unavailable' | 'invalid_request';

// ───────────────────────── Slice 1 · setup ─────────────────────────

export type SetupPurpose = 'initial_setup' | 'mfa_reset' | 'restore_recovery';

export type SetupExchangeState = Phase | { kind: 'rejected'; reason: 'invalid_token' | CommonReason } | { kind: 'closed' };

export interface SetupExchangeProps {
  state: SetupExchangeState;
  /** Receives the pasted token exactly once. The field is cleared whether or not the exchange succeeds. */
  onSubmit: (values: { token: string }) => void;
}

/** 30-minute absolute deadline shown on every setup screen. The container owns the timer. */
export type SetupClock = { kind: 'active'; minutesLeft: number } | { kind: 'expiring'; minutesLeft: number } | { kind: 'expired' };

export type AccountFormState = Phase | { kind: 'rejected'; reason: 'password_rejected'; guidance: string } | { kind: 'rejected'; reason: 'denied' | CommonReason };

export interface AccountFormValues {
  username: string;
  password: string;
  addresses: string[];
}

export interface SetupAccountProps {
  purpose: SetupPurpose;
  /** mfa_reset only: the existing administrator this ceremony is bound to. Shown read-only. */
  targetUser?: string;
  /** mfa_reset only: when false the password step is skipped entirely and the screen is not rendered. */
  replacePassword: boolean;
  /** false → address proof mails cannot be sent: the screen blocks with an operator-facing explanation. */
  mailConfigured: boolean;
  /** Maximum number of notification addresses (setup accepts 1–4). */
  maxAddresses: number;
  state: AccountFormState;
  onSubmit: (values: AccountFormValues) => void;
}

export type ProofState = { kind: 'idle' } | { kind: 'sending' } | { kind: 'sent' } | { kind: 'confirming' } | { kind: 'error'; reason: 'wrong_code' | CommonReason };

export interface AddressRow {
  id: string;
  address: string;
  confirmed: boolean;
  proof: ProofState;
}

export interface SetupAddressesProps {
  addresses: readonly AddressRow[];
  mailConfigured: boolean;
  onSendProof: (id: string) => void;
  onConfirm: (id: string, code: string) => void;
}

export type TotpEnrollState =
  | { kind: 'not_started' }
  | { kind: 'starting' }
  /** `seed` is shown exactly once and is dropped by the container as soon as the state leaves `seed_shown`/`confirming`/`rejected`. */
  | { kind: 'seed_shown'; seed: string }
  | { kind: 'confirming'; seed: string }
  | { kind: 'rejected'; reason: 'wrong_code' | CommonReason; seed: string }
  /** Enrollment was begun but the seed can no longer be shown (page reloaded). It is never re-displayed. */
  | { kind: 'seed_lost' }
  | { kind: 'proven' };

export interface TotpEnrollmentProps {
  state: TotpEnrollState;
  /** Algorithm label from the begin response, e.g. "SHA-256"; digits and period likewise. */
  algorithmLabel: string;
  digits: number;
  periodSeconds: number;
  onBegin: () => void;
  onConfirm: (code: string) => void;
  /** Present only where restarting a lost enrollment is a supported backend operation. */
  onRestart?: () => void;
  /** Gallery only. */
  synthetic?: boolean;
}

export interface SetupCompleteProps {
  accountStaged: boolean;
  confirmedAddressCount: number;
  totpProven: boolean;
  state: Phase | { kind: 'rejected'; reason: 'denied' | CommonReason } | { kind: 'done'; username: string };
  onComplete: () => void;
  /** Where "Go to sign in" points once setup is complete. NO session is issued by setup. */
  signInHref: string;
  /** Default `initial_setup`. `restore_recovery` words the screen for the recovery administrator of a restored installation. */
  purpose?: SetupPurpose;
}

// ───────────────────────── Slice 1 · login ─────────────────────────

/**
 * `denied` is the ONE outcome for unknown user, wrong password, exhausted factor and an account-level
 * throttle wait (generic 401 parity; the password contract forbids an account-existence signal).
 * `rate_limited` may be used ONLY for a connection-level admission refusal that does not depend on the
 * account. `recovery_required` is allowed only if the server can return it identically for every
 * account that could be in that state; if it cannot, map it to `denied`.
 */
export type LoginState = Phase | { kind: 'rejected'; reason: 'denied' | 'recovery_required' | CommonReason };

export interface LoginPasswordProps {
  state: LoginState;
  onSubmit: (values: { username: string; password: string }) => void;
  /** Where "Lost your second factor?" leads (restricted recovery), if the container supports it. */
  recoveryHref?: string;
}

export type LoginMethod = 'totp' | 'webauthn';

export type LoginFactorState =
  | Phase
  | { kind: 'webauthn_waiting' }
  | { kind: 'rejected'; reason: 'denied' | 'password_only_refused' | 'webauthn_cancelled' | 'webauthn_unsupported' | CommonReason }
  /** The 5-minute preauth capability ended. Start again from the password step. */
  | { kind: 'expired' };

/** A usable authenticator app, named for people (never by its identifier). */
export interface TotpChoiceRow {
  id: string;
  label: string;
}

export interface LoginFactorProps {
  /** Steps the server permitted for THIS login, in server order. Never computed by the UI. */
  next: readonly (LoginMethod | 'no-mfa')[];
  method: LoginMethod;
  state: LoginFactorState;
  /** The account's usable authenticator apps. With more than one the person names which app the code is from. */
  totpFactors?: readonly TotpChoiceRow[];
  onChooseMethod: (method: LoginMethod) => void;
  /** `authenticatorId` is present exactly when the person had to choose between several apps. */
  onSubmitTotp: (values: { code: string; authenticatorId?: string }) => void;
  onStartWebAuthn: () => void;
  /** Offered only when `next` contains 'no-mfa'. Produces a lower-assurance session. */
  onContinuePasswordOnly?: () => void;
  onRestart: () => void;
}

// ───────────────────────── Slice 2 · step-up ─────────────────────────

export type StepUpMethod = 'password' | 'totp' | 'webauthn';

export type StepUpState =
  | Phase
  | { kind: 'webauthn_waiting' }
  | { kind: 'rejected'; reason: 'denied' | 'webauthn_cancelled' | CommonReason }
  /** assurance_unavailable: the account cannot meet the required assurance right now. Not a retry case. */
  | { kind: 'unavailable' }
  | { kind: 'verified'; validMinutes: number };

export interface StepUpPanelProps {
  /** Which proof the server accepts for this account/action. */
  method: StepUpMethod;
  /** Plain-language name of the blocked action, e.g. "Add a security key". */
  actionLabel: string;
  state: StepUpState;
  /** Non-secret; lets password managers associate the password with the right account. */
  username: string;
  /** The account's usable authenticator apps; with more than one the person names the one the code is from. */
  totpFactors?: readonly TotpChoiceRow[];
  /** Every proof the server accepts for this step-up, in server order. With several, the person may switch. */
  methods?: readonly StepUpMethod[];
  onChooseMethod?: (method: StepUpMethod) => void;
  onSubmitPassword: (values: { password: string }) => void;
  onSubmitTotp: (values: { password: string; code: string; authenticatorId?: string }) => void;
  onStartWebAuthn: () => void;
  onDismiss: () => void;
}

// ───────────────────────── Slice 2 · sign-in methods ─────────────────────────

export interface TotpFactorRow {
  id: string;
  /** Server-provided non-secret label, e.g. "Authenticator app". */
  label: string;
  addedOn: string;
  status: 'active' | 'disabled';
}

export interface SecurityKeyRow {
  id: string;
  name: string;
  addedOn: string;
}

export interface SignInMethodsProps {
  totp: readonly TotpFactorRow[];
  keys: readonly SecurityKeyRow[];
  /** Keys are capped (16). */
  maxKeys: number;
  /** false when the installation has no WebAuthn service (its public origin is not an eligible relying party). Default true. */
  keysSupported?: boolean;
  /** The row awaiting remove confirmation, if any. */
  confirmingRemoval?: { kind: 'totp' | 'webauthn'; id: string };
  /** Removal in flight. */
  removing?: boolean;
  /** Unused saved recovery codes (a count; the inventory never shows a code). Used only to say what a last-factor removal leaves. Default 0. */
  recoveryRemaining?: number;
  /**
   * Where the inventory behind the confirmation stands (AUTH-08-L4). `checking`: it is being re-read right now, so the confirmation cannot be used yet.
   * `fresh`: it was re-read when the removal was asked for. `failed`: it could not be re-read, so the page assumes the worst. Default `fresh`.
   */
  removalCheck?: 'checking' | 'fresh' | 'failed';
  onAddTotp: () => void;
  onAddKey: () => void;
  onAskRemove: (kind: 'totp' | 'webauthn', id: string) => void;
  onCancelRemove: () => void;
  onConfirmRemove: () => void;
}

export type WebAuthnRegisterState =
  | { kind: 'idle' }
  | { kind: 'waiting' }
  | { kind: 'rejected'; reason: 'webauthn_cancelled' | 'webauthn_unsupported' | 'insecure_context' | 'limit_reached' | 'denied' | CommonReason }
  | { kind: 'registered' };

/**
 * No key name is collected: the server stores none (no schema field exists), and a label that the
 * page showed once and then lost would only mislead. Keys are listed by when they were added.
 */
export interface WebAuthnRegisterProps {
  state: WebAuthnRegisterState;
  onSubmit: () => void;
}

// ───────────────────────── Slice 2 · recovery ─────────────────────────

export type RecoveryCodesState =
  | { kind: 'none' }
  | { kind: 'issued'; remaining: number }
  | { kind: 'confirming_regenerate'; remaining: number }
  | { kind: 'working' }
  /** `codes` are shown exactly once; the container drops them in `onHidden`. */
  | { kind: 'reveal'; codes: readonly string[] }
  | { kind: 'rejected'; reason: 'denied' | CommonReason };

export interface RecoveryCodesProps {
  state: RecoveryCodesState;
  onIssue: () => void;
  onAskRegenerate: () => void;
  onCancelRegenerate: () => void;
  onConfirmRegenerate: () => void;
  onHidden: () => void;
  synthetic?: boolean;
}

export type RestrictedRecoveryState =
  | Phase
  | { kind: 'rejected'; reason: 'denied' | CommonReason }
  /**
   * A recovery session that existed has ended (ten minutes passed, or the server discarded it). A fixed neutral outcome: it says nothing about
   * whether any saved code was valid or already spent (P1.18.4 P116-L2), so it is never the credential-guess message of `rejected`.
   */
  | { kind: 'expired' }
  /**
   * Code accepted: a 10-minute capability exists; a replacement authenticator must now be proven.
   * `replacementCode` is the ONE replacement saved code, shown exactly once (the container drops it in
   * `onReplacementHidden`); it is absent when the capability is resumed after a reload.
   */
  | { kind: 'capability'; minutesLeft: number; totp: TotpEnrollState; methods?: readonly ('totp' | 'webauthn')[]; key?: WebAuthnRegisterState; replacementCode?: string }
  | { kind: 'completed' };

export interface RestrictedRecoveryProps {
  state: RestrictedRecoveryState;
  onSubmit: (values: { username: string; password: string; code: string }) => void;
  onBeginTotp: () => void;
  onConfirmTotp: (code: string) => void;
  /** Present only when the server offered WebAuthn for this capability. */
  onRegisterKey?: () => void;
  onReplacementHidden?: () => void;
  signInHref: string;
}

// ───────────────────────── Slice 2 · notification addresses ─────────────────────────

export interface ManagedAddress {
  id: string;
  address: string;
  status: 'confirmed' | 'unconfirmed';
}

export type AddressListState =
  | { kind: 'idle' }
  | { kind: 'adding'; step: 'enter' | 'proof'; pendingAddress?: string; error?: 'wrong_code' | 'denied' | CommonReason; busy?: boolean }
  | { kind: 'confirming_removal'; id: string; busy?: boolean }
  | { kind: 'rejected'; reason: 'denied' | CommonReason };

export interface AddressManagementProps {
  addresses: readonly ManagedAddress[];
  maxAddresses: number;
  state: AddressListState;
  mailConfigured: boolean;
  onStartAdd: () => void;
  onSubmitAddress: (values: { address: string }) => void;
  onSubmitProof: (values: { code: string }) => void;
  onCancelAdd: () => void;
  onAskRemove: (id: string) => void;
  onCancelRemove: () => void;
  onConfirmRemove: () => void;
  /** Sends (or re-sends) a confirmation code to an address that is not yet confirmed. */
  onSendCode?: (id: string) => void;
}

/** Aggregate counts only (auth.NoticeStatus). There is deliberately no recipient or SMTP detail. */
export interface NoticeHealthView {
  pending: number;
  failed: number;
  bounced: number;
  quarantined: number;
  protective: number;
  /** The status itself could not be read (storage/uncertain): shown as unknown, never as healthy. */
  unknown?: boolean;
}

export interface NoticeHealthProps {
  health: NoticeHealthView;
  /** Present only where a fresh-assurance repair action exists for the viewer. */
  onRetry?: () => void;
  retrying?: boolean;
}

// ───────────────────────── Slice 2 · agent credentials ─────────────────────────

export interface CredentialRow {
  id: string;
  /** Short non-secret display prefix, e.g. "mdt_ab12…". */
  displayId: string;
  status: 'active' | 'rotating_out' | 'revoked' | 'expired';
  expiresOn: string | null;
  /** rotating_out only: when the old token stops working. */
  overlapEndsOn?: string;
}

export type AgentCredentialState =
  | { kind: 'idle' }
  | { kind: 'working' }
  /** `token` is shown exactly once; the container drops it in `onHidden`. */
  | { kind: 'reveal'; token: string; expiresOn: string | null; rotatedOutDisplayId?: string }
  | { kind: 'confirming_revoke'; id: string }
  | { kind: 'rejected'; reason: 'step_up_required' | 'denied' | 'conflict' | CommonReason };

export interface AgentCredentialsProps {
  agentName: string;
  credentials: readonly CredentialRow[];
  state: AgentCredentialState;
  onIssue: () => void;
  onRotate: () => void;
  onAskRevoke: (id: string) => void;
  onCancelRevoke: () => void;
  onConfirmRevoke: () => void;
  onHidden: () => void;
  synthetic?: boolean;
}
