/**
 * Browser WebAuthn ceremony glue. The server issues the options and verifies the result (origin, RP ID,
 * challenge, user verification, owning session); this module only hands the options to the browser and
 * the browser's serialised credential back, UNMODIFIED. Nothing is stored, logged or put in the URL.
 */

export type KeyFailure = 'webauthn_cancelled' | 'webauthn_unsupported' | 'insecure_context';

export type KeyResult = { ok: true; response: unknown } | { ok: false; reason: KeyFailure };

interface JsonCredential {
  toJSON(): unknown;
}

function publicKeyOptions(options: unknown): Record<string, unknown> | null {
  if (typeof options !== 'object' || options === null) return null;
  const publicKey = (options as Record<string, unknown>).publicKey;
  return typeof publicKey === 'object' && publicKey !== null ? (publicKey as Record<string, unknown>) : null;
}

function supported(): boolean {
  return typeof globalThis.PublicKeyCredential === 'function' && typeof globalThis.navigator?.credentials?.create === 'function';
}

function failure(error: unknown): KeyResult {
  const name = error instanceof DOMException ? error.name : '';
  if (name === 'SecurityError') return { ok: false, reason: 'insecure_context' };
  // NotAllowedError (cancelled/timed out), AbortError, InvalidStateError (already registered) and the rest
  // are all "the browser did not produce a credential": nothing was changed.
  return { ok: false, reason: 'webauthn_cancelled' };
}

export async function createCredential(options: unknown): Promise<KeyResult> {
  const publicKey = publicKeyOptions(options);
  if (!supported() || publicKey === null || typeof PublicKeyCredential.parseCreationOptionsFromJSON !== 'function') return { ok: false, reason: 'webauthn_unsupported' };
  if (!globalThis.isSecureContext) return { ok: false, reason: 'insecure_context' };
  try {
    const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey as unknown as PublicKeyCredentialCreationOptionsJSON) });
    if (credential === null) return { ok: false, reason: 'webauthn_cancelled' };
    return { ok: true, response: (credential as unknown as JsonCredential).toJSON() };
  } catch (error) {
    return failure(error);
  }
}

export async function getCredential(options: unknown): Promise<KeyResult> {
  const publicKey = publicKeyOptions(options);
  if (!supported() || publicKey === null || typeof PublicKeyCredential.parseRequestOptionsFromJSON !== 'function') return { ok: false, reason: 'webauthn_unsupported' };
  if (!globalThis.isSecureContext) return { ok: false, reason: 'insecure_context' };
  try {
    const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey as unknown as PublicKeyCredentialRequestOptionsJSON) });
    if (credential === null) return { ok: false, reason: 'webauthn_cancelled' };
    return { ok: true, response: (credential as unknown as JsonCredential).toJSON() };
  } catch (error) {
    return failure(error);
  }
}
