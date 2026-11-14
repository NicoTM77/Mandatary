/**
 * Names of users, groups and agents are ASCII identifiers so a name in the UI, a log line or a URL cannot hide
 * a control character or a look-alike letter (docs/agent-credentials.md "Identity, ownership and membership").
 * This is the same rule the service applies, repeated here for early inline feedback only: the server refuses
 * anything else regardless of what this accepts.
 */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$/;

export const IDENTIFIER_RULE = 'Use letters and digits first, then letters, digits and . _ - @ + (up to 64, no spaces).';

/** Returns an inline error, or undefined when the (trimmed) value is acceptable. `noun` completes "Enter the …". */
export function validateIdentifier(value: string, noun: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed === '') return `Enter the ${noun}.`;
  return IDENTIFIER.test(trimmed) ? undefined : IDENTIFIER_RULE;
}
