import type { SubjectRef } from './contract';

/**
 * The "rules for this user, group or agent" link and filter (P1.18.4 P117-note-rule-link). A subject is identified by its kind and IMMUTABLE id,
 * never by its display name, so two accounts that share a name are never mixed up. The link is a plain same-origin document path with an
 * allowlisted fragment: `/policy#subject=<kind>:<id>`. A fragment is never sent to the server, so this adds no request and no authorization
 * surface; the Rules list is fetched and authorized exactly as before and only filtered on this page. Anything that does not match the
 * allowlist is ignored (the full list is shown), never partially interpreted.
 */

export const RULES_PATH = '/policy';

const SUBJECT_HASH = /^#subject=(user|group|agent):([A-Za-z0-9._-]{1,128})$/;

export function rulesHrefFor(subject: SubjectRef): string {
  return `${RULES_PATH}#subject=${subject.kind}:${subject.id}`;
}

/** The subject a location hash names, or null for anything outside the allowlist (including `.` and `..`). */
export function parseSubjectHash(hash: string): SubjectRef | null {
  const match = SUBJECT_HASH.exec(hash);
  if (!match) return null;
  const kind = match[1] as SubjectRef['kind'];
  const id = match[2] as string;
  return id === '.' || id === '..' ? null : { kind, id };
}
