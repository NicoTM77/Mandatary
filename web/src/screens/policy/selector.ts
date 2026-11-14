/**
 * Pure presentation helpers for policy rules and container selectors (P1.17.1).
 *
 * NOTHING HERE IS AUTHORITY. The server (internal/authz) validates every selector, applies every cap and
 * evaluates every request; these functions only help an administrator write a rule they can understand and
 * give early, inline feedback. They mirror the evaluator's documented limits (docs/authorization.md) so the
 * form does not offer what the server will refuse, but a form that accepts a value proves nothing about it.
 * No function here performs I/O, reads storage or matches a real container.
 */

export type Operation = 'container:logs' | 'container:inspect_status' | 'container:inspect_config' | 'container:start' | 'container:stop' | 'container:restart';
export type Effect = 'allow' | 'deny';
export type SubjectKind = 'user' | 'group' | 'agent';
export type CapName = 'logTailMax' | 'stopTimeoutMax';

export interface OperationInfo {
  key: Operation;
  /** Checkbox label. */
  label: string;
  /** What the operation does, in plain words. */
  description: string;
  kind: 'read' | 'change';
  /** The only ceiling this operation accepts (the evaluator rejects any other combination). */
  cap?: CapName;
}

/** Exactly the six approved Phase 1 permission keys (TD §3.3; internal/authz/params.go). No exec, no discovery. */
export const OPERATIONS: readonly OperationInfo[] = [
  { key: 'container:logs', label: 'Read logs', description: 'Read recent log lines, or follow them live.', kind: 'read', cap: 'logTailMax' },
  { key: 'container:inspect_status', label: 'View status', description: 'See whether it is running, and its health.', kind: 'read' },
  { key: 'container:inspect_config', label: 'Inspect configuration', description: 'Read its settings, labels and mounts.', kind: 'read' },
  { key: 'container:start', label: 'Start', description: 'Start a stopped container.', kind: 'change' },
  { key: 'container:stop', label: 'Stop', description: 'Stop a running container.', kind: 'change', cap: 'stopTimeoutMax' },
  { key: 'container:restart', label: 'Restart', description: 'Stop and start a container.', kind: 'change', cap: 'stopTimeoutMax' },
];

const BY_KEY = new Map<string, OperationInfo>(OPERATIONS.map((op) => [op.key, op]));

export function operationInfo(key: Operation): OperationInfo {
  const info = BY_KEY.get(key);
  if (!info) throw new Error('unknown operation');
  return info;
}

export function isStateChanging(key: Operation): boolean {
  return operationInfo(key).kind === 'change';
}

export const LOG_TAIL_RANGE = { min: 1, max: 10_000 } as const;
export const STOP_TIMEOUT_RANGE = { min: 1, max: 300 } as const;

// ───────────────────────── selector ─────────────────────────

/** All fields are strings; an empty string means "not set". Mirrors store.ContainerSelector without the ids. */
export interface SelectorDraft {
  containerName: string;
  /** false: exact name. true: a linear-time glob (`*`, `?`, `[...]`). */
  nameIsPattern: boolean;
  composeProject: string;
  composeService: string;
  imagePattern: string;
  pinnedContainerId: string;
  pinnedImageDigest: string;
}

export const EMPTY_SELECTOR: SelectorDraft = {
  containerName: '',
  nameIsPattern: false,
  composeProject: '',
  composeService: '',
  imagePattern: '',
  pinnedContainerId: '',
  pinnedImageDigest: '',
};

export type SelectorErrors = Partial<Record<keyof SelectorDraft, string>>;

const MAX_PATTERN = 255;
// Control characters are the evaluator's own refusal set for names and patterns (\x00, \r, \n); the rest are refused here too
// because no real container name or image reference can contain them.
// eslint-disable-next-line no-control-regex -- the point of the check
const CONTROL = /[\u0000-\u001f\u007f]/;
const HEX64 = /^[0-9a-fA-F]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const PATTERN_CHARS = /[*?[]/;

export function normalizeSelector(selector: SelectorDraft): SelectorDraft {
  return {
    containerName: selector.containerName.trim(),
    nameIsPattern: selector.nameIsPattern,
    composeProject: selector.composeProject.trim(),
    composeService: selector.composeService.trim(),
    imagePattern: selector.imagePattern.trim(),
    pinnedContainerId: selector.pinnedContainerId.trim(),
    pinnedImageDigest: selector.pinnedImageDigest.trim(),
  };
}

function textError(value: string): string | undefined {
  if (value.length > MAX_PATTERN) return `Use at most ${MAX_PATTERN} characters.`;
  if (value.includes('\\')) return 'Backslashes aren’t allowed.';
  if (CONTROL.test(value)) return 'Line breaks and control characters aren’t allowed.';
  return undefined;
}

/** Inline, convenience-only validation. The server validates again and its verdict wins. */
export function validateSelector(selector: SelectorDraft): SelectorErrors {
  const value = normalizeSelector(selector);
  const errors: SelectorErrors = {};
  if (value.containerName === '') errors.containerName = 'Enter the container name.';
  else {
    const problem = textError(value.containerName);
    if (problem) errors.containerName = problem;
    else if (!value.nameIsPattern && PATTERN_CHARS.test(value.containerName)) errors.containerName = 'This looks like a pattern. Tick “Match as a pattern”, or remove the pattern characters.';
  }
  const optional = (text: string) => (text === '' ? undefined : textError(text));
  const compose = optional(value.composeProject);
  if (compose) errors.composeProject = compose;
  const service = optional(value.composeService);
  if (service) errors.composeService = service;
  const image = optional(value.imagePattern);
  if (image) errors.imagePattern = image;
  if (value.pinnedContainerId !== '') {
    if (!HEX64.test(value.pinnedContainerId)) errors.pinnedContainerId = 'Use exactly 64 hexadecimal characters.';
    else if (value.pinnedContainerId !== value.pinnedContainerId.toLowerCase()) errors.pinnedContainerId = 'Use lowercase letters.';
  }
  if (value.pinnedImageDigest !== '' && !DIGEST.test(value.pinnedImageDigest)) errors.pinnedImageDigest = 'Use sha256: followed by 64 lowercase hexadecimal characters.';
  return errors;
}

export type CapValues = Record<CapName, string>;
export type CapErrors = Partial<Record<CapName, string>>;

function capApplies(cap: CapName, operations: readonly Operation[]): boolean {
  return operations.some((op) => operationInfo(op).cap === cap);
}

/** Caps for operations that are not selected are ignored: the evaluator refuses a cap on an operation that cannot take it. */
export function validateCaps(values: CapValues, operations: readonly Operation[]): CapErrors {
  const errors: CapErrors = {};
  const problem = (cap: CapName, text: string, range: { min: number; max: number }): string | undefined => {
    const raw = text.trim();
    if (raw === '' || !capApplies(cap, operations)) return undefined;
    const number = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
    return number >= range.min && number <= range.max ? undefined : `Use a whole number from ${range.min.toLocaleString('en-US')} to ${range.max.toLocaleString('en-US')}.`;
  };
  const tail = problem('logTailMax', values.logTailMax, LOG_TAIL_RANGE);
  if (tail) errors.logTailMax = tail;
  const timeout = problem('stopTimeoutMax', values.stopTimeoutMax, STOP_TIMEOUT_RANGE);
  if (timeout) errors.stopTimeoutMax = timeout;
  return errors;
}

// ───────────────────────── guardrail assessment ─────────────────────────

export type GuardLevel = 'pinned' | 'guarded' | 'name_only' | 'pattern' | 'broad';

export interface Assessment {
  level: GuardLevel;
  /** One short sentence for the heading of the guardrail summary. */
  headline: string;
  notes: readonly string[];
  /** An Allow this wide, or this loose on a state-changing action, needs an explicit tick before it can be saved. */
  needsAcknowledgement: boolean;
}

const SELF_NOTE = 'Mandatary itself and its peer containers are never reachable, whatever this rule says.';

function hasLiteralCharacters(pattern: string): boolean {
  return pattern.replace(/\[[^\]]*\]/g, '').replace(/[*?]/g, '').length > 0;
}

export function assessSelector(selector: SelectorDraft, rule: { effect: Effect; operations: readonly Operation[] }): Assessment {
  const value = normalizeSelector(selector);
  const pinned = value.pinnedContainerId !== '' || value.pinnedImageDigest !== '';
  const guarded = value.composeProject !== '' || value.composeService !== '' || value.imagePattern !== '';
  let level: GuardLevel;
  if (pinned) level = 'pinned';
  else if (guarded) level = 'guarded';
  else if (!value.nameIsPattern) level = 'name_only';
  else level = hasLiteralCharacters(value.containerName) ? 'pattern' : 'broad';

  const allow = rule.effect === 'allow';
  const notes: string[] = [];
  let headline: string;
  switch (level) {
    case 'pinned':
      headline = allow ? 'Pinned to one container or image' : 'Blocks one pinned container or image';
      notes.push('If the container is recreated, the pin stops matching until you update this rule. That is deliberate: a recreated container needs a new approval.');
      break;
    case 'guarded':
      headline = allow ? 'Guarded: the name plus identity checks' : 'Blocks matching containers that pass the identity checks';
      notes.push('A container must match the name and every identity check you set.');
      break;
    case 'name_only':
      headline = allow ? 'Name only' : 'Blocks by name only';
      notes.push('A different image started under this name would match too. Add a Compose project and service, an image pattern or a pin to prevent that.');
      break;
    case 'pattern':
      headline = allow ? 'Name pattern' : 'Blocks every container matching the pattern';
      notes.push('Any container whose name fits the pattern matches, including ones created later. Add an identity check to narrow it.');
      notes.push(SELF_NOTE);
      break;
    case 'broad':
      headline = allow ? 'Broad: every container on this endpoint' : 'Blocks every container on this endpoint';
      notes.push(allow ? 'This pattern has no fixed characters, so it fits every container, including ones created later.' : 'This pattern fits every container, including ones created later.');
      notes.push(SELF_NOTE);
      break;
  }
  const needsAcknowledgement = allow && (level === 'broad' || (level === 'pattern' && rule.operations.some(isStateChanging)));
  return { level, headline, notes, needsAcknowledgement };
}

/** Stable identity of a selector for "is this preview still about what is typed". */
export function selectorKey(selector: SelectorDraft): string {
  const value = normalizeSelector(selector);
  return JSON.stringify([value.containerName, value.nameIsPattern, value.composeProject, value.composeService, value.imagePattern, value.pinnedContainerId, value.pinnedImageDigest]);
}

/** The guardrails that are set, as short readable chips (the name itself is shown separately). */
export function describeSelector(selector: SelectorDraft): string[] {
  const value = normalizeSelector(selector);
  const chips: string[] = [];
  if (value.composeProject !== '') chips.push(`Compose project ${value.composeProject}`);
  if (value.composeService !== '') chips.push(`Compose service ${value.composeService}`);
  if (value.imagePattern !== '') chips.push(`Image ${value.imagePattern}`);
  if (value.pinnedContainerId !== '') chips.push(`Container ID ${value.pinnedContainerId.slice(0, 12)}…`);
  if (value.pinnedImageDigest !== '') chips.push(`Digest ${value.pinnedImageDigest.slice(0, 'sha256:'.length + 12)}…`);
  return chips;
}

// ───────────────────────── sentences ─────────────────────────

export interface RuleSentenceInput {
  effect: Effect;
  subjectKind: SubjectKind;
  subjectName: string;
  operation: Operation;
  target: string;
  nameIsPattern: boolean;
}

/** "Allow agent ci-runner to read logs of edge-proxy": the rule as one readable (and screen-reader-friendly) sentence. */
export function ruleSentence({ effect, subjectKind, subjectName, operation, target, nameIsPattern }: RuleSentenceInput): string {
  const noun = nameIsPattern ? `containers matching ${target}` : target;
  const allow = effect === 'allow';
  let phrase: string;
  switch (operation) {
    case 'container:logs':
      phrase = allow ? `to read logs of ${noun}` : `from reading logs of ${noun}`;
      break;
    case 'container:inspect_status':
      phrase = allow ? `to view the status of ${noun}` : `from viewing the status of ${noun}`;
      break;
    case 'container:inspect_config':
      phrase = allow ? `to inspect the configuration of ${noun}` : `from inspecting the configuration of ${noun}`;
      break;
    case 'container:start':
      phrase = allow ? `to start ${noun}` : `from starting ${noun}`;
      break;
    case 'container:stop':
      phrase = allow ? `to stop ${noun}` : `from stopping ${noun}`;
      break;
    case 'container:restart':
      phrase = allow ? `to restart ${noun}` : `from restarting ${noun}`;
      break;
  }
  return `${allow ? 'Allow' : 'Deny'} ${subjectKind} ${subjectName} ${phrase}`;
}
