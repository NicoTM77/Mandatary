import { useId, useLayoutEffect, useRef, useState } from 'react';
import { Alert, Badge, Button, CheckboxField, Disclosure, Panel, RadioGroup, SelectField, TextField } from '../../ui';
import type { InventoryRow, PreviewState, RuleDraft, RuleRow, RulesData, SubjectOption } from './contract';
import { MutationNotice, isWorking } from './shared';
import { EMPTY_SELECTOR, OPERATIONS, assessSelector, normalizeSelector, operationInfo, ruleSentence, selectorKey, validateCaps, validateSelector, type CapName, type Effect, type Operation, type SelectorDraft, type SubjectKind } from './selector';
import type { Mutation } from './contract';

type Errors = Partial<Record<'subject' | 'operations' | 'acknowledge' | keyof SelectorDraft | CapName, string>>;

function kindLabel(kind: SubjectKind): string {
  return kind === 'user' ? 'User' : kind === 'group' ? 'Group' : 'Agent';
}

function subjectLabel(subject: SubjectOption): string {
  const note = subject.state === 'active' ? '' : subject.state === 'disabled' ? ' (disabled)' : ' (waiting for approval)';
  return `${subject.name}${subject.administrator ? ' (policy administrator)' : ''}${note}`;
}

function initialCap(value: number | null | undefined): string {
  return value === null || value === undefined ? '' : String(value);
}

// ───────────────────────── preview ─────────────────────────

function Preview({ preview, currentKey, valid, onCheck }: { preview: PreviewState; currentKey: string; valid: boolean; onCheck: () => void }) {
  const stale = preview.kind === 'ready' && preview.forKey !== currentKey;
  return (
    <div className="rounded-control border border-line bg-sunken p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-medium">Which containers does this match?</p>
        <Button variant="secondary" icon="box" busy={preview.kind === 'checking'} busyLabel="Checking…" onClick={onCheck} disabled={!valid && preview.kind !== 'checking'}>
          Check matches
        </Button>
      </div>
      {preview.kind === 'idle' ? (
        <p className="mt-2 text-sm text-muted">
          Lists the containers on this endpoint that fit the selector right now. It’s a preview only: every request is evaluated again when it arrives.
          {valid ? '' : ' Enter a valid container name to check.'}
        </p>
      ) : null}
      {preview.kind === 'unavailable' ? (
        <Alert tone="warning" role="status" className="mt-3" title="Matches can’t be checked right now">
          Mandatary can’t list this endpoint’s containers at the moment. You can still save the rule, but you won’t see what it matches until the endpoint is available.
        </Alert>
      ) : null}
      {stale ? (
        <p role="status" className="mt-2 text-sm text-warn">
          The selector changed since the last check. Check again to see what it matches.
        </p>
      ) : null}
      {preview.kind === 'ready' && !stale ? (
        preview.matches.length === 0 ? (
          <Alert tone="warning" role="status" className="mt-3" title="No container matches yet">
            You can still save this rule. It will show as Inactive · target missing and take effect only when a matching container exists.
          </Alert>
        ) : (
          <div role="status" className="mt-3">
            <p className="text-sm text-muted">
              {preview.matches.length} {preview.matches.length === 1 ? 'container matches' : 'containers match'} right now.
            </p>
            <ul className="mt-2 divide-y divide-line rounded-control border border-line bg-surface">
              {preview.matches.map((row) => (
                <li key={`${row.name}-${row.shortId}`} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 px-3 py-2">
                  <span className="font-mono text-sm font-medium" translate="no">
                    {row.name}
                  </span>
                  <span className="min-w-0 break-all text-sm text-muted" translate="no">
                    {row.image} · {row.shortId}
                    {row.running ? '' : ' · stopped'}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )
      ) : null}
    </div>
  );
}

// ───────────────────────── editor ─────────────────────────

export interface RuleEditorProps {
  data: RulesData;
  /** Present when editing: subject and operation are fixed (create a new rule to change them). */
  editing: RuleRow | null;
  initial?: Partial<Pick<RuleDraft, 'subject' | 'effect'>>;
  mutation: Mutation;
  preview: PreviewState;
  onSubmit: (draft: RuleDraft, editingId: string | null) => void;
  onPreview: (selector: SelectorDraft) => void;
  onClose: () => void;
}

/**
 * Create or edit a rule. The draft is held in local state because nothing in it is secret (names, effects, operations,
 * selector text, numbers); it is sent once, at submit. The container must keep this component mounted while it opens the
 * step-up gate, so a "verify again" does not cost the administrator their draft (the blocked request is not replayed).
 *
 * Everything checked here is convenience. The server validates each selector and cap, refuses an operation that cannot take a cap,
 * stores one rule per operation (all or none), and decides every request. The "I understand" tick is a speed bump for the
 * person, not an input the server trusts.
 */
export function RuleEditor({ data, editing, initial, mutation, preview, onSubmit, onPreview, onClose }: RuleEditorProps) {
  const form = useRef<HTMLFormElement>(null);
  const uid = useId();
  const [kind, setKind] = useState<SubjectKind>(editing?.subject.kind ?? initial?.subject?.kind ?? 'agent');
  const [subjectId, setSubjectId] = useState(editing?.subject.id ?? initial?.subject?.id ?? '');
  const [effect, setEffect] = useState<Effect>(editing?.effect ?? initial?.effect ?? 'allow');
  const [operations, setOperations] = useState<readonly Operation[]>(editing ? [editing.operation] : []);
  const [selector, setSelector] = useState<SelectorDraft>(editing?.selector ?? EMPTY_SELECTOR);
  const [caps, setCaps] = useState<Record<CapName, string>>({ logTailMax: initialCap(editing?.limits.logTailMax), stopTimeoutMax: initialCap(editing?.limits.stopTimeoutMax) });
  const [acknowledged, setAcknowledged] = useState(false);
  const [errors, setErrors] = useState<Errors>({});
  const busy = isWorking(mutation, 'editor');

  const subjects = data.subjects.filter((subject) => subject.kind === kind);
  const chosen = data.subjects.find((subject) => subject.kind === kind && subject.id === subjectId) ?? null;
  const assessment = assessSelector(selector, { effect, operations });
  const selectorProblems = validateSelector(selector);
  const validSelector = Object.keys(selectorProblems).length === 0;
  const hasCap = (cap: CapName) => operations.some((op) => operationInfo(op).cap === cap);
  const patch = (change: Partial<SelectorDraft>) => setSelector((current) => ({ ...current, ...change }));
  const identityOpen = selector.composeProject !== '' || selector.composeService !== '' || selector.imagePattern !== '' || selector.pinnedContainerId !== '' || selector.pinnedImageDigest !== '';

  const fillFrom = (name: string) => {
    const row: InventoryRow | undefined = data.inventory?.find((candidate) => candidate.name === name);
    if (!row) return;
    setSelector({ ...EMPTY_SELECTOR, containerName: row.name, composeProject: row.composeProject ?? '', composeService: row.composeService ?? '' });
    setErrors({});
  };

  // Focus is requested at submit but applied after the render that shows the messages (see the layout effect below), so the
  // browser scrolls to the field against the final layout instead of a form that is about to grow.
  const pendingFocus = useRef<string | null>(null);
  const focusFirst = (found: Errors) => {
    const order = ['subject', 'operations', 'containerName', 'composeProject', 'composeService', 'imagePattern', 'pinnedContainerId', 'pinnedImageDigest', 'logTailMax', 'stopTimeoutMax', 'acknowledge'];
    pendingFocus.current = order.find((key) => key in found) ?? null;
  };
  useLayoutEffect(() => {
    const key = pendingFocus.current;
    if (key === null || !form.current) return;
    pendingFocus.current = null;
    const field = form.current.querySelector<HTMLElement>(`[name="${key}"]`);
    const disclosure = field?.closest('details');
    if (disclosure && !disclosure.open) disclosure.open = true;
    if (!field) return;
    // Engines disagree about where a focus scroll leaves the field (WebKit left it under the sticky header), so the position is set
    // explicitly: instant (no animation to finish, nothing for reduced motion to remove) and centred.
    field.focus({ preventScroll: true });
    field.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' });
  });

  const submit = () => {
    const found: Errors = {};
    if (!editing && !chosen) found.subject = `Choose the ${kind} this rule is for.`;
    if (!editing && chosen && chosen.state !== 'active') found.subject = `${chosen.name} isn’t active, so a rule for it can’t be added.`;
    if (operations.length === 0) found.operations = 'Choose at least one operation.';
    Object.assign(found, validateSelector(selector), validateCaps(caps, operations));
    if (assessment.needsAcknowledgement && !acknowledged) found.acknowledge = 'Tick the box to confirm you mean this.';
    setErrors(found);
    if (Object.keys(found).length > 0) {
      focusFirst(found);
      return;
    }
    const number = (cap: CapName, text: string) => (hasCap(cap) && text.trim() !== '' ? Number(text.trim()) : null);
    onSubmit(
      {
        subject: editing ? { kind: editing.subject.kind, id: editing.subject.id } : { kind, id: subjectId },
        effect,
        operations,
        selector: normalizeSelector(selector),
        caps: { logTailMax: number('logTailMax', caps.logTailMax), stopTimeoutMax: number('stopTimeoutMax', caps.stopTimeoutMax) },
        acknowledgedBroad: assessment.needsAcknowledgement && acknowledged,
      },
      editing?.id ?? null,
    );
  };

  const target = selector.containerName.trim() === '' ? 'the chosen containers' : selector.containerName.trim();
  const subjectName = editing?.subject.name ?? chosen?.name ?? `the ${kind}`;
  const sentences = operations.map((operation) => ruleSentence({ effect, subjectKind: editing?.subject.kind ?? kind, subjectName, operation, target, nameIsPattern: selector.nameIsPattern }));
  const assessTone = assessment.needsAcknowledgement ? 'danger' : assessment.level === 'name_only' || assessment.level === 'pattern' || assessment.level === 'broad' ? 'warning' : 'info';

  return (
    <Panel title={editing ? 'Edit rule' : 'Add a rule'} description={editing ? 'Subject and operation are fixed. Add a new rule to change either.' : 'A rule says who may, or may not, do what to which containers. Deny always wins over Allow.'}>
      <form
        ref={form}
        method="post"
        noValidate
        aria-label={editing ? 'Edit rule' : 'Add a rule'}
        className="space-y-6"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <MutationNotice mutation={mutation} target="editor" />

        <fieldset className="min-w-0 space-y-3">
          <legend className="mb-2 text-base font-semibold">Who</legend>
          {editing ? (
            <p>
              <span className="text-muted">{kindLabel(editing.subject.kind)}:</span> <span className="font-medium">{editing.subject.name}</span>
            </p>
          ) : (
            <>
              <RadioGroup
                name="subject-kind"
                legend="Applies to"
                columns={3}
                value={kind}
                onChange={(next) => {
                  setKind(next === 'user' ? 'user' : next === 'group' ? 'group' : 'agent');
                  setSubjectId('');
                }}
                options={[
                  { value: 'agent', label: 'An agent', hint: 'Gets access only from rules that name it or a group it belongs to.' },
                  { value: 'group', label: 'A group', hint: 'Reaches every explicit member, including any agents in it.' },
                  { value: 'user', label: 'A user', hint: 'One person signed in to Mandatary.' },
                ]}
              />
              <SelectField
                name="subject"
                label={kindLabel(kind)}
                placeholder={kind === 'agent' ? 'Choose an agent' : `Choose a ${kind}`}
                value={subjectId}
                onChange={(event) => setSubjectId(event.target.value)}
                options={subjects.map((subject) => ({ value: subject.id, label: subjectLabel(subject), disabled: subject.state !== 'active' }))}
                error={errors.subject}
                className="max-w-sm"
              />
            </>
          )}
          {chosen?.administrator || editing?.subject.administrator ? (
            <Alert tone="info" role="none" title="This is the policy administrator">
              The administrator role allows no container operation. This rule would be the only thing that gives this account any.
            </Alert>
          ) : null}
        </fieldset>

        <RadioGroup
          name="effect"
          legend="Decision"
          columns={2}
          value={effect}
          onChange={(next) => setEffect(next === 'deny' ? 'deny' : 'allow')}
          options={[
            { value: 'allow', label: 'Allow', hint: 'Permits the chosen operations on matching containers, unless any Deny matches.' },
            { value: 'deny', label: 'Deny', hint: 'Blocks them even if an Allow matches, for this subject or any group it belongs to. Use it to carve out exceptions.' },
          ]}
        />

        <fieldset className="min-w-0">
          <legend className="mb-1 text-base font-semibold">What</legend>
          {editing ? (
            <p className="font-medium">{operationInfo(editing.operation).label}</p>
          ) : (
            <>
              <p className="mb-2 text-sm text-muted">One rule is saved per operation you choose, all together or not at all. These six are the only operations Mandatary offers.</p>
              <div className="space-y-1">
                {OPERATIONS.map((op, index) => (
                  <CheckboxField
                    key={op.key}
                    name={index === 0 ? 'operations' : `operations-${op.key}`}
                    label={
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{op.label}</span>
                        {op.kind === 'change' ? (
                          <Badge tone="warning" icon="alert">
                            Changes the container
                          </Badge>
                        ) : null}
                      </span>
                    }
                    hint={op.description}
                    checked={operations.includes(op.key)}
                    onChange={(checked) => setOperations((current) => (checked ? [...current, op.key] : current.filter((key) => key !== op.key)))}
                  />
                ))}
              </div>
              {errors.operations ? <p className="mt-1.5 text-sm font-medium text-danger">{errors.operations}</p> : null}
            </>
          )}
        </fieldset>

        <fieldset className="min-w-0 space-y-4">
          <legend className="mb-1 text-base font-semibold">Where</legend>
          <p className="text-sm text-muted">
            Endpoint: <span className="font-medium text-fg">{data.endpoint.name}</span>. This version manages one endpoint, the Docker socket on this host, and a rule can never reach another. Mandatary and its peer containers are never listed and can’t be targeted.
          </p>
          {data.inventory && data.inventory.length > 0 && !editing ? (
            <SelectField
              name="start-from"
              label="Start from a running container"
              hint="Fills in the name and, for Compose containers, the Compose project and service."
              placeholder="Choose a container (optional)"
              onChange={(event) => fillFrom(event.target.value)}
              options={data.inventory.map((row) => ({ value: row.name, label: row.name }))}
              className="max-w-sm"
            />
          ) : null}
          <TextField name="containerName" label="Container name" mono value={selector.containerName} onChange={(event) => patch({ containerName: event.target.value })} error={errors.containerName} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} readOnly={busy} className="max-w-sm" />
          <CheckboxField label="Match as a pattern" hint="Use * for any characters, ? for one character and [abc] for a set. Without this, the name must match exactly." checked={selector.nameIsPattern} onChange={(checked) => patch({ nameIsPattern: checked })} />

          <Disclosure summary="Identity checks (recommended)" open={identityOpen}>
            <div className="space-y-4">
              <p className="text-sm text-muted">Without these, any container that ends up with this name matches, even one built from a different image. Set what you can; every one you set must match too.</p>
              <div className="grid gap-4 sm:grid-cols-2">
                <TextField name="composeProject" label="Compose project" mono value={selector.composeProject} onChange={(event) => patch({ composeProject: event.target.value })} error={errors.composeProject} autoComplete="off" spellCheck={false} readOnly={busy} />
                <TextField name="composeService" label="Compose service" mono value={selector.composeService} onChange={(event) => patch({ composeService: event.target.value })} error={errors.composeService} autoComplete="off" spellCheck={false} readOnly={busy} />
              </div>
              <TextField name="imagePattern" label="Image pattern" mono hint="For example ghcr.io/org/app:* (a pattern, with * and ?)." value={selector.imagePattern} onChange={(event) => patch({ imagePattern: event.target.value })} error={errors.imagePattern} autoComplete="off" spellCheck={false} readOnly={busy} />
              <TextField name="pinnedContainerId" label="Pin to one container ID" mono hint="64 lowercase hexadecimal characters. Recreating the container ends the match until you update the rule." value={selector.pinnedContainerId} onChange={(event) => patch({ pinnedContainerId: event.target.value })} error={errors.pinnedContainerId} autoComplete="off" spellCheck={false} readOnly={busy} />
              <TextField name="pinnedImageDigest" label="Pin to one image digest" mono hint="sha256: followed by 64 lowercase hexadecimal characters." value={selector.pinnedImageDigest} onChange={(event) => patch({ pinnedImageDigest: event.target.value })} error={errors.pinnedImageDigest} autoComplete="off" spellCheck={false} readOnly={busy} />
            </div>
          </Disclosure>

          {selector.containerName.trim() !== '' && validSelector ? (
            <Alert tone={assessTone} role="status" title={assessment.headline}>
              <ul className="list-inside list-disc space-y-0.5">
                {assessment.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </Alert>
          ) : null}
          {assessment.needsAcknowledgement ? (
            <CheckboxField
              name="acknowledge"
              label={`I understand this allows ${operations.some((op) => operationInfo(op).kind === 'change') ? 'changing' : 'reading'} every container this pattern matches now or later.`}
              checked={acknowledged}
              onChange={setAcknowledged}
              error={errors.acknowledge}
            />
          ) : null}
          <Preview preview={preview} currentKey={selectorKey(selector)} valid={validSelector && selector.containerName.trim() !== ''} onCheck={() => onPreview(normalizeSelector(selector))} />
        </fieldset>

        {hasCap('logTailMax') || hasCap('stopTimeoutMax') ? (
          <fieldset className="min-w-0 space-y-4">
            <legend className="mb-1 text-base font-semibold">Limits (optional)</legend>
            {hasCap('logTailMax') ? (
              <TextField name="logTailMax" label="Most log lines per request" hint="1 to 10,000. Leave empty for no extra limit." inputMode="numeric" mono value={caps.logTailMax} onChange={(event) => setCaps((current) => ({ ...current, logTailMax: event.target.value }))} error={errors.logTailMax} autoComplete="off" readOnly={busy} className="max-w-xs" />
            ) : null}
            {hasCap('stopTimeoutMax') ? (
              <TextField name="stopTimeoutMax" label="Longest stop timeout, in seconds" hint="1 to 300. Applies to Stop and Restart. Leave empty for no extra limit." inputMode="numeric" mono value={caps.stopTimeoutMax} onChange={(event) => setCaps((current) => ({ ...current, stopTimeoutMax: event.target.value }))} error={errors.stopTimeoutMax} autoComplete="off" readOnly={busy} className="max-w-xs" />
            ) : null}
          </fieldset>
        ) : null}

        <section aria-labelledby={`${uid}-review`} className="rounded-control border border-line-strong bg-sunken p-4">
          <h3 id={`${uid}-review`} className="text-base font-semibold">
            {editing ? 'After you save' : sentences.length > 1 ? `This adds ${sentences.length} rules` : 'This adds one rule'}
          </h3>
          {sentences.length === 0 ? (
            <p className="mt-1 text-sm text-muted">Choose at least one operation to see the rule.</p>
          ) : (
            <ul className="mt-1 list-inside list-disc space-y-0.5">
              {sentences.map((sentence) => (
                <li key={sentence}>{sentence}</li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-sm text-muted">Takes effect for new requests straight away, and ends open streams that the change no longer allows.</p>
        </section>

        <div className="flex flex-wrap gap-2">
          <Button type="submit" busy={busy} busyLabel="Saving…">
            {editing ? 'Save changes' : operations.length > 1 ? `Add ${operations.length} rules` : 'Add rule'}
          </Button>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
        </div>
      </form>
    </Panel>
  );
}
