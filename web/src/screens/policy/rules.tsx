import { useState, type ReactNode } from 'react';
import { Alert, Badge, Button, CheckboxField, ConfirmPanel, Disclosure, EmptyState, Icon, PageHeader, Panel, SelectField } from '../../ui';
import type { Effect, RuleRow, RulesData, RulesScreenProps, TargetStatus } from './contract';
import { RuleEditor } from './ruleEditor';
import { assessSelector, describeSelector, ruleSentence, type SubjectKind } from './selector';
import { AdministratorBadge, AuthorityNote, Fact, Facts, ManagedLoad, MutationNotice, isWorking, plural } from './shared';

export function EffectBadge({ effect }: { effect: Effect }) {
  return effect === 'allow' ? (
    <Badge tone="success" icon="check">
      Allow
    </Badge>
  ) : (
    <Badge tone="danger" icon="ban">
      Deny
    </Badge>
  );
}

function TargetBadge({ target }: { target: TargetStatus }) {
  switch (target.kind) {
    case 'present':
      return (
        <Badge tone="neutral" icon="box">
          Matches {plural(target.matches, 'container')} now
        </Badge>
      );
    case 'missing':
      return (
        <Badge tone="warning" icon="alert">
          Inactive · target missing
        </Badge>
      );
    case 'unknown':
      return (
        <Badge tone="warning" icon="alert">
          Target status unknown
        </Badge>
      );
  }
}

function RuleStateBadge({ state }: { state: RuleRow['state'] }) {
  if (state === 'active') return null;
  return state === 'disabled' ? (
    <Badge tone="neutral" icon="ban">
      Disabled
    </Badge>
  ) : (
    <Badge tone="warning" icon="clock">
      Waiting for approval
    </Badge>
  );
}

/** Whether the rule needs a person to look at it: its target is gone or unknowable, or it is not in force. */
export function needsAttention(rule: RuleRow): boolean {
  return rule.target.kind !== 'present' || rule.state !== 'active';
}

function targetExplanation(rule: RuleRow): ReactNode {
  if (rule.state === 'quarantined') return 'Imported by a restore. It grants and blocks nothing until it is approved explicitly.';
  if (rule.state === 'disabled') return rule.effect === 'allow' ? 'Disabled: it grants nothing until you enable it.' : 'Disabled: it blocks nothing until you enable it.';
  if (rule.target.kind === 'missing') {
    return rule.effect === 'allow'
      ? 'No container matches now, so this grants nothing and requests for it are refused. Mandatary keeps the rule rather than deleting it, so it applies again if a matching container appears.'
      : 'No container matches now, so this blocks nothing yet. Mandatary keeps the rule, and it blocks a matching container if one appears.';
  }
  if (rule.target.kind === 'unknown') return 'Mandatary can’t inspect this endpoint right now, so it can’t say whether anything matches. This is never treated as a match.';
  return null;
}

/** What a lifecycle action does to access, and whether it loosens it. Drives the tone and wording of the confirmation. */
export function ruleConsequence(rule: RuleRow, action: 'disable' | 'enable' | 'delete'): { loosens: boolean; text: string } {
  if (rule.effect === 'allow') {
    if (action === 'enable') return { loosens: true, text: 'It starts granting this access straight away.' };
    return { loosens: false, text: 'This access ends straight away, including streams that are open now. Other rules that allow it still apply.' };
  }
  if (action === 'enable') return { loosens: false, text: 'It starts blocking this access again straight away, even where an Allow matches.' };
  return { loosens: true, text: 'This stops blocking the access, so anything an Allow rule permits becomes possible again straight away.' };
}

function RuleItem({ rule, props }: { rule: RuleRow; props: RulesScreenProps }) {
  const { pending, mutation, onAsk, onCancel, onConfirm, onEdit } = props;
  const sentence = ruleSentence({ effect: rule.effect, subjectKind: rule.subject.kind, subjectName: rule.subject.name, operation: rule.operation, target: rule.selector.containerName, nameIsPattern: rule.selector.nameIsPattern });
  const chips = describeSelector(rule.selector);
  const level = assessSelector(rule.selector, { effect: rule.effect, operations: [rule.operation] }).level;
  // Only an Allow that reaches more than one named container without an identity check is worth a badge: it is the one that can surprise.
  const reach = rule.effect === 'allow' ? (level === 'broad' ? 'Every container' : level === 'pattern' ? 'Pattern, no identity check' : null) : null;
  const mine = pending?.id === rule.id ? pending : null;
  const id = (action: string) => `rule-${rule.id}-${action}`;
  const limits = [rule.limits.logTailMax === null ? null : `at most ${rule.limits.logTailMax.toLocaleString('en-US')} log lines per request`, rule.limits.stopTimeoutMax === null ? null : `stop timeout up to ${rule.limits.stopTimeoutMax} seconds`].filter((text) => text !== null);
  const explanation = targetExplanation(rule);
  const confirmCopy = mine ? ruleConsequence(rule, mine.action) : null;
  return (
    <li className="py-4 first:pt-0 last:pb-0">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <h3 className="break-words font-semibold leading-snug">{sentence}</h3>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <EffectBadge effect={rule.effect} />
            <RuleStateBadge state={rule.state} />
            <TargetBadge target={rule.target} />
            {reach ? (
              <Badge tone="warning" icon="alert">
                {reach}
              </Badge>
            ) : null}
            {rule.subject.state !== 'active' ? (
              <Badge tone={rule.subject.state === 'disabled' ? 'neutral' : 'warning'} icon={rule.subject.state === 'disabled' ? 'ban' : 'clock'}>
                {`${rule.subject.kind === 'user' ? 'User' : rule.subject.kind === 'group' ? 'Group' : 'Agent'} ${rule.subject.state === 'disabled' ? 'disabled' : 'waiting for approval'}`}
              </Badge>
            ) : null}
            {rule.subject.administrator ? <AdministratorBadge /> : null}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {rule.state !== 'quarantined' ? (
            <Button id={id('edit')} variant="secondary" icon="edit" aria-label={`Edit: ${sentence}`} onClick={() => onEdit(rule.id)}>
              Edit
            </Button>
          ) : null}
          {rule.state === 'active' ? (
            <Button id={id('disable')} variant="secondary" aria-label={`Disable: ${sentence}`} onClick={() => onAsk('disable', rule.id)}>
              Disable
            </Button>
          ) : null}
          {rule.state === 'disabled' ? (
            <Button id={id('enable')} variant="secondary" aria-label={`Enable: ${sentence}`} onClick={() => onAsk('enable', rule.id)}>
              Enable
            </Button>
          ) : null}
          <Button id={id('delete')} variant="danger" icon="trash" aria-label={`Delete: ${sentence}`} onClick={() => onAsk('delete', rule.id)}>
            Delete
          </Button>
        </div>
      </div>
      <Facts>
        <Fact label="Target">
          <span className="font-mono" translate="no">
            {rule.selector.containerName}
          </span>
          {rule.selector.nameIsPattern ? ' (pattern)' : ' (exact name)'}
          {chips.length > 0 ? (
            <span className="mt-1 flex flex-wrap gap-1.5">
              {chips.map((chip) => (
                <span key={chip} className="rounded-full border border-line bg-sunken px-2 py-0.5 text-xs" translate="no">
                  {chip}
                </span>
              ))}
            </span>
          ) : (
            <span className="block text-muted">No identity checks: the name alone decides.</span>
          )}
        </Fact>
        {limits.length > 0 ? <Fact label="Limits">{limits.join(' · ')}</Fact> : null}
      </Facts>
      {explanation ? <p className="mt-2 text-sm text-muted">{explanation}</p> : null}
      {mine && confirmCopy ? (
        <div className="mt-3">
          <ConfirmPanel
            title={`${mine.action === 'delete' ? 'Delete' : mine.action === 'disable' ? 'Disable' : 'Enable'} “${sentence}”?`}
            confirmLabel={mine.action === 'delete' ? 'Delete rule' : mine.action === 'disable' ? 'Disable rule' : 'Enable rule'}
            busyLabel={mine.action === 'delete' ? 'Deleting…' : mine.action === 'disable' ? 'Disabling…' : 'Enabling…'}
            tone={confirmCopy.loosens ? 'warning' : 'danger'}
            busy={isWorking(mutation, rule.id)}
            onConfirm={onConfirm}
            onCancel={onCancel}
            returnFocusId={id(mine.action)}
          >
            {mine.action === 'delete' ? 'This permanently removes the rule. ' : ''}
            {confirmCopy.text}
          </ConfirmPanel>
        </div>
      ) : null}
      <div className="mt-3 empty:hidden">
        <MutationNotice mutation={mutation} target={rule.id} onReload={props.onRetry} />
      </div>
    </li>
  );
}

function DecisionOrder() {
  return (
    <Disclosure summary="How Mandatary decides a request" className="bg-surface">
      <div className="space-y-2 text-sm">
        <ol className="list-inside list-decimal space-y-1">
          <li>Mandatary itself and its peer containers are refused, whatever any rule says.</li>
          <li>The sign-in or token must be valid, current and the right kind. If not, the request is refused.</li>
          <li>If any Deny matches (for the account, an agent or any group it belongs to), the request is refused.</li>
          <li>Otherwise an active Allow must match the operation, the container and any limits. If one does, the request is permitted.</li>
          <li>Anything else is refused.</li>
        </ol>
        <p className="text-muted">The administrator role and owning an agent are not in this list: neither allows anything. Rules in a state other than Active never allow.</p>
      </div>
    </Disclosure>
  );
}

function EndpointBanner({ endpoint }: { endpoint: RulesData['endpoint'] }) {
  if (endpoint.safety === 'verified') return null;
  return (
    <Alert tone="danger" role="alert" title={`Mandatary can’t verify its own container on ${endpoint.name}`}>
      Until it can, every container operation on this endpoint is refused, whatever the rules say, and target status and match previews are unavailable. Rules you save now take effect once Mandatary can verify itself.
    </Alert>
  );
}

function Filters({ filters, onChange, shown, total }: { filters: Filter; onChange: (filter: Filter) => void; shown: number; total: number }) {
  return (
    <div className="mb-4 space-y-1">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
      <SelectField
        label="Show"
        value={filters.effect}
        onChange={(event) => onChange({ ...filters, effect: event.target.value === 'allow' ? 'allow' : event.target.value === 'deny' ? 'deny' : 'all' })}
        options={[
          { value: 'all', label: 'Allow and Deny' },
          { value: 'allow', label: 'Allow only' },
          { value: 'deny', label: 'Deny only' },
        ]}
        className="w-44"
      />
      <SelectField
        label="For"
        value={filters.subject}
        onChange={(event) => onChange({ ...filters, subject: event.target.value === 'user' || event.target.value === 'group' || event.target.value === 'agent' ? event.target.value : 'all' })}
        options={[
          { value: 'all', label: 'Everyone' },
          { value: 'user', label: 'Users' },
          { value: 'group', label: 'Groups' },
          { value: 'agent', label: 'Agents' },
        ]}
        className="w-40"
      />
        <p role="status" className="pb-3 text-sm text-muted">
          Showing {shown} of {total}
        </p>
      </div>
      <CheckboxField label="Needs attention only" hint="Target missing or unknown, disabled, or waiting for approval." checked={filters.attention} onChange={(attention) => onChange({ ...filters, attention })} />
    </div>
  );
}

interface Filter {
  effect: 'all' | Effect;
  subject: 'all' | SubjectKind;
  attention: boolean;
}

const NO_FILTER: Filter = { effect: 'all', subject: 'all', attention: false };

function RulesList({ data, props }: { data: RulesData; props: RulesScreenProps }) {
  const [filters, setFilters] = useState<Filter>(NO_FILTER);
  const attention = data.rules.filter(needsAttention);
  const missing = data.rules.filter((rule) => rule.target.kind === 'missing');
  const shown = data.rules.filter((rule) => (filters.effect === 'all' || rule.effect === filters.effect) && (filters.subject === 'all' || rule.subject.kind === filters.subject) && (!filters.attention || needsAttention(rule)));
  const allow = data.rules.filter((rule) => rule.effect === 'allow').length;
  return (
    <>
      {missing.length > 0 ? (
        <Alert
          tone="warning"
          role="none"
          title={`${plural(missing.length, 'rule')} ${missing.length === 1 ? 'points' : 'point'} at a container that doesn’t exist`}
          actions={
            filters.attention ? null : (
              <Button variant="secondary" onClick={() => setFilters({ ...NO_FILTER, attention: true })}>
                Show rules that need attention
              </Button>
            )
          }
        >
          They stay here, marked Inactive · target missing, instead of vanishing: they allow nothing now and apply again if a matching container is created. Delete any you no longer need.
        </Alert>
      ) : null}
      <Panel title="All rules" description={`${plural(data.rules.length, 'rule')} · ${allow} Allow · ${data.rules.length - allow} Deny${attention.length > 0 ? ` · ${attention.length} need attention` : ''}`}>
        {data.rules.length === 0 ? (
          <EmptyState
            title="No rules yet"
            description="Until a rule allows something, every container request is refused. That includes the policy administrator’s own."
            action={{ label: 'Add the first rule', icon: 'plus', onClick: props.onNew }}
            headingLevel={3}
          />
        ) : (
          <>
            <Filters filters={filters} onChange={setFilters} shown={shown.length} total={data.rules.length} />
            {shown.length === 0 ? (
              <EmptyState title="No rules match these filters" description="Change the filters to see more." action={{ label: 'Clear filters', variant: 'secondary', onClick: () => setFilters(NO_FILTER) }} headingLevel={3} />
            ) : (
              <ul className="divide-y divide-line">
                {shown.map((rule) => (
                  <RuleItem key={rule.id} rule={rule} props={props} />
                ))}
              </ul>
            )}
          </>
        )}
      </Panel>
    </>
  );
}

/**
 * Policy rules (P1.17.1, F-R): the only place access is granted or blocked. The page distinguishes, in words and
 * badges, what a rule does (Allow / Deny), whether it is in force (state), and whether anything currently matches
 * (target status). A rule whose container is gone is kept and flagged, never hidden.
 */
export function RulesScreen(props: RulesScreenProps) {
  const { load, mutation, editor, preview, onRetry, onNew, onCloseEditor, onSubmit, onPreview } = props;
  return (
    <div className="space-y-6">
      <PageHeader
        title="Rules"
        description="Rules decide which operations an account, group or agent may perform on which containers. With no matching Allow, every request is refused."
        actions={
          load.kind === 'ready' && editor.kind === 'closed' ? (
            <Button icon="plus" onClick={onNew}>
              Add a rule
            </Button>
          ) : undefined
        }
      />
      <AuthorityNote />
      <MutationNotice mutation={mutation} onReload={onRetry} />
      <ManagedLoad load={load} label="rules" area="rules" onRetry={onRetry}>
        {(data) => {
          const editing = editor.kind === 'edit' ? (data.rules.find((rule) => rule.id === editor.id) ?? null) : null;
          return (
            <>
              <EndpointBanner endpoint={data.endpoint} />
              <DecisionOrder />
              {editor.kind === 'create' || (editor.kind === 'edit' && editing) ? (
                <RuleEditor key={editor.kind === 'edit' ? editor.id : 'create'} data={data} editing={editing} initial={editor.kind === 'create' ? editor.initial : undefined} mutation={mutation} preview={preview} onSubmit={onSubmit} onPreview={onPreview} onClose={onCloseEditor} />
              ) : null}
              {editor.kind === 'edit' && !editing ? (
                <Alert tone="warning" title="That rule no longer exists" actions={<Button onClick={onCloseEditor}>Close</Button>}>
                  It may have been removed in another window. Nothing was changed.
                </Alert>
              ) : null}
              <RulesList data={data} props={props} />
              <p className="flex items-center gap-2 text-sm text-muted">
                <Icon name="lock" className="size-4" />
                Nothing on this page runs a container operation. Rules only decide who may, when a request arrives.
              </p>
            </>
          );
        }}
      </ManagedLoad>
    </div>
  );
}
