import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

// P1.18.4: the findings/disposition ledger (docs/findings-ledger.json, rendered in docs/findings-ledger.md) is only useful if it cannot drift into
// vague or invented rows. This test is structural: it does not run the referenced tests (CI does), it proves every reference points at something
// that exists, every row has the fields its status requires, and the two files agree.

const ledger = JSON.parse(readFileSync('docs/findings-ledger.json', 'utf8'));
const markdown = readFileSync('docs/findings-ledger.md', 'utf8');
const STATUSES = ['fixed_here', 'already_resolved', 'bounded_limitation', 'future_gate'];
const GATE_OWNERS = new Set(['t_7f9cfaf3', 't_836268ff', 't_98b6209e', 't_1bb7a4c3']);
const nonEmpty = (value) => typeof value === 'string' && value.trim().length > 20;

function referenceExists(reference) {
  const [path, name] = reference.split('::');
  if (!existsSync(path)) return false;
  return name === undefined || readFileSync(path, 'utf8').includes(name);
}

test('the ledger covers the audit inventory: 49 cards, one explicit exclusion, 113 operations dispositions', () => {
  assert.equal(ledger.schema, 1);
  assert.equal(ledger.baseline, '563d796006851f030ac33d8a7cfd3ba9f95ff864');
  assert.equal(ledger.source_inventory.original_cards, 49);
  assert.equal(ledger.source_inventory.in_scope_cards, 48);
  assert.equal(ledger.cards.length, 49);
  assert.equal(new Set(ledger.cards.map((c) => c.task_id)).size, 49);
  assert.deepEqual(ledger.excluded.map((e) => e.task_id), ['t_3064b26e']);
  assert.deepEqual(ledger.cards.filter((c) => !c.in_scope).map((c) => c.task_id), ['t_3064b26e']);
  const ops = ledger.rows.filter((r) => r.group === 'ops');
  assert.equal(ops.length, 113, 'every operations disposition of the audit is a row');
  assert.equal(ops.filter((r) => r.status === 'fixed_here').length, 27, 'the 27 actionable operations items are all fixed here');
});

test('row ids are unique, every status is in the vocabulary and the counts agree', () => {
  const ids = ledger.rows.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
  const counts = {};
  for (const row of ledger.rows) {
    assert.ok(STATUSES.includes(row.status), `${row.id}: status ${row.status}`);
    assert.ok(nonEmpty(row.title), `${row.id}: title`);
    assert.ok(nonEmpty(row.disposition), `${row.id}: disposition`);
    assert.ok(Array.isArray(row.source_refs) && row.source_refs.length > 0, `${row.id}: keeps its source references`);
    counts[row.status] = (counts[row.status] ?? 0) + 1;
  }
  assert.deepEqual(counts, ledger.status_counts);
});

test('every fixed row names its commit, existing regression tests, red evidence and existing documentation', () => {
  for (const row of ledger.rows.filter((r) => r.status === 'fixed_here')) {
    assert.match(row.commit ?? '', /^[0-9a-f]{7,40}(, [0-9a-f]{7,40})*$/, `${row.id}: commit`);
    assert.ok(Array.isArray(row.tests) && row.tests.length > 0, `${row.id}: at least one regression test`);
    for (const reference of row.tests) assert.ok(referenceExists(reference), `${row.id}: test reference does not exist: ${reference}`);
    for (const doc of row.docs ?? []) assert.ok(existsSync(doc), `${row.id}: documentation path does not exist: ${doc}`);
    for (const file of row.files ?? []) assert.ok(existsSync(file), `${row.id}: file does not exist: ${file}`);
    assert.ok(nonEmpty(row.red), `${row.id}: red evidence or an explicit statement of why it is a characterization`);
  }
});

test('already-resolved rows keep a current source that exists, or say they are recorded-evidence only', () => {
  for (const row of ledger.rows.filter((r) => r.status === 'already_resolved')) {
    for (const source of row.current_source ?? []) assert.ok(existsSync(source), `${row.id}: current source does not exist: ${source}`);
    const hasEvidence = (row.current_source ?? []).length > 0 || (row.acceptance ?? []).length > 0;
    assert.ok(hasEvidence, `${row.id}: no current source and no recorded acceptance`);
  }
});

test('limitations carry a rationale and gates carry an existing owner, the missing evidence and the earlier evidence that stays valid', () => {
  for (const row of ledger.rows.filter((r) => r.status === 'bounded_limitation')) {
    assert.ok(nonEmpty(row.disposition), `${row.id}: disposition`);
    assert.ok(nonEmpty(row.rationale) || (row.owner_card ?? '').length > 1, `${row.id}: rationale or owning card`);
  }
  for (const row of ledger.rows.filter((r) => r.status === 'future_gate')) {
    assert.ok(GATE_OWNERS.has(row.owner_task), `${row.id}: owner task ${row.owner_task} is not an existing gate card`);
    assert.ok(typeof row.owner === 'string' && row.owner.length > 1, `${row.id}: owner`);
    assert.ok(nonEmpty(row.missing_evidence), `${row.id}: names the evidence that is still missing`);
    assert.ok(nonEmpty(row.valid_earlier_evidence), `${row.id}: names the earlier evidence and its limit`);
  }
  const text = JSON.stringify(ledger.rows).toLowerCase();
  for (const vague of ['follow up later', 'to be decided', 'tbd', 'todo']) assert.equal(text.includes(vague), false, `vague wording: ${vague}`);
});

test('every card links its rows by id that exist, and the rendered markdown mentions every row and every card', () => {
  const ids = new Set(ledger.rows.map((r) => r.id));
  for (const card of ledger.cards) for (const id of card.finding_rows) assert.ok(ids.has(id), `${card.task_id}: unknown row ${id}`);
  for (const row of ledger.rows) assert.ok(markdown.includes(`\`${row.id}\``) || markdown.includes(`### ${row.id} `), `markdown is missing ${row.id}`);
  for (const card of ledger.cards) assert.ok(markdown.includes(`\`${card.task_id}\``), `markdown is missing card ${card.task_id}`);
  assert.ok(markdown.includes('t_3064b26e') && /excluded/i.test(markdown));
});

test('the ledger does not claim the card is accepted, merged or that C4 is satisfied', () => {
  assert.equal(/c4 (is )?satisf(ied|y)/i.test(markdown), false);
  assert.equal(/\bmerged by nico\b/i.test(markdown), false);
  assert.match(markdown, /not a CI result/);
});

// Round-1 review sweep (run 496): the carried items recorded in the limitation/residual/carried/nonblocking fields of the P1.01-P1.10 and C2 runs
// must stay in the ledger with their source run identifiers, and no in-scope card may be left without a row.
test('every in-scope card has at least one row and cross references name existing rows', () => {
  const ids = new Set(ledger.rows.map((r) => r.id));
  for (const card of ledger.cards.filter((c) => c.in_scope)) assert.ok(card.finding_rows.length > 0, `${card.task_id}: no row, so the coverage note would be false`);
  for (const row of ledger.rows) for (const see of row.see_rows ?? []) assert.ok(ids.has(see), `${row.id}: see_rows names unknown row ${see}`);
});

test('the auth-card carried items found by the sweep keep their source run identifiers', () => {
  const expected = {
    'P108-R431-stranded-AAL1-session': 'run431',
    'P108-R431-authorizer-revalidation-end-to-end': 'run431',
    'P110-R440-bearer-http-evidence': 'run440',
    'P110-R440-AgentTokenHash-presentation': 'run440',
    'P110-R440-owner-state-cascade': 'run440',
    'P105-R238-repository-poison': 'run238',
    'P105-R238-normalizer-advisory-ownership': 'run238',
    'P104-R164-nested-worktree-vcs-stamp': 'run164',
    'P103-R132-modelled-persistence-loss': 'run132',
    'P103-R132-soft-go-limits-no-oom-guarantee': 'run132',
    'C2-O1-session-revocation-leases': 'run442',
  };
  for (const [id, run] of Object.entries(expected)) {
    const row = ledger.rows.find((r) => r.id === id);
    assert.ok(row, `${id}: missing`);
    assert.ok(row.source_refs.join(' ').includes(run), `${id}: source reference ${run} not kept`);
  }
});
