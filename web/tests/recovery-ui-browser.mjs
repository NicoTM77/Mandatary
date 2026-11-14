import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import { setTimeout as sleep } from 'node:timers/promises';
import path from 'node:path';
import process from 'node:process';
import { URL } from 'node:url';
import { engineName, launchEngine, viewport } from './engine.mjs';
import { auditAccessibility } from './a11y-audit.mjs';
import { allowsAppRequest, appOrigin, control, controlBase, rawRequest, scanSurfaces, totpCode } from './admin-ui-lib.mjs';

/* global console, document */

// Export, restore and reapproval browser tests (P1.18.3) against the REAL services (internal/auth/recovery_ui_browser_test.go starts
// them behind synthetic loopback TLS). One scenario per invocation, in one colour scheme (the theme follows prefers-color-scheme).
// Failures name a step and a surface, never a secret. All credentials are synthetic. The host recovery ceremony that ends restore
// quarantine is MODELED by the fixture's control server (a later card owns the real one): everything else is the product.

const [scenario, scheme, originArg, controlArg] = process.argv.slice(2);
assert.ok(['light', 'dark'].includes(scheme), 'scheme');
const origin = appOrigin(originArg);
const host = control(controlBase(controlArg));
const shotsDir = process.env.MANDATARY_UI_SHOTS ?? '';

const SESSION_COOKIE = '__Host-mandatary_session';
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const DOCUMENTS = ['/', '/login', '/security', '/agents', '/backup', '/restore', '/restore/review'];
const USER = 'synthetic-user';
const PASSWORD = 'a unique synthetic public phrase';

const browser = await launchEngine();
const observed = { blocked: [], console: [], errors: [], requests: [], responses: [] };
const pending = [];
const canaries = new Set();
let lastPage = null;

async function newContext() {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block', colorScheme: scheme, viewport: viewport(), acceptDownloads: true });
  await context.route('**/*', (route) => {
    const request = route.request();
    if (allowsAppRequest(origin, request.url(), request.method())) return route.continue();
    observed.blocked.push(`${request.method()} ${new URL(request.url()).pathname}`);
    return route.abort('blockedbyclient');
  });
  context.on('request', (request) => pending.push(request.allHeaders().then((headers) => observed.requests.push({ method: request.method(), url: request.url(), headers }))));
  context.on('response', (response) => pending.push(response.allHeaders().then((headers) => observed.responses.push({ url: response.url(), status: response.status(), headers }))));
  context.on('page', (page) => {
    page.on('console', (message) => observed.console.push({ type: message.type(), text: message.text() }));
    page.on('pageerror', (error) => observed.errors.push(error.name));
  });
  return context;
}

async function shot(page, name) {
  if (shotsDir) await page.screenshot({ path: path.join(shotsDir, `${scenario}-${scheme}-${name}.png`), fullPage: true });
}

const field = (page, label) => page.getByLabel(label, { exact: true });
const button = (page, name) => page.getByRole('button', { name, exact: true });
const step = (name) => ({ name, scan: (page, secrets) => scanSurfaces(page, [...secrets, ...canaries], name) });

/** On a phone-sized viewport the primary navigation is collapsed behind a Menu button (aria-expanded); open it. */
async function openMenu(page) {
  const menu = page.getByRole('button', { name: 'Menu', exact: true });
  if ((await menu.isVisible()) && (await menu.getAttribute('aria-expanded')) === 'false') await menu.click();
}

async function theme(page) {
  await page.waitForFunction((expected) => document.documentElement.dataset.theme === expected, scheme, { timeout: 5000 }).catch(() => undefined);
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), scheme, 'theme follows the colour scheme');
}

const requestsTo = async (method, pathname) => {
  await Promise.all(pending);
  return observed.requests.filter((request) => request.method === method && new URL(request.url).pathname === pathname).length;
};

// ───────────────────────── shared end-of-run assertions ─────────────────────────

async function finish(extraSecrets) {
  await Promise.all(pending);
  assert.deepEqual(observed.blocked, [], 'the page tried to reach something outside the fixture allowlist');
  assert.deepEqual(observed.errors, [], 'uncaught page errors');
  // Only the browser's own note about a non-2xx fetch (no body, no secret) may reach the console.
  for (const message of observed.console) assert.match(message.text, /^Failed to load resource: the server responded with a status of \d{3}/, `unexpected console output (${message.type})`);
  for (const request of observed.requests) {
    const url = new URL(request.url);
    assert.equal(url.search, '', 'no request carries a query string');
    assert.ok(!('authorization' in request.headers), 'no Authorization header');
    if (['POST', 'PUT', 'DELETE'].includes(request.method) && !/\/api\/v1\/(login|recovery)$/.test(url.pathname)) assert.ok(request.headers['x-csrf-token'], `CSRF header on ${request.method} ${url.pathname}`);
    if (request.method === 'POST') assert.equal(request.headers['content-type'], 'application/json');
  }
  for (const response of observed.responses) {
    const url = new URL(response.url);
    assert.equal(response.headers['cache-control'], 'no-store', `no-store on ${url.pathname}`);
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    if (DOCUMENTS.includes(url.pathname)) assert.equal(response.headers['content-security-policy'], CSP, `document CSP on ${url.pathname}`);
    if (url.pathname.startsWith('/api/') && response.status !== 204) assert.match(response.headers['content-type'] ?? '', /^application\/json/);
  }
  const all = JSON.stringify({ console: observed.console, errors: observed.errors, requests: observed.requests.map((r) => r.url) });
  const secrets = [...extraSecrets, ...canaries].filter((s) => s.length >= 8);
  for (const secret of secrets) assert.ok(!all.includes(secret), 'a secret reached console/error/URL output');
  assert.equal(await host.leaked(secrets), false, 'a secret reached the server log');
  assert.equal(await host.storeLeaked(secrets), false, 'a secret rests in the database in the clear');
}

// ───────────────────────── driving the real pages ─────────────────────────

let lastCode = '';
async function freshCode(seed) {
  let code;
  do {
    await host.advance(31);
    code = totpCode(seed, await host.now());
  } while (code === lastCode);
  lastCode = code;
  return code;
}

async function signIn(page, seed) {
  lastPage = page;
  await page.goto(new URL('/login', origin).href);
  await field(page, 'Username').fill(USER);
  await field(page, 'Password').fill(PASSWORD);
  await button(page, 'Sign in').click();
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  await field(page, '6-digit code').fill(await freshCode(seed));
  await button(page, 'Verify').click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
}

async function openRecovery(page, link, heading) {
  lastPage = page;
  await openMenu(page);
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: link, exact: true }).click();
  await page.getByRole('heading', { name: heading, level: 1 }).waitFor();
}

async function stepUp(page, seed, action) {
  await page.getByRole('heading', { name: `Confirm it’s you to ${action}` }).waitFor();
  await field(page, 'Password').fill(PASSWORD);
  await field(page, '6-digit code').fill(await freshCode(seed));
  await button(page, 'Verify').click();
  await page.getByRole('heading', { name: 'You’re verified' }).waitFor();
  await button(page, 'Continue').click();
}

/** Presses an export button and returns the saved file. The archive is a secret-bearing artefact: its sealed parts become canaries. */
async function exportFile(page, mode) {
  const label = mode === 'full' ? 'Export full backup' : 'Export clean backup';
  const [download] = await Promise.all([page.waitForEvent('download'), button(page, label).click()]);
  const name = download.suggestedFilename();
  assert.ok(/^mandatary-backup-[A-Za-z0-9_.-]+\.json$/.test(name) && name.endsWith(`-${mode}.json`), 'the saved name is the server-issued one');
  // The bytes are read from the download stream in memory; nothing is written to disk by this script.
  const chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString('utf8');
  const archive = JSON.parse(text);
  assert.equal(archive.format, 'mandatary-logical-backup');
  assert.equal(archive.mode, mode);
  if (mode === 'full') {
    assert.ok(archive.secrets?.ciphertext, 'a full backup carries a sealed envelope');
    canaries.add(archive.secrets.ciphertext.slice(0, 24));
  } else {
    assert.ok(archive.secrets === null || archive.secrets === undefined, 'a clean backup carries no credential material');
  }
  canaries.add(archive.integrity_hmac.slice(0, 16));
  return { name, text, archive, upload: upload(name, text) };
}

/** A file the page's file input can be given, held in memory (Playwright's payload form). */
function upload(name, content) {
  return { name, mimeType: 'application/json', buffer: Buffer.from(content) };
}

async function writeVariant(name, archive, edit) {
  const copy = JSON.parse(JSON.stringify(archive));
  edit(copy);
  return upload(name, JSON.stringify(copy));
}

const flip = (value) => (value[0] === 'A' ? 'B' : 'A') + value.slice(1);

async function chooseFile(page, file) {
  await field(page, 'Backup file').setInputFiles(file);
  await button(page, 'Restore from this file…').click();
}
async function typeAndConfirm(page, phrase = 'RESTORE') {
  await field(page, 'Type RESTORE to confirm').fill(phrase);
  await button(page, 'Restore this backup').click();
}

async function signedInStill(page) {
  await openMenu(page);
  await page.getByRole('navigation', { name: 'Primary' }).waitFor();
}

// ───────────────────────── scenario: export ─────────────────────────

async function exportFlows() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  await signIn(page, seed);
  await theme(page);
  await host.world();

  // The Recovery group is in the shell for this administrator, and is a convenience only (the server decides).
  await openMenu(page);
  for (const link of ['Export backup', 'Restore from backup', 'Review restored access']) await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: link, exact: true }).waitFor();
  await openRecovery(page, 'Export backup', 'Export a backup');
  await page.getByText('A backup is a snapshot, not a rollback').waitFor();
  await auditAccessibility(page, 'export idle');
  await shot(page, 'export-idle');
  const before = await host.state();

  // A clean backup is the default; the saved name is the server's and the page says nothing in this installation changed.
  assert.equal(await page.getByRole('radio', { name: /Clean backup/ }).isChecked(), true, 'clean is the default');
  const clean = await exportFile(page, 'clean');
  await page.getByText(clean.name).waitFor();
  await page.getByText(/Nothing in this installation changed/).waitFor();
  await shot(page, 'export-clean-done');
  await step('clean export done').scan(page, [PASSWORD, seed]);
  assert.deepEqual(await host.state(), before, 'an export changes nothing');

  // Full: the credential-material warning is on the page before the file is made.
  await page.getByRole('radio', { name: /Full backup/ }).check();
  await page.getByText('A full backup holds credential material').waitFor();
  await shot(page, 'export-full-chosen');
  const full = await exportFile(page, 'full');
  await page.getByText(full.name).waitFor();
  await step('full export done').scan(page, [PASSWORD, seed]); // the sealed parts are canaries now
  assert.deepEqual(await host.state(), before, 'a full export changes nothing');
  const rawFull = full.text;
  for (const forbidden of ['verifier', 'token_hash', 'secret_hash', 'password_hash']) assert.ok(!rawFull.includes(forbidden), `the full archive names ${forbidden}`);
  assert.ok(!/"sessions"|"csrf|usage_stats/.test(rawFull), 'no session or usage state is exported');

  // A request made after fifteen minutes needs a fresh verification; the blocked request is NOT replayed (no file is made).
  await host.advance(16 * 60);
  let downloaded = false;
  page.once('download', () => {
    downloaded = true;
  });
  await page.getByRole('radio', { name: /Clean backup/ }).check();
  await button(page, 'Export clean backup').click();
  await page.getByRole('heading', { name: 'Confirm it’s you to export a backup' }).waitFor();
  await sleep(500);
  assert.equal(downloaded, false, 'the blocked export was replayed');
  assert.equal(await requestsTo('POST', '/api/v1/admin/backup/export'), 3, 'the blocked export is one request that was refused, and none was replayed');
  await shot(page, 'export-step-up');
  await step('export step-up').scan(page, [PASSWORD]);
  await stepUp(page, seed, 'export a backup');
  const again = await exportFile(page, 'clean');
  assert.ok(again.name, 'after the step-up the person presses the button again and gets the file');

  await finish([PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── scenario: restore, reapproval, tamper, scope ─────────────────────────

async function restoreFlows() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  await signIn(page, seed);
  await theme(page);
  await host.world();
  await openRecovery(page, 'Export backup', 'Export a backup');
  const clean = await exportFile(page, 'clean');
  await page.getByRole('radio', { name: /Full backup/ }).check();
  const full = await exportFile(page, 'full');
  await host.localChange(); // a person and a DENY the file cannot know about
  const live = await host.state();
  assert.ok(live.activeUsers >= 2 && live.sessions >= 1 && live.quarantined === 0);

  await openRecovery(page, 'Restore from backup', 'Restore from a backup');
  await page.getByText('A backup is a snapshot, not a rollback').waitFor();
  await page.getByText(/can’t preview it/).waitFor();
  await auditAccessibility(page, 'restore idle');
  await shot(page, 'restore-idle');

  // ── refused before any request: a wrong phrase, an empty file, a file over the bound
  await chooseFile(page, full.upload);
  await page.getByRole('group', { name: /^Restore from / }).waitFor();
  await shot(page, 'restore-confirm');
  await auditAccessibility(page, 'restore confirm');
  await field(page, 'Type RESTORE to confirm').fill('restore');
  await button(page, 'Restore this backup').click();
  await page.getByText('Type RESTORE in capital letters to continue.').waitFor();
  assert.equal(await requestsTo('POST', '/api/v1/admin/restore'), 0, 'a wrong phrase sent nothing');
  await page.keyboard.press('Escape');
  await page.getByRole('group', { name: /^Restore from / }).waitFor({ state: 'detached' });
  const empty = upload('empty.json', '');
  await field(page, 'Backup file').setInputFiles(empty);
  await button(page, 'Restore from this file…').click();
  await page.getByText('That file is empty.').waitFor();
  const big = upload('big.json', Buffer.alloc(16 * 1024 * 1024 + 1024, 0x20));
  await field(page, 'Backup file').setInputFiles(big);
  await button(page, 'Restore from this file…').click();
  await page.getByText(/refuses anything over 16 MiB/).waitFor();
  assert.equal(await requestsTo('POST', '/api/v1/admin/restore'), 0, 'a local refusal sent nothing');

  // ── tamper: each is a fixed refusal, nothing changed, the person is still signed in, the file is kept
  const tampers = [
    ['integrity tag flipped', full.archive, (a) => (a.integrity_hmac = flip(a.integrity_hmac)), /Nothing was changed/],
    ['a record edited', full.archive, (a) => (a.scope.users[0].username = 'mallory'), /Nothing was changed/],
    ['sealed envelope flipped', full.archive, (a) => (a.secrets.ciphertext = flip(a.secrets.ciphertext)), /Nothing was changed/],
    ['a version from the future', full.archive, (a) => (a.schema_version = 2), /Nothing was changed/],
    ['a smuggled control field', full.archive, (a) => (a.restore_quarantined = 0), /Nothing was changed/],
  ];
  let n = 0;
  for (const [name, archive, edit, words] of tampers) {
    const file = await writeVariant(`tamper-${n++}.json`, archive, edit);
    await chooseFile(page, file);
    await typeAndConfirm(page);
    const alert = page.getByRole('alert').first();
    await alert.waitFor();
    assert.match((await alert.textContent()) ?? '', words, `${name}: says nothing changed`);
    assert.equal(await page.getByRole('heading', { level: 1, name: 'Restore complete' }).count(), 0, `${name}: not a restore`);
    await signedInStill(page);
    assert.deepEqual(await host.state(), live, `${name}: nothing changed in the installation`);
    if (n === 1) {
      await shot(page, 'restore-rejected');
      await auditAccessibility(page, 'restore rejected');
    }
  }
  const notJson = upload('not-json.json', 'this is not a backup {"x":1},"acknowledge_unauthenticated_provenance":true');
  await chooseFile(page, notJson);
  await typeAndConfirm(page);
  await page.getByText('That isn’t a readable Mandatary backup').waitFor();
  assert.deepEqual(await host.state(), live, 'a file that is not JSON changed nothing, and could not set the acknowledgement itself');

  // ── a clean file whose origin this installation cannot verify: ask, tick, restore (clean/new-key mode)
  const foreign = await writeVariant('foreign-clean.json', clean.archive, (a) => (a.integrity_hmac = 'A'.repeat(a.integrity_hmac.length)));
  await chooseFile(page, foreign);
  await typeAndConfirm(page);
  await page.getByText('This file’s origin can’t be verified', { exact: true }).waitFor();
  assert.deepEqual(await host.state(), live, 'the unacknowledged attempt changed nothing');
  const box = page.getByRole('checkbox', { name: /origin can’t be verified/ });
  assert.equal(await box.isChecked(), false, 'the acknowledgement starts unticked');
  await shot(page, 'restore-needs-acknowledgement');
  await auditAccessibility(page, 'restore needs acknowledgement');
  await box.check();
  await button(page, 'Restore this backup').click();

  // ── the terminal page: no shell, no retry, the truth about what the restore did
  await page.getByRole('heading', { level: 1, name: 'Restore complete' }).waitFor();
  await page.getByText('Sign-in is closed until the host recovery is done').waitFor();
  assert.equal(await page.getByRole('navigation', { name: 'Primary' }).count(), 0, 'the signed-in shell is gone');
  assert.equal(await page.getByRole('button', { name: /restore|try again|retry/i }).count(), 0, 'no retry is offered');
  await shot(page, 'restore-complete');
  await auditAccessibility(page, 'restore complete');
  await step('restore complete').scan(page, [PASSWORD, seed]);
  const after = await host.state();
  assert.equal(after.quarantined, 1, 'restore quarantine is in force');
  assert.equal(after.sessions, 0, 'every session ended, the initiator’s too');
  assert.equal(after.reports, 1);
  assert.deepEqual([after.activeUsers, after.activeGroups, after.activeAgents, after.activePolicies, after.activeCredentials], [0, 0, 0, 0, 0], 'nothing imported is effective');

  // ── signed out and closed: the page after a reload is the sign-in page, and sign-in does not open the installation
  await page.reload();
  await page.waitForURL(new URL('/login', origin).href);
  await field(page, 'Username').fill(USER);
  await field(page, 'Password').fill(PASSWORD);
  await button(page, 'Sign in').click();
  const outcome = await Promise.race([
    page.getByRole('alert').first().waitFor().then(() => 'alert'),
    page.getByRole('heading', { name: 'Verify it’s you' }).waitFor().then(() => 'factor'),
  ]);
  if (outcome === 'factor') {
    await field(page, '6-digit code').fill(await freshCode(seed));
    await button(page, 'Verify').click();
    await page.getByRole('alert').first().waitFor();
  }
  assert.equal(await page.getByRole('heading', { name: 'Overview', level: 1 }).count(), 0, 'sign-in did not open a quarantined installation');
  assert.equal((await host.state()).sessions, 0, 'no session exists while quarantined');
  await shot(page, 'login-closed');

  // ── the modeled host recovery, then explicit, per-record reapproval
  await host.ceremony();
  await signIn(page, seed);
  await openRecovery(page, 'Review restored access', 'Review restored access');
  await page.getByText('Nothing listed here is active until you approve it').waitFor();
  await shot(page, 'review');
  await auditAccessibility(page, 'review');
  await page.getByText('Not in the file').first().waitFor(); // the post-backup person and DENY were kept, switched off
  const checkboxes = await page.getByRole('checkbox').all();
  for (const checkbox of checkboxes) assert.equal(await checkbox.isChecked(), false, 'nothing is ticked by default');
  assert.equal(await page.getByRole('button', { name: /approve all|select all/i }).count(), 0, 'there is no approve-everything');

  await page.getByRole('checkbox', { name: 'User browser-alice' }).check();
  await page.getByRole('checkbox', { name: 'Group browser-ops' }).check();
  await button(page, 'Approve 2 selected…').click();
  const confirm = page.getByRole('group', { name: /^Approve 2 records\?/ });
  await confirm.waitFor();
  await shot(page, 'review-confirm');
  assert.equal(await requestsTo('POST', '/api/v1/admin/restore/approvals'), 0, 'naming the records sent nothing');
  await confirm.getByRole('button', { name: 'Approve 2 records' }).click();
  await page.getByText('Approved 2 records').waitFor();
  const approved = await host.state();
  assert.equal(approved.activeGroups, 1);
  assert.equal(approved.activePolicies, 0, 'no rule became effective by approving its group');
  assert.equal(approved.activeCredentials, 0, 'approval grants no credential');
  await page.getByRole('checkbox', { name: 'User browser-alice' }).waitFor({ state: 'detached' }); // the list is re-read: an approved record is not offered again

  // The agent and then one rule, each by name. The restored agent's token page is linked, never reimplemented.
  await page.getByRole('checkbox', { name: 'Agent browser-bot' }).check();
  const rules = page.getByRole('checkbox', { name: /^(Rule|Policy).*(ALLOW|Allow).*logs/i });
  await rules.first().check();
  await button(page, 'Approve 2 selected…').click();
  await page.getByRole('group', { name: /^Approve 2 records\?/ }).getByRole('button', { name: 'Approve 2 records' }).click();
  await page.getByText('Approved 2 records').waitFor();
  const final = await host.state();
  assert.equal(final.activeAgents, 1);
  assert.equal(final.activePolicies, 1, 'exactly the named rule is effective; the retained DENY and everything unnamed is not');
  assert.equal(final.activeCredentials, 0, 'the old token was never revived');
  const tokenLink = page.locator('a[href^="/agents#agent="]').first();
  assert.match((await tokenLink.getAttribute('href')) ?? '', /^\/agents#agent=/, 'the token page is linked');
  await shot(page, 'review-approved');
  await auditAccessibility(page, 'review approved');
  await step('review done').scan(page, [PASSWORD, seed]);

  // Credential reissuance goes through the agent-token flow: a NEW token, shown once, accepted by the shared verifier.
  await tokenLink.click();
  await page.getByRole('heading', { name: 'Agents', level: 1 }).waitFor();
  await page.getByRole('heading', { name: 'Credentials for browser-bot' }).waitFor();
  await button(page, 'Issue token').click();
  const reveal = page.getByRole('region', { name: 'New token for browser-bot' });
  await reveal.waitFor();
  const token = ((await reveal.locator('.secret-select').allTextContents())[0] ?? '').replace(/\s/g, '');
  assert.ok(token.length >= 20);
  canaries.add(token);
  assert.equal(await host.agentAccepts(token), true, 'a newly issued token for the approved agent works');
  assert.equal((await host.state()).activeCredentials, 1, 'exactly the new credential is effective');
  await page.getByLabel('I have copied this token to where the agent will read it.').check();
  await button(page, 'Hide the token').click();
  await step('token hidden').scan(page, [token]);

  await finish([PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── scenario: a failure inside the import ─────────────────────────

async function restoreFailure() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  await signIn(page, seed);
  await theme(page);
  await host.world();
  await openRecovery(page, 'Export backup', 'Export a backup');
  await page.getByRole('radio', { name: /Full backup/ }).check();
  const full = await exportFile(page, 'full');
  await openRecovery(page, 'Restore from backup', 'Restore from a backup');

  const beforeRestore = await host.state();
  await host.fault(true); // SQLite itself raises a constraint failure while the import writes a group
  await chooseFile(page, full.upload);
  await typeAndConfirm(page);
  await page.getByRole('heading', { level: 1, name: 'The restore didn’t finish' }).waitFor();
  await page.getByText('Sign-in is closed, and nothing was imported').waitFor();
  assert.equal(await page.getByRole('navigation', { name: 'Primary' }).count(), 0);
  assert.equal(await page.getByRole('button', { name: /restore|try again|retry/i }).count(), 0, 'no retry is offered');
  assert.ok(!/Nothing was changed/.test((await page.getByRole('alert').first().textContent()) ?? ''), 'the page never says nothing changed after the first step committed');
  await shot(page, 'restore-incomplete');
  await auditAccessibility(page, 'restore incomplete');
  const after = await host.state();
  assert.equal(after.quarantined, 1, 'the first step had happened: quarantine is in force');
  assert.equal(after.sessions, 0);
  assert.equal(after.reports, 0, 'nothing from the file was kept');
  assert.equal(after.users, beforeRestore.users, 'no record of the file was kept (the rolled-back import left the record set as it was)');
  assert.equal(after.policies, beforeRestore.policies);

  // The same file can be restored again after the host recovery, and that is safe.
  await host.fault(false);
  await host.ceremony();
  await signIn(page, seed);
  await openRecovery(page, 'Restore from backup', 'Restore from a backup');
  await chooseFile(page, full.upload);
  await typeAndConfirm(page);
  await page.getByRole('heading', { level: 1, name: 'Restore complete' }).waitFor();
  const retried = await host.state();
  assert.equal(retried.reports, 1);
  assert.equal(retried.quarantined, 1);
  assert.equal(retried.activeUsers, 0);
  await shot(page, 'restore-complete-after-retry');

  await finish([PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── scenario: two restores at once ─────────────────────────

async function parallelRestore() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const one = await context.newPage();
  await signIn(one, seed);
  await theme(one);
  await host.world();
  await openRecovery(one, 'Export backup', 'Export a backup');
  await one.getByRole('radio', { name: /Full backup/ }).check();
  const full = await exportFile(one, 'full');
  const two = await context.newPage(); // the same session, a second tab
  await two.goto(new URL('/restore', origin).href);
  await two.getByRole('heading', { name: 'Restore from a backup', level: 1 }).waitFor();
  await openRecovery(one, 'Restore from backup', 'Restore from a backup');
  for (const page of [one, two]) {
    await chooseFile(page, full.upload);
    await field(page, 'Type RESTORE to confirm').fill('RESTORE');
  }
  await Promise.all([button(one, 'Restore this backup').click(), button(two, 'Restore this backup').click()]);
  // Each tab ends on a page that says what it knows. Exactly one of them can say the restore completed.
  const verdict = async (page) => {
    const text = await Promise.race([
      page.getByRole('heading', { level: 1, name: 'Restore complete' }).waitFor({ timeout: 30_000 }).then(() => 'complete'),
      page.getByRole('heading', { level: 1, name: 'The restore didn’t finish' }).waitFor({ timeout: 30_000 }).then(() => 'incomplete'),
      page.getByRole('heading', { level: 1, name: 'Mandatary couldn’t confirm what happened' }).waitFor({ timeout: 30_000 }).then(() => 'unconfirmed'),
      page.waitForURL(new URL('/login', origin).href, { timeout: 30_000 }).then(() => 'signed-out'),
      page.getByRole('alert').first().waitFor({ timeout: 30_000 }).then(() => 'refused'),
    ]);
    return text;
  };
  const results = await Promise.all([verdict(one), verdict(two)]);
  assert.equal(results.filter((result) => result === 'complete').length, 1, `exactly one restore completed (${results.join(', ')})`);
  const after = await host.state();
  assert.equal(after.quarantined, 1);
  assert.equal(after.reports, 1, 'one restore, one report');
  assert.equal(after.sessions, 0);
  assert.deepEqual([after.activeUsers, after.activeGroups, after.activeAgents, after.activePolicies, after.activeCredentials], [0, 0, 0, 0, 0], 'nothing is effective');
  await shot(one, 'parallel-first-tab');

  await finish([PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── scenario: everyone who is not the administrator ─────────────────────────

async function denial() {
  const seed = await host.seed();
  canaries.add(seed);
  await host.world();
  const ordinary = await host.ordinary();
  canaries.add(ordinary);
  const context = await newContext();
  await context.addCookies([{ name: SESSION_COOKIE, value: ordinary, url: origin.href, secure: true, httpOnly: true }]);
  const page = await context.newPage();
  const before = await host.state();

  // The shell offers an ordinary person no Recovery group (a convenience), and the routes refuse them whatever the page does.
  await page.goto(new URL('/', origin).href);
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  await theme(page);
  await openMenu(page);
  for (const link of ['Export backup', 'Restore from backup', 'Review restored access']) assert.equal(await page.getByRole('link', { name: link, exact: true }).count(), 0, `${link} is not offered`);

  await page.goto(new URL('/backup', origin).href);
  await page.getByRole('heading', { name: 'Export a backup', level: 1 }).waitFor();
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 2000 }).catch(() => null), button(page, 'Export clean backup').click()]);
  await page.getByText('Export wasn’t allowed').waitFor();
  assert.equal(download, null, 'no file was produced for an ordinary person');
  await shot(page, 'denied-export');
  await auditAccessibility(page, 'denied export');

  await page.goto(new URL('/restore', origin).href);
  await page.getByRole('heading', { name: 'Restore from a backup', level: 1 }).waitFor();
  const file = upload('sample.json', JSON.stringify({ format: 'mandatary-logical-backup' }));
  await chooseFile(page, file);
  await typeAndConfirm(page);
  await page.getByText('Restore wasn’t allowed').waitFor();
  await shot(page, 'denied-restore');

  await page.goto(new URL('/restore/review', origin).href);
  await page.getByText('Policy administration isn’t available to this session').waitFor();
  assert.equal(await page.getByRole('checkbox').count(), 0, 'no record is offered to an ordinary person');
  await shot(page, 'denied-review');
  assert.deepEqual(await host.state(), before, 'nothing changed');

  // Directly crafted requests, with that same genuine ordinary session and with none: every one is refused and changes nothing.
  const cookie = `${SESSION_COOKIE}=${ordinary}`;
  const session = (await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie })).json;
  const csrf = session.csrf_token;
  const routes = [
    ['POST', '/api/v1/admin/backup/export', { mode: 'full' }],
    ['POST', '/api/v1/admin/restore', { archive: { format: 'x' }, confirm: 'RESTORE', acknowledge_unauthenticated_provenance: true }],
    ['POST', '/api/v1/admin/restore/approvals', { items: [{ kind: 'user', id: 'browser-alice' }] }],
    ['GET', '/api/v1/admin/restore/manifest', undefined],
  ];
  for (const [method, route, body] of routes) {
    const ordinaryResult = await rawRequest(origin, { method, path: route, body, cookie, csrf });
    assert.ok([403, 404].includes(ordinaryResult.status), `${method} ${route} as an ordinary person: ${ordinaryResult.status}`);
    assert.ok(!JSON.stringify(ordinaryResult.json ?? {}).includes('mandatary-logical-backup'), 'no archive reached an ordinary person');
    assert.equal((await rawRequest(origin, { method, path: route, body })).status, 401, `${method} ${route} without a session`);
    if (method === 'POST') {
      assert.equal((await rawRequest(origin, { method, path: route, body, cookie })).status, 403, `${route} without a CSRF token`);
      assert.equal((await rawRequest(origin, { method, path: route, body, cookie, csrf, headers: { Origin: 'https://evil.invalid' } })).status, 403, `${route} from a foreign origin`);
      assert.equal((await rawRequest(origin, { method, path: route, body: 'x=1', cookie, csrf, contentType: 'application/x-www-form-urlencoded' })).status, 415, `${route} as a form post`);
    }
  }
  assert.deepEqual(await host.state(), before, 'crafted requests changed nothing');

  await finish([seed, ordinary]);
  await context.close();
}

try {
  if (scenario === 'export-flows') await exportFlows();
  else if (scenario === 'restore-flows') await restoreFlows();
  else if (scenario === 'restore-failure') await restoreFailure();
  else if (scenario === 'parallel-restore') await parallelRestore();
  else if (scenario === 'denial') await denial();
  else throw new Error(`unknown scenario ${scenario}`);
  console.log(JSON.stringify({ scenario, scheme, engine: engineName, browser: browser.version(), requests: observed.requests.length, blockedEgress: 0, secretsInConsole: 0 }));
} catch (error) {
  // Diagnostics for a failed run: what the page showed and what it asked, never a secret-bearing value (every credential in this
  // suite is synthetic and the server never echoes one).
  if (lastPage) {
    const text = await lastPage.evaluate(() => document.body.innerText.slice(0, 700)).catch(() => '');
    console.error(`page at failure: ${lastPage.url()}\n${text}`);
  }
  console.error(observed.responses.slice(-8).map((r) => `${r.status} ${new URL(r.url).pathname}`).join('\n'));
  throw error;
} finally {
  await browser.close();
}
