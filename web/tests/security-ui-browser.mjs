import assert from 'node:assert/strict';
import path from 'node:path';
import process from 'node:process';
import { URL } from 'node:url';
import { engineName, launchEngine, viewport } from './engine.mjs';
import { _collectViolationsForTest, auditAccessibility } from './a11y-audit.mjs';
import { allowsAppRequest, appOrigin, control, controlBase, rawRequest, scanSurfaces, totpCode } from './admin-ui-lib.mjs';

/* global console, document */

// Account-security browser tests (P1.16.4) against the REAL services (internal/auth/security_ui_browser_test.go
// starts them behind synthetic loopback TLS and a loopback SMTP receiver). One scenario per invocation, in one
// colour scheme (the theme follows prefers-color-scheme). Failures name a step and a surface, never a secret.
// All credentials are synthetic. Revealed values (seeds, saved codes, agent tokens) are read from the page the
// way a person would copy them, then checked to be gone from every surface after the reveal is closed.

const [scenario, scheme, originArg, controlArg] = process.argv.slice(2);
assert.ok(['light', 'dark'].includes(scheme), 'scheme');
const origin = appOrigin(originArg);
const host = control(controlBase(controlArg));
const shotsDir = process.env.MANDATARY_UI_SHOTS ?? '';

const SESSION_COOKIE = '__Host-mandatary_session';
const RECOVERY_COOKIE = '__Host-mandatary_recovery';
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const DOCUMENTS = ['/', '/setup', '/login', '/security', '/recovery', '/agents'];

const USER = 'synthetic-user';
const PASSWORD = 'a unique synthetic public phrase';
const WRONG_PASSWORD = 'definitely not the right one';

const browser = await launchEngine();
const WEBKIT_SELECT_NOTE = "Refused to apply a stylesheet because its hash, its nonce, or 'unsafe-inline' does not appear in the style-src directive of the Content Security Policy.";
const observed = { blocked: [], console: [], errors: [], requests: [], responses: [], selectNotes: [] };
const pending = [];
const canaries = new Set();

async function newContext() {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block', colorScheme: scheme, viewport: viewport() });
  await context.route('**/*', (route) => {
    const request = route.request();
    if (allowsAppRequest(origin, request.url(), request.method())) return route.continue();
    observed.blocked.push(`${request.method()} ${new URL(request.url()).pathname}`);
    return route.abort('blockedbyclient');
  });
  context.on('request', (request) => pending.push(request.allHeaders().then((headers) => observed.requests.push({ method: request.method(), url: request.url(), headers }))));
  context.on('response', (response) => pending.push(response.allHeaders().then((headers) => observed.responses.push({ url: response.url(), status: response.status(), headers }))));
  context.on('page', (page) => {
    page.on('console', (message) => {
      const entry = { type: message.type(), text: message.text() };
      // Playwright's WebKit (27.2) reports this style-src note for ANY native <select>, with no application code
      // involved (reproduced on a bare page under the product CSP; Chromium and Firefox report nothing; C3
      // observation O3; docs/ui/p1.17-policy-management-ux-contract.md §9.3). The CSP itself is asserted unchanged
      // below and nothing is relaxed: only this exact message, only on WebKit, and only while the page really
      // contains a native <select>, is counted apart; anything else still fails the run.
      if (engineName === 'webkit' && entry.type === 'error' && entry.text === WEBKIT_SELECT_NOTE) {
        pending.push(
          page
            .evaluate(() => document.querySelector('select') !== null)
            .catch(() => false)
            .then((hasSelect) => (hasSelect ? observed.selectNotes.push(entry.text) : observed.console.push(entry))),
        );
        return;
      }
      observed.console.push(entry);
    });
    page.on('pageerror', (error) => observed.errors.push(error.name));
  });
  return context;
}

async function shot(page, name) {
  if (shotsDir) await page.screenshot({ path: path.join(shotsDir, `${scenario}-${scheme}-${name}.png`), fullPage: true });
}

const step = (name) => ({ name, scan: (page, secrets) => scanSurfaces(page, [...secrets, ...canaries], name) });
const field = (page, label) => page.getByLabel(label, { exact: true });

// On a phone-sized viewport the primary navigation is collapsed behind a Menu button (aria-expanded); open it.
async function openMenu(page) {
  const menu = page.getByRole('button', { name: 'Menu', exact: true });
  if ((await menu.isVisible()) && (await menu.getAttribute('aria-expanded')) === 'false') await menu.click();
}
const button = (page, name) => page.getByRole('button', { name, exact: true });

async function theme(page) {
  // The theme is applied by an effect after the first render: wait for it (a slower engine loses this race), then assert.
  await page.waitForFunction((expected) => document.documentElement.dataset.theme === expected, scheme, { timeout: 5000 }).catch(() => undefined);
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), scheme, 'theme follows the colour scheme');
}

// ───────────────────────── shared end-of-run assertions ─────────────────────────

async function finish(extraSecrets) {
  await Promise.all(pending);
  assert.deepEqual(observed.blocked, [], 'the page tried to reach something outside the fixture allowlist');
  assert.deepEqual(observed.errors, [], 'uncaught page errors');
  // Only the browser's own note about a non-2xx fetch (no body, no secret) may reach the console.
  for (const message of observed.console) {
    // The one other advisory: Chromium notes that the SERVER's registration options offer only ES256 (the
    // approved P-256-only key policy of the WebAuthn service). It carries no value and only appears when a
    // key is registered.
    if (scenario === 'key-flows' && message.type === 'warning' && /^publicKey\.pubKeyCredParams is missing at least one of the default algorithm identifiers: ES256 and RS256\./.test(message.text)) continue;
    assert.match(message.text, /^Failed to load resource: the server responded with a status of \d{3}/, `unexpected console output (${message.type})`);
  }
  for (const request of observed.requests) {
    const url = new URL(request.url);
    assert.equal(url.search, '', 'no request carries a query string');
    assert.ok(!('authorization' in request.headers), 'no Authorization header');
    if (['POST', 'PUT', 'DELETE'].includes(request.method) && !/\/api\/v1\/(login|recovery)$/.test(url.pathname)) assert.ok(request.headers['x-csrf-token'], `CSRF header on ${request.method} ${url.pathname}`);
    if (request.method === 'POST' && /\/api\/v1\/(login|recovery)$/.test(url.pathname)) assert.equal(request.headers['x-csrf-token'], undefined, 'no CSRF token before a session or capability exists');
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

let lastCode = "";
let lastPage = null;

/** A TOTP code for the server's present, in a period no earlier code of this seed used (the previous one is spent). */
async function freshCode(seed) {
  let code;
  do {
    await host.advance(31);
    code = totpCode(seed, await host.now());
  } while (code === lastCode);
  lastCode = code;
  return code;
}

async function signIn(page, seed, { app } = {}) {
  lastPage = page;
  await page.goto(new URL('/login', origin).href);
  await field(page, 'Username').fill(USER);
  await field(page, 'Password').fill(PASSWORD);
  await button(page, 'Sign in').click();
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  if (app) await page.getByLabel(app, { exact: true }).check();
  await field(page, '6-digit code').fill(await freshCode(seed));
  await button(page, 'Verify').click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
}

async function sessionCookie(context) {
  const found = (await context.cookies()).find((cookie) => cookie.name === SESSION_COOKIE);
  assert.ok(found, 'session cookie');
  canaries.add(found.value);
  return found;
}

const apiAs = (context, cookie, request) => rawRequest(origin, { ...request, cookie: `${SESSION_COOKIE}=${cookie.value}` });

/** The text of the one reveal-once region, whitespace removed. */
async function revealed(page, heading) {
  const region = page.getByRole('region', { name: heading });
  await region.waitFor();
  const parts = await region.locator('.secret-select').allTextContents();
  return parts.map((part) => part.replace(/\s/g, ''));
}

async function acknowledgeAndHide(page, confirmLabel, doneLabel) {
  await page.getByLabel(confirmLabel).check();
  await button(page, doneLabel).click();
}

async function openSecurity(page) {
  await page.goto(new URL('/security', origin).href);
  await page.getByRole('heading', { name: 'Account security', level: 1 }).waitFor();
}

async function stepUp(page, seed, action) {
  await page.getByRole('heading', { name: `Confirm it’s you to ${action}` }).waitFor();
  await field(page, 'Password').fill(PASSWORD);
  await field(page, '6-digit code').fill(await freshCode(seed));
  await button(page, 'Verify').click();
  await page.getByRole('heading', { name: 'You’re verified' }).waitFor();
  await button(page, 'Continue').click();
}

// ───────────────────────── scenario: signed-in security, agents, step-up ─────────────────────────

async function securityFlows() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  await signIn(page, seed);
  const first = await sessionCookie(context);
  await theme(page);
  await page.getByRole('link', { name: 'Account security' }).first().click();
  await page.getByRole('heading', { name: 'Account security', level: 1 }).waitFor();
  await page.getByText('Authenticator app 1', { exact: true }).waitFor();
  await page.getByText('first@example.invalid').waitFor();
  await page.getByText('second@example.invalid').waitFor();
  await openMenu(page); // a phone-sized viewport collapses the navigation behind the Menu button
  await page.getByRole('link', { name: 'Agent tokens' }).first().waitFor(); // the server said this account administers
  await step('security page').scan(page, [PASSWORD, first.value]);
  await shot(page, 'security');

  // ── step-up: after fifteen minutes a change needs a fresh verification; the blocked request is NOT replayed
  await host.advance(16 * 60);
  const before = await apiAs(context, first, { method: 'GET', path: '/api/v1/account/security' });
  assert.equal(before.status, 200, 'reads need no fresh verification');
  assert.equal(before.json.totp.length, 1);
  await button(page, 'Add authenticator app').click();
  await page.getByRole('heading', { name: 'Confirm it’s you to add an authenticator app' }).waitFor();
  assert.equal(await page.getByRole('heading', { name: 'Authenticator app 2' }).count(), 0);
  assert.equal(await page.getByRole('region', { name: 'Your authenticator key' }).count(), 0, 'no seed was created by the blocked request');
  await shot(page, 'step-up');
  await step('step-up panel').scan(page, [PASSWORD]);
  // A wrong password is refused with the generic outcome and the fields are cleared.
  await field(page, 'Password').fill(WRONG_PASSWORD);
  await field(page, '6-digit code').fill(await freshCode(seed));
  await button(page, 'Verify').click();
  await page.getByRole('alert').filter({ hasText: /verif|accepted|wrong|denied/i }).first().waitFor();
  assert.equal(await field(page, 'Password').inputValue(), '', 'a rejected password is cleared');
  await step('after rejected step-up').scan(page, [WRONG_PASSWORD, PASSWORD]);
  await stepUp(page, seed, 'add an authenticator app');
  // The old session is replaced by its successor: its cookie is dead.
  const second = await sessionCookie(context);
  assert.notEqual(second.value, first.value, 'step-up issues a successor session');
  assert.equal((await apiAs(context, first, { method: 'GET', path: '/api/v1/session' })).status, 401, 'the predecessor session is revoked');
  assert.equal((await apiAs(context, second, { method: 'GET', path: '/api/v1/session' })).status, 200);
  await step('after step-up').scan(page, [PASSWORD, first.value, second.value]);

  // ── a second authenticator app: seed shown once, proven with a code, then gone
  await button(page, 'Add authenticator app').click();
  const seedParts = await revealed(page, 'Your authenticator key');
  const seed2 = seedParts.join('');
  assert.match(seed2, /^[A-Z2-7]{26,}$/, 'a base32 seed was shown');
  await shot(page, 'totp-seed');
  const proof = totpCode(seed2, await host.now());
  await field(page, '6-digit code').fill(proof);
  await button(page, 'Confirm code').click();
  await page.getByRole('heading', { name: 'Authenticator confirmed' }).waitFor();
  assert.equal(await page.getByRole('region', { name: 'Your authenticator key' }).count(), 0);
  await step('seed gone after proof').scan(page, [seed2, PASSWORD]);
  canaries.add(seed2);
  await page.getByText('Authenticator app 2', { exact: true }).waitFor();
  // A reload never shows the seed again.
  await openSecurity(page);
  await step('seed gone after reload').scan(page, [seed2]);

  // ── recovery codes: revealed once, gone after hiding and after a reload
  await button(page, 'Create recovery codes').click();
  const codes = await revealed(page, 'Your recovery codes');
  assert.equal(codes.length, 10);
  for (const code of codes) canaries.add(code);
  await shot(page, 'recovery-codes');
  assert.equal(await button(page, 'Hide the codes').isDisabled(), true, 'hiding waits for the acknowledgement');
  await acknowledgeAndHide(page, 'I have stored these codes somewhere safe.', 'Hide the codes');
  await page.getByText('of 10 codes unused').waitFor();
  await step('codes hidden').scan(page, codes);
  await openSecurity(page);
  await page.getByText('of 10 codes unused').waitFor();
  await step('codes after reload').scan(page, codes);
  assert.equal((await apiAs(context, await sessionCookie(context), { method: 'GET', path: '/api/v1/account/security' })).json.recovery_codes.remaining, 10);

  // ── notification addresses: a wrong proof, then the right one; removal; the last confirmed address stays
  await button(page, 'Add address').click();
  await field(page, 'Email address').fill('third@example.invalid');
  await button(page, 'Send confirmation code').click();
  await page.getByRole('form', { name: 'Confirm notification address' }).waitFor();
  await field(page, 'Code from the email').fill('000000000');
  await button(page, 'Confirm address').click();
  await page.getByRole('alert').first().waitFor();
  const proofCode = await host.proofTo('third@example.invalid');
  canaries.add(proofCode);
  await field(page, 'Code from the email').fill(proofCode);
  await button(page, 'Confirm address').click();
  await page.getByRole('form', { name: 'Confirm notification address' }).waitFor({ state: 'detached' });
  await step('address confirmed').scan(page, [proofCode]);
  await page.getByRole('button', { name: 'Remove third@example.invalid' }).click();
  await shot(page, 'address-remove');
  await page.getByRole('group', { name: 'Confirm removing third@example.invalid' }).getByRole('button', { name: 'Remove address' }).click();
  await page.getByRole('button', { name: 'Remove third@example.invalid' }).waitFor({ state: 'detached' });

  // ── security notices were queued, are delivered on dispatch, and a delivery failure is shown honestly
  assert.ok((await host.dispatch()) > 0, 'queued notices were delivered');
  const mail = await host.mailbox();
  assert.ok(mail.to.includes('first@example.invalid') && mail.to.includes('second@example.invalid'), 'notices went to every confirmed address');
  await host.breakMail();
  await button(page, 'Replace all codes').click();
  await button(page, 'Replace codes').click();
  const replaced = await revealed(page, 'Your recovery codes');
  for (const code of replaced) canaries.add(code);
  await acknowledgeAndHide(page, 'I have stored these codes somewhere safe.', 'Hide the codes');
  await host.dispatch().catch(() => 0);
  await openSecurity(page);
  await page.getByText(/waiting to be sent|weren’t delivered/).first().waitFor();
  await shot(page, 'notice-health');

  // ── signing in with the second app: the person names which app the code is from
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(new URL('/login', origin).href);
  await signIn(page, seed2, { app: 'Authenticator app 2' });
  await shot(page, 'login-app-choice');

  // ── agents: reveal-once token, accepted by the shared verifier, revoked
  await openMenu(page); // a phone-sized viewport collapses the navigation behind the Menu button
  await page.getByRole('link', { name: 'Agent tokens' }).first().click();
  await page.getByRole('heading', { name: 'Agents', level: 1 }).waitFor();
  await page.getByRole('heading', { name: 'Credentials for synthetic-agent' }).waitFor();
  await button(page, 'Issue token').click();
  const [token] = await revealed(page, 'New token for synthetic-agent');
  assert.ok(token && token.length >= 20);
  canaries.add(token);
  assert.equal(await host.agentAccepts(token), true, 'the revealed token is the real credential');
  await shot(page, 'agent-token');
  await acknowledgeAndHide(page, 'I have copied this token to where the agent will read it.', 'Hide the token');
  await step('token hidden').scan(page, [token]);
  await page.reload();
  await page.getByRole('heading', { name: 'Credentials for synthetic-agent' }).waitFor();
  await step('token after reload').scan(page, [token]);
  const row = page.getByRole('button', { name: /^Revoke / }).first();
  await row.click();
  await page.getByRole('button', { name: 'Revoke token' }).click();
  await page.getByText('Revoked').first().waitFor();
  assert.equal(await host.agentAccepts(token), false, 'a revoked token is refused at once');
  await shot(page, 'agent-revoked');

  // ── removing an authenticator ends every session (including this one) and the page says so
  await openSecurity(page);
  const current = await sessionCookie(context);
  await page.getByRole('button', { name: 'Remove Authenticator app 2' }).click();
  await page.getByRole('group', { name: 'Confirm removing Authenticator app 2' }).getByRole('button', { name: 'Remove Authenticator app 2' }).click();
  await page.getByText('Sign-in method removed', { exact: true }).waitFor();
  await shot(page, 'removed');
  assert.equal((await context.cookies()).some((cookie) => cookie.name === SESSION_COOKIE), false, 'the server cleared the session cookie');
  assert.equal((await apiAs(context, current, { method: 'GET', path: '/api/v1/session' })).status, 401, 'removal ended the session');
  await button(page, 'Sign in').click();
  await page.waitForURL(new URL('/login', origin).href);

  await finish([PASSWORD, WRONG_PASSWORD, seed, seed2, token, ...codes, ...replaced]);
  await context.close();
}

// ───────────────────────── scenario: restricted recovery with a saved code ─────────────────────────

async function recoveryFlow() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  lastPage = page;

  // The saved codes exist because the person made them while signed in (the real UI path), then signed out.
  await signIn(page, seed);
  await openSecurity(page);
  await button(page, 'Create recovery codes').click();
  const codes = await revealed(page, 'Your recovery codes');
  assert.equal(codes.length, 10);
  for (const code of codes) canaries.add(code);
  await acknowledgeAndHide(page, 'I have stored these codes somewhere safe.', 'Hide the codes');
  await page.getByText('of 10 codes unused').waitFor();
  await button(page, 'Sign out').click();
  await page.waitForURL(new URL('/login', origin).href);
  await field(page, 'Password').waitFor();
  assert.equal(await page.getByRole('link', { name: /recover/i }).count() > 0, true, 'sign-in links to recovery');

  const attempt = async (user, password, code) => {
    await page.goto(new URL('/recovery', origin).href);
    await page.getByRole('form', { name: 'Recover access' }).waitFor();
    await theme(page);
    await field(page, 'Username').fill(user);
    await field(page, 'Password').fill(password);
    await field(page, 'Recovery code').fill(code);
    await button(page, 'Continue').click();
  };
  const denial = async () => {
    const alert = page.locator('form[aria-label="Recover access"] [role="alert"]');
    await alert.waitFor();
    const text = await alert.textContent();
    assert.equal(await field(page, 'Password').inputValue(), '', 'a rejected password is cleared');
    assert.equal(await field(page, 'Recovery code').inputValue(), '', 'a rejected code is cleared');
    return text;
  };

  // Unknown user, wrong password and a wrong code are ONE outcome (and nobody is signed in).
  const messages = [];
  await attempt('nobody-at-all', PASSWORD, codes[0]);
  messages.push(await denial());
  await attempt(USER, WRONG_PASSWORD, codes[0]);
  messages.push(await denial());
  await attempt(USER, PASSWORD, 'AAAA-AAAA-AAAA-AAAA');
  messages.push(await denial());
  assert.equal(new Set(messages).size, 1, 'unknown user, wrong password and wrong code are indistinguishable');
  await shot(page, 'recovery-denied');
  await step('after denied recovery').scan(page, [WRONG_PASSWORD, PASSWORD]);
  assert.equal((await context.cookies()).length, 0, 'a refused recovery sets no cookie');

  // The genuine attempt: a capability, never a session.
  await attempt(USER, PASSWORD, codes[0]);
  await page.getByText(/Recovery code accepted/).waitFor();
  const cookies = await context.cookies();
  assert.equal(cookies.some((cookie) => cookie.name === SESSION_COOKIE), false, 'recovery issues no session');
  const capability = cookies.find((cookie) => cookie.name === RECOVERY_COOKIE);
  assert.ok(capability, 'a distinct capability cookie');
  canaries.add(capability.value);
  assert.deepEqual({ httpOnly: capability.httpOnly, secure: capability.secure, sameSite: capability.sameSite, path: capability.path }, { httpOnly: true, secure: true, sameSite: 'Strict', path: '/' });
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie: `${SESSION_COOKIE}=${capability.value}` })).status, 401, 'the capability is not a session');
  const [replacement] = await revealed(page, 'Your replacement recovery code');
  assert.ok(replacement);
  canaries.add(replacement);
  await shot(page, 'recovery-capability');
  await acknowledgeAndHide(page, 'I have stored this code somewhere safe.', 'Hide the code');
  await step('replacement hidden').scan(page, [replacement, PASSWORD]);

  // A reload resumes the capability but never shows the replacement code again.
  await page.reload();
  await page.getByText(/Recovery code accepted/).waitFor();
  await step('capability after reload').scan(page, [replacement, PASSWORD]);

  // Re-enrol: the seed is shown once and is proven with a code.
  await button(page, 'Create authenticator key').click();
  const seed3 = (await revealed(page, 'Your authenticator key')).join('');
  assert.match(seed3, /^[A-Z2-7]{26,}$/);
  await field(page, '6-digit code').fill(totpCode(seed3, await host.now()));
  await button(page, 'Confirm code').click();
  await page.getByText('Recovery complete').waitFor();
  canaries.add(seed3);
  await shot(page, 'recovery-complete');
  await step('recovery complete').scan(page, [seed3, replacement, PASSWORD, capability.value]);
  assert.equal((await context.cookies()).some((cookie) => cookie.name === SESSION_COOKIE), false, 'completing recovery still issues no session');
  assert.equal((await context.cookies()).some((cookie) => cookie.name === RECOVERY_COOKIE), false, 'the capability ended');

  // The used code is spent (same outcome as garbage); the old authenticator no longer signs in; the new one does.
  await attempt(USER, PASSWORD, codes[0]);
  assert.equal(await denial(), messages[0], 'a replayed saved code is the one public refusal');
  await page.goto(new URL('/login', origin).href);
  await field(page, 'Username').fill(USER);
  await field(page, 'Password').fill(PASSWORD);
  await button(page, 'Sign in').click();
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  await field(page, '6-digit code').fill(await freshCode(seed));
  await button(page, 'Verify').click();
  await page.getByText('That code wasn’t accepted').waitFor();
  await field(page, '6-digit code').fill(await freshCode(seed3));
  await button(page, 'Verify').click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  await button(page, 'Sign out').click();
  await page.waitForURL(new URL('/login', origin).href);

  // The ten-minute capability ends on the server: the next step is refused and the form returns.
  await attempt(USER, PASSWORD, codes[1]);
  await page.getByText(/Recovery code accepted/).waitFor();
  await host.advance(11 * 60);
  await button(page, 'Create authenticator key').click();
  await page.locator('form[aria-label="Recover access"] [role="alert"]').waitFor();
  assert.equal(await page.getByRole('region', { name: 'Your authenticator key' }).count(), 0, 'an expired capability creates no seed');
  await shot(page, 'recovery-expired');

  await finish([PASSWORD, WRONG_PASSWORD, seed, seed3, replacement, ...codes]);
  await context.close();
}

// ───────────────────────── scenario: security keys (virtual authenticator) ─────────────────────────

async function keyFlows() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  lastPage = page;
  await page.goto(new URL('/login', origin).href);
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  await signIn(page, seed);
  await openSecurity(page);
  assert.equal(await button(page, 'Add security key').isEnabled(), true, 'the server offered security keys');
  await button(page, 'Add security key').click();
  await page.getByText('Your security key is ready to use').waitFor();
  await shot(page, 'key-added');
  await openSecurity(page);
  await page.getByText('Security key 1', { exact: true }).waitFor();
  await step('key added').scan(page, [PASSWORD]);
  await button(page, 'Sign out').click();
  await page.waitForURL(new URL('/login', origin).href);

  // Sign in with the key: user verification is required by the server, the session is phishing-resistant AAL2.
  await field(page, 'Username').fill(USER);
  await field(page, 'Password').fill(PASSWORD);
  await button(page, 'Sign in').click();
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  await page.getByRole('radio', { name: 'Security key' }).check({ force: true });
  await page.getByRole('button', { name: 'Use security key' }).click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  const keySession = await sessionCookie(context);
  const info = await apiAs(context, keySession, { method: 'GET', path: '/api/v1/session' });
  assert.deepEqual({ assurance: info.json.assurance, methods: info.json.methods, phishingResistant: info.json.phishing_resistant }, { assurance: 'aal2', methods: ['webauthn-uv'], phishingResistant: true });
  await page.getByText('Security key with verification').first().waitFor();
  await shot(page, 'key-session');

  // Step-up with the key after the window: a fresh session, no password typed.
  await host.advance(16 * 60);
  await openSecurity(page);
  await button(page, 'Add authenticator app').click();
  await page.getByRole('heading', { name: 'Confirm it’s you to add an authenticator app' }).waitFor();
  await shot(page, 'key-step-up');
  await page.getByRole('button', { name: /security key/i }).first().click();
  await page.getByRole('heading', { name: 'You’re verified' }).waitFor();
  await button(page, 'Continue').click();
  const successor = await sessionCookie(context);
  assert.notEqual(successor.value, keySession.value, 'step-up issued a successor');
  assert.equal((await apiAs(context, keySession, { method: 'GET', path: '/api/v1/session' })).status, 401);
  const stepped = await apiAs(context, successor, { method: 'GET', path: '/api/v1/session' });
  assert.equal(stepped.json.phishing_resistant, true, 'a key step-up keeps the phishing-resistant label');

  // A key that does NOT verify the user is refused by the server and signs nobody in.
  await button(page, 'Sign out').click();
  await page.waitForURL(new URL('/login', origin).href);
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
  await field(page, 'Username').fill(USER);
  await field(page, 'Password').fill(PASSWORD);
  await button(page, 'Sign in').click();
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  await page.getByRole('radio', { name: 'Security key' }).check({ force: true });
  await page.getByRole('button', { name: 'Use security key' }).click();
  await page.locator('[role="alert"]').first().waitFor();
  const leftover = (await context.cookies()).find((cookie) => cookie.name === SESSION_COOKIE);
  assert.equal(leftover === undefined || (await apiAs(context, leftover, { method: 'GET', path: '/api/v1/session' })).status === 401, true, 'no session was issued for an unverified key (only the sign-in capability remains)');
  await shot(page, 'key-unverified');
  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: true });
  await page.getByRole('radio', { name: 'Security key' }).check({ force: true });
  await page.getByRole('button', { name: 'Use security key' }).click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();

  // Removing the key ends every session.
  await openSecurity(page);
  await page.getByRole('button', { name: 'Remove Security key 1' }).click();
  await page.getByRole('group', { name: 'Confirm removing Security key 1' }).getByRole('button', { name: 'Remove Security key 1' }).click();
  await page.getByText('Sign-in method removed', { exact: true }).waitFor();
  assert.equal((await context.cookies()).some((cookie) => cookie.name === SESSION_COOKIE), false);

  await finish([PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── scenario: direct-request denial matrix ─────────────────────────

async function denialMatrix() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  lastPage = page;
  await signIn(page, seed);
  const session = await sessionCookie(context);
  const cookie = `${SESSION_COOKIE}=${session.value}`;
  const csrf = (await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie })).json.csrf_token;
  assert.ok(csrf);
  canaries.add(csrf);
  const wrong = `${csrf.slice(0, -1)}${csrf.endsWith('A') ? 'B' : 'A'}`;

  const mutations = [
    ['/api/v1/stepup/password', { password: WRONG_PASSWORD }],
    ['/api/v1/account/totp', {}],
    ['/api/v1/account/totp/confirm', { authenticator_id: 'x', code: '000000' }],
    ['/api/v1/account/totp/remove', { authenticator_id: 'x' }],
    ['/api/v1/account/recovery-codes', {}],
    ['/api/v1/account/addresses', { address: 'nobody@example.invalid' }],
    ['/api/v1/account/addresses/remove', { id: 'x' }],
    ['/api/v1/account/webauthn/register/begin', {}],
  ];
  const snapshot = async () => JSON.stringify((await rawRequest(origin, { method: 'GET', path: '/api/v1/account/security', cookie })).json);
  const before = await snapshot();
  for (const [route, body] of mutations) {
    const cases = [
      ['no CSRF', { method: 'POST', path: route, cookie, body }, 403],
      ['a wrong CSRF token', { method: 'POST', path: route, cookie, csrf: wrong, body }, 403],
      ['a foreign Origin', { method: 'POST', path: route, cookie, csrf, body, headers: { origin: 'https://evil.invalid' } }, 403],
      ['no Origin', { method: 'POST', path: route, cookie, csrf, body, omit: ['origin'] }, 403],
      ['a cross-site request', { method: 'POST', path: route, cookie, csrf, body, headers: { 'sec-fetch-site': 'cross-site' } }, 403],
      ['a simple form post', { method: 'POST', path: route, cookie, csrf, body: 'a=b', contentType: 'application/x-www-form-urlencoded' }, 415],
      ['a duplicate CSRF header', { method: 'POST', path: route, cookie, body, headers: { 'x-csrf-token': `${csrf}, ${csrf}` } }, 403],
      ['a query string', { method: 'POST', path: `${route}?assurance=aal2`, cookie, csrf, body }, 404],
      ['a client-asserted assurance', { method: 'POST', path: route, cookie, csrf, body: { ...body, assurance: 'aal2' } }, 400],
      ['a client-asserted method and time', { method: 'POST', path: route, cookie, csrf, body: { ...body, method: 'webauthn', now: 1 } }, 400],
      ['no session', { method: 'POST', path: route, csrf, body }, 401],
      ['a forged session', { method: 'POST', path: route, cookie: `${SESSION_COOKIE}=${'A'.repeat(43)}`, csrf, body }, 401],
      ['a GET', { method: 'GET', path: route, cookie }, 405],
    ];
    for (const [name, request, status] of cases) {
      const response = await rawRequest(origin, request);
      assert.equal(response.status, status, `${route}: ${name}: status ${response.status}`);
      assert.equal(response.headers['cache-control'], 'no-store', `${route}: ${name}`);
      // A refusal may CLEAR a dead cookie; it never sets a live one.
      assert.ok(
        response.setCookie.every((value) => /Max-Age=0|Max-Age=-1|Expires=Thu, 01 Jan 1970/i.test(value)),
        `${route}: ${name}: a refused request must not set a cookie`,
      );
    }
  }
  assert.equal(await snapshot(), before, 'no refused request changed any account-security state');

  // The recovery capability and the session are different credentials: neither opens the other's routes.
  const asCapability = await rawRequest(origin, { method: 'POST', path: '/api/v1/recovery/totp', cookie, csrf, body: {} });
  assert.ok([401, 403].includes(asCapability.status), `a session is not a recovery capability: ${asCapability.status}`);
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/recovery/state', cookie })).status, 401);
  // A preauth capability (password step only) opens none of the security routes.
  const preauth = await rawRequest(origin, { method: 'POST', path: '/api/v1/login', body: { username: USER, password: PASSWORD } });
  const preauthCookie = `${SESSION_COOKIE}=${/__Host-mandatary_session=([^;]+)/.exec(preauth.setCookie.join(';'))?.[1]}`;
  canaries.add(preauthCookie.split('=')[1]);
  for (const [route, body] of mutations) {
    const response = await rawRequest(origin, { method: 'POST', path: route, cookie: preauthCookie, csrf: preauth.json.csrf_token, body });
    assert.equal(response.status, 401, `${route}: a preauth capability is not a session`);
  }
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/account/security', cookie: preauthCookie })).status, 401);
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/admin/agents', cookie: preauthCookie })).status, 401);
  for (const route of ['users', 'groups', 'agents', 'rules']) {
    assert.equal((await rawRequest(origin, { method: 'GET', path: `/api/v1/admin/policy/${route}`, cookie: preauthCookie })).status, 401, `policy/${route}: a preauth capability is not a session`);
  }
  assert.equal((await rawRequest(origin, { method: 'POST', path: '/api/v1/admin/policy/rules', cookie: preauthCookie, csrf: preauth.json.csrf_token, body: {} })).status, 401);

  // Step-up: a password alone does not satisfy an MFA account, and a replayed code is refused.
  const spent = totpCode(seed, await host.now());
  const stale = await rawRequest(origin, { method: 'POST', path: '/api/v1/stepup/totp', cookie, csrf, body: { password: PASSWORD, code: spent } });
  assert.equal(stale.status, 403, 'the code the sign-in already used is a replay');
  assert.deepEqual(stale.json, { error: 'denied' });
  const passwordOnly = await rawRequest(origin, { method: 'POST', path: '/api/v1/stepup/password', cookie, csrf, body: { password: PASSWORD } });
  assert.equal(passwordOnly.status, 403, 'a password cannot step up an MFA-capable account');
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie })).status, 200, 'refused step-ups leave the session alone');

  // An administrator is never offered a password-only session, and asking for one directly is refused.
  await context.clearCookies();
  const signInStep = async () => {
    await page.goto(new URL('/login', origin).href);
    await field(page, 'Username').fill(USER);
    await field(page, 'Password').fill(PASSWORD);
    await button(page, 'Sign in').click();
    await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  };
  await signInStep();
  assert.equal(await page.getByRole('button', { name: 'Continue with password only' }).count(), 0, 'an administrator is not offered a password-only session');
  const asAdmin = await rawRequest(origin, { method: 'POST', path: '/api/v1/login', body: { username: USER, password: PASSWORD } });
  const adminPre = `${SESSION_COOKIE}=${/__Host-mandatary_session=([^;]+)/.exec(asAdmin.setCookie.join(';'))?.[1]}`;
  assert.equal((await rawRequest(origin, { method: 'POST', path: '/api/v1/login/no-mfa', cookie: adminPre, csrf: asAdmin.json.csrf_token, body: {} })).status, 403);

  // Lower assurance (an ordinary person under an optional-MFA policy): every change and the agent API are refused.
  await host.demote();
  await host.policy('optional');
  await signInStep();
  await button(page, 'Continue with password only').click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  const lower = await sessionCookie(context);
  const lowerCookie = `${SESSION_COOKIE}=${lower.value}`;
  const lowerCsrf = (await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie: lowerCookie })).json.csrf_token;
  for (const [route, body] of mutations.slice(1)) {
    const response = await rawRequest(origin, { method: 'POST', path: route, cookie: lowerCookie, csrf: lowerCsrf, body });
    assert.equal(response.status, 403, `${route}: password-only evidence is not enough`);
    assert.equal(response.json.error, 'step_up_required');
  }
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/admin/agents', cookie: lowerCookie })).status, 403, 'a password-only session cannot administer agents');
  // The policy pages and commands are refused to the same session before any service runs, and nothing is shown for them.
  for (const route of ['users', 'groups', 'agents', 'rules']) {
    assert.equal((await rawRequest(origin, { method: 'GET', path: `/api/v1/admin/policy/${route}`, cookie: lowerCookie })).status, 403, `policy/${route}: a password-only session cannot read policy administration`);
  }
  for (const [method, route] of [
    ['POST', '/api/v1/admin/users'],
    ['POST', '/api/v1/admin/policy/rules'],
    ['POST', '/api/v1/admin/policy/rules/preview'],
    ['POST', '/api/v1/admin/groups/g/disable'],
  ]) {
    const response = await rawRequest(origin, { method, path: route, cookie: lowerCookie, csrf: lowerCsrf, body: {} });
    assert.equal(response.status, 403, `${route}: password-only evidence cannot administer policy`);
  }
  await page.goto(new URL('/policy', origin).href);
  await page.getByText('Policy administration isn’t available to this session').waitFor();
  assert.equal(await page.getByRole('button', { name: 'Add a rule' }).count(), 0, 'nothing that could change access is offered');
  await openSecurity(page);
  await page.getByText('This session can’t show your security settings').waitFor();
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/account/security', cookie: lowerCookie })).status, 403, 'the inventory is withheld from a password-only session');
  await page.goto(new URL('/agents', origin).href);
  await page.getByText('Agent administration isn’t available to this session').waitFor();
  await shot(page, 'agents-forbidden');
  await step('forbidden agents').scan(page, [PASSWORD]);

  await finish([PASSWORD, WRONG_PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── scenario: policy administration (P1.17) ─────────────────────────

async function openPolicy(page, link, heading) {
  await openMenu(page); // a phone-sized viewport collapses the navigation behind the Menu button
  await page.getByRole('navigation', { name: 'Primary' }).getByRole('link', { name: link, exact: true }).click();
  await page.getByRole('heading', { name: heading, level: 1 }).waitFor();
}

async function policyFlows() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();
  await signIn(page, seed);
  await theme(page);

  // ── the authority note is on every management page, and the pages offer no operations console
  const audits = [];
  async function audit(name) {
    await page.getByText('Managing access isn’t the same as having it').waitFor();
    assert.equal(await page.getByRole('button', { name: /^(Start|Stop|Restart|Read logs|Inspect)\b/ }).count(), 0, `${name}: no container operation is offered`);
    audits.push(await auditAccessibility(page, name));
  }

  // ── users: add one (the session is fresh, so no step-up), then the page lists it
  await openPolicy(page, 'Users', 'Users');
  await audit('users');
  await field(page, 'Username').fill('browser-robin');
  await button(page, 'Add user').click();
  await page.getByText(/Added browser-robin\./).waitFor();
  await page.getByRole('heading', { level: 3, name: 'browser-robin' }).waitFor();
  await shot(page, 'policy-users');
  assert.equal(await page.getByRole('button', { name: /^Delete/ }).count(), 0, 'no user deletion exists');

  // ── a change after fifteen minutes needs a fresh verification; the blocked request is NOT replayed
  await host.advance(16 * 60);
  await openPolicy(page, 'Groups', 'Groups');
  await audit('groups');
  await field(page, 'Group name').fill('browser-ops');
  await button(page, 'Add group').click();
  await page.getByRole('heading', { name: 'Confirm it’s you to add a group' }).waitFor();
  assert.equal(await page.getByRole('heading', { level: 3, name: 'browser-ops' }).count(), 0, 'the blocked request created nothing');
  await shot(page, 'policy-step-up');
  await step('policy step-up').scan(page, [PASSWORD]);
  await stepUp(page, seed, 'add a group');
  await field(page, 'Group name').fill('browser-ops');
  await button(page, 'Add group').click();
  await page.getByRole('heading', { level: 3, name: 'browser-ops' }).waitFor();

  // ── membership and an agent owned by the user
  const addMember = page.getByRole('form', { name: 'Add a member to browser-ops' });
  await addMember.getByLabel('Add a member').selectOption({ label: 'browser-robin' });
  await addMember.getByRole('button', { name: 'Add to browser-ops' }).click();
  await page.getByText('Added browser-robin to browser-ops.').waitFor();
  await openPolicy(page, 'Agents', 'Agents');
  await audit('agents');
  await field(page, 'Agent name').fill('browser-bot');
  await page.getByLabel('Owning user').selectOption({ label: 'browser-robin' });
  await button(page, 'Add agent').click();
  await page.getByRole('heading', { level: 3, name: 'browser-bot' }).waitFor();
  const tokenLink = page.getByRole('link', { name: /browser-bot/ }).filter({ hasText: /token/i }).first();
  if ((await tokenLink.count()) > 0) assert.match((await tokenLink.getAttribute('href')) ?? '', /^\/agents#agent=/, 'the token page is linked, never reimplemented');
  assert.equal(await page.locator('input[type="password"]').count(), 0, 'no secret is handled on the agents page');

  // ── a rule: the only thing that grants. With no Docker backend in this fixture the endpoint is "unverified",
  //    and the page says so instead of listing anything as a match.
  await openPolicy(page, 'Rules', 'Rules');
  await audit('rules');
  await page.getByText('Mandatary can’t verify its own container').first().waitFor();
  await button(page, 'Add a rule').first().click();
  const form = page.getByRole('form', { name: 'Add a rule' });
  const option = form.locator('select[name="subject"] option', { hasText: 'browser-bot' });
  await form.locator('select[name="subject"]').selectOption(await option.getAttribute('value'));
  await form.getByRole('checkbox', { name: /Read logs/ }).check();
  await form.getByLabel('Container name', { exact: true }).fill('browser-proxy');
  await form.getByLabel('Most log lines per request').fill('25');
  await shot(page, 'policy-rule-editor');
  await audit('rule editor');
  await form.getByRole('button', { name: 'Add rule' }).click();
  await page.getByText('Added the rule.').waitFor();
  await page.getByText('Target status unknown').first().waitFor();
  assert.equal(await page.getByText(/Matches \d+ container/).count(), 0, 'an unverified endpoint never reports a match');
  await shot(page, 'policy-rules');
  // The page's own account of the rule, and the server's: one ALLOW logs rule with its cap.
  const listed = await apiAs(context, await sessionCookie(context), { method: 'GET', path: '/api/v1/admin/policy/rules' });
  assert.equal(listed.status, 200);
  assert.equal(listed.json.rules.length, 1);
  assert.deepEqual([listed.json.rules[0].effect, listed.json.rules[0].operation, listed.json.rules[0].log_tail_max, listed.json.rules[0].target.status], ['ALLOW', 'container:logs', 25, 'unknown']);

  // ── disabling asks first, and the rule stays listed as disabled; deleting asks too
  await page.getByRole('button', { name: /^Disable: / }).first().click();
  await page.getByRole('group', { name: /^Disable “/ }).getByRole('button', { name: /^Disable/ }).click();
  await page.getByText(/Disabled the rule for browser-bot\./).waitFor();
  await page.getByText('Disabled', { exact: true }).first().waitFor();
  await page.getByRole('button', { name: /^Delete: / }).first().click();
  await page.getByRole('group', { name: /^Delete “/ }).getByRole('button', { name: 'Delete rule' }).click();
  await page.getByText(/Deleted the rule for browser-bot\./).waitFor();
  assert.equal((await apiAs(context, await sessionCookie(context), { method: 'GET', path: '/api/v1/admin/policy/rules' })).json.rules.length, 0);

  // ── disabling the owner revokes the agent it owns, and the Agents page shows it
  await openPolicy(page, 'Users', 'Users');
  await button(page, 'Disable browser-robin').click();
  await page.getByRole('group', { name: 'Disable browser-robin?' }).getByRole('button', { name: 'Disable browser-robin' }).click();
  await page.getByText('Disabled browser-robin.').waitFor();
  await openPolicy(page, 'Agents', 'Agents');
  const agents = (await apiAs(context, await sessionCookie(context), { method: 'GET', path: '/api/v1/admin/policy/agents' })).json.agents;
  assert.equal(agents.find((a) => a.name === 'browser-bot').state, 'disabled', 'the owner’s disabling cascaded to its agent');
  await openMenu(page); // a phone-sized viewport collapses the navigation behind the Menu button
  await page.getByRole('link', { name: 'Agent tokens' }).first().waitFor();
  await step('policy pages').scan(page, [PASSWORD, seed]);
  assert.ok(audits.length >= 5);

  await finish([PASSWORD, seed]);
  await context.close();
}

// ───────────────────────── the accessibility audit detects what it claims to ─────────────────────────

const BAD_PAGE = `<!doctype html><html><head></head><body>
<div role="button" tabindex="0"></div>
<input type="text" id="a"><input type="text" id="a">
<img src="data:image/gif;base64,R0lGAD">
<p style="color:#bbb;background:#fff">low contrast text here</p>
<button aria-labelledby="missing">x</button>
<h1>one</h1><h3>skipped</h3><h1>again</h1>
<div aria-hidden="true"><button>hidden but focusable</button></div>
<button tabindex="3">positive</button></body></html>`;
const GOOD_PAGE = `<!doctype html><html lang="en"><head><title>ok</title></head><body><main><h1>Title</h1><h2>Part</h2>
<label for="u">User</label><input id="u" type="text"><button type="button">Go</button>
<p style="color:#111;background:#fff">readable text here</p></main></body></html>`;

async function auditSelfCheck() {
  const context = await newContext();
  const page = await context.newPage();
  await page.setContent(BAD_PAGE);
  const bad = await page.evaluate(_collectViolationsForTest);
  const rules = new Set(bad.violations.map((v) => v.rule));
  for (const rule of ['document-language', 'document-title', 'landmark-main', 'page-has-heading-one', 'heading-order', 'duplicate-id', 'control-name', 'label', 'image-alt', 'color-contrast', 'aria-reference', 'aria-hidden-focusable', 'tabindex-positive']) {
    assert.ok(rules.has(rule), `the audit must detect ${rule}; found ${[...rules].join(',')}`);
  }
  await assert.rejects(auditAccessibility(page, 'bad markup'), /accessibility violations/);
  await page.setContent(GOOD_PAGE);
  const good = await page.evaluate(_collectViolationsForTest);
  assert.deepEqual(good.violations, [], 'well-formed markup passes');
  const walked = await auditAccessibility(page, 'good markup');
  assert.equal(walked.tabStops, 2, 'the keyboard walk reaches both controls');
  // Controls inside a closed disclosure are not rendered and cannot take focus, so they are not "unreachable";
  // once it is open they are expected and reached.
  await page.setContent(GOOD_PAGE.replace('</main>', '<details id="d"><summary>More</summary><label for="x">Extra</label><input id="x" type="text"></details></main>'));
  assert.equal((await auditAccessibility(page, 'closed disclosure')).tabStops, 3, 'summary is a stop; its closed content is not expected');
  await page.evaluate(() => {
    document.getElementById('d').open = true;
  });
  assert.equal((await auditAccessibility(page, 'open disclosure')).tabStops, 4, 'an open disclosure’s controls are expected and reached');
  await context.close();
}

try {
  if (scenario === 'a11y-selfcheck') await auditSelfCheck();
  else if (scenario === 'security-flows') await securityFlows();
  else if (scenario === 'recovery-flow') await recoveryFlow();
  else if (scenario === 'key-flows') await keyFlows();
  else if (scenario === 'denial-matrix') await denialMatrix();
  else if (scenario === 'policy-flows') await policyFlows();
  else throw new Error(`unknown scenario ${scenario}`);
  console.log(JSON.stringify({ scenario, scheme, engine: engineName, browser: browser.version(), requests: observed.requests.length, blockedEgress: 0, secretsInConsole: 0, webkitSelectNotes: observed.selectNotes.length }));
} catch (error) {
  // Diagnostics for a failed run: what the page showed and what it asked, never a secret-bearing value
  // (every credential in this suite is synthetic and the server never echoes one).
  if (lastPage) {
    const text = await lastPage.evaluate(() => document.body.innerText.slice(0, 600)).catch(() => '');
    console.error(`page at failure: ${lastPage.url()}\n${text}`);
  }
  console.error(observed.responses.slice(-6).map((r) => `${r.status} ${new URL(r.url).pathname}`).join('\n'));
  throw error;
} finally {
  await browser.close();
}
