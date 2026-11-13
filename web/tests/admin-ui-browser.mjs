import assert from 'node:assert/strict';
import path from 'node:path';
import process from 'node:process';
import { URL } from 'node:url';
import { chromium } from '@playwright/test';
import { allowsAppRequest, appOrigin, control, controlBase, rawRequest, scanSurfaces, totpCode } from './admin-ui-lib.mjs';

/* global console, document, ClipboardEvent */

// Admin UI browser tests (P1.16.3) against the REAL services (internal/auth/admin_ui_browser_test.go starts
// them behind synthetic loopback TLS and a loopback SMTP receiver). One scenario per invocation, in one
// colour scheme (the theme follows prefers-color-scheme). Failures name a step and a surface, never a
// secret. All credentials are synthetic.

const [scenario, scheme, originArg, controlArg] = process.argv.slice(2);
assert.ok(['light', 'dark'].includes(scheme), 'scheme');
const origin = appOrigin(originArg);
const host = control(controlBase(controlArg));
const shotsDir = process.env.MANDATARY_UI_SHOTS ?? '';

const SESSION_COOKIE = '__Host-mandatary_session';
const SETUP_COOKIE = '__Host-mandatary_setup';
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

const SETUP_USER = 'first-admin';
const SETUP_PASSWORD = 'synthetic setup passphrase 41';
const LOGIN_USER = 'synthetic-user';
const LOGIN_PASSWORD = 'a unique synthetic public phrase';
const WRONG_PASSWORD = 'definitely not the right one';

const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP example.invalid 127.0.0.1', '--no-proxy-server'] });
const observed = { blocked: [], console: [], errors: [], requests: [], responses: [] };
const pending = [];
const canaries = new Set();

async function newContext() {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block', colorScheme: scheme, viewport: { width: 1280, height: 900 } });
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

const step = (name) => ({ name, scan: (page, secrets) => scanSurfaces(page, [...secrets, ...canaries], name) });

async function theme(page) {
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), scheme, 'theme follows the colour scheme');
}

const field = (page, label) => page.getByLabel(label, { exact: true });

async function login(page, user, password) {
  await page.goto(new URL('/login', origin).href);
  await field(page, 'Username').fill(user);
  await field(page, 'Password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
}

async function finishTotp(page, seed, { advance = 31 } = {}) {
  if (advance) await host.advance(advance); // a fresh TOTP period: the previous code is spent
  const code = totpCode(seed, await host.now());
  await field(page, '6-digit code').fill(code);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  return code;
}

// ───────────────────────── shared end-of-run assertions ─────────────────────────

async function finish(extraSecrets) {
  await Promise.all(pending);
  assert.deepEqual(observed.blocked, [], 'the page tried to reach something outside the fixture allowlist');
  assert.deepEqual(observed.errors, [], 'uncaught page errors');
  // The only console output allowed is the browser's own note about a non-2xx fetch (no body, no secret).
  for (const message of observed.console) assert.match(message.text, /^Failed to load resource: the server responded with a status of \d{3}/, `unexpected console output (${message.type})`);
  for (const request of observed.requests) {
    const url = new URL(request.url);
    assert.equal(url.search, '', 'no request carries a query string');
    assert.ok(!('authorization' in request.headers), 'no Authorization header');
    if (request.method === 'POST' && /\/api\/v1\/(setup\/(?!exchange)|login\/|logout)/.test(url.pathname)) assert.ok(request.headers['x-csrf-token'], `CSRF header on ${url.pathname}`);
    if (request.method === 'POST' && /\/api\/v1\/(setup\/exchange|login)$/.test(url.pathname)) assert.equal(request.headers['x-csrf-token'], undefined, 'no CSRF token before a session exists');
    if (request.method === 'POST') assert.equal(request.headers['content-type'], 'application/json');
  }
  for (const response of observed.responses) {
    const url = new URL(response.url);
    assert.equal(response.headers['cache-control'], 'no-store', `no-store on ${url.pathname}`);
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    if (['/', '/setup', '/login'].includes(url.pathname)) assert.equal(response.headers['content-security-policy'], CSP, `document CSP on ${url.pathname}`);
    if (url.pathname.startsWith('/api/') && response.status !== 204) assert.match(response.headers['content-type'] ?? '', /^application\/json/);
  }
  const all = JSON.stringify({ console: observed.console, errors: observed.errors, requests: observed.requests.map((r) => r.url) });
  for (const secret of [...extraSecrets, ...canaries]) if (secret.length >= 8) assert.ok(!all.includes(secret), 'a secret reached console/error/URL output');
  assert.equal(await host.leaked([...extraSecrets, ...canaries].filter((s) => s.length >= 8)), false, 'a secret reached the server log');
}

async function checkSessionCookie(context, { present }) {
  const cookies = await context.cookies();
  const found = cookies.find((cookie) => cookie.name === SESSION_COOKIE);
  if (!present) return assert.equal(found, undefined, 'no session cookie');
  assert.ok(found, 'session cookie');
  assert.deepEqual({ httpOnly: found.httpOnly, secure: found.secure, sameSite: found.sameSite, path: found.path, session: found.expires === -1 }, { httpOnly: true, secure: true, sameSite: 'Strict', path: '/', session: true });
  return found;
}

// ───────────────────────── scenario: setup, then the first login ─────────────────────────

async function setupAndLogin() {
  const context = await newContext();
  const page = await context.newPage();
  const token = await host.revealToken();
  canaries.add(token);

  await page.goto(new URL('/setup', origin).href);
  await theme(page);
  await page.getByRole('heading', { name: 'First-time setup', level: 1 }).waitFor({ state: 'attached' });
  await page.getByLabel('Setup token', { exact: true }).waitFor();
  assert.equal(await page.getByLabel('Setup token', { exact: true }).getAttribute('autocomplete'), 'off', 'setup token is not offered to password managers');
  await shot(page, 'setup-token');
  await page.getByLabel('Setup token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Verify token' }).click();
  await page.getByRole('form', { name: 'Create administrator' }).waitFor();
  await step('after exchange').scan(page, [token]);
  await shot(page, 'setup-account');
  const setupCookie = (await context.cookies()).find((cookie) => cookie.name === SETUP_COOKIE);
  assert.deepEqual({ httpOnly: setupCookie?.httpOnly, secure: setupCookie?.secure, sameSite: setupCookie?.sameSite }, { httpOnly: true, secure: true, sameSite: 'Strict' });

  // Password-manager attributes and paste on the real account form.
  assert.equal(await field(page, 'Username').getAttribute('autocomplete'), 'username');
  assert.equal(await field(page, 'Password').getAttribute('autocomplete'), 'new-password');
  assert.equal(await field(page, 'Password').getAttribute('type'), 'password');
  const pasteAllowed = await field(page, 'Password').evaluate((input) => input.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true })));
  assert.equal(pasteAllowed, true, 'paste into the password field is not blocked');

  await field(page, 'Username').fill(SETUP_USER);
  await field(page, 'Password').fill(SETUP_PASSWORD);
  await field(page, 'Email address 1').fill('first@example.invalid');
  await page.getByRole('button', { name: 'Save account' }).click();
  await page.getByRole('heading', { name: 'Confirm a notification address' }).waitFor();
  await step('after account').scan(page, [SETUP_PASSWORD, token]);

  await page.getByRole('button', { name: 'Send confirmation code' }).click();
  await field(page, 'Code from the email').waitFor();
  assert.equal(await field(page, 'Code from the email').getAttribute('autocomplete'), 'one-time-code');
  const proof = await host.lastProof();
  canaries.add(proof);
  await field(page, 'Code from the email').fill(proof);
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
  await page.getByText('1 of 1 addresses confirmed. You can continue.').waitFor();
  await step('after address proof').scan(page, [proof]);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();

  await page.getByRole('button', { name: 'Create authenticator key' }).click();
  const reveal = page.locator('section', { has: page.getByRole('heading', { name: 'Your authenticator key' }) }).locator('[translate="no"] p');
  await reveal.waitFor();
  const seed = ((await reveal.textContent()) ?? '').replace(/\s/g, '');
  assert.ok(/^[A-Z2-7]{52}$/.test(seed), 'the seed is shown once as base32');
  canaries.add(seed);
  const seedNode = await reveal.evaluate((element) => ({ attrs: element.getAttributeNames().join(','), parent: element.parentElement?.getAttributeNames().join(',') }));
  assert.ok(!JSON.stringify(seedNode).includes(seed));
  await page.getByRole('button', { name: 'Confirm code' }).waitFor();
  assert.equal(await page.title(), 'Mandatary');

  // A wrong code leaves the seed available for a retry; the right one removes it.
  await field(page, '6-digit code').fill('000000');
  await page.getByRole('button', { name: 'Confirm code' }).click();
  await page.getByText('That code didn’t match').waitFor();
  assert.ok((await field(page, '6-digit code').inputValue()) === '', 'the rejected code is cleared');
  assert.ok(((await reveal.textContent()) ?? '').replace(/\s/g, '') === seed, 'seed still shown for the retry');
  const code = totpCode(seed, await host.now());
  await field(page, '6-digit code').fill(`${code.slice(0, 3)} ${code.slice(3)}`); // pasted with a space
  await page.getByRole('button', { name: 'Confirm code' }).click();
  await page.getByText('Authenticator confirmed').waitFor();
  await step('after the key is proven (seed removed)').scan(page, []);
  assert.equal(await page.locator('[translate="no"]').count(), 0, 'no revealed-secret node remains');
  await page.getByRole('button', { name: 'Continue', exact: true }).click();

  await page.getByRole('button', { name: 'Finish setup' }).click();
  await page.getByText(`${SETUP_USER} is ready`).waitFor();
  await shot(page, 'setup-complete');
  assert.equal((await context.cookies()).find((cookie) => cookie.name === SETUP_COOKIE), undefined, 'the setup cookie is cleared at completion');
  await checkSessionCookie(context, { present: false }); // setup issues NO session
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/session' })).status, 401, 'setup completion did not sign anyone in');

  // First ordinary login (password + the authenticator just enrolled).
  await page.getByRole('link', { name: 'Go to sign in' }).click();
  await page.waitForURL(new URL('/login', origin).href);
  await field(page, 'Username').fill(SETUP_USER);
  await field(page, 'Password').fill(SETUP_PASSWORD);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Continue with password only' }).count(), 0, 'an administrator is never offered a password-only session');
  await shot(page, 'login-factor');
  await step('factor step').scan(page, [SETUP_PASSWORD]);
  await finishTotp(page, seed);
  await page.waitForURL(new URL('/', origin).href);
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  await page.getByText('Multi-factor verified').first().waitFor();
  await theme(page);
  await shot(page, 'home-aal2');
  const session = await checkSessionCookie(context, { present: true });
  canaries.add(session.value);
  await step('signed in').scan(page, [SETUP_PASSWORD, seed, token, session.value]);

  // Reload keeps the session; back/forward never restores a secret or a credential.
  await page.reload();
  await page.getByText(SETUP_USER).first().waitFor();
  await page.goBack();
  await page.getByRole('form', { name: 'Sign in' }).waitFor();
  assert.ok((await field(page, 'Password').inputValue()) === '', 'back to the sign-in form never restores a password');
  await page.goBack();
  await page.getByRole('heading', { name: 'Setup isn’t open' }).waitFor(); // the surface is closed after completion
  await step('after back navigation').scan(page, [SETUP_PASSWORD, seed, token]);
  await shot(page, 'setup-closed');

  // The consumed token and every setup route are closed (404): nothing else is revealed.
  assert.equal((await rawRequest(origin, { method: 'POST', path: '/api/v1/setup/exchange', body: { token } })).status, 404);

  // Theme toggle is in memory only and flips both ways.
  await page.goto(new URL('/', origin).href);
  await page.getByRole('button', { name: scheme === 'light' ? 'Use dark theme' : 'Use light theme' }).click();
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), scheme === 'light' ? 'dark' : 'light');
  await shot(page, 'home-toggled');

  // Sign out through the UI; the copied cookie is dead.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(new URL('/login', origin).href);
  await checkSessionCookie(context, { present: false });
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie: `${SESSION_COOKIE}=${session.value}` })).status, 401, 'a copied cookie does not survive logout');

  await finish([SETUP_PASSWORD, token, seed, proof, session.value]);
  await context.close();
}

// ───────────────────────── scenario: replayed and expired setup ─────────────────────────

async function setupReplayAndExpiry() {
  const token = await host.revealToken();
  canaries.add(token);
  const first = await newContext();
  const page = await first.newPage();
  await page.goto(new URL('/setup', origin).href);
  await page.getByLabel('Setup token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Verify token' }).click();
  await page.getByRole('form', { name: 'Create administrator' }).waitFor();

  // Replay: a second browser pastes the same (now consumed) token. The message is the one a garbage token gets.
  const second = await newContext();
  const replay = await second.newPage();
  const messages = [];
  for (const attempt of [token, 'GARBAGE-GARBAGE-GARBAGE-GARBAGE-0000']) {
    await replay.goto(new URL('/setup', origin).href);
    await replay.getByLabel('Setup token', { exact: true }).fill(attempt);
    await replay.getByRole('button', { name: 'Verify token' }).click();
    const heading = replay.getByText('That token wasn’t accepted');
    await heading.waitFor();
    messages.push(await replay.locator('form[aria-label="Enter setup token"] [role="alert"]').textContent());
    assert.ok((await replay.getByLabel('Setup token', { exact: true }).inputValue()) === '', 'a rejected token is cleared');
    await step('replay').scan(replay, [token]);
  }
  assert.equal(messages[0], messages[1], 'a replayed token is indistinguishable from a wrong one');
  await shot(replay, 'setup-token-rejected');
  await second.close();

  // Expiry: the 30-minute deadline passes on the server while the page is open.
  await host.advance(31 * 60);
  await field(page, 'Username').fill(SETUP_USER);
  await field(page, 'Password').fill(SETUP_PASSWORD);
  await field(page, 'Email address 1').fill('first@example.invalid');
  await page.getByRole('button', { name: 'Save account' }).click();
  await page.getByText('This setup session has expired').waitFor();
  assert.equal(await page.getByLabel('Password', { exact: true }).count(), 0, 'no form remains after expiry');
  await step('after expiry').scan(page, [SETUP_PASSWORD, token]);
  await shot(page, 'setup-expired');
  // Reload before the server's periodic cleanup has run: the dead session is simply not accepted, so the
  // token form returns, and the consumed token is refused with the same one message.
  await page.goto(new URL('/setup', origin).href);
  await page.getByLabel('Setup token', { exact: true }).waitFor();
  await page.getByLabel('Setup token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Verify token' }).click();
  await page.getByText('That token wasn’t accepted').waitFor();
  assert.ok((await page.getByLabel('Setup token', { exact: true }).inputValue()) === '');
  // After the cleanup tick the whole surface is closed (404): nothing else is revealed.
  await host.maintain();
  await page.goto(new URL('/setup', origin).href);
  await page.getByRole('heading', { name: 'Setup isn’t open' }).waitFor();
  assert.equal((await rawRequest(origin, { method: 'POST', path: '/api/v1/setup/exchange', body: { token } })).status, 404);
  await shot(page, 'setup-closed-after-expiry');

  // Nothing was created: a login with the staged credentials is the generic denial.
  const attempt = await rawRequest(origin, { method: 'POST', path: '/api/v1/login', body: { username: SETUP_USER, password: SETUP_PASSWORD } });
  assert.equal(attempt.status, 401);
  await finish([SETUP_PASSWORD, token]);
  await first.close();
}

// ───────────────────────── scenario: login, lower assurance, expiry, direct-request bypass ─────────────────────────

async function loginFlows() {
  const seed = await host.seed();
  canaries.add(seed);
  const context = await newContext();
  const page = await context.newPage();

  // Unknown user and wrong password are one message.
  const messages = [];
  for (const user of ['nobody-at-all', LOGIN_USER]) {
    await login(page, user, WRONG_PASSWORD);
    await page.getByText('Sign-in failed').waitFor();
    messages.push(await page.locator('form[aria-label="Sign in"] [role="alert"]').textContent());
    assert.ok((await field(page, 'Password').inputValue()) === '', 'a rejected password is cleared');
    assert.equal(await field(page, 'Username').inputValue(), user, 'the username is kept');
    await step('after a failed sign-in').scan(page, [WRONG_PASSWORD]);
  }
  assert.equal(messages[0], messages[1], 'unknown user and wrong password are indistinguishable');
  await shot(page, 'login-denied');
  assert.equal(await field(page, 'Username').getAttribute('autocomplete'), 'username');
  assert.equal(await field(page, 'Password').getAttribute('autocomplete'), 'current-password');

  // Password, a wrong code, then the right one.
  await login(page, LOGIN_USER, LOGIN_PASSWORD);
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  assert.equal(await field(page, '6-digit code').getAttribute('autocomplete'), 'one-time-code');
  await step('factor step').scan(page, [LOGIN_PASSWORD]);
  await field(page, '6-digit code').fill('000000');
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await page.getByText('That code wasn’t accepted').waitFor();
  assert.ok((await field(page, '6-digit code').inputValue()) === '');
  await shot(page, 'login-code-denied');
  await finishTotp(page, seed);
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  await page.getByText('Multi-factor verified').first().waitFor();
  const aal2 = await checkSessionCookie(context, { present: true });
  canaries.add(aal2.value);
  await theme(page);
  await step('aal2 home').scan(page, [LOGIN_PASSWORD, aal2.value]);

  // The server's own view of that session is what the page shows.
  const info = await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie: `${SESSION_COOKIE}=${aal2.value}` });
  assert.deepEqual({ assurance: info.json.assurance, methods: info.json.methods, username: info.json.username }, { assurance: 'aal2', methods: ['password', 'totp'], username: LOGIN_USER });

  // Idle expiry while the page is open: the next request is a 401 and the page says so by going to sign-in.
  await host.advance(31 * 60);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(new URL('/login', origin).href);
  await page.getByRole('form', { name: 'Sign in' }).waitFor();
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie: `${SESSION_COOKIE}=${aal2.value}` })).status, 401, 'an idle-expired session is dead');
  // A cold visit to the signed-in page with no session lands on sign-in as well.
  await page.goto(new URL('/', origin).href);
  await page.waitForURL(new URL('/login', origin).href);

  // Lower assurance: offered by the server, labelled, and never AAL2.
  await login(page, LOGIN_USER, LOGIN_PASSWORD);
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  await page.getByText('Password-only sessions can’t change security settings or administer Mandatary.').waitFor();
  await shot(page, 'login-password-only-offer');
  await page.getByRole('button', { name: 'Continue with password only' }).click();
  await page.getByRole('heading', { name: 'Overview', level: 1 }).waitFor();
  await page.getByText('This is a password-only session').waitFor();
  await page.getByText('Password only').first().waitFor();
  await shot(page, 'home-password-only');
  const lower = await checkSessionCookie(context, { present: true });
  canaries.add(lower.value);
  const lowerInfo = await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie: `${SESSION_COOKIE}=${lower.value}` });
  assert.deepEqual({ assurance: lowerInfo.json.assurance, methods: lowerInfo.json.methods }, { assurance: 'password-only', methods: ['password'] });
  assert.equal(await page.getByText('Multi-factor verified').count(), 0, 'a password-only session is never labelled multi-factor');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(new URL('/login', origin).href);

  // The five-minute preauth ends: the page says so and "Start again" returns to an empty password step.
  await login(page, LOGIN_USER, LOGIN_PASSWORD);
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  await host.advance(6 * 60);
  await field(page, '6-digit code').fill(totpCode(seed, await host.now()));
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await page.getByText('Your sign-in timed out').waitFor();
  await shot(page, 'login-timed-out');
  await page.getByRole('button', { name: 'Start again' }).click();
  assert.ok((await field(page, 'Password').inputValue()) === '');

  await directRequestMatrix(seed);
  await mandatoryMfa(context, page);
  await finish([LOGIN_PASSWORD, WRONG_PASSWORD, seed, aal2.value, lower.value]);
  await context.close();
}

// Direct-request and assurance bypass attempts: every one must fail, and a refused request creates no cookie.
async function directRequestMatrix(seed) {
  // A hostile client obtains its own preauth capability and CSRF token (the page keeps its own in memory only).
  const fresh = await rawRequest(origin, { method: 'POST', path: '/api/v1/login', body: { username: LOGIN_USER, password: LOGIN_PASSWORD } });
  assert.equal(fresh.status, 200);
  const sessionValue = /__Host-mandatary_session=([^;]+)/.exec(fresh.setCookie.join(';'))?.[1];
  assert.ok(sessionValue);
  const cookie = `${SESSION_COOKIE}=${sessionValue}`;
  const token = fresh.json.csrf_token;
  assert.ok(token, 'a fresh password step returns its own CSRF token');
  canaries.add(sessionValue);
  const body = { code: totpCode(seed, await host.now()) };

  const cases = [
    ['preauth cookie opens no session route', { method: 'GET', path: '/api/v1/session', cookie }, 401],
    ['preauth cookie cannot log out', { method: 'POST', path: '/api/v1/logout', cookie, csrf: token, body: {} }, 401],
    ['factor step without CSRF', { method: 'POST', path: '/api/v1/login/totp', cookie, body }, 403],
    ['factor step with a wrong CSRF token', { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: `${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`, body }, 403],
    ['factor step from a foreign Origin', { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: token, body, headers: { origin: 'https://evil.invalid' } }, 403],
    ['factor step without an Origin', { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: token, body, omit: ['origin'] }, 403],
    ['factor step flagged cross-site', { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: token, body, headers: { 'sec-fetch-site': 'cross-site' } }, 403],
    ['factor step as a simple form post', { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: token, body: 'code=000000', contentType: 'application/x-www-form-urlencoded' }, 415],
    ['factor step with a duplicate CSRF header', { method: 'POST', path: '/api/v1/login/totp', cookie, body, headers: { 'x-csrf-token': `${token}, ${token}` } }, 403],
    ['factor step with an unknown field', { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: token, body: { code: '000000', assurance: 'aal2' } }, 400],
    ['password step as a GET', { method: 'GET', path: '/api/v1/login' }, 405],
    ['credentials in a query string', { method: 'POST', path: '/api/v1/login?password=x', body: { username: LOGIN_USER, password: LOGIN_PASSWORD } }, 404],
    ['an assurance the client asserts', { method: 'POST', path: '/api/v1/login', body: { username: LOGIN_USER, password: LOGIN_PASSWORD, assurance: 'aal2' } }, 400],
    ['security-key login is not routed in this build', { method: 'POST', path: '/api/v1/login/webauthn', cookie, csrf: token, body: {} }, [404, 405]],
    ['step-up is not routed in this build', { method: 'POST', path: '/api/v1/stepup/password', cookie, csrf: token, body: {} }, [404, 405]],
    ['a forged cookie', { method: 'GET', path: '/api/v1/session', cookie: `${SESSION_COOKIE}=${'A'.repeat(43)}` }, 401],
    ['a duplicate session cookie', { method: 'GET', path: '/api/v1/session', headers: { cookie: `${cookie}; ${cookie}` } }, 401],
    ['a setup cookie is not a session', { method: 'GET', path: '/api/v1/session', cookie: `${SETUP_COOKIE}=${'A'.repeat(43)}` }, 401],
    ['another Host', { method: 'GET', path: '/api/v1/session', cookie, headers: { host: 'evil.invalid' } }, 421],
  ];
  for (const [name, request, status] of cases) {
    const response = await rawRequest(origin, request);
    assert.ok([status].flat().includes(response.status), `${name}: status ${response.status}`);
    if (status !== 200) assert.ok(!response.setCookie.some((value) => value.startsWith(`${SESSION_COOKIE}=`) && !/Max-Age=0|Max-Age=-1|Expires=Thu, 01 Jan 1970/i.test(value)), `${name}: a refused request must not set a session`);
    assert.equal(response.headers['cache-control'], 'no-store', name);
  }
  // The factor refusal is the SAME public outcome for a wrong code as for a replay-shaped one.
  const wrong = await rawRequest(origin, { method: 'POST', path: '/api/v1/login/totp', cookie, csrf: token, body: { code: '000000' } });
  assert.equal(wrong.status, 403);
  assert.deepEqual(wrong.json, { error: 'denied' });
}

// Mandatory MFA: when policy requires it the page offers no password-only step, and a direct call is refused.
async function mandatoryMfa(context, page) {
  await host.policy('required');
  await login(page, LOGIN_USER, LOGIN_PASSWORD);
  await page.getByRole('heading', { name: 'Verify it’s you' }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Continue with password only' }).count(), 0);
  await shot(page, 'login-mfa-required');
  const fresh = await rawRequest(origin, { method: 'POST', path: '/api/v1/login', body: { username: LOGIN_USER, password: LOGIN_PASSWORD } });
  assert.deepEqual(fresh.json.next, ['totp']);
  const cookie = `${SESSION_COOKIE}=${/__Host-mandatary_session=([^;]+)/.exec(fresh.setCookie.join(';'))?.[1]}`;
  const refused = await rawRequest(origin, { method: 'POST', path: '/api/v1/login/no-mfa', cookie, csrf: fresh.json.csrf_token, body: {} });
  assert.equal(refused.status, 403, 'the password-only step is refused under mandatory MFA');
  assert.equal(refused.setCookie.length, 0);
  assert.equal((await rawRequest(origin, { method: 'GET', path: '/api/v1/session', cookie })).status, 401, 'the refusal left only a capability, never a session');
  await context.clearCookies();
}

try {
  if (scenario === 'setup-login') await setupAndLogin();
  else if (scenario === 'setup-replay-expiry') await setupReplayAndExpiry();
  else if (scenario === 'login-flows') await loginFlows();
  else throw new Error(`unknown scenario ${scenario}`);
  console.log(JSON.stringify({ scenario, scheme, browser: browser.version(), requests: observed.requests.length, blockedEgress: 0, secretsInConsole: 0 }));
} finally {
  await browser.close();
}
