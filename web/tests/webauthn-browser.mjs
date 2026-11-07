import assert from 'node:assert/strict';
/* global fetch, navigator, PublicKeyCredential, console */
import process from 'node:process';
import { URL } from 'node:url';
import { chromium } from '@playwright/test';

// Test-only browser process, synthetic loopback HTTPS and disposable CTAP keys.
// No application routes, hardware-provider claims, traces or secret artifacts.
const origin = new URL(process.argv[2]);
assert.equal(origin.hostname, 'example.invalid');
assert.equal(origin.protocol, 'https:');
const browser = await chromium.launch({
  chromiumSandbox: true,
  args: ['--host-resolver-rules=MAP example.invalid 127.0.0.1', '--no-proxy-server'],
});
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await page.goto(origin.href);
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  for (const resident of [false, true]) {
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: resident,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    } });
    await page.evaluate(async (resident) => {
      const begin = await fetch(`/begin-registration?resident=${resident}`, { method: 'POST' });
      if (!begin.ok) throw new Error('registration begin denied');
      const ceremony = await begin.json();
      const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(ceremony.Options.publicKey) });
      const finish = await fetch(`/finish-registration?id=${ceremony.ID}`, { method: 'POST', body: JSON.stringify(credential.toJSON()) });
      if (!finish.ok) throw new Error('browser registration denied');
    }, resident);
    const assertion = await page.evaluate(async () => {
      const begin = await fetch('/begin-assertion', { method: 'POST' });
      if (!begin.ok) throw new Error('assertion begin denied');
      const ceremony = await begin.json();
      const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(ceremony.Options.publicKey) });
      const body = JSON.stringify(credential.toJSON());
      const finish = await fetch(`/finish-assertion?id=${ceremony.ID}`, { method: 'POST', body });
      if (!finish.ok) throw new Error('browser UV assertion denied');
      const replay = await fetch(`/finish-assertion?id=${ceremony.ID}`, { method: 'POST', body });
      if (replay.status !== 403) throw new Error('browser assertion replay accepted');
      return true;
    });
    assert.equal(assertion, true);
    await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
    await page.evaluate(async () => {
      const begin = await fetch('/begin-assertion', { method: 'POST' });
      const ceremony = await begin.json();
      const options = PublicKeyCredential.parseRequestOptionsFromJSON(ceremony.Options.publicKey);
      // A malicious client may change its requested UV. Server-bound required UV
      // must still reject the resulting genuinely signed UV=false response.
      options.userVerification = 'discouraged';
      const credential = await navigator.credentials.get({ publicKey: options });
      const finish = await fetch(`/finish-assertion?id=${ceremony.ID}`, { method: 'POST', body: JSON.stringify(credential.toJSON()) });
      if (finish.status !== 403) throw new Error('browser UV downgrade accepted');
    });
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  }
  console.log(JSON.stringify({ browser: browser.version(), resident: true, nonresident: true, signedUV: true, replayRejected: true, signedUVDowngradeRejected: true }));
} finally {
  await browser.close();
}
