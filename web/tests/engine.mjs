import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import process from 'node:process';
import { chromium, firefox, webkit } from '@playwright/test';

// Browser-engine selection for the admin UI browser tests (P1.16, SUP-04). Test-only.
//
// MANDATARY_BROWSER_ENGINE   chromium (default) | firefox | webkit    (Playwright-managed builds)
// MANDATARY_VIEWPORT         WIDTHxHEIGHT, default 1280x900 (a phone-sized run: 390x844)
//
// The product origin is the synthetic https://example.invalid:PORT (WebAuthn binds to its RP ID). Chromium maps
// that one host name to loopback with a resolver rule. Firefox and WebKit have no such switch, so they are
// pointed at a tiny loopback CONNECT proxy that tunnels ONLY example.invalid to 127.0.0.1 and refuses every
// other destination (a second, engine-independent egress block; the page-level route allowlist stays in force).
// A Playwright-managed engine is not Safari, branded Chrome or Edge: see docs/ui/p1.16-gate-integration.md.

const ENGINES = new Map([['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]);
const HOST = 'example.invalid';

export const engineName = process.env.MANDATARY_BROWSER_ENGINE ?? 'chromium';
assert.ok(ENGINES.has(engineName), `unknown MANDATARY_BROWSER_ENGINE ${engineName}`);

export function viewport() {
  const match = /^(\d{2,4})x(\d{2,4})$/.exec(process.env.MANDATARY_VIEWPORT ?? '1280x900');
  assert.ok(match, 'MANDATARY_VIEWPORT must be WIDTHxHEIGHT');
  return { width: Number(match[1]), height: Number(match[2]) };
}

/** Test seam: the loopback CONNECT tunnel (see above). Resolves to its http://127.0.0.1:PORT address. */
export function startTunnel() {
  const server = http.createServer((request, response) => {
    response.writeHead(405).end();
  });
  server.on('connect', (request, client, head) => {
    const [host, portText] = String(request.url).split(':');
    const port = Number(portText);
    if (host !== HOST || !Number.isInteger(port) || port < 1024 || port > 65535) {
      client.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }
    const upstream = net.connect(port, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      server.unref();
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

/** Launches the selected engine with the fixture origin reachable and nothing else. */
export async function launchEngine() {
  if (engineName === 'chromium') {
    return chromium.launch({ args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1`, '--no-proxy-server'] });
  }
  const server = await startTunnel();
  return ENGINES.get(engineName).launch({ proxy: { server } });
}

/** True when this engine can drive a WebAuthn virtual authenticator (Playwright exposes it over CDP only). */
export const supportsVirtualAuthenticator = engineName === 'chromium';
