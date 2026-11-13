import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { startTunnel } from '../web/tests/engine.mjs';

// The Firefox/WebKit browser tests reach the synthetic origin through a loopback CONNECT tunnel that must carry
// ONLY example.invalid -> 127.0.0.1 and refuse everything else (an engine-independent egress block).

async function connect(proxy, target) {
  const { port } = new URL(proxy);
  const socket = net.connect(Number(port), '127.0.0.1');
  await new Promise((resolve, reject) => socket.once('connect', resolve).once('error', reject));
  socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
  // A closed connection without a reply is an (empty) answer, so a broken tunnel fails the assertion, not hangs.
  const reply = await new Promise((resolve) => {
    socket.once('data', (chunk) => resolve(chunk.toString('latin1')));
    socket.once('close', () => resolve(''));
  });
  return { socket, reply };
}

test('the tunnel refuses every destination except example.invalid on a high port', async () => {
  const proxy = await startTunnel();
  for (const target of ['example.com:443', '127.0.0.1:8080', 'localhost:8080', 'example.invalid:22', 'example.invalid:80', 'example.invalid.evil.test:8443', 'example.invalid:notaport']) {
    const { socket, reply } = await connect(proxy, target);
    assert.match(reply, /^HTTP\/1\.1 403 /, `${target} must be refused`);
    socket.destroy();
  }
});

test('the tunnel carries example.invalid to loopback and nothing else', async () => {
  const echo = net.createServer((client) => client.on('data', (chunk) => client.write(`echo:${chunk}`)));
  await new Promise((resolve) => echo.listen(0, '127.0.0.1', resolve));
  try {
    const proxy = await startTunnel();
    const { socket, reply } = await connect(proxy, `example.invalid:${echo.address().port}`);
    assert.match(reply, /^HTTP\/1\.1 200 /);
    socket.write('ping');
    const answer = await new Promise((resolve) => socket.once('data', (chunk) => resolve(chunk.toString())));
    assert.equal(answer, 'echo:ping');
    socket.destroy();
  } finally {
    echo.close();
  }
});
