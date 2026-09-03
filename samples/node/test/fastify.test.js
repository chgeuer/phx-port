import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import test from 'node:test';
import Fastify from 'fastify';
import { attachPHXP } from '../src/fastify.js';
import { native } from '../src/native.js';
import { MessageType, decode, encode } from '../src/protocol.js';
import { runtime } from './helpers.js';

const certificate = await readFile(new URL('fixtures/cert.pem', import.meta.url));
const key = await readFile(new URL('fixtures/key.pem', import.meta.url));

function parseResponse(response) {
  const [head, body] = response.split('\r\n\r\n');
  const lines = head.split('\r\n');
  const headers = Object.fromEntries(
    lines.slice(1).map((line) => {
      const separator = line.indexOf(':');
      return [line.slice(0, separator).toLowerCase(), line.slice(separator + 1).trim()];
    }),
  );
  return { status: lines[0], headers, body: JSON.parse(body) };
}

function directRequest(port) {
  return new Promise((resolve, reject) => {
    const request = https.get(
      {
        host: '127.0.0.1',
        port,
        path: '/',
        servername: 'example.test',
        rejectUnauthorized: false,
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            status: `HTTP/${response.httpVersion} ${response.statusCode}`,
            headers: response.headers,
            body: JSON.parse(Buffer.concat(chunks).toString()),
          });
        });
      },
    );
    request.on('error', reject);
  });
}

function handoffRequest(clientFd) {
  return new Promise((resolve, reject) => {
    const raw = new net.Socket({ fd: clientFd, readable: true, writable: true });
    const socket = tls.connect({
      socket: raw,
      servername: 'example.test',
      rejectUnauthorized: false,
    });
    const chunks = [];
    socket.once('secureConnect', () => {
      socket.write('GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n');
    });
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => resolve(parseResponse(Buffer.concat(chunks).toString())));
    socket.on('error', reject);
  });
}

test('direct and PHXP TLS requests traverse the same Fastify hook and route', async () => {
  const fixture = await runtime('fastify');
  const app = Fastify({ https: { cert: certificate, key } });
  let hookCount = 0;
  app.addHook('onRequest', async (_request, reply) => {
    hookCount += 1;
    reply.header('x-phxp-pipeline', 'shared-fastify');
  });
  app.get('/', async (request) => ({
    route: 'shared',
    protocol: request.protocol,
    peer: [request.socket.remoteAddress, request.socket.remotePort],
    local: [request.socket.localAddress, request.socket.localPort],
  }));

  const ingress = attachPHXP(app, fixture.endpoint, { queueSize: 4 });
  ingress.on('error', (error) => {
    throw error;
  });
  try {
    const address = await app.listen({ host: '127.0.0.1', port: 0 });
    const port = Number(new URL(address).port);
    const direct = await directRequest(port);

    const connectionId = Buffer.alloc(16, 0x66);
    const handoff = await native.testHandoff({
      endpoint: fixture.endpoint.path,
      frame: encode({
        type: MessageType.HANDOFF,
        connectionId,
        peekedLength: 1,
        acceptedAtNs: 99n,
        requestedSni: 'example.test',
      }),
      descriptorKind: 'tcp',
      descriptorCount: 1,
      timeoutMs: 2000,
    });
    assert.equal(decode(handoff.response).type, MessageType.ADOPTED);
    const adopted = await handoffRequest(handoff.clientFd);

    assert.match(direct.status, /200/);
    assert.equal(adopted.status, 'HTTP/1.1 200 OK');
    assert.equal(direct.headers['x-phxp-pipeline'], 'shared-fastify');
    assert.equal(adopted.headers['x-phxp-pipeline'], 'shared-fastify');
    assert.equal(direct.body.route, 'shared');
    assert.equal(adopted.body.route, 'shared');
    assert.equal(direct.body.protocol, 'https');
    assert.equal(adopted.body.protocol, 'https');
    assert.equal(hookCount, 2);
    assert.equal(adopted.body.peer[0], '127.0.0.1');
    assert.equal(adopted.body.local[0], '127.0.0.1');
  } finally {
    await ingress.close();
    await app.close();
    await fixture.cleanup();
  }
});
