import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import {
  HandoffBroker,
  REJECT_ADOPTION_FAILED,
  REJECT_DUPLICATE_ID,
  REJECT_INVALID_DESCRIPTOR,
} from '../src/broker.js';
import { native } from '../src/native.js';
import { MessageType, decode, encode } from '../src/protocol.js';
import { onceEvent, runtime } from './helpers.js';

function request(connectionId) {
  return encode({
    type: MessageType.HANDOFF,
    connectionId,
    peekedLength: 123,
    acceptedAtNs: 456n,
    requestedSni: 'example.test',
  });
}

function send(endpoint, frame, descriptorKind = 'tcp', descriptorCount = 1) {
  return native.testHandoff({
    endpoint,
    frame,
    descriptorKind,
    descriptorCount,
    timeoutMs: 2000,
  });
}

test('native peer credential lookup enforces the effective UID boundary', () => {
  assert.equal(native.testPeerMatches(process.geteuid()), true);
  assert.equal(native.testPeerMatches(process.geteuid() + 1), false);
});

test('native broker validates TCP descriptors and preserves data and addresses', async () => {
  const fixture = await runtime('roundtrip');
  const broker = new HandoffBroker(fixture.endpoint);
  let server;
  const delivered = onceEvent(broker, 'connection');
  broker.on('connection', (handoff) => {
    server = handoff.wrapSocket();
    server.once('close', handoff.release);
    handoff.adopt();
  });

  try {
    const connectionId = Buffer.alloc(16, 0x31);
    const result = await send(fixture.endpoint.path, request(connectionId));
    const [handoff] = await delivered;
    assert.equal(decode(result.response).type, MessageType.ADOPTED);
    assert.equal(handoff.requestedSni, 'example.test');
    assert.equal(handoff.peekedLength, 123);
    assert.equal(handoff.acceptedAtNs, 456n);

    const client = new net.Socket({ fd: result.clientFd, readable: true, writable: true });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.once('data', (data) => {
        assert.equal(data.toString(), 'client payload');
        resolve();
      });
      client.end('client payload');
    });
    assert.equal(server.remoteAddress, client.localAddress);
    assert.equal(server.remotePort, client.localPort);
    assert.equal(server.localAddress, client.remoteAddress);
    assert.equal(server.localPort, client.remotePort);
    server.destroy();
  } finally {
    server?.destroy();
    await broker.close();
    await fixture.cleanup();
  }
});

test('native broker rejects missing, extra, and non-TCP descriptors', async () => {
  const fixture = await runtime('validation');
  const broker = new HandoffBroker(fixture.endpoint);
  try {
    const cases = [
      ['none', 0],
      ['unix', 1],
      ['unix', 2],
    ];
    for (const [kind, count] of cases) {
      const response = decode(
        (
          await send(
            fixture.endpoint.path,
            request(Buffer.alloc(16, count + kind.length)),
            kind,
            count,
          )
        ).response,
      );
      assert.equal(response.type, MessageType.REJECTED);
      assert.equal(response.rejectionCode, REJECT_INVALID_DESCRIPTOR);
    }
  } finally {
    await broker.close();
    await fixture.cleanup();
  }
});

test('duplicate active IDs are rejected and become reusable after release', async () => {
  const fixture = await runtime('duplicates');
  const broker = new HandoffBroker(fixture.endpoint);
  const servers = [];
  broker.on('connection', (handoff) => {
    const socket = handoff.wrapSocket();
    servers.push({ socket, handoff });
    socket.once('close', handoff.release);
    handoff.adopt();
  });
  const connectionId = Buffer.alloc(16, 0x44);

  try {
    const first = await send(fixture.endpoint.path, request(connectionId));
    assert.equal(decode(first.response).type, MessageType.ADOPTED);
    const second = await send(fixture.endpoint.path, request(connectionId));
    const duplicate = decode(second.response);
    assert.equal(duplicate.type, MessageType.REJECTED);
    assert.equal(duplicate.rejectionCode, REJECT_DUPLICATE_ID);

    new net.Socket({ fd: first.clientFd, readable: true, writable: true }).destroy();
    servers[0].socket.destroy();
    await onceEvent(servers[0].socket, 'close');

    const third = await send(fixture.endpoint.path, request(connectionId));
    assert.equal(decode(third.response).type, MessageType.ADOPTED);
    new net.Socket({ fd: third.clientFd, readable: true, writable: true }).destroy();
    servers[1].socket.destroy();
  } finally {
    for (const item of servers) item.socket.destroy();
    await broker.close();
    await fixture.cleanup();
  }
});

test('undecided deliveries are rejected before JavaScript ownership', async () => {
  const fixture = await runtime('undecided');
  const broker = new HandoffBroker(fixture.endpoint);
  broker.on('error', () => {});
  broker.on('connection', () => {});
  try {
    const result = await send(fixture.endpoint.path, request(Buffer.alloc(16, 0x55)));
    const response = decode(result.response);
    assert.equal(response.type, MessageType.REJECTED);
    assert.equal(response.rejectionCode, REJECT_ADOPTION_FAILED);
    assert.equal(result.clientFd, -1);
  } finally {
    await broker.close();
    await fixture.cleanup();
  }
});

test('a wrapped delivery can be rejected without retaining native ownership', async () => {
  const fixture = await runtime('wr');
  const broker = new HandoffBroker(fixture.endpoint);
  broker.on('connection', (handoff) => {
    handoff.wrapSocket();
    handoff.reject(REJECT_ADOPTION_FAILED);
  });
  try {
    const result = await send(fixture.endpoint.path, request(Buffer.alloc(16, 0x56)));
    const response = decode(result.response);
    assert.equal(response.type, MessageType.REJECTED);
    assert.equal(response.rejectionCode, REJECT_ADOPTION_FAILED);
    assert.equal(result.clientFd, -1);
  } finally {
    await broker.close();
    await fixture.cleanup();
  }
});

test('the native delivery queue rejects overflow before adoption', async () => {
  const fixture = await runtime('queue');
  const broker = new HandoffBroker(fixture.endpoint, {
    queueSize: 1,
    maxControlConnections: 8,
  });
  const servers = [];
  broker.on('connection', (handoff) => {
    const socket = handoff.wrapSocket();
    servers.push({ socket, handoff });
    socket.once('close', handoff.release);
    handoff.adopt();
  });
  try {
    const transfers = Array.from({ length: 4 }, (_, index) =>
      send(fixture.endpoint.path, request(Buffer.alloc(16, 0x70 + index))),
    );
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    const results = await Promise.all(transfers);
    const responses = results.map((result) => decode(result.response));
    assert.ok(responses.some((response) => response.type === MessageType.ADOPTED));
    assert.ok(
      responses.some(
        (response) =>
          response.type === MessageType.REJECTED &&
          response.rejectionCode === REJECT_ADOPTION_FAILED,
      ),
    );
    for (const result of results) {
      if (result.clientFd >= 0) {
        new net.Socket({ fd: result.clientFd, readable: true, writable: true }).destroy();
      }
    }
  } finally {
    for (const item of servers) item.socket.destroy();
    await broker.close();
    await fixture.cleanup();
  }
});

test('clean shutdown removes the endpoint and is idempotent in JavaScript', async () => {
  const fixture = await runtime('shutdown');
  const broker = new HandoffBroker(fixture.endpoint);
  await broker.close();
  await broker.close();
  await fixture.cleanup();
});
