import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { HandoffBroker } from '../src/broker.js';
import { native } from '../src/native.js';
import {
  EndpointError,
  deriveEndpoint,
  development,
  endpointHash,
  production,
} from '../src/endpoint.js';
import { runtime } from './helpers.js';

test('endpoint derivation matches development and production authority', async () => {
  const project = await development('.');
  const root = '/x';
  const developmentEndpoint = deriveEndpoint(project, 'https', root);
  assert.equal(
    developmentEndpoint.path,
    path.join(root, 'handoff', `${endpointHash(project.value, 'https')}.sock`),
  );
  assert.equal(developmentEndpoint.validateRuntimeRoot, true);

  const productionEndpoint = deriveEndpoint(production('contoso-web'), 'https', root);
  assert.equal(
    productionEndpoint.path,
    path.join(root, 'handoff', `${endpointHash('contoso-web', 'https')}.sock`),
  );
  assert.equal(productionEndpoint.validateRuntimeRoot, false);
});

test('identity and role validation is strict', () => {
  assert.throws(() => production('../bad'), EndpointError);
  assert.throws(
    () => deriveEndpoint({ kind: 'production', value: 'valid' }, 'UPPER', '.'),
    EndpointError,
  );
});

test('broker creates secure directories and socket and rejects a live duplicate', async () => {
  const fixture = await runtime('secure');
  const broker = new HandoffBroker(fixture.endpoint);
  try {
    const directory = await lstat(path.dirname(fixture.endpoint.path));
    const socket = await lstat(fixture.endpoint.path);
    assert.equal(directory.mode & 0o777, 0o700);
    assert.equal(socket.mode & 0o777, 0o600);
    assert.equal(socket.isSocket(), true);
    assert.equal(directory.uid, process.geteuid());
    assert.equal(socket.uid, process.geteuid());
    assert.throws(() => new HandoffBroker(fixture.endpoint), /already listening/);
  } finally {
    await broker.close();
    await assert.rejects(lstat(fixture.endpoint.path), { code: 'ENOENT' });
    await fixture.cleanup();
  }
});

test('broker refuses non-sockets, open directories, and symlinked runtime roots', async () => {
  const nonSocket = await runtime('nonsocket');
  await mkdir(path.dirname(nonSocket.endpoint.path), { mode: 0o700 });
  await writeFile(nonSocket.endpoint.path, 'not a socket');
  assert.throws(() => new HandoffBroker(nonSocket.endpoint), /non-socket/);
  await nonSocket.cleanup();

  const open = await runtime('open');
  await chmod(open.root, 0o755);
  assert.throws(() => new HandoffBroker(open.endpoint), /group or other/);
  await open.cleanup();

  const linked = await runtime('linked');
  const target = path.join(linked.root, 'target');
  const link = path.join(linked.root, 'runtime-link');
  await mkdir(target, { mode: 0o700 });
  await symlink(target, link);
  assert.throws(
    () =>
      new HandoffBroker({
        path: path.join(link, 'handoff', 'receiver.sock'),
        validateRuntimeRoot: true,
      }),
    /not a directory/,
  );
  await linked.cleanup();
});

test('an unreachable stale control socket is replaced safely', async () => {
  const fixture = await runtime('stale');
  await mkdir(path.dirname(fixture.endpoint.path), { mode: 0o700 });
  native.testCreateStaleEndpoint(fixture.endpoint.path);
  assert.equal((await lstat(fixture.endpoint.path)).isSocket(), true);
  const broker = new HandoffBroker(fixture.endpoint);
  try {
    assert.equal((await lstat(fixture.endpoint.path)).mode & 0o777, 0o600);
  } finally {
    await broker.close();
    await fixture.cleanup();
  }
});
