import assert from 'node:assert/strict';
import test from 'node:test';
import {
  HEADER_LENGTH,
  MAX_PACKET_LENGTH,
  MessageType,
  ProtocolError,
  decode,
  encode,
  frameLength,
} from '../src/protocol.js';

test('PHXP v1 messages round trip through the fixed envelope', () => {
  const connectionId = Buffer.alloc(16, 0xab);
  const messages = [
    { type: MessageType.HELLO },
    { type: MessageType.READY },
    {
      type: MessageType.HANDOFF,
      connectionId,
      peekedLength: 517,
      acceptedAtNs: 42n,
      requestedSni: 'www.contoso.com',
    },
    { type: MessageType.ADOPTED, connectionId },
    { type: MessageType.REJECTED, connectionId, rejectionCode: 7 },
  ];
  for (const message of messages) {
    const decoded = decode(encode(message));
    assert.equal(decoded.type, message.type);
    assert.deepEqual(decoded.connectionId, message.connectionId ?? Buffer.alloc(16));
    assert.equal(decoded.peekedLength, message.peekedLength ?? 0);
    assert.equal(decoded.acceptedAtNs, message.acceptedAtNs ?? 0n);
    assert.equal(decoded.requestedSni, message.requestedSni ?? '');
    assert.equal(decoded.rejectionCode, message.rejectionCode ?? 0);
  }
});

test('malformed and oversized PHXP frames are rejected', () => {
  const hello = encode({ type: MessageType.HELLO });
  assert.equal(hello.length, HEADER_LENGTH);
  assert.throws(() => decode(hello.subarray(0, 39)), ProtocolError);

  const badMagic = Buffer.from(hello);
  badMagic[0] = 0;
  assert.throws(() => decode(badMagic), /invalid magic/);

  const badVersion = Buffer.from(hello);
  badVersion[4] = 2;
  assert.throws(() => decode(badVersion), /unsupported/);

  const oversized = Buffer.from(hello);
  oversized.writeUInt16BE(MAX_PACKET_LENGTH - HEADER_LENGTH + 1, 36);
  assert.throws(() => frameLength(oversized), /exceeds/);

  assert.throws(
    () => encode({ type: MessageType.REJECTED, connectionId: Buffer.alloc(16) }),
    /unexpected/,
  );
});
