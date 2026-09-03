export const MAGIC = Buffer.from('PHXP');
export const VERSION = 1;
export const HEADER_LENGTH = 40;
export const MAX_PACKET_LENGTH = 512;
export const MAX_SNI_LENGTH = 253;

export const MessageType = Object.freeze({
  HELLO: 1,
  READY: 2,
  HANDOFF: 3,
  ADOPTED: 4,
  REJECTED: 5,
});

const VALID_TYPES = new Set(Object.values(MessageType));
const ZERO_ID = Buffer.alloc(16);

export class ProtocolError extends Error {}

export function encode(message) {
  const type = integer(message.type, 8, 'message type');
  if (!VALID_TYPES.has(type)) {
    throw new ProtocolError(`unknown PHXP message type ${type}`);
  }
  const connectionId = message.connectionId ?? ZERO_ID;
  if (!Buffer.isBuffer(connectionId) || connectionId.length !== 16) {
    throw new ProtocolError('PHXP connection ID must contain exactly 16 bytes');
  }
  const peekedLength = integer(message.peekedLength ?? 0, 32, 'peeked length');
  const acceptedAtNs = bigint(message.acceptedAtNs ?? 0n, 64, 'accepted timestamp');
  const rejectionCode = integer(message.rejectionCode ?? 0, 16, 'rejection code');
  const requestedSni = message.requestedSni ?? '';
  let payload = Buffer.alloc(0);

  if (type === MessageType.HELLO || type === MessageType.READY) {
    if (
      !connectionId.equals(ZERO_ID) ||
      peekedLength !== 0 ||
      acceptedAtNs !== 0n ||
      requestedSni !== '' ||
      rejectionCode !== 0
    ) {
      throw new ProtocolError('PHXP handshake has unexpected field values');
    }
  } else if (type === MessageType.HANDOFF) {
    payload = Buffer.from(requestedSni, 'utf8');
    if (payload.toString('utf8') !== requestedSni) {
      throw new ProtocolError('PHXP handoff SNI is not valid UTF-8');
    }
    if (payload.length < 1 || payload.length > MAX_SNI_LENGTH) {
      throw new ProtocolError('PHXP handoff SNI length is outside protocol bounds');
    }
    if (rejectionCode !== 0) {
      throw new ProtocolError('PHXP handoff request has a rejection code');
    }
  } else if (type === MessageType.ADOPTED) {
    requireResponseFields(peekedLength, acceptedAtNs, requestedSni, rejectionCode, false);
  } else {
    requireResponseFields(peekedLength, acceptedAtNs, requestedSni, rejectionCode, true);
  }

  const frame = Buffer.alloc(HEADER_LENGTH + payload.length);
  if (frame.length > MAX_PACKET_LENGTH) {
    throw new ProtocolError('PHXP packet exceeds protocol limit');
  }
  MAGIC.copy(frame, 0);
  frame[4] = VERSION;
  frame[5] = type;
  frame.writeUInt16BE(0, 6);
  connectionId.copy(frame, 8);
  frame.writeUInt32BE(peekedLength, 24);
  frame.writeBigUInt64BE(acceptedAtNs, 28);
  frame.writeUInt16BE(payload.length, 36);
  frame.writeUInt16BE(rejectionCode, 38);
  payload.copy(frame, HEADER_LENGTH);
  return frame;
}

export function decode(frame) {
  if (!Buffer.isBuffer(frame)) {
    throw new ProtocolError('PHXP frame must be a Buffer');
  }
  const length = frameLength(frame);
  if (frame.length !== length) {
    throw new ProtocolError('PHXP payload length does not match packet');
  }
  const type = frame[5];
  const connectionId = Buffer.from(frame.subarray(8, 24));
  const peekedLength = frame.readUInt32BE(24);
  const acceptedAtNs = frame.readBigUInt64BE(28);
  const payloadLength = frame.readUInt16BE(36);
  const rejectionCode = frame.readUInt16BE(38);
  const requestedSni = frame.subarray(HEADER_LENGTH).toString('utf8');

  if (type === MessageType.HELLO || type === MessageType.READY) {
    if (
      payloadLength !== 0 ||
      !connectionId.equals(ZERO_ID) ||
      peekedLength !== 0 ||
      acceptedAtNs !== 0n ||
      rejectionCode !== 0
    ) {
      throw new ProtocolError('PHXP handshake has unexpected field values');
    }
    return { type, connectionId: ZERO_ID, peekedLength: 0, acceptedAtNs: 0n, requestedSni: '', rejectionCode: 0 };
  }
  if (type === MessageType.HANDOFF) {
    if (payloadLength < 1 || payloadLength > MAX_SNI_LENGTH || rejectionCode !== 0) {
      throw new ProtocolError('PHXP handoff request has invalid field values');
    }
    if (!Buffer.from(requestedSni, 'utf8').equals(frame.subarray(HEADER_LENGTH))) {
      throw new ProtocolError('PHXP handoff SNI is not valid UTF-8');
    }
    return { type, connectionId, peekedLength, acceptedAtNs, requestedSni, rejectionCode: 0 };
  }
  if (payloadLength !== 0 || peekedLength !== 0 || acceptedAtNs !== 0n) {
    throw new ProtocolError('PHXP response has unexpected field values');
  }
  if (type === MessageType.ADOPTED) {
    if (rejectionCode !== 0) {
      throw new ProtocolError('PHXP response has unexpected field values');
    }
  } else if (rejectionCode === 0) {
    throw new ProtocolError('PHXP rejection has invalid field values');
  }
  return { type, connectionId, peekedLength: 0, acceptedAtNs: 0n, requestedSni: '', rejectionCode };
}

export function frameLength(header) {
  if (!Buffer.isBuffer(header) || header.length < HEADER_LENGTH) {
    throw new ProtocolError('PHXP packet is shorter than its fixed header');
  }
  if (!header.subarray(0, 4).equals(MAGIC)) {
    throw new ProtocolError('PHXP packet has invalid magic');
  }
  if (header[4] !== VERSION) {
    throw new ProtocolError(`unsupported PHXP protocol version ${header[4]}`);
  }
  if (!VALID_TYPES.has(header[5])) {
    throw new ProtocolError(`unknown PHXP message type ${header[5]}`);
  }
  if (header.readUInt16BE(6) !== 0) {
    throw new ProtocolError('PHXP packet uses unsupported flags');
  }
  const length = HEADER_LENGTH + header.readUInt16BE(36);
  if (length > MAX_PACKET_LENGTH) {
    throw new ProtocolError('PHXP packet exceeds protocol limit');
  }
  return length;
}

function integer(value, bits, field) {
  const maximum = bits === 32 ? 0xffffffff : (2 ** bits) - 1;
  if (!Number.isInteger(value) || value < 0 || value > maximum) {
    throw new ProtocolError(`PHXP ${field} is outside its unsigned ${bits}-bit range`);
  }
  return value;
}

function bigint(value, bits, field) {
  if (typeof value !== 'bigint' || value < 0n || value >= (1n << BigInt(bits))) {
    throw new ProtocolError(`PHXP ${field} is outside its unsigned ${bits}-bit range`);
  }
  return value;
}

function requireResponseFields(peekedLength, acceptedAtNs, requestedSni, rejectionCode, rejected) {
  if (
    peekedLength !== 0 ||
    acceptedAtNs !== 0n ||
    requestedSni !== '' ||
    (rejected ? rejectionCode === 0 : rejectionCode !== 0)
  ) {
    throw new ProtocolError(`PHXP ${rejected ? 'rejected' : 'adopted'} response has unexpected field values`);
  }
}
