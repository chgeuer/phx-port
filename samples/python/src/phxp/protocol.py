from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

MAGIC = b"PHXP"
VERSION = 1
HEADER_LENGTH = 40
MAX_PACKET_LENGTH = 512
MAX_SNI_LENGTH = 253
_HEADER = struct.Struct("!4sBBH16sIQHH")
_ZERO_ID = bytes(16)


class ProtocolError(ValueError):
    pass


class MessageType(IntEnum):
    HELLO = 1
    READY = 2
    HANDOFF = 3
    ADOPTED = 4
    REJECTED = 5


@dataclass(frozen=True, slots=True)
class Message:
    type: MessageType
    connection_id: bytes = _ZERO_ID
    peeked_length: int = 0
    accepted_at_ns: int = 0
    requested_sni: str = ""
    rejection_code: int = 0


def encode(message: Message) -> bytes:
    _validate_uint(message.peeked_length, 32, "peeked length")
    _validate_uint(message.accepted_at_ns, 64, "accepted timestamp")
    _validate_uint(message.rejection_code, 16, "rejection code")
    if len(message.connection_id) != 16:
        raise ProtocolError("PHXP connection ID must contain exactly 16 bytes")

    payload = b""
    if message.type in (MessageType.HELLO, MessageType.READY):
        if (
            message.connection_id != _ZERO_ID
            or message.peeked_length
            or message.accepted_at_ns
            or message.requested_sni
            or message.rejection_code
        ):
            raise ProtocolError("PHXP handshake has unexpected field values")
    elif message.type is MessageType.HANDOFF:
        try:
            payload = message.requested_sni.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ProtocolError("PHXP handoff SNI is not valid UTF-8") from error
        if not 1 <= len(payload) <= MAX_SNI_LENGTH:
            raise ProtocolError("PHXP handoff SNI length is outside protocol bounds")
        if message.rejection_code:
            raise ProtocolError("PHXP handoff request has a rejection code")
    elif message.type is MessageType.ADOPTED:
        if (
            message.peeked_length
            or message.accepted_at_ns
            or message.requested_sni
            or message.rejection_code
        ):
            raise ProtocolError("PHXP adopted response has unexpected field values")
    elif message.type is MessageType.REJECTED:
        if (
            message.peeked_length
            or message.accepted_at_ns
            or message.requested_sni
            or not message.rejection_code
        ):
            raise ProtocolError("PHXP rejected response has unexpected field values")
    else:
        raise ProtocolError(f"unknown PHXP message type {message.type}")

    if HEADER_LENGTH + len(payload) > MAX_PACKET_LENGTH:
        raise ProtocolError("PHXP packet exceeds protocol limit")
    return (
        _HEADER.pack(
            MAGIC,
            VERSION,
            int(message.type),
            0,
            message.connection_id,
            message.peeked_length,
            message.accepted_at_ns,
            len(payload),
            message.rejection_code,
        )
        + payload
    )


def decode(packet: bytes) -> Message:
    length = frame_length(packet)
    if len(packet) != length:
        raise ProtocolError("PHXP payload length does not match packet")
    (
        _magic,
        _version,
        raw_type,
        _flags,
        connection_id,
        peeked_length,
        accepted_at_ns,
        payload_length,
        rejection_code,
    ) = _HEADER.unpack_from(packet)
    message_type = MessageType(raw_type)

    if message_type in (MessageType.HELLO, MessageType.READY):
        if (
            payload_length
            or connection_id != _ZERO_ID
            or peeked_length
            or accepted_at_ns
            or rejection_code
        ):
            raise ProtocolError("PHXP handshake has unexpected field values")
        return Message(message_type)
    if message_type is MessageType.HANDOFF:
        if not 1 <= payload_length <= MAX_SNI_LENGTH or rejection_code:
            raise ProtocolError("PHXP handoff request has invalid field values")
        try:
            requested_sni = packet[HEADER_LENGTH:].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("PHXP handoff SNI is not valid UTF-8") from error
        return Message(
            message_type,
            connection_id,
            peeked_length,
            accepted_at_ns,
            requested_sni,
        )
    if payload_length or peeked_length or accepted_at_ns:
        raise ProtocolError("PHXP response has unexpected field values")
    if message_type is MessageType.ADOPTED:
        if rejection_code:
            raise ProtocolError("PHXP response has unexpected field values")
        return Message(message_type, connection_id)
    if not rejection_code:
        raise ProtocolError("PHXP rejection has invalid field values")
    return Message(message_type, connection_id, rejection_code=rejection_code)


def frame_length(header: bytes) -> int:
    if len(header) < HEADER_LENGTH:
        raise ProtocolError("PHXP packet is shorter than its fixed header")
    magic, version, raw_type, flags = struct.unpack_from("!4sBBH", header)
    if magic != MAGIC:
        raise ProtocolError("PHXP packet has invalid magic")
    if version != VERSION:
        raise ProtocolError(f"unsupported PHXP protocol version {version}")
    try:
        MessageType(raw_type)
    except ValueError as error:
        raise ProtocolError(f"unknown PHXP message type {raw_type}") from error
    if flags:
        raise ProtocolError("PHXP packet uses unsupported flags")
    payload_length = struct.unpack_from("!H", header, 36)[0]
    length = HEADER_LENGTH + payload_length
    if length > MAX_PACKET_LENGTH:
        raise ProtocolError("PHXP packet exceeds protocol limit")
    return length


def accumulate_stream_frame(initial: bytes, receive: Callable[[int], bytes]) -> bytes:
    if len(initial) > MAX_PACKET_LENGTH:
        raise ProtocolError("PHXP stream contains bytes beyond the maximum frame")
    frame = bytearray(initial)
    while len(frame) < HEADER_LENGTH:
        chunk = receive(HEADER_LENGTH - len(frame))
        if not chunk:
            raise ProtocolError("unexpected EOF in PHXP frame header")
        frame.extend(chunk)
    length = frame_length(frame)
    if len(frame) > length:
        raise ProtocolError("PHXP stream contains bytes beyond the declared frame")
    while len(frame) < length:
        chunk = receive(length - len(frame))
        if not chunk:
            raise ProtocolError("unexpected EOF in PHXP frame payload")
        frame.extend(chunk)
    return bytes(frame)


def _validate_uint(value: int, bits: int, field: str) -> None:
    if not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise ProtocolError(f"PHXP {field} is outside its unsigned {bits}-bit range")
