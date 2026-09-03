from __future__ import annotations

import io
import struct

import pytest

from phxp.protocol import (
    HEADER_LENGTH,
    MAX_PACKET_LENGTH,
    Message,
    MessageType,
    ProtocolError,
    accumulate_stream_frame,
    decode,
    encode,
    frame_length,
)


def test_protocol_round_trip() -> None:
    connection_id = bytes.fromhex("ab" * 16)
    messages = [
        Message(MessageType.HELLO),
        Message(MessageType.READY),
        Message(
            MessageType.HANDOFF,
            connection_id,
            peeked_length=517,
            accepted_at_ns=42,
            requested_sni="www.contoso.com",
        ),
        Message(MessageType.ADOPTED, connection_id),
        Message(MessageType.REJECTED, connection_id, rejection_code=7),
    ]
    for message in messages:
        assert decode(encode(message)) == message


def test_protocol_rejects_malformed_envelopes() -> None:
    hello = encode(Message(MessageType.HELLO))
    malformed = [
        hello[: HEADER_LENGTH - 1],
        b"X" + hello[1:],
        hello[:4] + b"\x02" + hello[5:],
        hello[:6] + b"\x00\x01" + hello[8:],
        hello[:8] + b"\x01" + hello[9:],
    ]
    too_long = bytearray(hello)
    struct.pack_into("!H", too_long, 36, MAX_PACKET_LENGTH - HEADER_LENGTH + 1)
    malformed.append(bytes(too_long))
    for packet in malformed:
        with pytest.raises(ProtocolError):
            decode(packet)


def test_stream_framing_is_bounded_and_exact() -> None:
    packet = encode(
        Message(
            MessageType.HANDOFF,
            bytes.fromhex("01" * 16),
            peeked_length=123,
            accepted_at_ns=456,
            requested_sni="example.test",
        )
    )
    for boundary in range(1, len(packet)):
        reader = io.BytesIO(packet[boundary:])
        assert accumulate_stream_frame(packet[:boundary], reader.read) == packet

    coalesced = encode(Message(MessageType.HELLO)) + encode(Message(MessageType.READY))
    with pytest.raises(ProtocolError, match="beyond the declared frame"):
        accumulate_stream_frame(coalesced, io.BytesIO().read)

    oversized = bytearray(encode(Message(MessageType.HELLO)))
    struct.pack_into("!H", oversized, 36, MAX_PACKET_LENGTH)
    with pytest.raises(ProtocolError, match="exceeds"):
        frame_length(oversized)
