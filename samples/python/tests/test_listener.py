from __future__ import annotations

import fcntl
import os
import socket
import time
from pathlib import Path

import pytest

from phxp.endpoint import Endpoint
from phxp.listener import (
    REJECT_ADOPTION_FAILED,
    REJECT_DUPLICATE_ID,
    REJECT_INVALID_DESCRIPTOR,
    PHXPListener,
    _adopt_tcp_descriptor,
    authenticate_peer,
    validate_connected_tcp,
    verify_descriptor_policy,
)
from phxp.protocol import Message, MessageType

from .helpers import await_handoff, send_handoff, start_handoff, tcp_pair


def endpoint_in(tmp_path: Path) -> Endpoint:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    return Endpoint(private / "receiver.sock")


def test_peer_and_descriptor_validation() -> None:
    left, right = socket.socketpair()
    try:
        authenticate_peer(left)
        try:
            validate_connected_tcp(left)
        except RuntimeError:
            pass
        else:
            raise AssertionError("connected Unix stream was accepted as TCP")
    finally:
        left.close()
        right.close()

    listener, client, server = tcp_pair()
    try:
        validate_connected_tcp(server)
        server.setblocking(False)
        server.set_inheritable(False)
        verify_descriptor_policy(server)
    finally:
        listener.close()
        client.close()
        server.close()


def test_peer_authentication_rejects_a_different_effective_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left, right = socket.socketpair()
    try:
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
        with pytest.raises(RuntimeError, match="different user"):
            authenticate_peer(left)
    finally:
        left.close()
        right.close()


def test_adoption_owns_received_descriptor_without_duplication() -> None:
    listener, client, server = tcp_pair()
    descriptor = os.dup(server.fileno())
    server.close()
    adopted = _adopt_tcp_descriptor(descriptor)
    try:
        assert adopted is not None
        assert adopted.fileno() == descriptor
        verify_descriptor_policy(adopted)
    finally:
        if adopted is not None:
            adopted.close()
        listener.close()
        client.close()
    try:
        fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError:
        pass
    else:
        raise AssertionError("received descriptor remains usable after adopted socket close")


def test_handoff_round_trip_retains_addresses_and_data(short_path: Path) -> None:
    receiver = PHXPListener(endpoint_in(short_path), queue_size=2)
    public, client, accepted = tcp_pair()
    try:
        peer = client.getsockname()
        local = public.getsockname()
        payload = b"untouched client hello"
        client.sendall(payload)
        connection_id = bytes.fromhex("5a" * 16)
        result = start_handoff(
            str(receiver.endpoint.path),
            accepted,
            Message(
                MessageType.HANDOFF,
                connection_id,
                peeked_length=len(payload),
                accepted_at_ns=42,
                requested_sni="www.contoso.com",
            ),
        )
        adopted = receiver.accept(timeout=2.0)
        adopted.adopt()
        assert await_handoff(result) == Message(MessageType.ADOPTED, connection_id)
        try:
            assert adopted.socket.getpeername() == peer
            assert adopted.socket.getsockname() == local
            assert adopted.metadata.connection_id == connection_id
            assert adopted.metadata.requested_sni == "www.contoso.com"
            assert adopted.metadata.peeked_length == len(payload)
            assert adopted.metadata.accepted_at_ns == 42
            adopted.socket.setblocking(True)
            assert adopted.socket.recv(len(payload)) == payload
            adopted.socket.sendall(b"server reply")
            assert client.recv(len(b"server reply")) == b"server reply"
        finally:
            adopted.release()
    finally:
        receiver.close()
        public.close()
        client.close()


def test_duplicate_active_connection_ids_are_rejected(short_path: Path) -> None:
    receiver = PHXPListener(endpoint_in(short_path), queue_size=2)
    public1, client1, accepted1 = tcp_pair()
    public2, client2, accepted2 = tcp_pair()
    connection_id = bytes.fromhex("77" * 16)
    try:
        first_result = start_handoff(
            str(receiver.endpoint.path),
            accepted1,
            Message(
                MessageType.HANDOFF,
                connection_id,
                requested_sni="one.example",
            ),
        )
        adopted = receiver.accept(timeout=2.0)
        adopted.adopt()
        assert await_handoff(first_result).type is MessageType.ADOPTED
        second = send_handoff(
            str(receiver.endpoint.path),
            accepted2,
            Message(
                MessageType.HANDOFF,
                connection_id,
                requested_sni="two.example",
            ),
        )
        assert second == Message(
            MessageType.REJECTED,
            connection_id,
            rejection_code=REJECT_DUPLICATE_ID,
        )
        adopted.release()
    finally:
        receiver.close()
        public1.close()
        public2.close()
        client1.close()
        client2.close()


def test_more_than_one_descriptor_is_rejected(short_path: Path) -> None:
    receiver = PHXPListener(endpoint_in(short_path))
    public, client, accepted = tcp_pair()
    connection_id = bytes.fromhex("33" * 16)
    try:
        response = send_handoff(
            str(receiver.endpoint.path),
            accepted,
            Message(
                MessageType.HANDOFF,
                connection_id,
                requested_sni="example.test",
            ),
            descriptor_count=2,
        )
        assert response == Message(
            MessageType.REJECTED,
            connection_id,
            rejection_code=REJECT_INVALID_DESCRIPTOR,
        )
    finally:
        receiver.close()
        public.close()
        client.close()


def test_non_tcp_descriptor_is_rejected(short_path: Path) -> None:
    receiver = PHXPListener(endpoint_in(short_path))
    left, right = socket.socketpair()
    connection_id = bytes.fromhex("55" * 16)
    try:
        response = send_handoff(
            str(receiver.endpoint.path),
            left,
            Message(
                MessageType.HANDOFF,
                connection_id,
                requested_sni="example.test",
            ),
        )
        assert response == Message(
            MessageType.REJECTED,
            connection_id,
            rejection_code=REJECT_INVALID_DESCRIPTOR,
        )
    finally:
        receiver.close()
        right.close()


def test_full_adoption_queue_rejects_before_ownership(short_path: Path) -> None:
    receiver = PHXPListener(endpoint_in(short_path), queue_size=1)
    public1, client1, accepted1 = tcp_pair()
    public2, client2, accepted2 = tcp_pair()
    first_id = bytes.fromhex("11" * 16)
    second_id = bytes.fromhex("22" * 16)
    try:
        first_result = start_handoff(
            str(receiver.endpoint.path),
            accepted1,
            Message(
                MessageType.HANDOFF,
                first_id,
                requested_sni="one.example",
            ),
        )
        deadline = time.monotonic() + 2.0
        while receiver._queue.qsize() != 1 and time.monotonic() < deadline:
            time.sleep(0.001)
        assert receiver._queue.qsize() == 1
        assert send_handoff(
            str(receiver.endpoint.path),
            accepted2,
            Message(
                MessageType.HANDOFF,
                second_id,
                requested_sni="two.example",
            ),
        ) == Message(
            MessageType.REJECTED,
            second_id,
            rejection_code=REJECT_ADOPTION_FAILED,
        )
        adopted = receiver.accept(timeout=2.0)
        adopted.adopt()
        assert await_handoff(first_result) == Message(MessageType.ADOPTED, first_id)
        adopted.release()
    finally:
        receiver.close()
        public1.close()
        public2.close()
        client1.close()
        client2.close()


def test_close_rejects_an_accepted_but_undecided_handoff(short_path: Path) -> None:
    receiver = PHXPListener(endpoint_in(short_path), queue_size=1)
    public, client, accepted = tcp_pair()
    connection_id = bytes.fromhex("66" * 16)
    result = start_handoff(
        str(receiver.endpoint.path),
        accepted,
        Message(
            MessageType.HANDOFF,
            connection_id,
            requested_sni="closing.example",
        ),
    )
    adopted = receiver.accept(timeout=2.0)
    receiver.close()
    try:
        assert await_handoff(result) == Message(
            MessageType.REJECTED,
            connection_id,
            rejection_code=REJECT_ADOPTION_FAILED,
        )
        with pytest.raises(RuntimeError, match="transferred"):
            _ = adopted.socket
    finally:
        adopted.release()
        public.close()
        client.close()
