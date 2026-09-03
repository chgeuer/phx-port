from __future__ import annotations

import array
import platform
import queue
import socket
import threading

from phxp.protocol import (
    MAX_PACKET_LENGTH,
    Message,
    MessageType,
    accumulate_stream_frame,
    decode,
    encode,
)

HandoffResult = tuple[Message | None, BaseException | None]


def start_handoff(
    path: str,
    connection: socket.socket,
    request: Message,
) -> queue.Queue[HandoffResult]:
    result: queue.Queue[HandoffResult] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result.put((send_handoff(path, connection, request), None))
        except BaseException as error:
            result.put((None, error))

    threading.Thread(target=run, name="test-phxp-sender", daemon=True).start()
    return result


def await_handoff(result: queue.Queue[HandoffResult]) -> Message:
    response, error = result.get(timeout=3.0)
    if error is not None:
        raise error
    assert response is not None
    return response


def send_handoff(
    path: str,
    connection: socket.socket,
    request: Message,
    *,
    descriptor_count: int = 1,
) -> Message:
    control_type = socket.SOCK_SEQPACKET if platform.system() == "Linux" else socket.SOCK_STREAM
    control = socket.socket(socket.AF_UNIX, control_type)
    try:
        control.settimeout(2.0)
        control.connect(path)
        _write_frame(control, encode(Message(MessageType.HELLO)))
        ready = decode(_read_frame(control))
        if ready.type is not MessageType.READY:
            raise RuntimeError("PHXP receiver did not return READY")

        packet = encode(request)
        rights = array.array("i", [connection.fileno()] * descriptor_count)
        sent = control.sendmsg(
            [packet],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
            getattr(socket, "MSG_NOSIGNAL", 0),
        )
        if sent <= 0:
            raise RuntimeError("descriptor-bearing sendmsg wrote no bytes")
        connection.close()
        if platform.system() == "Linux" and sent != len(packet):
            raise RuntimeError("descriptor-bearing seqpacket send was partial")
        if sent < len(packet):
            control.sendall(packet[sent:])
        return decode(_read_frame(control))
    finally:
        control.close()


def tcp_pair() -> tuple[socket.socket, socket.socket, socket.socket]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname(), timeout=2.0)
    server, _ = listener.accept()
    return listener, client, server


def _read_frame(control: socket.socket) -> bytes:
    initial = control.recv(MAX_PACKET_LENGTH + 1)
    if platform.system() == "Linux":
        return initial
    return accumulate_stream_frame(initial, control.recv)


def _write_frame(control: socket.socket, packet: bytes) -> None:
    if platform.system() == "Linux":
        sent = control.send(packet, getattr(socket, "MSG_NOSIGNAL", 0))
        if sent != len(packet):
            raise RuntimeError("partial PHXP seqpacket send")
    else:
        control.sendall(packet)
