from __future__ import annotations

import array
import ctypes
import fcntl
import logging
import os
import platform
import queue
import socket
import struct
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Final

from .endpoint import (
    Endpoint,
    EndpointIdentity,
    inspect_socket,
    prepare_endpoint,
    remove_endpoint_if_owned,
)
from .protocol import (
    MAX_PACKET_LENGTH,
    Message,
    MessageType,
    ProtocolError,
    accumulate_stream_frame,
    decode,
    encode,
)

REJECT_INVALID_DESCRIPTOR: Final = 1
REJECT_DUPLICATE_ID: Final = 2
REJECT_ADOPTION_FAILED: Final = 3
_FD_SIZE = array.array("i").itemsize
_CMSG_BUFFER_SIZE = socket.CMSG_SPACE(2 * _FD_SIZE)
_CLOSED = object()


class ListenerClosedError(RuntimeError):
    pass


class DescriptorError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Metadata:
    connection_id: bytes
    requested_sni: str
    peeked_length: int
    accepted_at_ns: int


class AdoptedSocket:
    def __init__(
        self,
        connection: socket.socket,
        metadata: Metadata,
        owner: PHXPListener,
    ) -> None:
        self._socket: socket.socket | None = connection
        self.metadata = metadata
        self._owner = owner
        self._released = False
        self._decision: bool | None = None
        self._decision_ready = threading.Event()
        self._lock = threading.Lock()

    @property
    def socket(self) -> socket.socket:
        with self._lock:
            if self._socket is None:
                raise RuntimeError("PHXP socket ownership has already been transferred")
            return self._socket

    def transfer(self) -> socket.socket:
        with self._lock:
            if self._socket is None:
                raise RuntimeError("PHXP socket ownership has already been transferred")
            connection = self._socket
            self._socket = None
            return connection

    def adopt(self) -> None:
        with self._lock:
            if self._released:
                raise RuntimeError("released PHXP socket cannot be adopted")
            if self._decision is not None:
                raise RuntimeError("PHXP socket ownership was already decided")
            self._decision = True
            self._decision_ready.set()
        self._owner.resolve_pending(self)

    def reject(self) -> None:
        decided = False
        with self._lock:
            if self._decision is None:
                self._decision = False
                self._decision_ready.set()
                decided = True
        if decided:
            self._owner.resolve_pending(self)

    def wait_for_decision(self) -> bool:
        self._decision_ready.wait()
        with self._lock:
            assert self._decision is not None
            return self._decision

    def release(self) -> None:
        connection: socket.socket | None
        with self._lock:
            if self._released:
                return
            self._released = True
            if self._decision is None:
                self._decision = False
                self._decision_ready.set()
            connection = self._socket
            self._socket = None
        if connection is not None:
            connection.close()
        self._owner.resolve_pending(self)
        self._owner.release_id(self.metadata.connection_id)

    def __enter__(self) -> AdoptedSocket:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class PHXPListener:
    def __init__(
        self,
        endpoint: Endpoint,
        *,
        queue_size: int = 128,
        backlog: int = 128,
        control_timeout: float = 2.0,
        max_control_connections: int = 32,
        logger: logging.Logger | None = None,
    ) -> None:
        if queue_size < 1:
            raise ValueError("PHXP queue size must be positive")
        if backlog < 1:
            raise ValueError("PHXP backlog must be positive")
        if control_timeout < 0.001:
            raise ValueError("PHXP control timeout is too short")
        if max_control_connections < 1:
            raise ValueError("PHXP control connection limit must be positive")

        prepare_endpoint(endpoint)
        listener = _bind_control_socket(endpoint.path)
        identity: EndpointIdentity | None = None
        try:
            identity = inspect_socket(endpoint.path, require_mode=False)
            os.chmod(endpoint.path, 0o600)
            secured_identity = inspect_socket(endpoint.path, require_mode=True)
            if secured_identity != identity:
                raise RuntimeError("PHXP endpoint identity changed while it was being secured")
            listener.listen(backlog)
            listener.settimeout(0.2)
        except BaseException:
            listener.close()
            if identity is not None:
                remove_endpoint_if_owned(endpoint.path, identity)
            raise

        self.endpoint = endpoint
        self._listener = listener
        self._identity = identity
        self._timeout = control_timeout
        self._queue: queue.Queue[AdoptedSocket | object] = queue.Queue(queue_size)
        self._logger = logger or logging.getLogger(__name__)
        self._closed = threading.Event()
        self._state_lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active_ids: set[bytes] = set()
        self._pending: set[AdoptedSocket] = set()
        self._control_slots = threading.BoundedSemaphore(max_control_connections)
        self._thread = threading.Thread(
            target=self._accept_loop,
            name="phxp-control-listener",
            daemon=True,
        )
        self._thread.start()

    def accept(self, timeout: float | None = None) -> AdoptedSocket:
        if self._closed.is_set() and self._queue.empty():
            raise ListenerClosedError("PHXP listener is closed")
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty as error:
            raise TimeoutError("timed out waiting for a PHXP connection") from error
        if item is _CLOSED:
            self._queue.put_nowait(_CLOSED)
            raise ListenerClosedError("PHXP listener is closed")
        assert isinstance(item, AdoptedSocket)
        return item

    def close(self) -> None:
        pending: list[AdoptedSocket]
        with self._state_lock:
            if self._closed.is_set():
                return
            self._closed.set()
            self._listener.close()
            pending = list(self._pending)
            self._pending.clear()
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
            with suppress(queue.Full):
                self._queue.put_nowait(_CLOSED)
        for item in pending:
            item.release()
        self._thread.join(timeout=self._timeout + 0.5)
        remove_endpoint_if_owned(self.endpoint.path, self._identity)

    def resolve_pending(self, item: AdoptedSocket) -> None:
        with self._state_lock:
            self._pending.discard(item)

    def release_id(self, connection_id: bytes) -> None:
        with self._active_lock:
            self._active_ids.discard(connection_id)

    def __enter__(self) -> PHXPListener:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _accept_loop(self) -> None:
        while not self._closed.is_set():
            try:
                control, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._closed.is_set():
                    self._logger.exception("accept PHXP control connection")
                continue
            control.set_inheritable(False)
            if not self._control_slots.acquire(blocking=False):
                control.close()
                continue
            threading.Thread(
                target=self._handle_control_guarded,
                args=(control,),
                name="phxp-control",
                daemon=True,
            ).start()

    def _handle_control_guarded(self, control: socket.socket) -> None:
        try:
            self._handle_control(control)
        except (OSError, ProtocolError, DescriptorError, RuntimeError):
            self._logger.exception("PHXP control connection failed")
        finally:
            control.close()
            self._control_slots.release()

    def _handle_control(self, control: socket.socket) -> None:
        control.settimeout(self._timeout)
        _configure_no_sigpipe(control)
        if _peer_euid(control) != os.geteuid():
            raise DescriptorError("PHXP peer belongs to a different user")
        hello_packet = _read_control_frame(control)
        if decode(hello_packet) != Message(MessageType.HELLO):
            raise ProtocolError("invalid PHXP HELLO")
        _write_control_frame(control, encode(Message(MessageType.READY)))

        packet, descriptors = _receive_descriptor_frame(control)
        try:
            request = decode(packet)
        except ProtocolError:
            _close_descriptors(descriptors)
            raise
        if request.type is not MessageType.HANDOFF:
            _close_descriptors(descriptors)
            raise ProtocolError("invalid PHXP HANDOFF")
        if len(descriptors) != 1:
            _close_descriptors(descriptors)
            self._reject(control, request.connection_id, REJECT_INVALID_DESCRIPTOR)
            raise DescriptorError(
                f"PHXP HANDOFF contained {len(descriptors)} descriptors instead of one"
            )

        connection = _adopt_tcp_descriptor(descriptors[0])
        if connection is None:
            self._reject(control, request.connection_id, REJECT_INVALID_DESCRIPTOR)
            return
        if not self._reserve_id(request.connection_id):
            connection.close()
            self._reject(control, request.connection_id, REJECT_DUPLICATE_ID)
            return
        adopted = AdoptedSocket(
            connection,
            Metadata(
                request.connection_id,
                request.requested_sni,
                request.peeked_length,
                request.accepted_at_ns,
            ),
            self,
        )

        queued = False
        with self._state_lock:
            if not self._closed.is_set():
                self._pending.add(adopted)
                try:
                    self._queue.put_nowait(adopted)
                    queued = True
                except queue.Full:
                    pass
        if not queued:
            adopted.release()
            self._reject(control, request.connection_id, REJECT_ADOPTION_FAILED)
            return
        if adopted.wait_for_decision():
            try:
                _write_control_frame(
                    control,
                    encode(Message(MessageType.ADOPTED, request.connection_id)),
                )
            except OSError:
                self._logger.exception("PHXP connection was accepted but acknowledgement was lost")
        else:
            self._reject(control, request.connection_id, REJECT_ADOPTION_FAILED)

    def _reserve_id(self, connection_id: bytes) -> bool:
        with self._active_lock:
            if connection_id in self._active_ids:
                return False
            self._active_ids.add(connection_id)
            return True

    @staticmethod
    def _reject(control: socket.socket, connection_id: bytes, code: int) -> None:
        with suppress(OSError):
            _write_control_frame(
                control,
                encode(
                    Message(
                        MessageType.REJECTED,
                        connection_id,
                        rejection_code=code,
                    )
                ),
            )


def authenticate_peer(control: socket.socket) -> None:
    if _peer_euid(control) != os.geteuid():
        raise DescriptorError("PHXP peer belongs to a different user")


def validate_connected_tcp(connection: socket.socket) -> None:
    if connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise DescriptorError("handed-off descriptor is not a stream socket")
    try:
        connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
    except OSError as error:
        raise DescriptorError("handed-off stream is not TCP") from error
    try:
        peer = connection.getpeername()
    except OSError as error:
        raise DescriptorError("handed-off TCP descriptor is not connected") from error
    try:
        local = connection.getsockname()
    except OSError as error:
        raise DescriptorError("inspect handed-off TCP local address") from error
    if connection.family not in (socket.AF_INET, socket.AF_INET6) or not peer or not local:
        raise DescriptorError("handed-off descriptor lacks Internet socket addresses")


def verify_descriptor_policy(connection: socket.socket) -> None:
    descriptor = connection.fileno()
    if not fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
        raise DescriptorError("adopted descriptor is not close-on-exec")
    if not fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_NONBLOCK:
        raise DescriptorError("adopted descriptor is not nonblocking")


def _adopt_tcp_descriptor(descriptor: int) -> socket.socket | None:
    try:
        os.set_inheritable(descriptor, False)
        connection = socket.socket(fileno=descriptor)
    except OSError:
        with suppress(OSError):
            os.close(descriptor)
        return None
    try:
        validate_connected_tcp(connection)
        connection.setblocking(False)
        connection.set_inheritable(False)
        verify_descriptor_policy(connection)
        return connection
    except (OSError, DescriptorError):
        connection.close()
        return None


def _bind_control_socket(path: Path) -> socket.socket:
    system = platform.system()
    if system == "Linux":
        listener = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
        )
    elif system == "Darwin":
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _configure_no_sigpipe(listener)
    else:
        raise RuntimeError(f"PHXP requires Linux or macOS, not {system}")
    try:
        listener.set_inheritable(False)
        listener.bind(str(path))
        return listener
    except BaseException:
        listener.close()
        raise


def _read_control_frame(control: socket.socket) -> bytes:
    if platform.system() == "Linux":
        packet, ancillary, flags, _ = control.recvmsg(MAX_PACKET_LENGTH + 1, _CMSG_BUFFER_SIZE)
        descriptors = _extract_descriptors(ancillary)
        _close_descriptors(descriptors)
        if ancillary:
            raise DescriptorError("PHXP non-HANDOFF frame contained ancillary data")
        if not packet:
            raise ProtocolError("unexpected EOF in PHXP frame")
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) > MAX_PACKET_LENGTH:
            raise ProtocolError("PHXP packet was truncated or exceeds its bound")
        return packet
    initial = control.recv(MAX_PACKET_LENGTH + 1)
    if not initial:
        raise ProtocolError("unexpected EOF in PHXP frame")
    return accumulate_stream_frame(initial, control.recv)


def _write_control_frame(control: socket.socket, packet: bytes) -> None:
    if platform.system() == "Linux":
        sent = control.send(packet, getattr(socket, "MSG_NOSIGNAL", 0))
        if sent != len(packet):
            raise OSError("PHXP seqpacket response was partially sent")
    else:
        control.sendall(packet)


def _receive_descriptor_frame(control: socket.socket) -> tuple[bytes, list[int]]:
    flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0) if platform.system() == "Linux" else 0
    packet, ancillary, message_flags, _ = control.recvmsg(
        MAX_PACKET_LENGTH + 1,
        _CMSG_BUFFER_SIZE,
        flags,
    )
    descriptors: list[int] = []
    try:
        descriptors = _extract_descriptors(ancillary)
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        if not packet:
            raise ProtocolError("unexpected EOF in PHXP descriptor frame")
        if (
            message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(packet) > MAX_PACKET_LENGTH
        ):
            raise ProtocolError("PHXP packet or ancillary data was truncated")
        if platform.system() == "Darwin":
            packet = accumulate_stream_frame(packet, control.recv)
        return packet, descriptors
    except BaseException:
        _close_descriptors(descriptors)
        raise


def _extract_descriptors(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    descriptors: list[int] = []
    try:
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise DescriptorError("PHXP HANDOFF contains unsupported ancillary data")
            if len(data) % _FD_SIZE:
                raise DescriptorError("PHXP SCM_RIGHTS data is malformed")
            rights = array.array("i")
            rights.frombytes(data)
            descriptors.extend(rights.tolist())
        return descriptors
    except BaseException:
        _close_descriptors(descriptors)
        raise


def _close_descriptors(descriptors: list[int]) -> None:
    for descriptor in descriptors:
        with suppress(OSError):
            os.close(descriptor)


def _configure_no_sigpipe(control: socket.socket) -> None:
    option = getattr(socket, "SO_NOSIGPIPE", None)
    if option is not None:
        control.setsockopt(socket.SOL_SOCKET, option, 1)


def _peer_euid(control: socket.socket) -> int:
    system = platform.system()
    if system == "Linux":
        option = getattr(socket, "SO_PEERCRED", 17)
        credentials = control.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", credentials)
        return uid
    if system == "Darwin":
        return _darwin_peer_euid(control.fileno())
    raise DescriptorError(f"PHXP requires Linux or macOS, not {system}")


def _darwin_peer_euid(descriptor: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    getpeereid = libc.getpeereid
    getpeereid.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    getpeereid.restype = ctypes.c_int
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    if getpeereid(descriptor, ctypes.byref(uid), ctypes.byref(gid)) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(uid.value)
