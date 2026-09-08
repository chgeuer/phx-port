"""One-shot PHXP sender, isolated from the receiving BEAM VM.

Report the OS PID and an ephemeral loopback port, then read the PHXP endpoint
from stdin. Only this process accepts and delivers the client descriptor.
"""

import array
import os
import signal
import socket
import struct
import sys


SEQPACKET = sys.platform == "linux"


def frame(kind, connection_id=b"\0" * 16, sni=b""):
    return (
        struct.pack(
            "!4sBBH16sIQHH", b"PHXP", 1, kind, 0, connection_id, 0, 0, len(sni), 0
        )
        + sni
    )


def write_frame(control, packet):
    if SEQPACKET:
        if control.send(packet) != len(packet):
            raise RuntimeError("partial PHXP packet")
    else:
        control.sendall(packet)


def read_reply(control):
    if SEQPACKET:
        return control.recv(513)

    reply = b""
    while len(reply) < 40:
        data = control.recv(40 - len(reply))
        if not data:
            raise RuntimeError("PHXP reply closed before its complete header")
        reply += data
    return reply


def hand_off(accepted, path):
    control_type = socket.SOCK_SEQPACKET if SEQPACKET else socket.SOCK_STREAM

    with socket.socket(socket.AF_UNIX, control_type) as control:
        control.settimeout(2)
        control.connect(path)
        write_frame(control, frame(1))
        if read_reply(control) != frame(2):
            raise RuntimeError("PHXP receiver did not return READY")

        connection_id = os.urandom(16)
        packet = frame(3, connection_id, b"localhost")
        rights = array.array("i", [accepted.fileno()])
        sent = control.sendmsg(
            [packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
        )
        if sent <= 0 or (SEQPACKET and sent != len(packet)):
            raise RuntimeError("incomplete descriptor-bearing PHXP send")
        if sent < len(packet):
            control.sendall(packet[sent:])
        if read_reply(control) != frame(4, connection_id):
            raise RuntimeError("PHXP receiver did not acknowledge adoption")


def main():
    # Independent of BEAM timers, including while waiting for the parent.
    signal.alarm(15)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(10)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        print(f"READY {os.getpid()} {listener.getsockname()[1]}", flush=True)

        path = sys.stdin.readline().rstrip("\n")
        if not path:
            raise RuntimeError("parent closed before supplying a PHXP endpoint")

        accepted, _ = listener.accept()
        with accepted:
            # SCM_RIGHTS shares the open file description. Never change these
            # flags after delivery, and close without shutdown after ADOPTED.
            accepted.setblocking(True)
            hand_off(accepted, path)

    print("ADOPTED", flush=True)


if __name__ == "__main__":
    main()
