"""External PHXP sender and stalled peers for the scheduler evidence probes.

Only this process delivers descriptors. Never change their shared O_NONBLOCK
flags after delivery. The peer sockets remain observable until the workload
finishes its measurement and requests STOP; an independent alarm bounds exit.
"""

import array
import math
import os
import select
import signal
import socket
import struct
import sys
from contextlib import ExitStack


SEQPACKET = sys.platform == "linux"


def header(kind, connection_id=b"\0" * 16, sni=b""):
    return (
        struct.pack(
            "!4sBBH16sIQHH", b"PHXP", 1, kind, 0, connection_id, 0, 0, len(sni), 0
        )
        + sni
    )


def read_reply(control):
    if SEQPACKET:
        return control.recv(513)

    reply = b""
    while len(reply) < 40:
        data = control.recv(40 - len(reply))
        if not data:
            raise RuntimeError("incomplete PHXP reply")
        reply += data
    return reply


def hand_off(accepted, path):
    kind = socket.SOCK_SEQPACKET if SEQPACKET else socket.SOCK_STREAM
    with socket.socket(socket.AF_UNIX, kind) as control:
        control.settimeout(2)
        control.connect(path)
        packet = header(1)
        if SEQPACKET:
            if control.send(packet) != len(packet):
                raise RuntimeError("partial PHXP HELLO")
        else:
            control.sendall(packet)
        if read_reply(control) != header(2):
            raise RuntimeError("PHXP receiver did not return READY")

        connection_id = os.urandom(16)
        packet = header(3, connection_id, b"localhost")
        sent = control.sendmsg(
            [packet],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", [accepted.fileno()]),
                )
            ],
        )
        if sent <= 0 or (SEQPACKET and sent != len(packet)):
            raise RuntimeError("incomplete descriptor-bearing PHXP send")
        if sent < len(packet):
            control.sendall(packet[sent:])
        if read_reply(control) != header(4, connection_id):
            raise RuntimeError("PHXP receiver did not acknowledge adoption")


def check_peers(peers):
    readable, _, _ = select.select(peers, [], [], 0)
    for peer in readable:
        if not peer.recv(1, socket.MSG_PEEK):
            raise RuntimeError("premature stalled peer closure")
        raise RuntimeError("unexpected data on a stalled peer")


def serve_commands(peers):
    while True:
        # Observe peer closure between requests too, not merely at both ends
        # of the heartbeat window. In-VM peers are checked by the workload.
        select.select([sys.stdin, *peers], [], [], 1)
        check_peers(peers)
        if not select.select([sys.stdin], [], [], 0)[0]:
            continue
        line = sys.stdin.readline()
        if not line:
            raise RuntimeError("parent closed before STOP")
        command = line.rstrip("\n")
        if command == "STOP":
            print("STOPPED", flush=True)
            return
        fields = command.split()
        if len(fields) != 2 or fields[0] != "CHECK" or not fields[1].isdigit():
            raise RuntimeError("invalid parent command")
        print(f"CHECKED {fields[1]}", flush=True)


def main(in_vm_peers=False):
    path, count, blocking, lifetime = sys.argv[1:]
    count = int(count)
    lifetime = float(lifetime)
    if not 1 <= count <= 64 or blocking not in ("0", "1") or not 0 < lifetime <= 30:
        raise ValueError("invalid bounded sender arguments")
    signal.alarm(math.ceil(lifetime))

    with ExitStack() as resources:
        listener = resources.enter_context(socket.socket())
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(count)
        print(f"READY {os.getpid()} {listener.getsockname()[1]}", flush=True)
        peers = []

        for index in range(count):
            if not in_vm_peers:
                peer = resources.enter_context(
                    socket.create_connection(listener.getsockname(), timeout=2)
                )
                peer.setblocking(False)
                peers.append(peer)
            accepted, _ = listener.accept()
            with accepted:
                accepted.setblocking(blocking == "1")
                hand_off(accepted, path)
            print(f"ADOPTED {index + 1}", flush=True)

        listener.close()
        print(f"HOLDING {count}", flush=True)
        serve_commands(peers)


if __name__ == "__main__":
    main()
