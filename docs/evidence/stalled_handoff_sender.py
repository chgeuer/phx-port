"""Hands off descriptors from stalled clients, exactly as phx-port's ingress does.

phx-port sets the accepted client socket to blocking (proxy.rs set_nonblocking(false))
immediately before SCM_RIGHTS delivery. O_NONBLOCK lives on the open file
description, which SCM_RIGHTS shares with the receiver, so the workload imports a
blocking socket. Each stalled client then parks one normal BEAM scheduler thread
inside inet_drv's synchronous recv().

Usage: stalled_handoff_sender.py <endpoint_path> <count> <blocking:0|1> <hold_seconds>
"""

import array
import socket
import struct
import sys
import time


def header(kind, connection_id=b"\0" * 16, sni=b""):
    return struct.pack(
        "!4sBBH16sIQHH", b"PHXP", 1, kind, 0, connection_id, 0, 0, len(sni), 0
    ) + sni


path = sys.argv[1]
count = int(sys.argv[2])
blocking = sys.argv[3] == "1"
hold_seconds = float(sys.argv[4])

held = []

for index in range(count):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    # A stalled public client: completes the TCP handshake, then sends nothing.
    stalled_client = socket.create_connection(listener.getsockname(), timeout=3)
    accepted, _ = listener.accept()

    # This is the line that matters: it mirrors phx-port's ingress.
    accepted.setblocking(blocking)

    control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    control.settimeout(5)
    control.connect(path)
    control.sendall(header(1))
    assert control.recv(512) == header(2)
    connection_id = (index + 1).to_bytes(16, "big")
    control.sendmsg(
        [header(3, connection_id, b"localhost")],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [accepted.fileno()]))],
    )
    assert control.recv(512) == header(4, connection_id)
    accepted.close()
    control.close()
    held.append((listener, stalled_client))
    print(f"handed off stalled client {index + 1} (blocking={blocking})", flush=True)

time.sleep(hold_seconds)
