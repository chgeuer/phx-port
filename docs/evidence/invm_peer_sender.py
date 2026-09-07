"""Out-of-VM PHXP sender whose public peer is a client inside the workload VM.

Listens, prints the port, then hands off each accepted descriptor. The workload
connects to that port itself, so the handed-off socket's peer lives in the same
BEAM as the importing workload. This isolates the in-VM-peer variable from the
sender-location variable.

Usage: invm_peer_sender.py <endpoint_path> <count> <blocking:0|1> <hold_seconds>
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

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(16)
print(f"PORT {listener.getsockname()[1]}", flush=True)

held = []
for index in range(count):
    accepted, _ = listener.accept()
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
    print(f"handed off {index + 1} (blocking={blocking})", flush=True)

time.sleep(hold_seconds)
