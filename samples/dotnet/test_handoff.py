#!/usr/bin/env python3
"""Send one connected TCP socket through PHXP and verify TLS/HTTP on it."""

import argparse
import array
import os
import socket
import ssl
import struct
import uuid


def packet(message_type, connection_id=b"\0" * 16, sni=b""):
    return struct.pack(
        "!4sBBH16sIQHH",
        b"PHXP",
        1,
        message_type,
        0,
        connection_id,
        0,
        0,
        len(sni),
        0,
    ) + sni


parser = argparse.ArgumentParser()
parser.add_argument("endpoint")
parser.add_argument("--sni", default="localhost")
args = parser.parse_args()

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
client = socket.create_connection(listener.getsockname())
server, expected_peer = listener.accept()
listener.close()

control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
control.connect(args.endpoint)
control.sendall(packet(1))
ready = control.recv(512)
assert ready == packet(2), f"unexpected READY: {ready!r}"

connection_id = uuid.uuid4().bytes
control.sendmsg(
    [packet(3, connection_id, args.sni.encode())],
    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [server.fileno()]))],
)
server.close()
response = control.recv(512)
assert response == packet(4, connection_id), f"unexpected ADOPTED: {response!r}"
control.close()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
with context.wrap_socket(client, server_hostname=args.sni) as tls:
    tls.sendall(
        f"GET /handoff-test HTTP/1.1\r\nHost: {args.sni}\r\nConnection: close\r\n\r\n".encode()
    )
    chunks = []
    while chunk := tls.recv(4096):
        chunks.append(chunk)

http_response = b"".join(chunks)
assert http_response.startswith(b"HTTP/1.1 200 OK\r\n"), http_response
assert b"phxp .NET 10 handoff example" in http_response, http_response
assert b"listener=phxp-handoff-https" in http_response, http_response
assert f"peer={expected_peer[0]}:{expected_peer[1]}".encode() in http_response, http_response
print(http_response.decode())
