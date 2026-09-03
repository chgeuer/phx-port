from __future__ import annotations

import asyncio
import datetime
import json
import ssl
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from phxp.endpoint import Endpoint
from phxp.protocol import Message, MessageType
from phxp.sample import create_app
from phxp.uvicorn import PHXPUvicornServer

from .helpers import send_handoff, tcp_pair


def test_direct_and_phxp_tls_share_fastapi_pipeline(short_path: Path) -> None:
    asyncio.run(_exercise_shared_pipeline(short_path))


async def _exercise_shared_pipeline(short_path: Path) -> None:
    certificate, key = _certificate(short_path)
    private = short_path / "private"
    private.mkdir(mode=0o700)
    endpoint = Endpoint(private / "receiver.sock")
    config = uvicorn.Config(
        create_app(),
        host="127.0.0.1",
        port=0,
        ssl_certfile=str(certificate),
        ssl_keyfile=str(key),
        http="h11",
        access_log=False,
        log_level="warning",
    )
    config.load()
    assert config.ssl is not None
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    server = PHXPUvicornServer(config, endpoint, handoff_queue_size=2)
    serve_task = asyncio.create_task(server.serve())
    await _wait_until_started(server)

    client_context = ssl.create_default_context()
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    direct_address = server.direct_addresses[0]
    assert isinstance(direct_address, tuple)
    direct_reader, direct_writer = await asyncio.open_connection(
        direct_address[0],
        direct_address[1],
        ssl=client_context,
        server_hostname="example.test",
    )
    direct_headers, direct_body = await _exchange(direct_reader, direct_writer)

    public, raw_client, accepted = await asyncio.to_thread(tcp_pair)
    handoff_peer = raw_client.getsockname()
    handoff_local = public.getsockname()
    connection_id = bytes.fromhex("44" * 16)
    response = await asyncio.to_thread(
        send_handoff,
        str(endpoint.path),
        accepted,
        Message(
            MessageType.HANDOFF,
            connection_id,
            peeked_length=1,
            accepted_at_ns=99,
            requested_sni="example.test",
        ),
    )
    assert response == Message(MessageType.ADOPTED, connection_id)
    handoff_reader, handoff_writer = await asyncio.open_connection(
        sock=raw_client,
        ssl=client_context,
        server_hostname="example.test",
    )
    handoff_headers, handoff_body = await _exchange(handoff_reader, handoff_writer)
    public.close()

    try:
        assert direct_headers["x-phxp-pipeline"] == "fastapi-starlette"
        assert handoff_headers["x-phxp-pipeline"] == "fastapi-starlette"
        assert direct_body["message"] == handoff_body["message"]
        assert direct_body["method"] == handoff_body["method"] == "GET"
        assert direct_body["path"] == handoff_body["path"] == "/"
        assert direct_body["scheme"] == handoff_body["scheme"] == "https"
        assert direct_body["http_version"] == handoff_body["http_version"] == "1.1"
        assert tuple(handoff_body["client"]) == handoff_peer
        assert tuple(handoff_body["server"]) == handoff_local
    finally:
        server.should_exit = True
        await asyncio.wait_for(serve_task, timeout=5.0)


async def _wait_until_started(server: PHXPUvicornServer) -> None:
    for _ in range(200):
        if server.started:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("Uvicorn server did not start")


async def _exchange(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> tuple[dict[str, str], dict[str, object]]:
    writer.write(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=3.0)
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    assert lines[0] == "HTTP/1.1 200 OK"
    headers = {
        name.lower(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])
    }
    return headers, json.loads(body)


def _certificate(short_path: Path) -> tuple[Path, Path]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), False)
        .sign(private_key, algorithm=None)
    )
    certificate_path = short_path / "certificate.pem"
    key_path = short_path / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path
