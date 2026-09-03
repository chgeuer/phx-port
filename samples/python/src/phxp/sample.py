from __future__ import annotations

import argparse
import ipaddress
import os
import ssl
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from .endpoint import Endpoint, derive_endpoint, development, production
from .uvicorn import PHXPUvicornServer


def create_app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def shared_pipeline(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers["X-PHXP-Pipeline"] = "fastapi-starlette"
        return response

    @app.get("/")
    async def index(request: Request) -> dict[str, object]:
        return {
            "message": "phxp Python handoff example",
            "method": request.method,
            "path": request.url.path,
            "client": list(request.scope["client"]) if request.scope.get("client") else None,
            "server": list(request.scope["server"]) if request.scope.get("server") else None,
            "scheme": request.scope["scheme"],
            "http_version": request.scope["http_version"],
        }

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    return app


def main() -> None:
    arguments = _arguments()
    host, port = _parse_address(arguments.https)
    if not ipaddress.ip_address(host).is_loopback:
        raise SystemExit("ordinary HTTPS listener must use an explicit loopback address")
    endpoint = _endpoint(arguments)
    config = uvicorn.Config(
        create_app(),
        host=host,
        port=port,
        ssl_certfile=arguments.cert,
        ssl_keyfile=arguments.key,
        http="h11",
    )
    config.load()
    assert config.ssl is not None
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    server = PHXPUvicornServer(config, endpoint)
    server.run()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FastAPI/Uvicorn PHXP v1 sample")
    parser.add_argument(
        "--https",
        default=_environment("PHXP_HTTPS_ADDR", "127.0.0.1:8443"),
        help="ordinary loopback HTTPS listen address",
    )
    parser.add_argument("--cert", default=os.environ.get("PHXP_TLS_CERT"), required=False)
    parser.add_argument("--key", default=os.environ.get("PHXP_TLS_KEY"), required=False)
    parser.add_argument("--project", default=_environment("PHXP_PROJECT", "."))
    parser.add_argument("--workload-id", default=os.environ.get("PHXP_WORKLOAD_ID"))
    parser.add_argument("--role", default=_environment("PHXP_ROLE", "https"))
    parser.add_argument("--handoff-socket", default=os.environ.get("PHXP_HANDOFF_SOCKET"))
    arguments = parser.parse_args()
    if not arguments.cert or not arguments.key:
        parser.error("--cert/PHXP_TLS_CERT and --key/PHXP_TLS_KEY are required")
    return arguments


def _endpoint(arguments: argparse.Namespace) -> Endpoint:
    if arguments.handoff_socket:
        path = Path(arguments.handoff_socket).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return Endpoint(path)
    identity = (
        production(arguments.workload_id)
        if arguments.workload_id
        else development(arguments.project)
    )
    return derive_endpoint(identity, arguments.role)


def _parse_address(value: str) -> tuple[str, int]:
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or value[closing + 1 : closing + 2] != ":":
            raise SystemExit(f"invalid HTTPS address: {value}")
        host, raw_port = value[1:closing], value[closing + 2 :]
    else:
        host, separator, raw_port = value.rpartition(":")
        if not separator:
            raise SystemExit(f"invalid HTTPS address: {value}")
    try:
        address = ipaddress.ip_address(host)
        port = int(raw_port)
    except ValueError as error:
        raise SystemExit(f"invalid HTTPS address: {value}") from error
    if not 1 <= port <= 65535:
        raise SystemExit(f"invalid HTTPS port: {port}")
    return str(address), port


def _environment(name: str, fallback: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or fallback
