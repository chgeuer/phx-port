from __future__ import annotations

import os
import platform
import socket
import stat
from pathlib import Path

import pytest

from phxp.endpoint import (
    Endpoint,
    EndpointError,
    Identity,
    IdentityKind,
    derive_endpoint,
    development,
    endpoint_hash,
    ensure_private_directory,
    prepare_endpoint,
    production,
    validate_role,
    validate_workload_id,
)
from phxp.listener import PHXPListener


def test_endpoint_derivation_matches_authority() -> None:
    runtime = Path("/runtime")
    development_endpoint = derive_endpoint(
        Identity(IdentityKind.DEVELOPMENT, "/srv/contoso"),
        "https",
        runtime,
    )
    assert development_endpoint.path == (
        runtime / "handoff" / f"{endpoint_hash('/srv/contoso', 'https')}.sock"
    )
    assert development_endpoint.validate_runtime_root

    production_endpoint = derive_endpoint(production("contoso-web"), "https", runtime)
    assert production_endpoint.path == (
        runtime / "handoff" / f"{endpoint_hash('contoso-web', 'https')}.sock"
    )
    assert not production_endpoint.validate_runtime_root


def test_production_endpoint_requires_runtime_override_outside_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("phxp.endpoint.platform.system", lambda: "Darwin")
    with pytest.raises(EndpointError, match="require PHX_PORT_RUNTIME_DIR"):
        derive_endpoint(production("contoso-web"), "https")
    endpoint = derive_endpoint(production("contoso-web"), "https", "/service/runtime")
    assert endpoint.path == (
        Path("/service/runtime") / "handoff" / f"{endpoint_hash('contoso-web', 'https')}.sock"
    )


def test_development_identity_canonicalizes_project(short_path: Path) -> None:
    actual = short_path / "actual"
    actual.mkdir()
    link = short_path / "link"
    link.symlink_to(actual)
    assert development(link).value == str(actual)


def test_endpoint_security_live_and_stale_handling(short_path: Path) -> None:
    private = short_path / "private"
    private.mkdir(mode=0o700)
    endpoint = Endpoint(private / "receiver.sock")
    listener = PHXPListener(endpoint)
    try:
        info = endpoint.path.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        with pytest.raises(EndpointError, match="already listening"):
            PHXPListener(endpoint)
    finally:
        listener.close()
    assert not endpoint.path.exists()

    endpoint.path.write_text("not a socket")
    with pytest.raises(EndpointError, match="non-socket"):
        PHXPListener(endpoint)


def test_stale_socket_is_replaced(short_path: Path) -> None:
    private = short_path / "private"
    private.mkdir(mode=0o700)
    endpoint = Endpoint(private / "receiver.sock")
    control_type = socket.SOCK_SEQPACKET if platform.system() == "Linux" else socket.SOCK_STREAM
    stale = socket.socket(socket.AF_UNIX, control_type)
    stale.bind(str(endpoint.path))
    stale.listen(1)
    stale.close()

    listener = PHXPListener(endpoint)
    listener.close()
    assert not endpoint.path.exists()


def test_open_and_symlinked_directories_are_rejected(short_path: Path) -> None:
    open_directory = short_path / "open"
    open_directory.mkdir(mode=0o755)
    os.chmod(open_directory, 0o755)
    with pytest.raises(EndpointError, match="group or other"):
        ensure_private_directory(open_directory)

    actual = short_path / "actual"
    actual.mkdir(mode=0o700)
    runtime_link = short_path / "runtime"
    runtime_link.symlink_to(actual)
    endpoint = Endpoint(runtime_link / "handoff" / "receiver.sock", True)
    with pytest.raises(EndpointError, match="not a directory"):
        prepare_endpoint(endpoint)
    assert not (actual / "handoff").exists()


def test_identity_validation() -> None:
    for value in ("a", "contoso-web", "api.v2_worker"):
        validate_workload_id(value)
        validate_role(value)
    for value in ("", "-contoso", "contoso-", "Contoso", "../contoso"):
        with pytest.raises(EndpointError):
            validate_workload_id(value)
    validate_role("-https")
