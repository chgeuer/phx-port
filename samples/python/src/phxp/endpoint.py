from __future__ import annotations

import hashlib
import os
import platform
import socket
import stat
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

PRODUCTION_RUNTIME_ROOT = Path("/run/phx-port")
_VALID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")


class EndpointError(RuntimeError):
    pass


class IdentityKind(Enum):
    DEVELOPMENT = auto()
    PRODUCTION = auto()


@dataclass(frozen=True, slots=True)
class Identity:
    kind: IdentityKind
    value: str


@dataclass(frozen=True, slots=True)
class Endpoint:
    path: Path
    validate_runtime_root: bool = False


@dataclass(frozen=True, slots=True)
class EndpointIdentity:
    device: int
    inode: int


def development(project: str | os.PathLike[str]) -> Identity:
    try:
        canonical = Path(project).expanduser().resolve(strict=True)
    except OSError as error:
        raise EndpointError(f"canonicalize project path: {error}") from error
    return Identity(IdentityKind.DEVELOPMENT, str(canonical))


def production(workload_id: str) -> Identity:
    validate_workload_id(workload_id)
    return Identity(IdentityKind.PRODUCTION, workload_id)


def validate_workload_id(value: str) -> None:
    if (
        not 1 <= len(value) <= 128
        or value[0] not in _VALID_CHARS - frozenset("._-")
        or value[-1] not in _VALID_CHARS - frozenset("._-")
        or any(character not in _VALID_CHARS for character in value)
    ):
        raise EndpointError(
            "logical workload ID must contain 1 through 128 lowercase ASCII letters, "
            "digits, '.', '_', or '-', and start and end with a letter or digit"
        )


def validate_role(role: str) -> None:
    if not 1 <= len(role) <= 128 or any(character not in _VALID_CHARS for character in role):
        raise EndpointError(
            "role must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-'"
        )


def derive_endpoint(
    identity: Identity,
    role: str,
    runtime_override: str | os.PathLike[str] | None = None,
) -> Endpoint:
    validate_role(role)
    if identity.kind is IdentityKind.DEVELOPMENT:
        if not identity.value or not Path(identity.value).is_absolute():
            raise EndpointError("development identity must be a canonical absolute project path")
    elif identity.kind is IdentityKind.PRODUCTION:
        validate_workload_id(identity.value)
    else:
        raise EndpointError("unknown PHXP endpoint identity")

    if runtime_override is None:
        environment_override = os.environ.get("PHX_PORT_RUNTIME_DIR")
        runtime_override = environment_override if environment_override else None
    validate_runtime_root = identity.kind is IdentityKind.DEVELOPMENT
    if runtime_override is not None:
        root = Path(runtime_override)
    elif identity.kind is IdentityKind.PRODUCTION:
        if platform.system() != "Linux":
            raise EndpointError(
                "production PHXP endpoints require PHX_PORT_RUNTIME_DIR outside Linux"
            )
        root = PRODUCTION_RUNTIME_ROOT
    else:
        root = _development_runtime_root()
    path = root / "handoff" / f"{endpoint_hash(identity.value, role)}.sock"
    _validate_socket_path(path)
    return Endpoint(path, validate_runtime_root)


def endpoint_hash(identity: str, role: str) -> str:
    digest = hashlib.sha256()
    digest.update(identity.encode())
    digest.update(b"\0")
    digest.update(role.encode())
    return digest.hexdigest()


def ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise EndpointError(f"create PHXP directory {path}: {error}") from error
    try:
        info = path.lstat()
    except OSError as error:
        raise EndpointError(f"inspect PHXP directory {path}: {error}") from error
    if not stat.S_ISDIR(info.st_mode):
        raise EndpointError(f"PHXP directory {path} is not a directory")
    if info.st_uid != os.geteuid():
        raise EndpointError(f"PHXP directory {path} belongs to a different user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise EndpointError(f"PHXP directory {path} must not grant group or other permissions")


def prepare_endpoint(endpoint: Endpoint) -> None:
    path = endpoint.path
    _validate_socket_path(path)
    if not path.is_absolute() or path.parent == Path(path.anchor):
        raise EndpointError("PHXP endpoint must have an absolute private parent directory")
    if endpoint.validate_runtime_root:
        ensure_private_directory(path.parent.parent)
    ensure_private_directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise EndpointError(f"inspect PHXP endpoint {path}: {error}") from error
    if not stat.S_ISSOCK(info.st_mode):
        raise EndpointError(f"refusing to replace non-socket PHXP path {path}")
    if endpoint_is_live(path):
        raise EndpointError(f"another PHXP receiver is already listening at {path}")
    try:
        current = path.lstat()
    except OSError as error:
        raise EndpointError(f"reinspect stale PHXP endpoint {path}: {error}") from error
    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        raise EndpointError(f"PHXP endpoint {path} changed during stale-socket inspection")
    try:
        path.unlink()
    except OSError as error:
        raise EndpointError(f"remove stale PHXP endpoint {path}: {error}") from error


def inspect_socket(path: Path, *, require_mode: bool) -> EndpointIdentity:
    try:
        info = path.lstat()
    except OSError as error:
        raise EndpointError(f"inspect PHXP endpoint {path}: {error}") from error
    if not stat.S_ISSOCK(info.st_mode):
        raise EndpointError(f"PHXP endpoint {path} is not a socket")
    if info.st_uid != os.geteuid():
        raise EndpointError(f"PHXP endpoint {path} belongs to a different user")
    if require_mode and stat.S_IMODE(info.st_mode) != 0o600:
        raise EndpointError(f"PHXP endpoint {path} must have mode 0600")
    return EndpointIdentity(info.st_dev, info.st_ino)


def remove_endpoint_if_owned(path: Path, identity: EndpointIdentity) -> None:
    try:
        info = path.lstat()
    except OSError:
        return
    if (
        stat.S_ISSOCK(info.st_mode)
        and info.st_dev == identity.device
        and info.st_ino == identity.inode
    ):
        with suppress(OSError):
            path.unlink()


def endpoint_is_live(path: Path) -> bool:
    control_type = socket.SOCK_SEQPACKET if platform.system() == "Linux" else socket.SOCK_STREAM
    control = socket.socket(socket.AF_UNIX, control_type)
    try:
        control.settimeout(0.2)
        control.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        control.close()


def _development_runtime_root() -> Path:
    system = platform.system()
    if system == "Linux":
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if not runtime:
            raise EndpointError("XDG_RUNTIME_DIR is unavailable; set it or specify a PHXP endpoint")
        return Path(runtime) / "phx-port"
    if system == "Darwin":
        return Path(f"/tmp/phx-port-{os.geteuid()}")
    raise EndpointError(f"PHXP requires Linux or macOS, not {system}")


def _validate_socket_path(path: Path) -> None:
    system = platform.system()
    maximum = 107 if system == "Linux" else 103 if system == "Darwin" else 0
    if not maximum:
        raise EndpointError(f"PHXP requires Linux or macOS, not {system}")
    if len(os.fsencode(path)) > maximum:
        raise EndpointError(f"PHXP endpoint path is too long: {path}")
