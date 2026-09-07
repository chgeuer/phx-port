import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time


BASE = Path.cwd()
BIN = BASE / "runtime-target/debug/phx-port"
STATE = BASE / "s"
RUNTIME = BASE / "r"
CONFIG = BASE / "runtime-audit.toml"
CONTROL = RUNTIME / "control/control.sock"


def emit(**values):
    print(json.dumps(values), flush=True)


def unused_address():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()


def prepare():
    for path, mode in [(STATE, 0o700), (RUNTIME, 0o750)]:
        path.mkdir(mode=mode)
        path.chmod(mode)
    (RUNTIME / "handoff").mkdir(mode=0o700)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:P-256", "-nodes", "-keyout", "s/key.pem",
         "-out", "s/cert.pem", "-days", "2", "-subj", "/CN=a.audit.test",
         "-addext", "subjectAltName=DNS:a.audit.test,DNS:b.audit.test"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=5,
    )
    (STATE / "key.pem").chmod(0o600)
    (STATE / "cert.pem").chmod(0o600)


def configure(routes, assignments):
    text = "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n"
    for host, workload, required in routes:
        text += (
            f'\n[ingress.hosts."{host}"]\nworkload = "{workload}"\n'
            f'role = "https"\nrequired = {str(required).lower()}\n'
        )
    CONFIG.write_text(text)
    CONFIG.chmod(0o600)
    ports = "[ports]\n"
    for workload, port in assignments:
        ports += f"\n[ports.{workload}]\nhttps = {port}\n"
    (STATE / "ports.toml").write_text(ports)
    (STATE / "ports.toml").chmod(0o600)


def control():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.8)
        sock.connect(str(CONTROL))
        sock.sendall(b"STATUS JSON")
        sock.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return json.loads(data)
            data += chunk


def await_status(predicate, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            current = control()
            if predicate(current):
                return current
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
    raise AssertionError("daemon state did not reach expected condition")


class Daemon:
    def __init__(self, tag):
        self.address = unused_address()
        self.log_path = BASE / f"runtime-{tag}.stderr"
        self.log = self.log_path.open("wb")
        env = dict(os.environ)
        env.update(
            PHX_PORT_CONFIG=str(STATE / "ports.toml"),
            PHX_PORT_RUNTIME_DIR=str(RUNTIME),
            SSL_CERT_FILE=str(STATE / "cert.pem"),
            TMPDIR=str(BASE / "runtime-compiler"),
        )
        for key in ["PHX_PORT_INGRESS_CONFIG", "XDG_RUNTIME_DIR",
                    "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]:
            env.pop(key, None)
        self.child = subprocess.Popen(
            [str(BIN), "daemon", "--listen", f"127.0.0.1:{self.address[1]}",
             "--ingress-config", str(CONFIG),
             "--active-connections", "32", "--pre-routing-connections", "32",
             "--relay-connections", "24", "--handoff-negotiations", "4",
             "--accepts-per-second", "100", "--accept-burst", "100",
             "--source-accepts-per-second", "100", "--source-accept-burst", "100",
             "--source-pre-routing-connections", "32", "--task-budget", "128"],
            env=env, stdout=subprocess.DEVNULL, stderr=self.log,
        )
        try:
            await_status(lambda status: status["live"])
        except BaseException:
            self.close()
            raise AssertionError(self.log_path.read_text())

    def close(self):
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGINT)
            try:
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=3)
        self.log.close()


class Backend:
    def __init__(self, enabled=True, silent=False):
        self.enabled = enabled
        self.silent = silent
        self.stop = threading.Event()
        self.accepted = []
        self.completed_tls = 0
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(32)
        self.listener.settimeout(0.05)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain("s/cert.pem", "s/key.pem")
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=12)
        self.thread = threading.Thread(target=self.accept_loop)
        self.thread.start()

    def accept_loop(self):
        while not self.stop.is_set():
            try:
                stream, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted.append(time.monotonic())
            if not self.enabled:
                stream.close()
            else:
                self.pool.submit(self.serve, stream)

    def serve(self, stream):
        try:
            stream.settimeout(0.5)
            if self.silent:
                # One bounded silent TLS workload operation, not a public load generator.
                self.stop.wait(0.6)
                return
            with self.context.wrap_socket(stream, server_side=True) as tls:
                self.completed_tls += 1
                while not self.stop.is_set():
                    try:
                        data = tls.recv(1024)
                    except socket.timeout:
                        continue
                    if not data:
                        return
                    tls.sendall(data)
        except (OSError, ssl.SSLError):
            pass
        finally:
            stream.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        self.pool.shutdown(wait=True)


def connect(address, host="a.audit.test", timeout=1):
    ctx = ssl.create_default_context(cafile=str(STATE / "cert.pem"))
    stream = socket.create_connection(address, timeout=timeout)
    stream.settimeout(timeout)
    try:
        return ctx.wrap_socket(stream, server_hostname=host)
    except BaseException:
        stream.close()
        raise


def echo(stream, data):
    stream.sendall(data)
    return stream.recv(len(data)) == data


def signal_proof():
    backend = Backend()
    configure([("a.audit.test", "web", True)], [("web", backend.port)])
    results = []
    try:
        for signum, tag in [(signal.SIGTERM, "term"), (signal.SIGINT, "int")]:
            daemon = Daemon(tag)
            peer = None
            try:
                await_status(lambda status: status["ready"])
                peer = connect(daemon.address)
                assert echo(peer, b"before")
                start = time.monotonic()
                daemon.child.send_signal(signum)
                time.sleep(0.12)
                try:
                    after = echo(peer, b"after")
                except (OSError, ssl.SSLError):
                    after = False
                peer.close()
                peer = None
                code = daemon.child.wait(timeout=3)
                daemon.log.flush()
                results.append(dict(
                    signal=tag, return_code=code,
                    existing_relay_echo_after_signal=after,
                    elapsed_ms=round((time.monotonic() - start) * 1000, 1),
                    shutdown_event="event=ingress_shutdown" in daemon.log_path.read_text(),
                ))
            finally:
                if peer is not None:
                    peer.close()
                daemon.close()
        assert results[0]["return_code"] == -signal.SIGTERM
        assert not results[0]["existing_relay_echo_after_signal"]
        assert not results[0]["shutdown_event"]
        assert results[1]["return_code"] == 0
        assert results[1]["existing_relay_echo_after_signal"]
        assert results[1]["shutdown_event"]
        emit(experiment="signal_drain", results=results)
    finally:
        backend.close()


def cache_lock_proof():
    first = Backend()
    second = Backend(enabled=False)
    daemon = peer = None
    configure(
        [("a.audit.test", "web", True), ("b.audit.test", "other", False)],
        [("web", first.port), ("other", second.port)],
    )
    try:
        daemon = Daemon("cache-lock")
        await_status(lambda status: status["ready"] and status["active_routes"] == 1)
        peer = connect(daemon.address, timeout=0.5)
        assert echo(peer, b"before")
        second.enabled = True
        with (STATE / "routes.toml.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as clients:
                def attempt(host):
                    try:
                        with connect(daemon.address, host, timeout=0.5) as stream:
                            return echo(stream, b"test")
                    except (OSError, ssl.SSLError):
                        return False

                started = time.monotonic()
                futures = [clients.submit(attempt, "b.audit.test")]
                deadline = time.monotonic() + 2
                while second.completed_tls == 0:
                    assert time.monotonic() < deadline, "new route proof did not complete"
                    time.sleep(0.01)
                time.sleep(0.1)
                futures += [clients.submit(attempt, "a.audit.test") for _ in range(8)]
                time.sleep(0.2)
                direct = connect(("127.0.0.1", first.port), timeout=0.5)
                assert echo(direct, b"direct")
                direct.close()
                peer.sendall(b"during")
                try:
                    response = peer.recv(6)
                    stalled = False
                except socket.timeout:
                    response = b""
                    stalled = True
                try:
                    control()
                    status_stalled = False
                except (OSError, ValueError):
                    status_stalled = True
                tasks = Path(f"/proc/{daemon.child.pid}/task")
                wait_channels = {}
                for task in tasks.iterdir():
                    try:
                        name = (task / "comm").read_text().strip()
                        wait = (task / "wchan").read_text().strip()
                        wait_channels.setdefault(name, []).append(wait)
                    except FileNotFoundError:
                        pass
                fcntl.flock(lock, fcntl.LOCK_UN)
                held_ms = round((time.monotonic() - started) * 1000, 1)
                client_results = [future.result(timeout=2) for future in futures]
            peer.settimeout(2)
            if not response:
                response = peer.recv(6)
            assert response == b"during", response
            assert echo(peer, b"recovered")
            assert stalled and status_stalled, (stalled, status_stalled)
            emit(
                experiment="derived_cache_lock",
                lock_held_ms=held_ms,
                unrelated_live_relay_stalled=stalled,
                status_stalled=status_stalled,
                direct_workload_healthy=True,
                warmed_route_clients_succeeded=sum(client_results[1:]),
                warmed_route_clients_attempted=8,
                relay_recovered_after_unlock=True,
                daemon_wait_channels=wait_channels,
            )
        peer.close()
        peer = None
        await_status(lambda status: status["admission"]["active_connections"]["in_use"] == 0)
    finally:
        if peer is not None:
            peer.close()
        if daemon is not None:
            daemon.close()
        first.close()
        second.close()


def serial_shutdown_proof():
    count = 8
    backend = Backend(silent=True)
    daemon = None
    configure(
        [(f"r{index}.audit.test", "web", False) for index in range(count)],
        [("web", backend.port)],
    )
    try:
        daemon = Daemon("serial-shutdown")
        end = time.monotonic() + 3
        while not backend.accepted:
            assert time.monotonic() < end
            time.sleep(0.005)
        start = time.monotonic()
        daemon.child.send_signal(signal.SIGINT)
        code = daemon.child.wait(timeout=5)
        elapsed = time.monotonic() - start
        post_signal = sum(at > start for at in backend.accepted)
        assert code == 0
        assert len(backend.accepted) == count, backend.accepted
        assert post_signal >= count - 2
        assert elapsed > 1
        emit(
            experiment="serial_reconciler_shutdown",
            declared_names=count, ingress_connections=0,
            total_workload_probes=len(backend.accepted),
            probes_started_after_shutdown=post_signal,
            stop_elapsed_ms=round(elapsed * 1000, 1),
            daemon_exit_code=code,
        )
    finally:
        if daemon is not None:
            daemon.close()
        backend.close()


def mixed_control_response_proof():
    count = 64
    active_hosts = [
        f"a{index:04}." + ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 55])
        for index in range(count)
    ]
    inactive_hosts = [
        f"z{index:04}." + ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 55])
        for index in range(count)
    ]
    workload = "w" + "a" * 127
    missing_workload = "m" + "b" * 127
    role = "r" * 128
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:P-256", "-nodes", "-keyout", "s/key.pem",
         "-out", "s/cert.pem", "-days", "2", "-subj", "/CN=a.audit.test",
         "-addext", "subjectAltName=" + ",".join(f"DNS:{host}" for host in active_hosts)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
    )
    backend = Backend()
    daemon = None
    try:
        text = "[ingress]\nmode = \"public\"\nunknown_sni = \"reject\"\n"
        for hosts, owner, required in [
            (active_hosts, workload, True), (inactive_hosts, missing_workload, False)
        ]:
            for host in hosts:
                text += (
                    f'\n[ingress.hosts."{host}"]\nworkload = "{owner}"\n'
                    f'role = "{role}"\nrequired = {str(required).lower()}\n'
                )
        CONFIG.write_text(text)
        CONFIG.chmod(0o600)
        (STATE / "ports.toml").write_text(
            f"[ports]\n\n[ports.{workload}]\n{role} = {backend.port}\n"
        )
        (STATE / "ports.toml").chmod(0o600)
        daemon = Daemon("mixed-control")
        status = await_status(
            lambda value: value["active_routes"] == count and value["degraded_route_count"] == count,
            timeout=15,
        )
        wire_size = len(json.dumps(status, separators=(",", ":")).encode()) + 1
        env = dict(os.environ)
        env.update(
            PHX_PORT_INGRESS_CONFIG=str(CONFIG),
            PHX_PORT_CONFIG=str(STATE / "ports.toml"),
            PHX_PORT_RUNTIME_DIR=str(RUNTIME),
        )
        outcomes = []
        for command in [["status", "--json"], ["check", "--live"], ["check", "--ready"]]:
            result = subprocess.run(
                [str(BIN), "proxy", *command], env=env, capture_output=True, timeout=3,
            )
            error = result.stderr.decode().strip()
            assert result.returncode != 0 and "65536 byte limit" in error, (command, error)
            outcomes.append(dict(command=command, exit_code=result.returncode, stderr=error))
        assert status["live"] and status["ready"] and wire_size > 65536
        emit(
            experiment="mixed_control_response", active_routes=count, degraded_routes=count,
            hostname_length=len(active_hosts[0]), workload_length=len(workload), role_length=len(role),
            status_wire_bytes=wire_size, response_limit=65536,
            actual_live=status["live"], actual_ready=status["ready"], cli_results=outcomes,
        )
    finally:
        if daemon is not None:
            daemon.close()
        backend.close()


if __name__ == "__main__":
    prepare()
    try:
        signal_proof()
        cache_lock_proof()
        serial_shutdown_proof()
        mixed_control_response_proof()
    finally:
        shutil.rmtree(STATE)
        shutil.rmtree(RUNTIME)
        CONFIG.unlink(missing_ok=True)
