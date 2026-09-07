import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import time

import runtime_audit as harness


class QueueDaemon(harness.Daemon):
    def __init__(self, tag, active, handoffs):
        self.address = harness.unused_address()
        self.log_path = harness.BASE / f"runtime-{tag}.stderr"
        self.log = self.log_path.open("wb")
        env = dict(os.environ)
        env.update(
            PHX_PORT_CONFIG=str(harness.STATE / "ports.toml"),
            PHX_PORT_RUNTIME_DIR="r",
            XDG_RUNTIME_DIR=str(harness.BASE),
            SSL_CERT_FILE=str(harness.STATE / "cert.pem"),
            TMPDIR=str(harness.BASE / "runtime-compiler"),
        )
        for key in ["PHX_PORT_INGRESS_CONFIG", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]:
            env.pop(key, None)
        self.child = subprocess.Popen(
            [str(harness.BIN), "daemon", "--listen", f"127.0.0.1:{self.address[1]}",
             "--active-connections", str(active), "--pre-routing-connections", str(active),
             "--relay-connections", str(active), "--handoff-negotiations", str(handoffs),
             "--accepts-per-second", "100", "--accept-burst", "100",
             "--source-accepts-per-second", "100", "--source-accept-burst", "100",
             "--source-pre-routing-connections", str(active), "--task-budget", "128"],
            env=env, stdout=subprocess.DEVNULL, stderr=self.log,
        )
        try:
            harness.await_status(lambda status: status["active_routes"] > 0)
        except BaseException:
            self.close()
            raise AssertionError(self.log_path.read_text())


def client_hello():
    context = ssl.create_default_context(cafile=str(harness.STATE / "cert.pem"))
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname="a.audit.test")
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def resource_snapshot(pid):
    base = Path(f"/proc/{pid}")
    waits = {}
    for task in (base / "task").iterdir():
        try:
            name = (task / "comm").read_text().strip()
            wait = (task / "wchan").read_text().strip()
            waits.setdefault(name, []).append(wait)
        except FileNotFoundError:
            pass
    return dict(fds=len(list((base / "fd").iterdir())), wait_channels=waits)


def run_case(active, request_shutdown):
    handoffs = 2
    backend = harness.Backend()
    registry = harness.STATE / "ports.toml"
    project = str(harness.STATE)
    registry.write_text(f'[ports."{project}"]\nhttps = {backend.port}\n')
    registry.chmod(0o600)
    digest = hashlib.sha256(project.encode() + b"\0https").hexdigest()
    endpoint = Path("r/handoff") / f"{digest}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(str(endpoint))
    endpoint.chmod(0o600)
    listener.listen(1)
    fillers = []
    peers = []
    daemon = None
    try:
        for _ in range(2):
            filler = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            filler.settimeout(0.2)
            filler.connect(str(endpoint))
            fillers.append(filler)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as check:
            check.setblocking(False)
            assert check.connect_ex(str(endpoint)) == 11, "fixture queue is not full"

        daemon = QueueDaemon(f"handoff-queue-{active}", active, handoffs)
        baseline = resource_snapshot(daemon.child.pid)
        for _ in range(handoffs):
            peer = socket.create_connection(daemon.address, timeout=0.5)
            peer.sendall(client_hello())
            peers.append(peer)
        harness.await_status(
            lambda status: status["admission"]["handoff_negotiations"]["in_use"] == handoffs
        )
        for peer in peers:
            peer.close()
        peers.clear()
        closed_at = time.monotonic()
        time.sleep(3)
        status = harness.control()
        admission = status["admission"]
        assert admission["active_connections"]["in_use"] == handoffs
        assert admission["pre_routing_connections"]["in_use"] == handoffs
        assert admission["handoff_negotiations"]["in_use"] == handoffs
        assert status["activity"]["queued_connections"] == 0
        occupied = resource_snapshot(daemon.child.pid)

        if active == handoffs:
            rejected_before = status["counters"]["rejected_global_capacity"]
            with socket.create_connection(daemon.address, timeout=0.5) as rejected:
                rejected.sendall(client_hello())
                try:
                    assert rejected.recv(1) == b""
                except ConnectionResetError:
                    pass
            harness.await_status(
                lambda current: current["counters"]["rejected_global_capacity"] > rejected_before
            )
            other_service = "global_capacity_rejection"
        else:
            with harness.connect(daemon.address, timeout=1) as relayed:
                assert harness.echo(relayed, b"bounded-fallback")
            after = harness.await_status(
                lambda current: current["counters"]["handoff_capacity_skips"] >= 1
            )
            assert after["counters"]["relayed_connections"] >= 1
            other_service = "relay_fallback_succeeds"

        draining = None
        if request_shutdown:
            daemon.child.send_signal(signal.SIGINT)
            harness.await_status(lambda current: current["draining"])
            time.sleep(0.3)
            draining = harness.control()["admission"]
            assert daemon.child.poll() is None
            assert draining["active_connections"]["in_use"] == handoffs
            assert draining["handoff_negotiations"]["in_use"] == handoffs

        blocked_ms = round((time.monotonic() - closed_at) * 1000, 1)
        released_at = time.monotonic()
        listener.close()
        for filler in fillers:
            filler.close()
        fillers.clear()
        if request_shutdown:
            assert daemon.child.wait(timeout=3) == 0
        else:
            harness.await_status(
                lambda current: current["admission"]["active_connections"]["in_use"] == 0
            )
        harness.emit(
            experiment="saturated_handoff_accept_queue",
            profile="development_relative_runtime_same_ingress_state_machine",
            configured_active=active,
            configured_handoffs=handoffs,
            listener_backlog=1,
            queue_fillers=2,
            closed_public_peers=handoffs,
            minimum_blocked_after_peer_close_ms=blocked_ms,
            retained_admission=admission,
            queued_blocking_jobs=status["activity"]["queued_connections"],
            independent_connection_result=other_service,
            draining_admission=draining,
            recovery_after_listener_release_ms=round((time.monotonic() - released_at) * 1000, 1),
            baseline_resources=baseline,
            blocked_resources=occupied,
        )
    finally:
        listener.close()
        for filler in fillers:
            filler.close()
        for peer in peers:
            peer.close()
        if daemon is not None:
            daemon.close()
        endpoint.unlink(missing_ok=True)
        backend.close()
        (harness.STATE / "routes.toml").unlink(missing_ok=True)


if __name__ == "__main__":
    harness.CONTROL = harness.BASE / "phx-port/control.sock"
    assert not (harness.BASE / "phx-port").exists(), "refusing to reuse another runtime"
    harness.prepare()
    try:
        run_case(active=2, request_shutdown=True)
        run_case(active=8, request_shutdown=False)
    finally:
        harness.shutil.rmtree(harness.STATE)
        harness.shutil.rmtree(harness.RUNTIME)
        harness.shutil.rmtree(harness.BASE / "phx-port", ignore_errors=True)
        harness.CONFIG.unlink(missing_ok=True)
