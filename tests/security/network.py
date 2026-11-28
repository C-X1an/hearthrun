#!/usr/bin/env python3
"""Finite AC-006 positive observations using existing bounded native helpers.

Requires an already prepared, scoped non-root Linux UID and the reviewed static
network_probe fixture. Creates only owned loopback listeners and a pathname Unix
socket in the NEW bounded work directory. No resolver, privileged setup, external
target, policy alteration, inherited descriptor injection or negative control.
This is partial AC-006 coverage, not a full locked acceptance result.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import sys
import time
from typing import Any

sys.dont_write_bytecode = True
from network_observation import CONTROLS, TRANSPORTS, parse_guest, validate, validate_controls

SPEC = importlib.util.spec_from_file_location("hearthrun_network_native_helper", Path(__file__).resolve().parents[1] / "e2e" / "native.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native e2e helper is unavailable")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)


class Listeners:
    """Single-threaded owned listeners; no child, resolver or background service."""

    def __init__(self, work: Path):
        self.path = work / "network.sock"
        self.identity: tuple[int, int] | None = None
        self.sockets: dict[str, socket.socket] = {}
        self.pending: dict[socket.socket, tuple[str, str, bytearray]] = {}
        self.addresses: dict[str, Any] = {}
        self.phase = "before"
        self.events = 0
        self.records = {phase: {name: {"accepts": 0, "messages": []} for name in TRANSPORTS}
                        for phase in ("before", "guest", "after")}

    def open(self) -> None:
        native.require(len(os.fsencode(self.path)) < 108, "owned Unix socket pathname exceeds Linux bound")
        native.private_directory(self.path.parent)
        native.require(not self.path.exists() and not self.path.is_symlink(), "owned Unix socket path already exists")
        # The caller's finally block owns close even if any bind fails.
        for name in TRANSPORTS:
            family = socket.AF_UNIX if name == "unix" else socket.AF_INET
            kind = socket.SOCK_STREAM if name in {"tcp", "unix"} else socket.SOCK_DGRAM
            endpoint = socket.socket(family, kind)
            self.sockets[name] = endpoint
            endpoint.set_inheritable(False)
            endpoint.bind(str(self.path) if name == "unix" else ("127.0.0.1", 0))
            if name == "unix":
                info = self.path.lstat()
                self.identity = (info.st_dev, info.st_ino)
                native.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
                               and stat.S_IMODE(info.st_mode) == 0o700,
                               "owned Unix socket has unexpected identity/permissions")
            else:
                host, port = endpoint.getsockname()
                native.require(host == "127.0.0.1" and 1024 <= port <= 65535,
                               "listener did not bind exact unprivileged loopback")
            self.addresses[name] = endpoint.getsockname()
            if kind == socket.SOCK_STREAM:
                endpoint.listen(8)
            endpoint.setblocking(False)

    def event(self) -> None:
        self.events += 1
        native.require(self.events <= 64, "finite listener event budget exceeded")

    def poll(self, timeout: float = 0) -> None:
        if not self.sockets:
            return
        names = {endpoint: name for name, endpoint in self.sockets.items()}
        ready, _, _ = select.select(list(names) + list(self.pending), [], [], timeout)
        for endpoint in ready:
            if endpoint in names:
                name = names[endpoint]
                if name in {"tcp", "unix"}:
                    connection, _ = endpoint.accept()
                    # Own the accepted handle before any operation that can fail.
                    self.pending[connection] = (name, self.phase, bytearray())
                    connection.setblocking(False)
                    connection.set_inheritable(False)
                    self.event()
                    self.records[self.phase][name]["accepts"] += 1
                else:
                    data, _ = endpoint.recvfrom(1025)
                    self.event()
                    native.require(len(data) <= 1024, "owned datagram exceeds finite bound")
                    self.records[self.phase][name]["messages"].append(data.hex())
            else:
                name, phase, data = self.pending[endpoint]
                chunk = endpoint.recv(1025)
                native.require(len(data) + len(chunk) <= 1024, "owned stream exceeds finite bound")
                if chunk:
                    data.extend(chunk)
                else:
                    self.event()
                    self.records[phase][name]["messages"].append(bytes(data).hex())
                    endpoint.close()
                    del self.pending[endpoint]

    def observe(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.poll(min(0.02, max(0, deadline - time.monotonic())))
        native.require(not self.pending, "test-owned accepted connection did not close in observation window")

    def controls(self) -> None:
        for name in TRANSPORTS:
            endpoint = self.sockets[name]
            with socket.socket(endpoint.family, endpoint.type) as client:
                client.set_inheritable(False)
                client.settimeout(1)
                client.connect(self.addresses[name])
                client.sendall(CONTROLS[name])
            self.observe(0.25)
        self.observe(0.25)
        validate_controls(self.records[self.phase], self.phase)

    def close(self) -> list[str]:
        errors = []
        for endpoint in list(self.pending) + list(self.sockets.values()):
            try:
                endpoint.close()
            except OSError as error:
                errors.append(f"owned network descriptor close failed: {error}")
        self.pending.clear()
        self.sockets.clear()
        if self.identity is not None:
            try:
                info = self.path.lstat()
                native.require((info.st_dev, info.st_ino) == self.identity
                               and stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid(),
                               "owned Unix socket pathname identity changed before unlink")
                self.path.unlink()
                self.identity = None
            except Exception as error:
                errors.append(f"owned Unix socket removal failed: {error}")
        return errors


class NetworkSuite(native.Harness):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.listeners: Listeners | None = None
        self.observed: dict[str, Any] = {"guest": {}, "listeners": {}}
        self.observation_complete = False

    def preflight(self) -> None:
        if sys.platform != "linux" or os.geteuid() == 0:
            raise native.Blocked("network test requires existing scoped non-root Linux UID")
        super().preflight()

    def pump_server(self, excluding=None) -> None:
        super().pump_server(excluding)
        if self.listeners is not None:
            self.listeners.poll()

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile",
                                      str(self.state), "example", str(self.fixture)])
        profile = native.strict_json(stdout)
        native.require(code == 0 and profile.get("profile_id") == "example"
                       and native.DIGEST.fullmatch(profile.get("executable_digest", "")) is not None,
                       "approved network profile installation failed")
        self.start()
        self.case("doctor_and_socket", self.doctor_case)
        self.listeners = Listeners(self.work)
        self.observed["listeners"] = self.listeners.records
        self.listeners.open()
        self.listeners.controls()
        source = self.work / "probe.txt"
        native.write_synthetic(source, b"synthetic finite network test input\n")
        stage = self.cli("stage", f"probe.txt={source}").get("stage_id")
        native.require(isinstance(stage, str) and native.ID.fullmatch(stage) is not None, "network stage lacks identity")
        self.case("controlled_listener_socket_refusals", lambda: self.network(stage))

    def network(self, stage: str) -> dict[str, Any]:
        listeners = self.listeners
        native.require(listeners is not None, "owned listeners are unavailable")
        listeners.phase = "guest"
        value = self.cli("submit", secrets.token_hex(16), "example", stage, "10000", "--",
                         *(str(listeners.addresses[name][1]) for name in ("tcp", "udp", "dns")),
                         str(listeners.path))
        job = value.get("job_id")
        native.require(isinstance(job, str) and native.ID.fullmatch(job) is not None, "network submit lacks job identity")
        self.jobs.add(job)
        self.record(job)
        self.terminal(job, "SUCCEEDED")
        metadata, stdout, stderr = self.verify_result(job, "SUCCEEDED")
        native.require(metadata["exit_code"] == 0 and metadata["signal"] is None
                       and metadata["artifacts"] == [] and stderr == b""
                       and metadata["stdout_truncated"] is False and metadata["stderr_truncated"] is False,
                       "network guest did not finish normally with bounded streams/no artifacts")
        native.require(not self.group_names(), "network guest cgroup remains after terminal publication")
        self.observed["guest"] = parse_guest(stdout)
        listeners.observe(0.25)
        listeners.phase = "after"
        listeners.controls()
        validate(self.observed)
        self.observation_complete = True
        return {"job_id": job, "observations": self.observed,
                "guest_observation_ms_after_terminal": 250,
                "inherited_descriptor_coverage": "NOT RUN; no injected FD claimed"}

    def cleanup(self) -> list[str]:
        errors = []
        try:
            errors.extend(super().cleanup())
        except Exception as error:
            errors.append(f"native cleanup failed: {error}")
        finally:
            if self.listeners is not None:
                if self.observation_complete:
                    try:
                        self.listeners.observe(0.1)
                        validate(self.observed)
                    except Exception as error:
                        errors.append(f"final listener validation failed: {error}")
                errors.extend(self.listeners.close())
            if self.created_work:
                try:
                    native.write_synthetic(self.logs / "network-observations.json",
                                           json.dumps(self.observed, sort_keys=True).encode("ascii") + b"\n")
                except Exception as error:
                    errors.append(f"network evidence retention failed: {error}")
        return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("bin-dir", "doctor", "fixture", "cgroup-root", "work"):
        parser.add_argument(f"--{flag}", required=True)
    args = parser.parse_args()

    def terminate(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("network harness termination requested; reconciling owned resources")

    signal.signal(signal.SIGTERM, terminate)
    harness = None
    code = 1
    try:
        harness = NetworkSuite(args)
        harness.preflight()
        harness.exercise()
        code = 0
    except native.Blocked as error:
        native.emit("network_security", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except KeyboardInterrupt:
        native.emit("network_security", "FAIL", reason="network harness interrupted")
    except Exception as error:
        native.emit("network_security", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        if harness is not None:
            errors = harness.cleanup()
            if errors:
                native.emit("teardown", "FAIL", errors=errors[:16])
                code = 1
            elif harness.created_work:
                native.emit("teardown", "PASS", owned_children_reaped=True,
                            owned_cgroups_remaining=0, owned_network_handles_closed=True)
            if code == 0:
                native.emit("network_security", "PASS", passed_cases=harness.passes,
                            scope="finite socket-refusal/listener positive; inherited FD and negative control remain open")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
