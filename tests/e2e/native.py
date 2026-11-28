#!/usr/bin/env python3
"""Real, bounded CLI/supervisor/launcher end-to-end checks on a prepared host.

This does not provision delegation or lower host protections. Run as the scoped
trusted user with no supplementary groups. --work must be a NEW directory on an
already OS-bounded noswap tmpfs. All inputs are synthetic. Evidence remains under
that directory; this script never recursively deletes it or the operator root.

Example (replace all placeholders with existing absolute operator paths):
  python3 tests/e2e/native.py --bin-dir ABS_DEBUG --doctor ABS_DOCTOR \
    --fixture ABS_STATIC_TASK --cgroup-root ABS_JOBS --work ABS_NEW_WORK

No native acceptance claim follows from merely authoring or compiling this file.
The script performs a small finite functional run, not the full mutation,
fault-injection, security, performance, or 1000-schedule acceptance campaigns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from typing import Any


MAX_HEADER = 65_536
MAX_RECORDS = 1024
MAX_CATALOG = 256 * 1024
MAX_CAPTURE = 256 * 1024
MAX_ALL_CAPTURE = 8 * 1024 * 1024
MAX_COMMANDS = 512
MAX_RUN_SECONDS = 180
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED"}
ID = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
COMPONENT = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


class Failure(RuntimeError):
    pass


class Blocked(Failure):
    pass


class RetiredOwnedFile(Failure):
    """An owned descriptor still refers to a record generation just replaced."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def emit(case: str, status: str, **details: Any) -> None:
    print(json.dumps({"case": case, "status": status, **details}, sort_keys=True), flush=True)


def duplicate_checked(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate decoded JSON key in observed data")
        result[key] = value
    return result


def strict_json(data: bytes) -> Any:
    require(len(data) <= MAX_CAPTURE, "observed JSON exceeds harness capture bound")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=duplicate_checked,
                          parse_float=lambda _: (_ for _ in ()).throw(Failure("floating-point JSON number")),
                          parse_constant=lambda _: (_ for _ in ()).throw(Failure("nonfinite JSON number")))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Failure(f"observed output is not strict JSON: {type(error).__name__}") from error


def read_fd(fd: int, maximum: int) -> bytes:
    output = bytearray()
    while len(output) <= maximum:
        chunk = os.read(fd, min(16 * 1024, maximum + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
    raise Failure("observed file exceeds its byte bound")


def read_file(path: Path, maximum: int, *, owner: bool = False, mode: int | None = None, virtual: bool = False) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "expected a bounded regular file")
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, "unexpected protected file permissions")
        if owner:
            require(before.st_uid == os.geteuid(), "untrusted protected file ownership")
            if before.st_nlink == 0:
                raise RetiredOwnedFile("owned file generation was already replaced")
            require(before.st_nlink == 1, "untrusted protected file link count")
        data = read_fd(fd, maximum)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "file identity changed during verification")
        if not virtual:
            require(before.st_size == after.st_size == len(data), "file size changed during independent verification")
        return data
    finally:
        os.close(fd)


def private_directory(path: Path) -> None:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), "expected a real private directory")
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "directory must be current-UID mode 0700")


def new_private(path: Path) -> None:
    path.mkdir(mode=0o700)
    private_directory(path)


def write_synthetic(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def absolute(value: str) -> Path:
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "all operator paths must be absolute and normalized")
    return path


def mount_for(path: Path) -> tuple[str, set[str]]:
    data = read_file(Path("/proc/self/mountinfo"), 1024 * 1024, virtual=True)
    candidates: list[tuple[int, str, set[str]]] = []
    for line in data.decode("utf-8").splitlines():
        fields = line.split()
        separator = fields.index("-")
        mountpoint = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        mount = Path(mountpoint)
        if path == mount or mount in path.parents:
            options = set(fields[5].split(",")) | set(fields[separator + 3].split(","))
            candidates.append((len(mount.parts), fields[separator + 1], options))
    require(bool(candidates), "could not establish an actual mount identity")
    _, filesystem, options = max(candidates, key=lambda item: item[0])
    return filesystem, options


class _StartupSocket:
    """Pin one stale generation and the first replacement; never chase replacements."""

    def __init__(self, path: Path):
        self.path = path
        self.directory = self._open_directory()
        self.stale: int | None = None
        self.fresh: int | None = None
        self.secured = False
        try:
            self.stale = self._open_socket()
            if self.stale is not None:
                self._socket_metadata(self.stale, {0o600})
            self._check_directory()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    def _open_directory(self) -> int:
        require(self.path.is_absolute() and ".." not in self.path.parts, "startup directory must be absolute")
        flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(self.path.anchor, flags)
        try:
            for name in self.path.parts[1:]:
                child = os.open(name, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o700, "startup directory must be owner0700")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _check_directory(self) -> None:
        current = self._open_directory()
        try:
            require(self._identity(os.fstat(current)) == self._identity(os.fstat(self.directory)),
                    "startup directory identity changed")
        finally:
            os.close(current)

    def _open_socket(self) -> int | None:
        try:
            return os.open("control.sock", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        except FileNotFoundError:
            return None

    def _socket_metadata(self, descriptor: int, modes: set[int]) -> os.stat_result:
        info = os.fstat(descriptor)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in modes, "startup socket must be an owned single-link socket with expected mode")
        named = os.stat("control.sock", dir_fd=self.directory, follow_symlinks=False)
        require(self._identity(named) == self._identity(info), "startup socket identity changed while opening")
        return info

    def ready(self) -> bool:
        self._check_directory()
        current = self._open_socket()
        if current is None:
            require(self.fresh is None, "startup socket disappeared after first fresh generation")
            return False
        try:
            identity = self._identity(os.fstat(current))
            if self.fresh is None and self.stale is not None and identity == self._identity(os.fstat(self.stale)):
                # This exact inode was validated and pinned before spawn. Its
                # link/name may now retire normally; it is never a connection
                # candidate. Strict metadata/name checks apply only to fresh.
                self._check_directory()
                return False
            if self.fresh is None:
                # preflight's inherited umask077 gives bind mode0700, then
                # Server::bind chmods this same inode to0600 before listen.
                self._socket_metadata(current, {0o700, 0o600})
                self.fresh, current = current, None
            else:
                require(identity == self._identity(os.fstat(self.fresh)), "startup socket identity changed after first fresh generation")
            info = self._socket_metadata(self.fresh, {0o600} if self.secured else {0o700, 0o600})
            self._check_directory()
            if stat.S_IMODE(info.st_mode) != 0o600:
                return False
            self.secured = True
            return True
        finally:
            if current is not None:
                os.close(current)

    def close(self) -> None:
        for descriptor in (self.fresh, self.stale, self.directory):
            if descriptor is not None:
                os.close(descriptor)
        self.fresh = self.stale = self.directory = None


class Process:
    """A direct owned child with bounded pipe capture and explicit reaping."""

    def __init__(self, harness: Harness, name: str, argv: list[str], *, gated: bool = False):
        self.harness = harness
        self.name = name
        stdin = subprocess.PIPE if gated else subprocess.DEVNULL
        self.proc = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=harness.work,
                                     env=harness.environment, start_new_session=True, close_fds=True)
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.pipes: dict[int, tuple[str, Any]] = {}
        for label in self.buffers:
            stream = getattr(self.proc, label)
            require(stream is not None, "owned child capture pipe is missing")
            os.set_blocking(stream.fileno(), False)
            self.pipes[stream.fileno()] = (label, stream)
        self.saved = False

    def pump(self) -> None:
        for fd in list(self.pipes):
            label, stream = self.pipes[fd]
            while True:
                try:
                    data = os.read(fd, 16 * 1024)
                except BlockingIOError:
                    break
                if not data:
                    stream.close()
                    del self.pipes[fd]
                    break
                self.harness.captured += len(data)
                require(len(self.buffers[label]) + len(data) <= MAX_CAPTURE,
                        f"{self.name} exceeded per-stream capture bound")
                require(self.harness.captured <= MAX_ALL_CAPTURE, "total harness capture budget exceeded")
                self.buffers[label].extend(data)

    def poll(self) -> int | None:
        self.pump()
        return self.proc.poll()

    def wait(self, timeout: float, *, cleanup: bool = False) -> int:
        deadline = time.monotonic() + timeout
        if not cleanup:
            deadline = min(self.harness.deadline, deadline)
        while True:
            self.pump()
            self.harness.pump_server(excluding=self)
            code = self.proc.poll()
            if code is not None:
                self.pump()
                require(not self.pipes, f"{self.name} left inherited output descriptors open")
                self.save()
                return code
            require(time.monotonic() < deadline, f"{self.name} exceeded subprocess deadline")
            select.select(list(self.pipes), [], [], min(0.02, max(0.0, deadline - time.monotonic())))

    def save(self) -> None:
        if not self.saved:
            for label, data in self.buffers.items():
                write_synthetic(self.harness.logs / f"{self.name}.{label}", bytes(data))
            self.saved = True


class Harness:
    def __init__(self, args: argparse.Namespace):
        self.work = absolute(args.work)
        self.bin_dir = absolute(args.bin_dir)
        self.doctor = absolute(args.doctor)
        self.fixture = absolute(args.fixture)
        self.cgroup_root = absolute(args.cgroup_root)
        self.deadline = time.monotonic() + MAX_RUN_SECONDS
        self.captured = 0
        self.commands = 0
        self.passes = 0
        self.server: Process | None = None
        self.children: list[Process] = []
        self.instance: str | None = None
        self.jobs: set[str] = set()
        self.cgroup_fd: int | None = None
        self.cgroup_identity: tuple[int, int] | None = None
        self.created_work = False
        self.state = self.work / "state"
        self.logs = self.work / "logs"
        self.environment = {"PATH": os.defpath, "LANG": "C", "TZ": "UTC", "TMPDIR": str(self.work / "tmp")}

    def preflight(self) -> None:
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise Blocked("native harness requires Linux Unix peer credentials")
        if os.getuid() != os.geteuid() or os.getgroups():
            raise Blocked("run as the scoped trusted UID with no supplementary groups")
        require(not self.work.exists() and not self.work.is_symlink(), "--work must be a NEW directory")
        require(self.work.parent.resolve(strict=True) == self.work.parent, "work parent must not contain symlinks")
        filesystem, options = mount_for(self.work.parent)
        capacity = os.statvfs(self.work.parent)
        hard_bytes = capacity.f_blocks * capacity.f_frsize
        if filesystem != "tmpfs" or "noswap" not in options or not 0 < hard_bytes <= 12_000_000_000:
            raise Blocked("--work must be inside an OS-bounded noswap tmpfs of at most 12000000000 bytes")
        for path in [self.bin_dir / "hearthrun", self.bin_dir / "hearthrun-supervisor",
                     self.bin_dir / "hearthrun-launcher", self.doctor, self.fixture]:
            require(path.resolve(strict=True) == path, "operator binary path contains a symlink")
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK), "required binary/fixture is not executable regular source")
        require(self.cgroup_root.resolve(strict=True) == self.cgroup_root, "cgroup root contains a symlink")
        filesystem, _ = mount_for(self.cgroup_root)
        if filesystem != "cgroup2":
            raise Blocked("operator jobs parent must be actual cgroup v2")
        group_info = self.cgroup_root.lstat()
        require(stat.S_ISDIR(group_info.st_mode) and group_info.st_uid == os.geteuid()
                and stat.S_IMODE(group_info.st_mode) & 0o022 == 0,
                "operator cgroup parent must be current-UID owned and not writable by other UIDs")
        self.cgroup_fd = os.open(self.cgroup_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(self.cgroup_fd)
        self.cgroup_identity = (info.st_dev, info.st_ino)
        require(not self.group_names(), "operator jobs parent must have no existing child cgroups for this fresh run")
        os.umask(0o077)
        new_private(self.work)
        self.created_work = True
        new_private(self.logs)
        new_private(self.work / "tmp")
        new_private(self.state)
        emit("preflight", "PASS", tmpfs_hard_bytes=hard_bytes, supplementary_groups=0)
        self.passes += 1

    def pump_server(self, excluding: Process | None = None) -> None:
        if self.server is not None and self.server is not excluding:
            self.server.pump()

    def command(self, argv: list[str], timeout: float = 25) -> tuple[int, bytes, bytes]:
        self.commands += 1
        require(self.commands <= MAX_COMMANDS, "harness command budget exceeded")
        require(time.monotonic() < self.deadline, "total harness deadline exceeded")
        process = Process(self, f"command-{self.commands:03d}", argv)
        self.children.append(process)
        code = process.wait(timeout)
        return code, bytes(process.buffers["stdout"]), bytes(process.buffers["stderr"])

    def cli(self, *arguments: str, ok: bool = True, error: str | None = None) -> dict[str, Any]:
        code, stdout, stderr = self.command([str(self.bin_dir / "hearthrun"), "--state", str(self.state), *arguments])
        value = strict_json(stdout if stdout.strip() else stderr)
        require(isinstance(value, dict) and value.get("v") == 1 and type(value.get("ok")) is bool,
                "CLI did not return a typed v1 envelope")
        if ok:
            require(code == 0 and value["ok"] is True, f"CLI {arguments[0]} refused: {value.get('error')}")
            require(isinstance(value.get("result"), dict), "CLI operation result must be an object")
            return value["result"]
        require(code != 0 and value["ok"] is False, "expected nonzero typed rejection")
        require(isinstance(value.get("error"), dict), "typed error detail is missing")
        if error is not None:
            require(value["error"].get("code") == error, f"expected {error}, observed {value['error'].get('code')}")
        return value["error"]

    def start(self) -> None:
        require(self.server is None or self.server.proc.poll() is not None, "refusing a second active supervisor")
        observed = _StartupSocket(self.state)
        try:
            number = len([child for child in self.children if child.name.startswith("server-")]) + 1
            owner = Process(self, f"server-{number:02d}", [str(self.bin_dir / "hearthrun-supervisor"), "serve",
                str(self.state), str(self.cgroup_root), str(self.bin_dir / "hearthrun-launcher"), str(self.doctor)])
            self.server = owner
            self.children.append(owner)
            deadline = min(self.deadline, time.monotonic() + 30)
            while time.monotonic() < deadline:
                require(self.server is owner and owner.poll() is None, "supervisor exited or changed before socket readiness; inspect captured server logs")
                if observed.ready():
                    code, stdout, stderr = self.command([str(self.bin_dir / "hearthrun"), "--state", str(self.state), "doctor"],
                        timeout=min(25, max(0.001, deadline - time.monotonic())))
                    require(self.server is owner and owner.poll() is None, "supervisor exited or changed during socket readiness")
                    require(observed.ready(), "startup socket lost secured readiness")
                    require(time.monotonic() < deadline, "supervisor readiness deadline expired")
                    value = strict_json(stdout if stdout.strip() else stderr)
                    require(isinstance(value, dict) and value.get("v") == 1 and type(value.get("ok")) is bool,
                            "startup doctor did not return a typed v1 envelope")
                    if value["ok"]:
                        report = value.get("result", {})
                        require(isinstance(report, dict), "startup doctor result is not an object")
                        if code == 78 or report.get("compatible") is not True:
                            emit("doctor", "BLOCKED", report=report)
                            raise Blocked("operational doctor did not authorize native execution")
                        require(code == 0, "compatible doctor returned an unsuccessful exit")
                        self.read_instance()
                        require(observed.ready(), "startup socket lost secured readiness")
                        require(self.server is owner and owner.poll() is None, "supervisor exited or changed after readiness")
                        require(time.monotonic() < deadline, "supervisor readiness deadline expired")
                        return
                    error = value.get("error")
                    require(code == 2 and isinstance(error, dict) and error.get("code") == "IO_UNCERTAIN"
                            and error.get("retryable") is False and error.get("message") ==
                            "cannot connect to owner-only supervisor: Connection refused (os error 111)",
                            "startup doctor refusal is not the same-generation pre-listen connection refusal")
                time.sleep(0.02)
            raise Failure("supervisor readiness deadline expired")
        finally:
            observed.close()

    def read_instance(self) -> str:
        value = strict_json(read_file(self.state / "instance.json", 256, owner=True, mode=0o600))
        require(value.get("v") == 1 and isinstance(value.get("instance_id"), str) and ID.fullmatch(value["instance_id"]) is not None,
                "invalid persistent test instance")
        if self.instance is not None:
            require(value["instance_id"] == self.instance, "restart changed persistent instance identity")
        self.instance = value["instance_id"]
        return self.instance

    def record(self, job: str) -> dict[str, Any]:
        require(ID.fullmatch(job) is not None, "invalid observed job ID")
        path = self.state / "records" / f"{job}.json"
        for _ in range(12):
            try:
                value = strict_json(read_file(path, MAX_HEADER, owner=True, mode=0o600))
                break
            except RetiredOwnedFile:
                # The journal intentionally publishes via atomic rename. Do
                # not trust an unlinked generation, and retry only this race.
                time.sleep(0.002)
        else:
            raise Failure("could not observe a linked durable journal generation")
        require(value.get("v") == 1 and value.get("instance_id") == self.read_instance() and value.get("job_id") == job,
                "journal record is not owned by this test instance/job")
        require(isinstance(value.get("request_id"), str) and ID.fullmatch(value["request_id"]) is not None,
                "journal request identity is invalid")
        return value

    def inventory(self) -> set[str]:
        names = list((self.state / "records").iterdir())
        require(len(names) <= MAX_RECORDS + 1, "journal inventory exceeds test bound")
        catalog = strict_json(read_file(self.state / "records" / "catalog.json", MAX_CATALOG, owner=True, mode=0o600))
        require(catalog.get("v") == 1 and catalog.get("instance_id") == self.read_instance(), "invalid retry catalog identity")
        entries = catalog.get("entries")
        require(isinstance(entries, list) and len(entries) <= MAX_RECORDS, "invalid bounded retry catalog")
        expected: set[str] = set()
        for entry in entries:
            job = entry.get("job_id")
            require(isinstance(job, str) and ID.fullmatch(job) is not None and job not in expected, "ambiguous retry catalog job")
            record = self.record(job)
            require(entry.get("request_id") == record["request_id"] and entry.get("canonical_request_sha256") == record.get("canonical_request_sha256"),
                    "catalog differs from durable request identity")
            expected.add(job)
        actual = {path.stem for path in names if path.name != "catalog.json"}
        require(actual == expected and all(path.name == "catalog.json" or ID.fullmatch(path.stem) is not None and path.suffix == ".json" for path in names),
                "journal is missing a record or has an uncommitted temporary")
        return expected

    def submit(self, request: str, stage: str, mode: str) -> str:
        value = self.cli("submit", request, "example", stage, "60000", "--", mode)
        job = value.get("job_id")
        require(isinstance(job, str) and ID.fullmatch(job) is not None, "submit did not acknowledge a job ID")
        self.jobs.add(job)
        self.record(job)
        return job

    def terminal(self, job: str, expected: str, timeout: float = 15) -> dict[str, Any]:
        deadline = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < deadline:
            require(self.server is not None and self.server.poll() is None, "supervisor died while awaiting terminal cleanup")
            result = self.cli("inspect", job)
            if result.get("state") in TERMINAL:
                require(result["state"] == expected, f"expected {expected}, observed {result['state']}")
                require(result.get("cleanup_confirmed") is True and DIGEST.fullmatch(result.get("result_digest", "")) is not None,
                        "terminal state lacks cleanup or durable result identity")
                record = self.record(job)
                require(record.get("state") == expected and record.get("cleanup_confirmed") is True and record.get("result_digest") == result["result_digest"],
                        "visible terminal state differs from durable journal")
                return result
            time.sleep(0.04)
        raise Failure("terminal cleanup/result deadline expired")

    def group_names(self) -> set[str]:
        require(self.cgroup_fd is not None, "cgroup root descriptor unavailable")
        info = os.fstat(self.cgroup_fd)
        require((info.st_dev, info.st_ino) == self.cgroup_identity, "operator cgroup root identity changed")
        names = os.listdir(self.cgroup_fd)
        require(len(names) <= 512, "cgroup root inventory exceeds bound")
        directories = set()
        for name in names:
            try:
                info = os.stat(name, dir_fd=self.cgroup_fd, follow_symlinks=False)
            except FileNotFoundError:
                # A real supervisor may remove its empty leaf between readdir
                # and stat. No vanished leaf is treated as populated or retained.
                continue
            if stat.S_ISDIR(info.st_mode):
                directories.add(name)
        return directories

    def group_name(self, job: str) -> str:
        self.record(job)
        require(self.instance is not None, "persistent instance unavailable")
        return f"hr-{self.instance}-{job}"

    def open_group(self, job: str) -> int:
        require(self.record(job).get("launch_stage") in {"CGROUP_CREATED", "LAUNCHER_SPAWNED", "CGROUP_ATTACHED", "SETUP_READY", "EXEC_RELEASED", "CLEANED"},
                "journal does not establish cgroup creation ownership")
        name = self.group_name(job)
        require(self.cgroup_fd is not None, "operator cgroup descriptor is missing")
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.cgroup_fd)
        root = os.fstat(self.cgroup_fd)
        child = os.fstat(fd)
        require(root.st_dev == child.st_dev and child.st_uid == os.geteuid(), "cgroup is not an owned same-filesystem leaf")
        return fd

    @staticmethod
    def control_read(group: int, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group)
        try:
            return read_fd(fd, 4096)
        finally:
            os.close(fd)

    @staticmethod
    def process_identity(pid: int) -> dict[str, Any] | None:
        try:
            data = read_file(Path(f"/proc/{pid}/stat"), 4096, virtual=True)
        except (FileNotFoundError, ProcessLookupError):
            return None
        closing = data.rfind(b")")
        require(closing > 0, "invalid observed process stat")
        fields = data[closing + 2:].split()
        require(len(fields) >= 20, "truncated observed process stat")
        return {"pid": pid, "state": fields[0].decode("ascii"), "ppid": int(fields[1]),
                "pgrp": int(fields[2]), "session": int(fields[3]), "start_ticks": int(fields[19])}

    def detached_ready(self, job: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        require(self.server is not None, "supervisor unavailable")
        deadline = min(self.deadline, time.monotonic() + 4)
        stable_since: float | None = None
        last: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            result = self.cli("inspect", job)
            require(result.get("state") not in TERMINAL, "hold fixture exited before readiness proof")
            if self.record(job).get("launch_stage") == "INTENT":
                time.sleep(0.02)
                continue
            try:
                fd = self.open_group(job)
            except FileNotFoundError:
                time.sleep(0.02)
                continue
            try:
                raw = self.control_read(fd, "cgroup.procs")
            finally:
                os.close(fd)
            lines = raw.splitlines()
            require(len(lines) <= 32 and all(line.isdigit() for line in lines), "invalid bounded cgroup process list")
            identities = [self.process_identity(int(line)) for line in lines]
            last = [entry for entry in identities if entry is not None]
            launchers = [entry for entry in last if entry["ppid"] == self.server.proc.pid]
            detached = [entry for entry in last if entry["session"] != self.server.proc.pid
                        and entry["session"] == entry["pgrp"] and entry["ppid"] != self.server.proc.pid]
            if result.get("state") == "RUNNING" and len(last) >= 4 and len(launchers) == 1 and detached:
                stable_since = stable_since or time.monotonic()
                if time.monotonic() - stable_since >= 0.10:
                    return last, launchers
            else:
                stable_since = None
            time.sleep(0.02)
        raise Failure(f"hold did not establish actual detached cgroup membership (last count {len(last)})")

    def cleanup_observed(self, job: str, members: list[dict[str, Any]], launchers: list[dict[str, Any]]) -> None:
        deadline = min(self.deadline, time.monotonic() + 4)
        while True:
            live = []
            unreaped_launchers = []
            for original in members:
                current = self.process_identity(original["pid"])
                if current is not None and current["start_ticks"] == original["start_ticks"]:
                    if current["state"] != "Z":
                        live.append(current["pid"])
                    if original in launchers:
                        unreaped_launchers.append(current["pid"])
            removed = self.group_name(job) not in self.group_names()
            if not live and not unreaped_launchers and removed:
                # Kernel cgroup removal requires emptiness. We report removal,
                # rather than inventing a populated=0 sample after the removal.
                return
            require(time.monotonic() < deadline, f"cleanup unresolved: live={live}, launcher_not_reaped={unreaped_launchers}, group_removed={removed}")
            time.sleep(0.02)

    def verify_result(self, job: str, expected: str) -> tuple[dict[str, Any], bytes, bytes]:
        approved = self.cli("result", job)
        require(set(approved) == {"metadata", "result_digest"}, "result response shape differs from approved interface")
        directory = self.state / "results" / job
        private_directory(directory)
        require({path.name for path in directory.iterdir()} == {"result.json", "artifacts", "stdout.bin", "stderr.bin"},
                "committed result has unexpected bundle entries")
        raw = read_file(directory / "result.json", MAX_HEADER, owner=True, mode=0o600)
        metadata = strict_json(raw)
        require(metadata == approved["metadata"] and metadata.get("job_id") == job and metadata.get("status") == expected
                and metadata.get("cleanup_confirmed") is True, "approved metadata differs from actual committed result")
        stdout = read_file(directory / "stdout.bin", 1024 * 1024, owner=True, mode=0o600)
        stderr = read_file(directory / "stderr.bin", 1024 * 1024, owner=True, mode=0o600)
        digest = hashlib.sha256(b"HearthRun result bundle v1\0" + len(raw).to_bytes(8, "big") + raw
            + len(stdout).to_bytes(8, "big") + hashlib.sha256(stdout).hexdigest().encode("ascii")
            + len(stderr).to_bytes(8, "big") + hashlib.sha256(stderr).hexdigest().encode("ascii")).hexdigest()
        require(digest == approved["result_digest"] == self.record(job).get("result_digest"), "bundle bytes do not match journal/approved digest")
        manifest = metadata.get("artifacts")
        require(isinstance(manifest, list) and len(manifest) <= 128, "unbounded artifact manifest")
        artifact_root = directory / "artifacts"
        private_directory(artifact_root)
        observed: dict[str, tuple[int, str]] = {}
        total = 0
        entries = 0
        stack = [(artifact_root, "")]
        while stack:
            parent, prefix = stack.pop()
            for path in parent.iterdir():
                entries += 1
                require(entries <= 256, "committed artifact tree entry bound exceeded")
                logical = f"{prefix}/{path.name}" if prefix else path.name
                components = logical.split("/")
                require(len(logical) <= 240 and len(components) <= 8 and all(COMPONENT.fullmatch(part) and part not in {".", ".."} for part in components),
                        "committed artifact path violates logical grammar")
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    private_directory(path)
                    stack.append((path, logical))
                else:
                    require(stat.S_ISREG(info.st_mode), "committed artifact is a special object")
                    total += info.st_size
                    require(total <= 32 * 1024 * 1024 and len(observed) < 128, "committed artifact count/byte bound exceeded")
                    data = read_file(path, 32 * 1024 * 1024, owner=True, mode=0o600)
                    observed[logical] = (len(data), hashlib.sha256(data).hexdigest())
        expected_manifest = [{"path": name, "size_bytes": value[0], "sha256": value[1]} for name, value in sorted(observed.items())]
        require(manifest == expected_manifest, "manifest is not the exact independently hashed protected artifact inventory")
        return metadata, stdout, stderr

    def raw_request(self, header: bytes, *, prefix: int | None = None) -> dict[str, Any]:
        path = self.state / "control.sock"
        info = path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600,
                "raw protocol target is not the owner-only test socket")
        deadline = min(self.deadline, time.monotonic() + 6)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(str(path))
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.geteuid(), "raw request peer UID differs")
            connection.sendall(struct.pack("!I", len(header) if prefix is None else prefix) + header)
            connection.shutdown(socket.SHUT_WR)
            def exact(size: int) -> bytes:
                data = bytearray()
                while len(data) < size:
                    connection.settimeout(max(0.001, deadline - time.monotonic()))
                    chunk = connection.recv(size - len(data))
                    require(bool(chunk), "raw response ended before its frame")
                    data.extend(chunk)
                return bytes(data)
            length, = struct.unpack("!I", exact(4))
            require(0 < length <= MAX_HEADER, "raw response header exceeds bound")
            value = strict_json(exact(length))
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            require(connection.recv(1) == b"", "raw response has surplus bytes")
            return value

    def case(self, name: str, callback: Any) -> None:
        started = time.monotonic()
        details = callback() or {}
        emit(name, "PASS", elapsed_ms=round((time.monotonic() - started) * 1000), **details)
        self.passes += 1

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile",
                                      str(self.state), "example", str(self.fixture)])
        require(code == 0, "operator profile installation failed")
        profile = strict_json(stdout)
        require(profile.get("profile_id") == "example" and DIGEST.fullmatch(profile.get("executable_digest", "")) is not None,
                "installed profile did not report actual executable identity")
        self.start()
        self.case("doctor_and_socket", self.doctor_case)
        data = self.work / "data.ndjson"
        notes = self.work / "notes.txt"
        write_synthetic(data, b'{"value":7}\n{"value":-2}\n{"value":0}\n{"value":11}\n')
        write_synthetic(notes, b"synthetic HearthRun end-to-end fixture\n")
        stage = self.cli("stage", f"data.ndjson={data}", f"notes.txt={notes}")
        stage_id = stage.get("stage_id")
        require(isinstance(stage_id, str) and ID.fullmatch(stage_id) is not None and DIGEST.fullmatch(stage.get("manifest_digest", "")) is not None,
                "actual CLI staging response is invalid")
        self.case("summary_and_idempotency", lambda: self.summary_case(stage_id))
        self.case("refusal_has_no_execution_side_effect", lambda: self.refusal_case(stage_id))
        self.case("detached_cancellation", lambda: self.cancel_case(stage_id))
        self.case("interrupted_restart_without_replay", lambda: self.restart_case(stage_id))

    def doctor_case(self) -> dict[str, Any]:
        report = self.cli("doctor")
        require(report.get("compatible") is True, "doctor did not authorize native execution")
        metrics = self.cli("metrics")
        require(metrics.get("admission_open") is True and metrics.get("active") == 0 and metrics.get("queued") == 0,
                "fresh supervisor is not ready and idle")
        socket_info = (self.state / "control.sock").lstat()
        require(stat.S_ISSOCK(socket_info.st_mode) and stat.S_IMODE(socket_info.st_mode) == 0o600 and socket_info.st_uid == os.geteuid(),
                "supervisor socket ownership/mode differs")
        return {"compatible": True, "socket_mode": "0600"}

    def summary_case(self, stage: str) -> dict[str, Any]:
        request = secrets.token_hex(16)
        job = self.submit(request, stage, "summary")
        self.terminal(job, "SUCCEEDED")
        metadata, _, _ = self.verify_result(job, "SUCCEEDED")
        require(len(metadata["artifacts"]) == 1 and metadata["artifacts"][0]["path"] == "summary.json", "summary produced the wrong artifact set")
        summary = strict_json(read_file(self.state / "results" / job / "artifacts" / "summary.json", 1024, owner=True, mode=0o600))
        require(summary == {"count": 4, "sum": 16}, "real native summary bytes are incorrect")
        before = self.record(job)
        records = self.inventory()
        retry = self.cli("submit", request, "example", stage, "60000", "--", "summary")
        require(retry.get("job_id") == job and retry.get("state") == "SUCCEEDED", "identical retry did not return the existing job")
        self.cli("submit", request, "example", stage, "59999", "--", "summary", ok=False, error="CONFLICT")
        require(self.inventory() == records and self.record(job) == before and not self.group_names(), "retry/conflict mutated identity or launched work")
        page = self.cli("events", job, "0", "2")
        require(isinstance(page.get("events"), list) and len(page["events"]) <= 2 and type(page.get("truncated")) is bool, "events page is not bounded")
        sequences = [entry["sequence"] for entry in page["events"]]
        require(sequences == sorted(set(sequences)) and page.get("next_seq") == (sequences[-1] if sequences else 0), "event continuation sequence differs")
        return {"job_id": job, "count": 4, "sum": 16, "retry_preserved_job": True}

    def refusal_case(self, stage: str) -> dict[str, Any]:
        before = self.inventory()
        groups = self.group_names()
        self.cli("submit", secrets.token_hex(16), "missing", stage, "10000", "--", "empty", ok=False, error="PROFILE_NOT_FOUND")
        self.cli("submit", secrets.token_hex(16), "example", secrets.token_hex(16), "10000", "--", "empty", ok=False, error="STAGE_NOT_FOUND")
        malformed = {"v": 1, "op": "submit", "request_id": secrets.token_hex(16), "profile_id": "example",
                     "stage_id": stage, "argv": ["empty"], "wall_ms": 10000, "host_path": "/not-authorized"}
        for header, prefix, expected in [(json.dumps(malformed).encode(), None, "UNKNOWN_FIELD"),
                (b'{"v":1,"op":"metrics","op":"doctor"}', None, "DUPLICATE_KEY"), (b"", MAX_HEADER + 1, "BAD_FRAME")]:
            rejected = self.raw_request(header, prefix=prefix)
            require(rejected.get("ok") is False and rejected.get("error", {}).get("code") == expected, "malformed native socket request was not rejected as specified")
        require(self.inventory() == before and self.group_names() == groups, "rejected request persisted/launched a job")
        metrics = self.cli("metrics")
        require(metrics.get("active") == 0 and metrics.get("queued") == 0, "refused input changed scheduler admission")
        return {"rejections": 5, "record_count_unchanged": True}

    def cancel_case(self, stage: str, *, cleanup_timeout: float | None = None) -> dict[str, Any]:
        submitted = time.monotonic()
        job = self.submit(secrets.token_hex(16), stage, "hold")
        members, launchers = self.detached_ready(job)
        self.cli("result", job, ok=False, error="NOT_READY")
        require(not (self.state / "results" / job).exists(), "result was published while hold writers were live")
        cancelled = self.cli("cancel", job)
        require(cancelled.get("cancel_requested") is True, "cancellation was not acknowledged")
        remaining = 15.0 if cleanup_timeout is None else cleanup_timeout - (time.monotonic() - submitted)
        require(remaining > 0, "cancel fixture readiness consumed the scoped cleanup window")
        self.terminal(job, "CANCELLED", timeout=remaining)
        self.cleanup_observed(job, members, launchers)
        elapsed = time.monotonic() - submitted
        if cleanup_timeout is not None:
            require(elapsed < cleanup_timeout, "whole-group owner cleanup was not observed before natural hold completion")
        metadata, stdout, _ = self.verify_result(job, "CANCELLED")
        require(metadata["artifacts"] == [] and b"detached-ready\n" in stdout, "cancel result lacks actual detached fixture readiness or discarded-artifact policy")
        before = self.record(job)
        self.cli("cancel", job)
        require(self.record(job) == before, "repeat cancel overwrote the committed terminal record")
        observed = {"job_id": job, "observed_cgroup_processes": len(members),
                    "launcher_reaped": True, "cgroup_removed": True}
        if cleanup_timeout is not None:
            observed.update(members_before_cancel=members, launchers_before_cancel=launchers,
                            cancel_reason=before.get("cancel_reason"), result_status=metadata.get("status"),
                            result_digest=before.get("result_digest"), cleanup_elapsed_ms=round(elapsed * 1000))
        return observed

    def restart_case(self, stage: str) -> dict[str, Any]:
        request = secrets.token_hex(16)
        job = self.submit(request, stage, "hold")
        return self.restart_interrupted(job, request, stage)

    def restart_interrupted(self, job: str, request: str, stage: str) -> dict[str, Any]:
        members, launchers = self.detached_ready(job)
        self.cli("result", job, ok=False, error="NOT_READY")
        require(not (self.state / "results" / job).exists(), "active interrupted job already had a result")
        require(self.server is not None and self.server.poll() is None, "no owned supervisor available for crash test")
        # Intentional fault injection targets only the Popen-owned supervisor.
        self.server.proc.kill()
        require(self.server.wait(5) == -signal.SIGKILL, "supervisor crash was not observed and reaped")
        self.start()
        self.terminal(job, "INTERRUPTED")
        self.cleanup_observed(job, members, launchers)
        metadata, _, _ = self.verify_result(job, "INTERRUPTED")
        require(metadata["artifacts"] == [] and self.record(job).get("cancel_reason") == "SUPERVISOR_RESTART", "recovery did not preserve explicit interrupted/no-artifact outcome")
        before = self.record(job)
        records = self.inventory()
        retry = self.cli("submit", request, "example", stage, "60000", "--", "hold")
        require(retry.get("job_id") == job and retry.get("state") == "INTERRUPTED", "restart retry replayed or changed the interrupted identity")
        self.cli("submit", request, "example", stage, "60000", "--", "empty", ok=False, error="CONFLICT")
        observation_deadline = time.monotonic() + 0.5
        while time.monotonic() < observation_deadline:
            metrics = self.cli("metrics")
            require(metrics.get("active") == 0 and metrics.get("queued") == 0 and not self.group_names(), "recovery automatically replayed uncertain work")
            time.sleep(0.04)
        require(self.inventory() == records and self.record(job) == before, "recovery retry modified committed identity/state")
        return {"job_id": job, "state": "INTERRUPTED", "retry_preserved_job": True, "replay_observation_ms": 500}

    def cleanup(self) -> list[str]:
        errors: list[str] = []
        for child in reversed(self.children):
            if child.proc.poll() is None:
                try:
                    child.proc.terminate()
                    require(child.wait(20 if child is self.server else 3, cleanup=True) == 0, f"{child.name} failed graceful shutdown")
                except Exception as error:
                    errors.append(f"{child.name}: {error}")
                    if child.proc.poll() is None:
                        child.proc.kill()
                        try:
                            child.proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            errors.append(f"{child.name}: direct child remains unreaped")
            try:
                child.pump()
                child.save()
            except Exception as error:
                errors.append(f"{child.name}: capture finalization failed: {error}")
        # Emergency recovery is restricted to exact checked journal-owned leaves.
        # Any use of this fallback is a test failure, never a passing teardown.
        if self.cgroup_fd is not None:
            for job in sorted(self.jobs):
                try:
                    name = self.group_name(job)
                    if name not in self.group_names():
                        continue
                    errors.append(f"owned cgroup required forced recovery: {name}")
                    group = self.open_group(job)
                    try:
                        descriptor = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=group)
                        try:
                            require(os.write(descriptor, b"1\n") == 2, "short owned cgroup kill write")
                        finally:
                            os.close(descriptor)
                        deadline = time.monotonic() + 4
                        while b"populated 0\n" not in self.control_read(group, "cgroup.events"):
                            require(time.monotonic() < deadline, "owned cgroup remains populated")
                            time.sleep(0.02)
                        named = os.stat(name, dir_fd=self.cgroup_fd, follow_symlinks=False)
                        opened = os.fstat(group)
                        require((named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino), "owned cgroup name changed before removal")
                        os.rmdir(name, dir_fd=self.cgroup_fd)
                    finally:
                        os.close(group)
                except Exception as error:
                    errors.append(f"owned cgroup cleanup refused: {error}")
            try:
                require(not self.group_names(), "operator jobs parent has unresolved children")
            except Exception as error:
                errors.append(str(error))
            os.close(self.cgroup_fd)
            self.cgroup_fd = None
        return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--doctor", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--cgroup-root", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args()
    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise Failure("harness termination requested; reconciling only owned test resources")
    signal.signal(signal.SIGTERM, terminate)
    harness: Harness | None = None
    code = 1
    try:
        harness = Harness(args)
        harness.preflight()
        harness.exercise()
        code = 0
    except Blocked as error:
        emit("native_e2e", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except KeyboardInterrupt:
        emit("native_e2e", "FAIL", reason="harness interrupted; reconciling only owned test resources")
    except Exception as error:
        emit("native_e2e", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        if harness is not None:
            errors = harness.cleanup()
            if errors:
                emit("teardown", "FAIL", errors=errors[:16])
                code = 1
            elif harness.created_work:
                emit("teardown", "PASS", owned_children_reaped=True, owned_cgroups_remaining=0)
            if code == 0:
                emit("native_e2e", "PASS", passed_cases=harness.passes, commands=harness.commands,
                     captured_bytes=harness.captured, scope="finite native functional run; full acceptance remains separate")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
