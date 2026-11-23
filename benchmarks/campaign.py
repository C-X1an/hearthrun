#!/usr/bin/env python3
"""Bounded local native B-01/B-02 campaign; no provisioning or automatic builds."""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import platform
import random
import signal
import stat
import statistics
import sys
import tarfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load public harness dependency")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


n = load("benchmark_native", ROOT / "tests/e2e/native.py")
c = load("benchmark_capture", ROOT / "scripts/capture.py")
n.MAX_COMMANDS = 4096
n.MAX_RUN_SECONDS = 900
SHARD_JOBS = 128                 # Strictly below Store's 256 request IDs.
MAX_CAMPAIGN_SECONDS = 24 * 3600
MAX_EVIDENCE_BYTES = 2_000_000_000
SHARD_HEADROOM_BYTES = 256 * 1024 * 1024
SHARD_HEADROOM_INODES = 16_384
MAX_SHARD_ENTRIES = 12_000
MAX_SHARD_CONTENT = 128 * 1024 * 1024
RESERVE_FILES = 64
RESERVE_FILE_BYTES = 64 * 1024
COMPACT_ROOTS = ("state", "logs", "tmp", "data.ndjson")
SIZES = (16 * 1024, 1024 * 1024, 8 * 1024 * 1024)
AGGREGATE_CORE = ROOT / "fixtures/native/aggregate_core.rs"
AGGREGATE_ENTRY = ROOT / "fixtures/native/aggregate_entry.c"


def encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(path: Path) -> str:
    return hashlib.sha256(n.read_file(path, 64 * 1024 * 1024)).hexdigest()


def json_file(path: Path, value: Any) -> None:
    n.write_synthetic(path, encode(value))


def capacity(path: Path) -> dict[str, int]:
    value = os.statvfs(path)
    n.require(value.f_files > 0, "filesystem does not report an inode bound")
    return {"available_bytes": value.f_bavail * value.f_frsize, "available_inodes": value.f_favail,
            "hard_bytes": value.f_blocks * value.f_frsize, "hard_inodes": value.f_files}


def compact_shard(h: Shard) -> None:
    """Losslessly aggregate only this stopped, successful shard's owned transients.

    No extraction or recursive pathname deletion is used. Every removal checks
    the descriptor-relative identity captured while archiving. The original
    files remain until the archive has been reread and its index fsynced.
    """
    root = os.open(h.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    root_info = os.fstat(root)
    entries: list[dict[str, Any]] = []
    total = 0
    archive_path = h.work / "transients.tar.gz"
    try:
        fd = os.open("transients.tar.gz", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                     0o600, dir_fd=root)
        with os.fdopen(fd, "wb") as output:
            with tarfile.open(fileobj=output, mode="w|gz", format=tarfile.PAX_FORMAT) as archive:
                def visit(parent: int, name: str, relative: str) -> None:
                    nonlocal total
                    n.require(name not in {"", ".", ".."} and "/" not in name and "\\" not in name,
                              "invalid transient component")
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    n.require(info.st_uid == os.geteuid() and info.st_dev == root_info.st_dev
                              and not info.st_mode & 0o022, "unowned/writable/cross-device shard transient")
                    n.require(len(entries) < MAX_SHARD_ENTRIES, "shard transient inode bound exceeded")
                    entry: dict[str, Any] = {"path": relative, "device": info.st_dev, "inode": info.st_ino,
                                             "mode": stat.S_IMODE(info.st_mode), "size": 0}
                    item = tarfile.TarInfo(relative)
                    item.mode = entry["mode"]
                    if stat.S_ISDIR(info.st_mode):
                        entry["type"] = "directory"
                        entries.append(entry)
                        item.type = tarfile.DIRTYPE
                        archive.addfile(item)
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=parent)
                        try:
                            n.require((os.fstat(child).st_dev, os.fstat(child).st_ino) == (info.st_dev, info.st_ino),
                                      "transient directory identity changed")
                            for leaf in sorted(os.listdir(child)):
                                visit(child, leaf, f"{relative}/{leaf}")
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        n.require(info.st_size <= 64 * 1024 * 1024, "transient file exceeds bound")
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                        dir_fd=parent)
                        try:
                            opened = os.fstat(child)
                            n.require((opened.st_dev, opened.st_ino, opened.st_size) ==
                                      (info.st_dev, info.st_ino, info.st_size), "transient file identity changed")
                            data = n.read_fd(child, 64 * 1024 * 1024)
                            after = os.fstat(child)
                            n.require(len(data) == info.st_size == after.st_size and
                                      after.st_mtime_ns == info.st_mtime_ns, "transient file changed during archive")
                        finally:
                            os.close(child)
                        total += len(data)
                        n.require(total <= MAX_SHARD_CONTENT, "shard transient content bound exceeded")
                        entry.update(type="file", size=len(data), sha256=hashlib.sha256(data).hexdigest())
                        entries.append(entry)
                        item.size = len(data)
                        archive.addfile(item, io.BytesIO(data))
                    else:
                        # A stopped supervisor may deliberately leave its exact
                        # owner-only stale socket. It has metadata, no file bytes.
                        n.require(relative == "state/control.sock" and stat.S_ISSOCK(info.st_mode)
                                  and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                                  "unexpected special shard transient")
                        entry["type"] = "stale_socket"
                        entries.append(entry)
                for name in COMPACT_ROOTS:
                    if name in os.listdir(root):
                        visit(root, name, name)
            output.flush()
            os.fsync(output.fileno())
        # Verify the aggregate before any original is reclaimed.
        expected = [entry for entry in entries if entry["type"] != "stale_socket"]
        with tarfile.open(archive_path, "r|gz") as archive:
            for entry in expected:
                item = archive.next()
                n.require(item is not None and item.name.rstrip("/") == entry["path"]
                          and item.mode == entry["mode"], "archive inventory differs")
                if entry["type"] == "directory":
                    n.require(item.isdir(), "archive directory type differs")
                else:
                    n.require(item.isfile() and item.size == entry["size"], "archive file type/size differs")
                    stream = archive.extractfile(item)
                    n.require(stream is not None, "archive content missing")
                    with stream:
                        n.require(hashlib.sha256(stream.read(64 * 1024 * 1024 + 1)).hexdigest() == entry["sha256"],
                                  "archive content digest differs")
            n.require(archive.next() is None, "archive contains unindexed entries")
        json_file(h.work / "transients-index.json", {"format": "hearthrun-shard-tar-gzip-v1", "status": "PASS",
                  "archive_sha256": digest(archive_path), "content_bytes": total, "entries": entries})
        os.fsync(root)
        for entry in reversed(entries):
            parts = entry["path"].split("/")
            parent = os.dup(root)
            try:
                for name in parts[:-1]:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                n.require((info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)) ==
                          (entry["device"], entry["inode"], entry["mode"]), "transient identity changed before removal")
                if entry["type"] == "directory":
                    os.rmdir(parts[-1], dir_fd=parent)
                else:
                    os.unlink(parts[-1], dir_fd=parent)
            finally:
                os.close(parent)
        os.fsync(root)
        json_file(h.work / "compaction.json", {"status": "PASS", "entries": len(entries), "content_bytes": total,
                  "index_sha256": digest(h.work / "transients-index.json"), "originals_removed": True})
    finally:
        os.close(root)


def fixture_bytes(size: int, seed: int) -> tuple[bytes, dict[str, int]]:
    """64-byte valid NDJSON rows; independent stdlib JSON/integer oracle."""
    rng = random.Random(seed)
    chunks = []
    for _ in range(size // 64):
        line = json.dumps({"value": rng.randint(-1_000_000, 1_000_000)}, separators=(",", ":")).encode()
        chunks.append(line + b" " * (63 - len(line)) + b"\n")
    data = b"".join(chunks)
    n.require(len(data) == size, "synthetic fixture byte count differs")
    values = [json.loads(line)["value"] for line in data.splitlines()]
    return data, {"count": len(values), "sum": sum(values), "min": min(values), "max": max(values)}


class Shard(n.Harness):
    def cleanup(self) -> list[str]:
        errors = []
        if self.created_work and (self.state / "records/catalog.json").exists():
            try:
                # Fresh state belongs solely to this shard, including an accepted
                # submission whose response was lost before its ID reached us.
                self.jobs.update(self.inventory())
            except Exception as error:
                errors.append(f"could not reconcile shard catalog: {error}")
        errors.extend(super().cleanup())
        if self.created_work and hasattr(self, "protocol_log"):
            try:
                n.write_synthetic(self.work / "protocol.jsonl", bytes(self.protocol_log))
            except Exception as error:
                errors.append(f"protocol log finalization failed: {error}")
        return errors

    def rpc(self, op: str, **fields: Any) -> dict[str, Any]:
        n.require(time.monotonic() < self.deadline, "shard deadline expired")
        self.pump_server()
        request = {"v": 1, "op": op, **fields}
        value = self.raw_request(json.dumps(request, separators=(",", ":")).encode())
        if not hasattr(self, "protocol_log"):
            self.protocol_log = bytearray()
        observed = encode({"request": request, "response": value})
        self.captured += len(observed)
        n.require(self.captured <= n.MAX_ALL_CAPTURE, "total protocol/process capture bound exceeded")
        self.protocol_log.extend(observed)
        n.require(isinstance(value, dict) and value.get("v") == 1 and value.get("ok") is True,
                  f"native {op} refused: {value.get('error') if isinstance(value, dict) else 'bad envelope'}")
        n.require(isinstance(value.get("result"), dict), "native response lacks result object")
        return value["result"]

    def prepare(self, data: bytes) -> str:
        self.preflight()
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile",
                                        str(self.state), "example", str(self.fixture)])
        n.require(code == 0, "profile installation failed")
        installed = n.strict_json(stdout)
        n.require(installed.get("executable_digest") == digest(self.fixture), "installed fixture digest differs")
        self.start()
        n.write_synthetic(self.work / "data.ndjson", data)
        staged = self.cli("stage", f"data.ndjson={self.work / 'data.ndjson'}")
        stage = staged.get("stage_id")
        n.require(isinstance(stage, str) and n.ID.fullmatch(stage), "invalid stage identity")
        json_file(self.work / "stage.json", staged)
        return stage


class Campaign:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.work = n.absolute(args.work)
        self.rows: list[dict[str, Any]] = []
        self.serial = 0
        self.shard_serial = 0
        self.allocated = 0
        self.retained_inodes = 0
        self.reserve: list[tuple[str, int, int]] = []
        self.reserve_directory: tuple[int, int] | None = None
        self.deadline = time.monotonic() + MAX_CAMPAIGN_SECONDS
        self.failed = False
        self.active: Shard | None = None
        self.environment_id = ""
        self.run_id = n.secrets.token_hex(16)
        self.workloads = ("B-01", "B-02") if args.workload == "both" else (args.workload,)
        self.transform_fields = ("count", "sum", "min", "max") if args.aggregate_fixture else ("count", "sum")
        self.transform_concurrency = (1, 4) if args.aggregate_fixture else (1, 2, 4)
        self.shortfalls = [*SHORTFALLS]
        if "B-02" in self.workloads and not args.aggregate_fixture:
            self.shortfalls.append("The C fixture measures count and sum. B-02 also requires the Rust fixture and extrema.")

    def preflight(self) -> None:
        # Use the same mandatory host/storage/owner/descriptor checks as native E2E.
        initial = Shard(self.args)
        self.active = initial
        initial.preflight()
        errors = initial.cleanup()
        self.active = None
        n.require(not errors, f"root preflight teardown failed: {errors}")
        self.storage_checkpoint("campaign-start")
        n.new_private(self.work / ".finalization-reserve")
        reserve_info = (self.work / ".finalization-reserve").lstat()
        self.reserve_directory = (reserve_info.st_dev, reserve_info.st_ino)
        for index in range(RESERVE_FILES):
            name = f"{index:03d}"
            path = self.work / ".finalization-reserve" / name
            n.write_synthetic(path, b"\0" * RESERVE_FILE_BYTES)
            info = path.lstat()
            self.reserve.append((name, info.st_dev, info.st_ino))
        build = n.strict_json(n.read_file(n.absolute(self.args.build_record), 64 * 1024))
        n.require(build.get("source_sha256") == c.source_digest(ROOT), "build record does not match current public source")
        n.require(isinstance(build.get("rustc_verbose"), str) and build["rustc_verbose"].startswith("rustc 1.99.1 "),
                  "build record must identify pinned Rust 1.99.1")
        n.require(build.get("profile") == "release" and isinstance(build.get("optimization_flags"), list)
                  and build["optimization_flags"] and isinstance(build.get("target"), str), "missing release optimization/target record")
        n.require(isinstance(build.get("build_command"), list) and build["build_command"]
                  and n.DIGEST.fullmatch(build.get("capture_manifest_sha256", "")), "missing captured build provenance")
        binaries = {name: digest(n.absolute(self.args.bin_dir) / name) for name in
                    ("hearthrun", "hearthrun-supervisor", "hearthrun-launcher")}
        n.require(build.get("binary_sha256") == binaries, "binary bytes differ from pinned build record")
        filesystem, mount_options = n.mount_for(self.work)
        environment: dict[str, Any] = {
            "runtime": "actual local Linux native supervisor/launcher", "kernel": platform.release(),
            "machine": platform.machine(), "cpu_count": os.cpu_count(), "build": build,
            "fixture_sha256": digest(n.absolute(self.args.fixture)),
            "fixture_source_sha256": digest(ROOT / "fixtures/native/task.c"),
            "doctor_sha256": digest(n.absolute(self.args.doctor)),
            "source_sha256": c.source_digest(ROOT), "python": platform.python_version(),
            "mount": {"filesystem": filesystem, "options": sorted(mount_options)}, "background_load_start": os.getloadavg(),
            "host_record": json.loads(n.read_file(n.absolute(self.args.host_record), 32 * 1024)),
            "clock": time.get_clock_info("monotonic").implementation,
            "mode": self.args.mode, "campaign_seed": self.args.seed,
        }
        if self.args.aggregate_fixture:
            aggregate_path = n.absolute(self.args.aggregate_fixture)
            n.require(aggregate_path.resolve(strict=True) == aggregate_path and aggregate_path.is_file()
                      and os.access(aggregate_path, os.X_OK), "aggregate fixture must be an exact executable file")
            aggregate = build.get("rust_aggregate")
            n.require(isinstance(aggregate, dict) and aggregate.get("fixture_sha256") == digest(aggregate_path)
                      and aggregate.get("source_sha256") == digest(AGGREGATE_CORE)
                      and aggregate.get("entry_source_sha256") == digest(AGGREGATE_ENTRY)
                      and n.DIGEST.fullmatch(aggregate.get("capture_manifest_sha256", ""))
                      and n.DIGEST.fullmatch(aggregate.get("core_capture_manifest_sha256", ""))
                      and n.DIGEST.fullmatch(aggregate.get("archive_sha256", ""))
                      and isinstance(aggregate.get("build_command"), list) and aggregate["build_command"]
                      and isinstance(aggregate.get("core_build_command"), list) and aggregate["core_build_command"],
                      "Rust aggregate executable or build provenance differs")
            environment["rust_aggregate"] = aggregate
        for field, path, bound in (("cpuinfo", "/proc/cpuinfo", 1024 * 1024),
                                   ("meminfo", "/proc/meminfo", 64 * 1024),
                                   ("boot_id", "/proc/sys/kernel/random/boot_id", 128),
                                   ("cgroup_controllers", str(n.absolute(self.args.cgroup_root) / "cgroup.controllers"), 4096)):
            raw = n.read_file(Path(path), bound, virtual=True).decode("utf-8")
            if field == "cpuinfo":
                raw = "\n".join(sorted({line for line in raw.splitlines() if line.startswith(("model name", "cpu cores", "siblings"))}))
            environment[field] = raw
        host = environment["host_record"]
        n.require(isinstance(host, dict) and all(key in host for key in
                  ("power_policy", "background_load_control", "filesystem_mount_options", "landlock_abi", "seccomp_mode")),
                  "host record lacks mandatory operator observations")
        self.environment_id = hashlib.sha256(encode(environment)).hexdigest()
        environment["environment_id"] = self.environment_id
        json_file(self.work / "environment.json", environment)
        json_file(self.work / "schedule.json", {"run_id": self.run_id, "mode": self.args.mode,
            "seed": self.args.seed, "shard_native_request_limit": SHARD_JOBS,
            "workloads": self.workloads, "transform_fields": self.transform_fields,
            "transform_concurrency": self.transform_concurrency,
            "storage_policy": {"format": "hearthrun-shard-tar-gzip-v1", "headroom_bytes": SHARD_HEADROOM_BYTES,
                "headroom_inodes": SHARD_HEADROOM_INODES, "retained_bytes_bound": MAX_EVIDENCE_BYTES,
                "finalization_reserved_bytes": RESERVE_FILES * RESERVE_FILE_BYTES,
                "finalization_reserved_inodes": RESERVE_FILES + 1},
            "full_counts": {"B-01": "5 batches x concurrency 1/2/4 x (30 warmup +1000 measured) x 2 backends",
                            "B-02": f"5 seeds x 3 sizes x concurrency {self.transform_concurrency} x (30 warmup +100 measured)"},
            "scope_shortfalls": self.shortfalls})

    def release_reserve(self) -> None:
        if self.reserve_directory is None:
            return
        parent = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        directory = None
        try:
            directory = os.open(".finalization-reserve", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
            info = os.fstat(directory)
            n.require((info.st_dev, info.st_ino) == self.reserve_directory, "finalization reserve identity changed")
            for name, device, inode in self.reserve:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                n.require((info.st_dev, info.st_ino) == (device, inode) and stat.S_ISREG(info.st_mode)
                          and info.st_uid == os.geteuid(), "finalization reserve file identity changed")
                os.unlink(name, dir_fd=directory)
            os.rmdir(".finalization-reserve", dir_fd=parent)
            os.fsync(parent)
            self.reserve = []
            self.reserve_directory = None
        finally:
            if directory is not None:
                os.close(directory)
            os.close(parent)

    def account(self) -> None:
        self.allocated = 0
        self.retained_inodes = 1
        for parent, directories, files in os.walk(self.work, followlinks=False):
            for name in directories + files:
                info = (Path(parent) / name).lstat()
                self.allocated += max(info.st_size, info.st_blocks * 512)
                self.retained_inodes += 1

    def storage_checkpoint(self, context: str) -> None:
        self.account()
        observed = capacity(self.work)
        with (self.work / "storage.jsonl").open("ab") as stream:
            stream.write(encode({"context": context, "monotonic_ns": time.monotonic_ns(), **observed,
                "required_bytes": SHARD_HEADROOM_BYTES, "required_inodes": SHARD_HEADROOM_INODES,
                "retained_accounted_bytes": self.allocated, "retained_inodes": self.retained_inodes}))
            stream.flush()
            os.fsync(stream.fileno())
        n.require(self.allocated <= MAX_EVIDENCE_BYTES, "retained evidence exceeded 2GB campaign bound")
        n.require(observed["available_bytes"] >= SHARD_HEADROOM_BYTES
                  and observed["available_inodes"] >= SHARD_HEADROOM_INODES,
                  "insufficient byte/inode headroom for a new shard; partial evidence retained")

    def save(self, row: dict[str, Any]) -> None:
        n.require(len(self.rows) < 40_000, "sample count bound exceeded")
        self.rows.append(row)
        self.failed |= row["status"] != "PASS"
        with (self.work / "samples.jsonl").open("ab") as stream:
            stream.write(encode(row))
            stream.flush()
            os.fsync(stream.fileno())

    def sample(self, workload: str, phase: str, batch: int, seed: int, size: int,
               concurrency: int, backend: str, index: int) -> dict[str, Any]:
        self.serial += 1
        row = {"run_id": f"{self.run_id}-{self.serial:06d}", "campaign_id": self.run_id,
               "environment_id": self.environment_id, "policy_digest": None,
               "workload": workload, "phase": phase, "batch": batch, "seed": seed,
               "sample_index": index, "concurrency": concurrency, "backend": backend,
               "bytes": size, "submit_ns": None, "start_ns": None, "finish_ns": None,
               "cancel_ns": None, "cleanup_ns": None, "status": "FAIL", "exit_code": None,
               "max_rss_bytes": None, "cpu_usec": None, "output_digest": None,
               "duration_ms": None, "execution_only_ms": None, "throughput_bytes_per_second": None,
               "observed_running_ns": None, "running_seen_per_sweep": 0,
               "start_clock": "supervisor-relative Instant; not comparable to Python monotonic",
               "terminal_clock": "Python monotonic_ns after inspect confirms terminal cleanup",
               "shard": self.shard_serial, "job_id": None, "error": None}
        # An fsynced intent preserves attempts even if the driver is interrupted.
        with (self.work / "attempts.jsonl").open("ab") as stream:
            stream.write(encode({"run_id": row["run_id"], "status": "STARTED", "planned": row}))
            stream.flush()
            os.fsync(stream.fileno())
        return row

    def native_wave(self, h: Shard, stage: str, rows: list[dict[str, Any]], expected: dict[str, int] | None) -> None:
        pending: dict[str, dict[str, Any]] = {}
        completed = []
        try:
            for row in rows:
                row["submit_ns"] = time.monotonic_ns()
                response = h.rpc("submit", request_id=n.secrets.token_hex(16), profile_id="example",
                                 stage_id=stage, argv=["empty" if expected is None else "summary"], wall_ms=60000)
                job = response.get("job_id")
                n.require(isinstance(job, str) and n.ID.fullmatch(job), "submit lacks job identity")
                h.jobs.add(job)
                row["job_id"] = job
                pending[job] = row
            deadline = min(h.deadline, time.monotonic() + 75)
            while pending:
                running = []
                for job, row in list(pending.items()):
                    view = h.rpc("inspect", job_id=job)
                    if view.get("state") == "RUNNING":
                        running.append(row)
                        row["observed_running_ns"] = row["observed_running_ns"] or time.monotonic_ns()
                    if view.get("state") not in n.TERMINAL:
                        continue
                    row["finish_ns"] = time.monotonic_ns()
                    row["duration_ms"] = (row["finish_ns"] - row["submit_ns"]) / 1e6
                    completed.append((job, row, view))
                    del pending[job]
                for row in running:
                    row["running_seen_per_sweep"] = max(row["running_seen_per_sweep"], len(running))
                n.require(time.monotonic() < deadline, "wave terminal deadline expired")
                if pending:
                    time.sleep(.001)
            # Verify/export/read/fsync only after every wave endpoint is observed;
            # this keeps those operations out of later jobs' latency intervals.
            for job, row, view in completed:
                record = h.record(job)
                row["policy_digest"] = record["policy_digest"]
                row["profile_digest"] = record["profile_digest"]
                row["start_ns"] = record["started_monotonic_ns"]
                row["exit_code"] = (record["observed_exit"] or {}).get("exit_code")
                row["exit_signal"] = (record["observed_exit"] or {}).get("signal")
                row["cleanup_confirmed"] = view.get("cleanup_confirmed")
                n.require(view.get("state") == "SUCCEEDED" and view.get("cleanup_confirmed") is True,
                          f"native unsuccessful terminal: {view.get('state')}")
                metadata, stdout, stderr = h.verify_result(job, "SUCCEEDED")
                n.require(not stdout and not stderr, "approved fixture emitted unexpected diagnostics")
                n.require(h.group_name(job) not in h.group_names(), "native leaf persists after terminal")
                row["output_digest"] = view.get("result_digest")
                row["artifact_verified_ns"] = time.monotonic_ns()
                artifacts = []
                if expected is None:
                    n.require(metadata["artifacts"] == [], "empty fixture produced artifacts")
                else:
                    raw = n.read_file(h.state / "results" / job / "artifacts/summary.json", 1024, owner=True, mode=0o600)
                    result = n.strict_json(raw)
                    n.require(result == expected and all(type(value) is int for value in result.values()),
                              "independent aggregation oracle differs")
                    n.require(len(metadata["artifacts"]) == 1 and metadata["artifacts"][0]["path"] == "summary.json",
                              "transform artifact set differs")
                    row["verified_output"] = result
                    row["artifact_sha256"] = hashlib.sha256(raw).hexdigest()
                    artifacts.append({"path": "summary.json", "content_hex": raw.hex(),
                                      "sha256": row["artifact_sha256"]})
                    row["throughput_bytes_per_second"] = row["bytes"] * 1e9 / (row["finish_ns"] - row["submit_ns"])
                # Runtime retention can evict an earlier result after 100 jobs.
                # Preserve its verified bytes in one aggregate before later waves.
                raw_metadata = n.read_file(h.state / "results" / job / "result.json", n.MAX_HEADER,
                                           owner=True, mode=0o600)
                verified_result = encode({"run_id": row["run_id"], "job_id": job, "record": record,
                    "result_digest": row["output_digest"], "metadata_hex": raw_metadata.hex(),
                    "stdout_hex": stdout.hex(), "stderr_hex": stderr.hex(), "artifacts": artifacts})
                n.require(len(verified_result) <= 16 * 1024, "verified result summary exceeds analysis line bound")
                with (h.work / "verified-results.jsonl").open("ab") as stream:
                    stream.write(verified_result)
                    stream.flush()
                    os.fsync(stream.fileno())
                row["status"] = "PASS"
                self.save(row)
        except BaseException as error:
            for row in rows:
                if row not in self.rows:
                    if row["submit_ns"] is not None:
                        row["finish_ns"] = row["finish_ns"] or time.monotonic_ns()
                        row["duration_ms"] = (row["finish_ns"] - row["submit_ns"]) / 1e6
                    row["error"] = f"{type(error).__name__}: {error}"[:1024]
                    self.save(row)
            raise

    def direct_wave(self, h: Shard, rows: list[dict[str, Any]]) -> None:
        children = []
        try:
            for row in rows:
                row["policy_digest"] = "DIRECT_NO_SANDBOX"
                row["start_clock"] = "not observable; Python Popen call begins at submit_ns"
                row["submit_ns"] = time.monotonic_ns()
                process = n.Process(h, f"direct-{row['run_id']}", [str(h.fixture), "empty"])
                h.children.append(process)
                children.append((row, process))
            pending = list(children)
            deadline = min(h.deadline, time.monotonic() + 10)
            while pending:
                for row, process in list(pending):
                    if process.poll() is None:
                        continue
                    row["finish_ns"] = time.monotonic_ns()
                    row["duration_ms"] = (row["finish_ns"] - row["submit_ns"]) / 1e6
                    pending.remove((row, process))
                n.require(time.monotonic() < deadline, "direct wave deadline expired")
                if pending:
                    time.sleep(.001)
            for row, process in children:
                code = process.wait(1)
                row["exit_code"] = code
                n.require(code == 0 and not any(process.buffers.values()), "direct empty fixture failed or emitted output")
                row["status"] = "PASS"
                self.save(row)
        except BaseException as error:
            for row in rows:
                if row not in self.rows:
                    row["finish_ns"] = time.monotonic_ns()
                    if row["submit_ns"] is not None:
                        row["duration_ms"] = (row["finish_ns"] - row["submit_ns"]) / 1e6
                    row["error"] = f"{type(error).__name__}: {error}"[:1024]
                    self.save(row)
            raise

    def close_shard(self, h: Shard, succeeded: bool) -> None:
        errors = h.cleanup()
        self.active = None
        json_file(h.work / "teardown.json", {"status": "FAIL" if errors else "PASS", "errors": errors})
        rows = [row for row in self.rows if row["shard"] == self.shard_serial]
        json_file(h.work / "shard-summary.json", {"shard": self.shard_serial,
            "status": "PASS" if succeeded and not errors and all(row["status"] == "PASS" for row in rows) else "FAIL",
            "samples": len(rows), "run_ids": [row["run_id"] for row in rows],
            "rows_sha256": hashlib.sha256(b"".join(encode(row) for row in rows)).hexdigest()})
        n.require(not errors, f"shard teardown failed: {errors}")
        if succeeded and all(row["status"] == "PASS" for row in rows):
            n.require(all(child.proc.poll() is not None and not child.pipes for child in h.children),
                      "refusing compaction before owned child reaping/pipe closure")
            compact_shard(h)
        self.account()
        n.require(self.allocated <= MAX_EVIDENCE_BYTES, "retained shard evidence exceeded 2GB campaign bound")

    def run_group(self, workload: str, batch: int, seed: int, size: int, concurrency: int) -> None:
        warmups, repetitions = (2, 4) if self.args.mode == "smoke" else (30, 1000 if workload == "B-01" else 100)
        data, reference = fixture_bytes(size or 64, seed)
        expected = {key: reference[key] for key in self.transform_fields} if workload == "B-02" else None
        rng = random.Random(self.args.seed + batch * 10000 + seed * 100 + size + concurrency)
        planned = [("warmup" if index < warmups else "measured", index) for index in range(warmups + repetitions)]
        for offset in range(0, len(planned), SHARD_JOBS):
            n.require(time.monotonic() < self.deadline, "campaign deadline expired")
            self.storage_checkpoint(f"before-shard-{self.shard_serial + 1:04d}")
            self.shard_serial += 1
            hargs = argparse.Namespace(**vars(self.args))
            hargs.work = str(self.work / f"shard-{self.shard_serial:04d}")
            if workload == "B-02" and self.args.aggregate_fixture:
                hargs.fixture = self.args.aggregate_fixture
            h = Shard(hargs)
            self.active = h
            succeeded = False
            try:
                stage = h.prepare(data)
                json_file(h.work / "input.json", {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                    "seed": seed, "reference": reference, "generator": "fixed 64-byte NDJSON rows / Python random.Random"})
                part = planned[offset:offset + SHARD_JOBS]
                for wave in range(0, len(part), concurrency):
                    segment = part[wave:wave + concurrency]
                    # Separate warmup/measured waves so neither population contaminates the other.
                    for phase in dict.fromkeys(item[0] for item in segment):
                        entries = [item for item in segment if item[0] == phase]
                        backends = ["native", "direct"] if workload == "B-01" else ["native"]
                        rng.shuffle(backends)
                        for backend in backends:
                            rows = [self.sample(workload, phase, batch, seed, size, concurrency, backend, index)
                                    for _, index in entries]
                            if backend == "native":
                                self.native_wave(h, stage, rows, expected)
                            else:
                                self.direct_wave(h, rows)
                succeeded = True
            finally:
                if h.created_work:
                    self.close_shard(h, succeeded)
                else:
                    errors = h.cleanup()
                    self.active = None
                    n.require(not errors, f"preflight cleanup failed: {errors}")

    def hold_smoke(self) -> None:
        self.storage_checkpoint(f"before-shard-{self.shard_serial + 1:04d}")
        self.shard_serial += 1
        hargs = argparse.Namespace(**vars(self.args))
        hargs.work = str(self.work / f"shard-{self.shard_serial:04d}")
        h = Shard(hargs)
        self.active = h
        succeeded = False
        try:
            stage = h.prepare(b'{"value":0}\n')
            details = h.cancel_case(stage)
            json_file(h.work / "hold-control.json", {"status": "PASS", "scope": "separate functional control; not B-03 timing", **details})
            succeeded = True
        finally:
            if h.created_work:
                self.close_shard(h, succeeded)
            else:
                errors = h.cleanup()
                self.active = None
                n.require(not errors, f"hold preflight cleanup failed: {errors}")

    def summary(self, interrupted: str | None) -> None:
        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = collections.defaultdict(list)
        for row in self.rows:
            groups[(row["workload"], row["phase"], row["backend"], row["bytes"], row["concurrency"], row["policy_digest"])].append(row)
        results = []
        for identity, rows in groups.items():
            success = sorted(row["duration_ms"] for row in rows if row["status"] == "PASS")
            all_timed = sorted(row["duration_ms"] for row in rows if row["duration_ms"] is not None)
            def distribution(values: list[float]) -> dict[str, Any]:
                return {"count": len(values), "min_ms": min(values) if values else None,
                        "max_ms": max(values) if values else None,
                        **{f"p{q}_ms": values[max(0, math.ceil(q / 100 * len(values)) - 1)] if values else None for q in (50, 95, 99)}}
            batch_medians = {str(batch): statistics.median(values) for batch in sorted({row["batch"] for row in rows})
                             if (values := [row["duration_ms"] for row in rows if row["batch"] == batch and row["status"] == "PASS"])}
            results.append({"workload_phase_backend_bytes_concurrency_policy": identity,
                "samples_total": len(rows), "samples_success": len(success), "samples_failed": len(rows) - len(success),
                "success_fraction": len(success) / len(rows), "successful_latency": distribution(success),
                "all_attempt_observed_duration": distribution(all_timed), "untimed_attempts": len(rows) - len(all_timed),
                "batch_success_median_ms": batch_medians,
                "cross_batch_median_range_ms": max(batch_medians.values()) - min(batch_medians.values()) if batch_medians else None,
                "p99_warning": "exploratory below 1000 successful samples" if len(success) < 1000 else None})
        json_file(self.work / "summary.json", {"status": "FAIL" if self.failed or interrupted else "PASS",
            "scope": self.args.mode, "acceptance_status": "NOT ESTABLISHED; scoped campaign and independent review required",
            "interrupted": interrupted, "completed_samples": len(self.rows), "quantile_method": "nearest rank",
            "latency_population": "successful samples; all-attempt observed durations separately, failures retained in denominator",
            "groups": results, "scope_shortfalls": self.shortfalls, "retained_shard_accounted_bytes": self.allocated,
            "retained_accounted_inodes": self.retained_inodes,
            "background_load_end": os.getloadavg()})


SHORTFALLS = [
    "Direct baseline is same empty binary without sandbox; Python Popen-to-reap versus native submit-to-terminal observation includes different client/IPC costs; no subtraction/ranking as equivalent isolation.",
    "Native start_ns uses supervisor-relative Instant, not Python monotonic epoch. No submit-to-RUNNING duration is derived; short jobs may never be polled RUNNING.",
    "No trusted execution-end/CPU/peak-memory telemetry; execution_only_ms/cpu_usec/max_rss_bytes remain null.",
    "Configured concurrency means bounded waves, not proven simultaneous guest execution; running_seen_per_sweep is sequential polling and does not prove overlap.",
    "Fresh 128-ID shards change cold/cache state; successful stopped shard transients are losslessly compacted after verified teardown; failed diagnostics remain unmodified.",
    "B-03/B-04/B-05/B-06/B-07 and native pass/fail/pass performance negative controls are outside this driver.",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bin-dir", "doctor", "fixture", "cgroup-root", "work", "build-record", "host-record"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--mode", choices=("smoke", "full"), required=True)
    parser.add_argument("--workload", choices=("both", "B-01", "B-02"), default="both")
    parser.add_argument("--aggregate-fixture", help="approved static Rust B-02 executable; keep --fixture for the held-job control")
    parser.add_argument("--seed", type=int, default=21080)
    args = parser.parse_args()
    if args.aggregate_fixture and args.workload == "B-01":
        parser.error("--aggregate-fixture requires B-02")
    campaign = Campaign(args)
    error = None
    code = 1
    def terminate(_signum: int, _frame: Any) -> None:
        raise n.Failure("campaign termination requested")
    signal.signal(signal.SIGTERM, terminate)
    try:
        campaign.preflight()
        campaign.hold_smoke()
        batches = range(1 if args.mode == "smoke" else 5)
        if "B-01" in campaign.workloads:
            for batch in batches:
                for concurrency in (1, 2, 4):
                    campaign.run_group("B-01", batch, args.seed + batch, 0, concurrency)
        if "B-02" in campaign.workloads:
            for seed in batches:
                for size in SIZES:
                    for concurrency in campaign.transform_concurrency:
                        campaign.run_group("B-02", seed, seed, size, concurrency)
        code = 1 if campaign.failed else 0
    except n.Blocked as exc:
        error, code = str(exc), 78
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"[:1024]
    finally:
        try:
            campaign.release_reserve()
        except Exception as exc:
            error = f"{error}; finalization reserve: {type(exc).__name__}: {exc}"[:2048]
            code = 1
        if campaign.active is not None:
            cleanup_errors = campaign.active.cleanup()
            if cleanup_errors:
                error = f"{error}; teardown: {cleanup_errors}"[:2048]
                code = 1
        if campaign.work.exists() and campaign.environment_id:
            try:
                campaign.account()
                campaign.summary(error)
            except Exception as exc:
                error = f"{error}; summary: {type(exc).__name__}: {exc}; raw attempts/samples retained"[:2048]
                code = 1
        print(json.dumps({"case": "benchmark_campaign", "status": "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL",
                          "mode": args.mode, "completed_samples": len(campaign.rows), "error": error}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
