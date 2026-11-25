#!/usr/bin/env python3
"""B-06 native lifecycle retention, no provisioning/builds or mid-seed resets.

Full = five seeds, EACH 1000 jobs in waves of four on one live supervisor/store.
Smoke = one seed, 16 jobs; it never establishes B-06. Supply absolute existing
--public-root --bin-dir --doctor --fixture --fixture-source --cgroup-root
--build-record --host-record, and NEW --work on approved bounded noswap tmpfs.
Capture this command through scripts/capture.py. The product enforces its own
catalog and byte limits. A typed STORAGE_FULL is a failed attempt and all
remaining jobs in that seed stay NOT RUN. The driver never replaces the store.

RPCs use the native helper's authenticated bounded Unix socket/framing checks;
only profile install, readiness and stage use CLI subprocesses. Process capture
keeps the native 8MiB total bound; protocol journals have256MiB total,
128KiB/row and40,000 RPC/seed bounds. Samples have a separate16KiB/row budget,
planned_count*16KiB actual pre-run disk reservation and a preallocated summary.
No CLI-per-job inflation. Failed appends roll back or seal an uncertain tail;
finalization preserves the full denominator in a distinct recovery file.
Only five fixed approved benign fixture modes are executable. No direct host
execution controls or arbitrary workload/path/size arguments are supported.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from functools import lru_cache
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import signal
import stat
import sys
import time
from typing import Any

sys.dont_write_bytecode = True
SIZES = (4096, 16384, 65536, 262144, 1048576)
MAX_JOURNAL = 256 * 1024 * 1024
MAX_ROW = 128 * 1024
MAX_SAMPLE_ROW = 16 * 1024
MAX_SUMMARY = 128 * 1024
MAX_RPC = 40_000
OBSERVER_RECORD_BOUND = 2048  # Observer bound, never a mutation of product cap.
MAX_CAMPAIGN_SECONDS = 3 * 3600
LIMITS = {"memory.max": "268435456", "memory.swap.max": "0", "memory.oom.group": "1",
          "pids.max": "32", "cpu.max": "100000 100000"}


def require(value: Any, detail: str) -> None:
    if not value:
        raise ValueError(detail)


def encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def parse(raw: bytes, bound: int = MAX_ROW) -> Any:
    require(len(raw) <= bound, "JSON evidence exceeds bounded read")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def constant(_value: str) -> None:
        raise ValueError("nonfinite JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


@lru_cache(maxsize=5)
def oracle(variant: int) -> tuple[int, str]:
    require(type(variant) is int and 0 <= variant < 5, "unknown fixed fixture mode")
    period = bytes((17 * index + 29 * variant + 3) % 256 for index in range(256))
    size = SIZES[variant]
    return size, hashlib.sha256(period * (size // 256)).hexdigest()


def schedule(mode: str, master_seed: int, run_id: str) -> tuple[list[int], list[dict[str, Any]]]:
    require(mode in {"smoke", "full"}, "unknown retention mode")
    seeds = random.Random(master_seed).sample(range(1 << 32), 5 if mode == "full" else 1)
    rows = []
    for seed_index, seed in enumerate(seeds):
        for index in range(1000 if mode == "full" else 16):
            variant = (seed + index) % 5
            size, digest = oracle(variant)
            rows.append({"benchmark": "B-06", "run_id": run_id, "sample_index": len(rows), "seed_index": seed_index,
                         "seed": seed, "job_index": index, "wave": index // 4, "concurrency": 4,
                         "workload": f"v{variant}", "variant": variant, "bytes": size, "expected_sha256": digest,
                         "request_id": hashlib.sha256(f"B06 {run_id} {seed} {index}".encode()).hexdigest()[:32],
                         "job_id": None, "status": "NOT RUN", "submit_ns": None, "start_ns": None,
                         "finish_ns": None, "cancel_ns": None, "cleanup_ns": None, "exit_code": None,
                         "max_rss_bytes": None, "cpu_usec": None, "output_digest": None, "reason": None,
                         "start_clock": "supervisor-relative Instant; incomparable with harness monotonic submit/finish clocks"})
    return seeds, rows


def slope(points: list[dict[str, Any]], field: str, required: int = 1000) -> dict[str, Any]:
    # Late growth per completed job. No rate/plateau claim from truncated seeds.
    selected = [point for point in points if point["completed_jobs"] >= 500]
    if not points or points[-1]["completed_jobs"] != required or len(selected) < 2:
        return {"status": "NOT YET MEASURED", "per_job": None, "n": len(selected), "reason": "full sustained seed incomplete"}
    xs = [point["completed_jobs"] for point in selected]
    ys = [point[field] for point in selected]
    xbar, ybar = sum(xs) / len(xs), sum(ys) / len(ys)
    denominator = sum((value - xbar) ** 2 for value in xs)
    require(denominator > 0 and all(math.isfinite(value) for value in ys), "invalid slope population")
    return {"status": "MEASURED", "per_job": sum((x - xbar) * (y - ybar) for x, y in zip(xs, ys)) / denominator,
            "n": len(xs), "first_completed": xs[0], "last_completed": xs[-1], "method": "ordinary least squares, unweighted late wave snapshots"}


class Refusal(RuntimeError):
    def __init__(self, response: dict[str, Any]):
        super().__init__(f"native refusal: {response.get('error')}")
        self.response = response


class AppendFailure(RuntimeError):
    def __init__(self, committed_prefix: int, error: BaseException, rollback_error: BaseException | None):
        self.committed_prefix = committed_prefix
        self.rolled_back = rollback_error is None
        self.rollback_error = None if rollback_error is None else f"{type(rollback_error).__name__}: {rollback_error}"
        super().__init__(f"evidence append failed at committed prefix {committed_prefix}: {type(error).__name__}: {error}; rollback={self.rollback_error or 'fsynced'}")


def write_all(fd: int, raw: bytes, io_ops: Any = os) -> None:
    pending = memoryview(raw)
    while pending:
        written = io_ops.write(fd, pending)
        if written <= 0:
            raise OSError("evidence write made no progress")
        pending = pending[written:]


def transactional_append(fd: int, raw: bytes, io_ops: Any = os) -> int:
    """Commit a whole JSONL row or restore/fsync its exact prior prefix."""
    start = io_ops.lseek(fd, 0, os.SEEK_END)
    try:
        write_all(fd, raw, io_ops)
        io_ops.fsync(fd)
    except BaseException as error:
        rollback_error = None
        try:
            io_ops.ftruncate(fd, start)
            io_ops.fsync(fd)
        except BaseException as rollback:
            rollback_error = rollback
        raise AppendFailure(start, error, rollback_error) from error
    return start + len(raw)


def validate_profile(profile: dict[str, Any], manifest_raw: bytes, image: bytes, expected: str) -> str:
    require(re.fullmatch(r"[a-f0-9]{64}", expected) is not None, "captured fixture digest missing")
    require(profile.get("profile_id") == "example" and profile.get("executable_digest") == expected
            and hashlib.sha256(image).hexdigest() == expected, "installed executable differs from captured approved fixture")
    require(parse(manifest_raw) == {"v": 1, "profile_id": "example", "sha256": expected}
            and profile.get("profile_digest") == hashlib.sha256(manifest_raw).hexdigest(), "retained profile manifest differs from installation acknowledgement")
    return profile["profile_digest"]


def validate_record_identity(row: dict[str, Any], record: dict[str, Any], executable: str, profile: str,
                             stage_manifest: str, stage_id: str | None = None, require_ack: bool = True) -> None:
    require(row["request_id"] == hashlib.sha256(f"B06 {row['run_id']} {row['seed']} {row['job_index']}".encode()).hexdigest()[:32],
            "request ID differs from immutable schedule")
    require(row["workload"] == f"v{row['variant']}" and (row["bytes"], row["expected_sha256"]) == oracle(row["variant"]), "scheduled fixture mode/oracle differs")
    submitted = row.get("submission")
    require(isinstance(submitted, dict), "durable record lacks recorded submission intent")
    expected = {"v": 1, "op": "submit", "request_id": row["request_id"], "profile_id": "example",
                "stage_id": stage_id if stage_id is not None else submitted.get("stage_id"),
                "argv": [row["workload"]], "wall_ms": 10000}
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"))
    require(isinstance(expected["stage_id"], str) and re.fullmatch(r"[a-f0-9]{32}", expected["stage_id"]), "actual staged identity missing")
    require(json.dumps(submitted, sort_keys=True, separators=(",", ":")) == canonical and record.get("canonical_request") == canonical
            and record.get("canonical_request_sha256") == hashlib.sha256(canonical.encode()).hexdigest(), "durable canonical request differs from exact scheduled submission")
    require(type(record.get("v")) is int and record["v"] == 1 and record.get("request_id") == row["request_id"] and record.get("profile_id") == "example"
            and record.get("stage_id") == expected["stage_id"] and record.get("stage_manifest_digest") == stage_manifest
            and record.get("profile_digest") == profile and record.get("executable_digest") == executable,
            "durable job identity or approved executable/profile/stage differs")
    require(isinstance(record.get("job_id"), str) and re.fullmatch(r"[a-f0-9]{32}", record["job_id"]), "invalid durable job ID")
    require(row.get("job_id") is None or row["job_id"] == record["job_id"], "durable job differs from acknowledged job")
    if require_ack:
        require(isinstance(row.get("submit_ack"), dict) and row["submit_ack"].get("job_id") == record["job_id"]
                and row["submit_ack"].get("state") == "QUEUED" and type(row["submit_ack"].get("sequence")) is int
                and row["submit_ack"]["sequence"] == 1
                and row["job_id"] == record["job_id"] and type(row.get("submit_rpc_id")) is int and row["submit_rpc_id"] > 0,
                "durable job lacks exact authenticated submit acknowledgement")


class Journal:
    def __init__(self, root: Path, rows: list[dict[str, Any]], schedule_sha256: str):
        self.fds: dict[str, int] = {}
        self.root_fd: int | None = None
        self.bytes = 0
        self.sizes: dict[str, int] = {}
        self.identities: dict[str, tuple[int, int]] = {}
        self.poisoned: dict[str, dict[str, Any]] = {}
        self.errors: list[dict[str, Any]] = []
        self.sample_indices: dict[str, set[int]] = {"samples.jsonl": set(), "samples-recovery.jsonl": set()}
        self.planned = [(row["run_id"], row["seed"], row["job_index"], row["request_id"]) for row in rows]
        require(0 < len(rows) <= 5000, "invalid reserved sample denominator")
        self.sample_bound = len(rows) * MAX_SAMPLE_ROW
        self.finalizing = False
        self.reserve_released = False
        self.schedule_sha256 = schedule_sha256
        try:
            capacity = os.statvfs(root)
            require(capacity.f_bavail * capacity.f_frsize >= self.sample_bound + MAX_SUMMARY + 256 * 1024 * 1024
                    and capacity.f_favail >= 16_384, "cannot physically reserve final denominator and sample/finalization headroom")
            self.root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            owner = os.fstat(self.root_fd)
            require(owner.st_uid == os.geteuid() and stat.S_ISDIR(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o700,
                    "evidence root is not the owned private directory")
            for name in ("attempts.jsonl", "samples.jsonl", "events.jsonl", "samples-recovery.jsonl", "summary.json", "finalization.reserve"):
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.root_fd)
                self.fds[name] = fd
                info = os.fstat(fd)
                self.identities[name] = info.st_dev, info.st_ino
                self.sizes[name] = 0
            baseline = {"benchmark": "B-06", "status": "INCOMPLETE", "evidence_finalized": False, "planned": len(rows),
                        "counts": None, "schedule_sha256": schedule_sha256,
                        "recovery_required": "Read immutable schedule and committed attempts/result events; do not infer PASS from an unfinished capture"}
            raw = self.summary_bytes(baseline)
            write_all(self.fds["summary.json"], raw)
            os.fsync(self.fds["summary.json"])
            self.sizes["summary.json"] = len(raw)
            # Actual writes, not sparse truncation or a claimed quota. Keep this
            # space reserved even while successful samples are saved incrementally.
            remaining = self.sample_bound
            while remaining:
                part = b"\0" * min(65536, remaining)
                write_all(self.fds["finalization.reserve"], part)
                remaining -= len(part)
            os.fsync(self.fds["finalization.reserve"])
            self.sizes["finalization.reserve"] = self.sample_bound
            os.fsync(self.root_fd)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def summary_bytes(value: Any) -> bytes:
        raw = encode(value)
        require(len(raw) <= MAX_SUMMARY, "summary exceeds preallocated finalization slot")
        return raw[:-1] + b" " * (MAX_SUMMARY - len(raw)) + b"\n"

    def checked_fd(self, name: str) -> int:
        require(name not in self.poisoned, f"evidence channel sealed after unrecoverable write: {name}")
        fd = self.fds[name]
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=self.root_fd, follow_symlinks=False)
        require((opened.st_dev, opened.st_ino) == self.identities[name] == (named.st_dev, named.st_ino)
                and opened.st_uid == os.geteuid() and stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_size == self.sizes[name],
                "owned evidence descriptor/name/size changed")
        return fd

    def save(self, name: str, value: Any) -> None:
        require(name in {"attempts.jsonl", "events.jsonl", "samples.jsonl", "samples-recovery.jsonl"}, "unknown evidence channel")
        require(name not in self.poisoned, f"evidence channel sealed after unrecoverable write: {name}")
        raw = encode(value)
        sample = name in self.sample_indices
        require(len(raw) <= (MAX_SAMPLE_ROW if sample else MAX_ROW), "bounded evidence row exhausted")
        if sample:
            index = value["sample_index"]
            require(type(index) is int and 0 <= index < len(self.planned) and index not in self.sample_indices[name]
                    and (value["run_id"], value["seed"], value["job_index"], value["request_id"]) == self.planned[index], "sample denominator/identity duplicate or mismatch")
            require(self.sizes[name] + len(raw) <= self.sample_bound, "reserved sample-channel bound exhausted")
            require(name != "samples-recovery.jsonl" or self.finalizing, "recovery channel is finalization-only")
        else:
            require(self.bytes + len(raw) <= MAX_JOURNAL, "bounded protocol journal exhausted; final samples use separate reserved capacity")
        fd = self.checked_fd(name)
        try:
            end = transactional_append(fd, raw)
        except AppendFailure as error:
            failure = {"channel": name, "committed_prefix_bytes": error.committed_prefix, "rolled_back": error.rolled_back,
                       "reason": str(error)[:2048], "rollback_error": error.rollback_error}
            self.errors.append(failure)
            if not error.rolled_back:
                # Never append behind an uncertain partial record. Retain it
                # verbatim, identify its safe prefix, and use recovery samples.
                self.poisoned[name] = failure
                self.sizes[name] = os.fstat(fd).st_size
                if not sample:
                    self.bytes = sum(self.sizes[key] for key in ("attempts.jsonl", "events.jsonl"))
            raise
        self.sizes[name] = end
        if sample:
            self.sample_indices[name].add(value["sample_index"])
        else:
            self.bytes += len(raw)

    def record_sample(self, row: dict[str, Any]) -> None:
        self.save("samples.jsonl", row)

    def begin_finalization(self) -> None:
        self.finalizing = True
        if not self.reserve_released:
            fd = self.checked_fd("finalization.reserve")
            os.ftruncate(fd, 0)
            self.sizes["finalization.reserve"] = 0
            os.fsync(fd)
            self.reserve_released = True

    def finish(self, rows: list[dict[str, Any]], summary: dict[str, Any]) -> bool:
        """Use reserved capacity even if protocol logging has exhausted/failed.

        A damaged primary sample file is retained; one separate recovery file
        contains the complete denominator instead. No uncertain tail is parsed,
        trimmed optimistically or followed by more records.
        """
        final_errors = []
        try:
            self.begin_finalization()
        except BaseException as error:
            final_errors.append(f"reserve release: {type(error).__name__}: {error}")
        target = "samples-recovery.jsonl" if "samples.jsonl" in self.poisoned else "samples.jsonl"
        try:
            for row in rows:
                if row["sample_index"] not in self.sample_indices[target]:
                    self.save(target, row)
        except BaseException as error:
            final_errors.append(f"{target}: {type(error).__name__}: {error}")
            if target == "samples.jsonl":
                target = "samples-recovery.jsonl"
                try:
                    for row in rows:
                        self.save(target, row)
                except BaseException as recovery_error:
                    final_errors.append(f"recovery denominator: {type(recovery_error).__name__}: {recovery_error}")
        complete = self.sample_indices[target] == set(range(len(self.planned)))
        evidence_good = complete and not final_errors and not self.errors and not self.poisoned
        success = evidence_good and summary["status"] == "PASS"
        report = {**summary, "status": "PASS" if success else "FAIL" if final_errors or self.errors or self.poisoned else summary["status"],
                  "planned": len(self.planned), "counts": dict(Counter(row["status"] for row in rows)),
                  "schedule_sha256": self.schedule_sha256, "samples_complete": complete,
                  "authoritative_samples_file": target, "evidence_finalized": complete and not final_errors,
                  "evidence_errors": self.errors, "finalization_errors": final_errors,
                  "recovery": {"poisoned_channels": self.poisoned,
                               "committed_prefix_bytes": {name: self.poisoned.get(name, {}).get("committed_prefix_bytes", self.sizes[name])
                                                          for name in ("attempts.jsonl", "events.jsonl", "samples.jsonl", "samples-recovery.jsonl")},
                               "rule": "Keep uncertain tails unchanged; use only declared committed prefixes and authoritative complete samples. An incomplete capture never establishes PASS."}}
        try:
            self.write_summary(report)
        except BaseException as error:
            print(json.dumps({"benchmark": "B-06", "status": "FAIL", "planned": len(self.planned),
                              "counts": report["counts"], "samples_complete": complete,
                              "authoritative_samples_file": target, "evidence_finalized": False,
                              "summary_error": f"{type(error).__name__}: {error}"[:2048],
                              "schedule_sha256": self.schedule_sha256}), file=sys.stderr)
            return False
        return evidence_good

    def write_summary(self, value: dict[str, Any]) -> None:
        fd = self.checked_fd("summary.json")
        previous = os.pread(fd, MAX_SUMMARY, 0)
        require(len(previous) == MAX_SUMMARY, "preallocated summary slot lost")
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            write_all(fd, self.summary_bytes(value))
            os.fsync(fd)
        except BaseException as error:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                write_all(fd, previous)
                os.fsync(fd)
            except BaseException as rollback:
                self.poisoned["summary.json"] = {"reason": str(error)[:2048], "rollback_error": str(rollback)[:2048]}
            raise

    def close(self) -> None:
        errors = []
        for descriptor in [*self.fds.values(), *([self.root_fd] if self.root_fd is not None else [])]:
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(str(error))
        self.fds.clear()
        self.root_fd = None
        if errors:
            raise OSError(f"evidence close failed: {errors}")


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "native helper unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def resource_fields(raw: str) -> dict[str, int]:
    result = {}
    for name in ("VmRSS", "VmHWM"):
        values = [line.split() for line in raw.splitlines() if line.startswith(name + ":")]
        require(len(values) == 1 and len(values[0]) == 3 and values[0][1].isdigit() and values[0][2] == "kB", f"missing real {name}")
        result[name + "_bytes"] = int(values[0][1]) * 1024
    require(result["VmHWM_bytes"] >= result["VmRSS_bytes"], "kernel high-water below current RSS")
    return result


def footprint(root: Path, native: Any) -> dict[str, Any]:
    """Exact file-content versus allocated accounting; no symlinks or guesses."""
    native.private_directory(root)
    owner = root.stat()
    files, content, allocated, entries = [], 0, 0, 0
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        for path in sorted(directory.iterdir()):
            entries += 1
            require(entries <= 20_000, "retention tree inventory exceeded bound")
            value = path.lstat()
            require(value.st_uid == os.geteuid() and value.st_dev == owner.st_dev, "unowned/cross-device retention entry")
            relative = f"{prefix}/{path.name}" if prefix else path.name
            allocated += value.st_blocks * 512
            if stat.S_ISDIR(value.st_mode):
                native.private_directory(path)
                stack.append((path, relative))
            else:
                require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o600,
                        "unexpected retention file type/link/mode")
                content += value.st_size
                files.append({"path": relative, "size_bytes": value.st_size, "allocated_bytes": value.st_blocks * 512})
    return {"content_bytes": content, "allocated_bytes": allocated, "entries": entries, "files": files}


def make_harness(native: Any) -> type:
    class SeedHarness(native.Harness):
        def __init__(self, args: Any, journal: Journal, seed_index: int, fixture_sha256: str):
            super().__init__(args)
            require(re.fullmatch(r"[a-f0-9]{64}", fixture_sha256), "captured approved fixture identity required")
            self.fixture_sha256 = fixture_sha256
            self.profile_digest: str | None = None
            self.stage_id: str | None = None
            self.stage_manifest_digest: str | None = None
            self.deadline = time.monotonic() + 1800
            self.journal, self.seed_index = journal, seed_index
            self.rpc_count = 0
            self.snapshot_count = 0
            self.spawn_identity: dict[str, Any] | None = None
            self.bundle_bytes: dict[str, int] = {}
            self.results: dict[str, str] = {}
            self.observed_markers: set[str] = set()
            self.last_catalog: dict[str, Any] = {}
            self.points: list[dict[str, Any]] = []
            self.rows: dict[str, dict[str, Any]] = {}

        def event(self, kind: str, **value: Any) -> None:
            self.journal.save("events.jsonl", {"type": kind, "seed_index": self.seed_index,
                                              "monotonic_ns": time.monotonic_ns(), **value})

        def bound_record(self, row: dict[str, Any], record: dict[str, Any], require_ack: bool = True) -> None:
            require(self.profile_digest is not None and self.stage_id is not None and self.stage_manifest_digest is not None,
                    "actual installed profile/stage bindings unavailable")
            validate_record_identity(row, record, self.fixture_sha256, self.profile_digest,
                                     self.stage_manifest_digest, self.stage_id, require_ack)

        def rpc(self, op: str, **fields: Any) -> dict[str, Any]:
            self.rpc_count += 1
            require(self.rpc_count <= MAX_RPC and time.monotonic() < self.deadline, "seed RPC/deadline budget exceeded")
            self.pump_server()
            request = {"v": 1, "op": op, **fields}
            key = self.rpc_count
            self.event("rpc_intent", rpc_id=key, request=request)
            value = self.raw_request(encode(request).strip())
            self.event("rpc_response", rpc_id=key, response=value)
            require(isinstance(value, dict) and value.get("v") == 1 and type(value.get("ok")) is bool, "untyped socket envelope")
            if value["ok"] is False:
                require(isinstance(value.get("error"), dict) and isinstance(value["error"].get("code"), str), "untyped native refusal")
                raise Refusal(value)
            require(isinstance(value.get("result"), dict), "native result object unavailable")
            return value["result"]

        def cli(self, *args: str, ok: bool = True, error: str | None = None) -> dict[str, Any]:
            require(ok and error is None, "B-06 has no synthetic expected-success rejection wrapper")
            op = args[0]
            if op in {"metrics", "doctor"}:
                return self.rpc(op)
            if op in {"result", "inspect", "cancel"}:
                return self.rpc(op, job_id=args[1])
            require(op == "stage", "B-06 CLI-per-job operation refused")
            return super().cli(*args, ok=ok, error=error)

        def inventory(self) -> set[str]:
            # Observe the actual runtime limit without an earlier observer cap.
            root = self.state / "records"
            names = list(root.iterdir())
            require(len(names) <= OBSERVER_RECORD_BOUND + 1, "observer ledger bound exceeded")
            raw = native.read_file(root / "catalog.json", 2 * 1024 * 1024, owner=True, mode=0o600)
            catalog = parse(raw, 2 * 1024 * 1024)
            require(catalog.get("v") == 1 and catalog.get("instance_id") == self.read_instance(), "ledger catalog identity differs")
            entries = catalog.get("entries")
            require(isinstance(entries, list) and len(entries) <= OBSERVER_RECORD_BOUND, "unsupported bounded ledger layout")
            expected = set()
            for item in entries:
                job = item.get("job_id")
                require(isinstance(job, str) and native.ID.fullmatch(job) and job not in expected, "ambiguous catalog identity")
                record = self.record(job)
                require(item.get("request_id") == record["request_id"] and item.get("canonical_request_sha256") == record["canonical_request_sha256"],
                        "ledger differs from durable job identity")
                row = self.rows.get(record["request_id"])
                require(row is not None, "ledger contains an unscheduled request identity")
                self.bound_record(row, record, require_ack=False)
                expected.add(job)
            require({path.name for path in names} == {"catalog.json", *(job + ".json" for job in expected)}, "unexpected/missing ledger entry")
            self.last_catalog = {"content_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                 "instance_id": catalog["instance_id"], "entries": len(expected)}
            return expected

        def prepare(self) -> str:
            self.preflight()
            code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile", str(self.state), "example", str(self.fixture)])
            require(code == 0, "approved retention fixture installation failed")
            installed = native.strict_json(stdout)
            manifest = native.read_file(self.state / "profiles/example/manifest.json", 4096, owner=True, mode=0o600)
            image = native.read_file(self.state / "profiles/example/task", 64 * 1024 * 1024, owner=True, mode=0o400)
            self.profile_digest = validate_profile(installed, manifest, image, self.fixture_sha256)
            self.event("installed_profile", profile=installed, captured_fixture_sha256=self.fixture_sha256,
                       retained_image_sha256=hashlib.sha256(image).hexdigest(),
                       retained_manifest_base64=base64.b64encode(manifest).decode("ascii"))
            self.start()  # Exactly once per seed. No resume/restart method here.
            require(self.server is not None and self.server.proc.poll() is None, "owned supervisor unavailable")
            self.spawn_identity = self.process_identity(self.server.proc.pid)
            require(self.spawn_identity is not None, "owned Popen identity unavailable")
            self.event("supervisor_spawn", popen_pid=self.server.proc.pid, identity=self.spawn_identity)
            self.doctor_case()
            source = self.work / "data.ndjson"
            native.write_synthetic(source, b'{"value":1}\n')
            staged = self.cli("stage", f"data.ndjson={source}")
            stage = staged.get("stage_id")
            require(isinstance(stage, str) and native.ID.fullmatch(stage), "stage has no native identity")
            require(re.fullmatch(r"[a-f0-9]{64}", staged.get("manifest_digest", "")), "stage has no actual manifest identity")
            self.stage_id, self.stage_manifest_digest = stage, staged["manifest_digest"]
            self.event("staged_input", response=staged)
            return stage

        def process_sample(self) -> dict[str, Any]:
            require(self.server is not None and self.server.proc.poll() is None and self.spawn_identity is not None, "seed supervisor stopped/restarted")
            pid = self.server.proc.pid
            before = self.process_identity(pid)
            require(before is not None and (pid, before["start_ticks"]) == (self.spawn_identity["pid"], self.spawn_identity["start_ticks"]), "borrowed supervisor PID")
            require(Path(f"/proc/{pid}").stat().st_uid == os.geteuid(), "supervisor UID differs")
            raw = native.read_file(Path(f"/proc/{pid}/status"), 64 * 1024, virtual=True).decode("ascii")
            values = resource_fields(raw)
            fd = os.open(f"/proc/{pid}/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                directory_info = os.fstat(fd)
                require(directory_info.st_uid == os.geteuid() and stat.S_ISDIR(directory_info.st_mode), "unowned proc FD directory")
                descriptors = sorted(int(name) for name in os.listdir(fd))
                require(len(descriptors) <= 1024, "supervisor FD bound exceeded")
            finally:
                os.close(fd)
            after = self.process_identity(pid)
            require(after is not None and after["start_ticks"] == before["start_ticks"] and after["state"] != "Z", "supervisor changed during proc sampling")
            value = {"identity": before, "identity_after": after, "fd_numbers": descriptors, "fd_count": len(descriptors),
                     "fd_directory_identity": {"device": directory_info.st_dev, "inode": directory_info.st_ino, "uid": directory_info.st_uid},
                     "status_raw": "\n".join(line for line in raw.splitlines() if line.startswith(("VmRSS:", "VmHWM:"))), **values}
            self.event("supervisor_proc", **value)
            return value

        def observe_live(self, row: dict[str, Any]) -> dict[str, Any] | None:
            record = self.record(row["job_id"])
            self.bound_record(row, record)
            require(record["state"] not in native.TERMINAL, "short fixture ended before actual live membership observation")
            if record["state"] != "RUNNING" or record.get("launch_stage") != "EXEC_RELEASED":
                return None
            started = record.get("started_monotonic_ns")
            require(type(started) is int and started >= 0, "durable RUNNING record has no start witness")
            group = self.open_group(row["job_id"])
            try:
                controls = {name: self.control_read(group, name).decode("ascii").strip() for name in LIMITS}
                require(controls == LIMITS, "live fixed job resource controls differ")
                lines = self.control_read(group, "cgroup.procs").splitlines()
                require(0 < len(lines) <= 32 and all(line.isdigit() for line in lines), "invalid owned job PID inventory")
                members = [value for line in lines if (value := self.process_identity(int(line))) is not None]
                launchers = [value for value in members if value["ppid"] == self.server.proc.pid]
                if len(members) < 3 or len(launchers) != 1:
                    return None
                require(b"populated 1\n" in self.control_read(group, "cgroup.events"), "observed fixture group is not populated")
                value = {"members": members, "launchers": launchers, "controls": controls, "cgroup_inode": os.fstat(group).st_ino,
                         "cgroup_device": os.fstat(group).st_dev, "observed_group_fd": group,
                         "group_name": self.group_name(row["job_id"])}
                self.event("live_membership", sample_index=row["sample_index"], job_id=row["job_id"], **value)
                row["start_ns"] = started
                return value
            finally:
                os.close(group)

        def verify_output(self, row: dict[str, Any], live: dict[str, Any]) -> None:
            job = row["job_id"]
            self.terminal(job, "SUCCEEDED", timeout=10)  # Uses socket inspect override.
            self.cleanup_observed(job, live["members"], live["launchers"])
            row["cleanup_ns"] = time.monotonic_ns()
            metadata, stdout, stderr = self.verify_result(job, "SUCCEEDED")  # Result approval uses socket override.
            require(stdout == stderr == b"" and metadata["exit_code"] == 0 and metadata["signal"] is None
                    and metadata["stdout_truncated"] is False and metadata["stderr_truncated"] is False, "unexpected streams/exit")
            expected = [{"path": "payload.bin", "size_bytes": row["bytes"], "sha256": row["expected_sha256"]}]
            require(metadata["artifacts"] == expected, "actual artifact size/hash differs from independent fixed oracle")
            raw = native.read_file(self.state / "results" / job / "result.json", 65536, owner=True, mode=0o600)
            record = self.record(job)
            self.bound_record(row, record)
            page = self.rpc("events", job_id=job, after_seq=0, limit=100)
            require(page.get("truncated") is False and isinstance(page.get("events"), list) and len(page["events"]) < 100, "short-job phase history lost")
            witness = {"members": [{"original": item, "current": self.process_identity(item["pid"])} for item in live["members"]],
                       "launchers": [{"original": item, "current": self.process_identity(item["pid"])} for item in live["launchers"]],
                       "leaf_removed": self.group_name(job) not in self.group_names(), "direct_populated_zero": None}
            require(witness["leaf_removed"] and all(item["current"] is None or item["current"]["start_ticks"] != item["original"]["start_ticks"]
                    for item in witness["launchers"]), "launcher not reaped/owned leaf retained")
            self.bundle_bytes[job] = len(raw) + len(stdout) + len(stderr) + row["bytes"]
            self.results[job] = record["result_digest"]
            self.event("result_evidence", sample_index=row["sample_index"], job_id=job, record=record,
                       metadata_raw_base64=base64.b64encode(raw).decode("ascii"), metadata_sha256=hashlib.sha256(raw).hexdigest(),
                       actual_artifact_manifest=metadata["artifacts"], phase_page=page, cleanup_witness=witness,
                       bundle_content_bytes=self.bundle_bytes[job])
            row.update(status="PASS", finish_ns=time.monotonic_ns(), exit_code=0,
                       output_digest=record["result_digest"], supervisor_peak_scope="separate seed VmHWM; job RSS unavailable")

        def snapshot(self, completed: int) -> dict[str, Any]:
            self.snapshot_count += 1
            snapshot_id = self.snapshot_count
            metrics = self.rpc("metrics")
            require(metrics.get("active") == metrics.get("queued") == 0 and metrics.get("admission_open") is True, "wave did not become idle")
            jobs = self.inventory()
            require(len(jobs) == completed and jobs == set(self.results), "growing request ledger lost/added an identity")
            require(metrics.get("retained_requests") == completed, "native retained request metric differs from ledger")
            results = footprint(self.state / "results", native)
            ledger = footprint(self.state / "records", native)
            evicted = footprint(self.state / "evicted", native)
            retained = {path.name for path in (self.state / "results").iterdir()}
            markers = {path.name for path in (self.state / "evicted").iterdir()}
            require(len(retained) <= 100 and not retained & markers and retained | markers == jobs, "retained/evicted identity partition differs")
            require(results["content_bytes"] == sum(self.bundle_bytes[job] for job in retained), "exact retained bundle byte sum differs")
            require(evicted["content_bytes"] == 64 * len(markers), "eviction marker content-byte count differs")
            for job in markers:
                marker = native.read_file(self.state / "evicted" / job, 64, owner=True, mode=0o600)
                require(marker == self.results[job].encode("ascii"), "eviction marker differs from observed committed digest")
                if job not in self.observed_markers:
                    self.event("eviction_marker", job_id=job, raw_ascii=marker.decode("ascii"), size_bytes=len(marker),
                               sha256=hashlib.sha256(marker).hexdigest())
                    self.observed_markers.add(job)
            groups = sorted(self.group_names())
            require(not groups, "orphan cgroups after idle wave")
            proc = self.process_sample()
            # Full 1000-record/marker inventories exceed a single protocol-sized
            # journal row. Retain exact entries in bounded chunks and bind their
            # aggregate digest into the concise snapshot; never truncate them.
            for category, tree in (("results", results), ("ledger", ledger), ("evicted", evicted)):
                files = tree.pop("files")
                tree["file_count"] = len(files)
                tree["file_inventory_sha256"] = hashlib.sha256(encode(files)).hexdigest()
                for offset in range(0, len(files), 128):
                    self.event("footprint_files", snapshot_id=snapshot_id, completed_jobs=completed, category=category, offset=offset,
                               file_count=len(files), files=files[offset:offset + 128],
                               file_inventory_sha256=tree["file_inventory_sha256"])
            value = {"snapshot_id": snapshot_id, "completed_jobs": completed, "monotonic_ns": time.monotonic_ns(), "metrics": metrics,
                     "request_records": len(jobs), "retained_results": len(retained), "eviction_markers": len(markers),
                     "ledger_catalog": dict(self.last_catalog),
                     "retained_result_ids": sorted(retained), "evicted_job_ids": sorted(markers),
                     "results": results, "ledger": ledger, "evicted": evicted, "orphan_cgroups": groups,
                     "VmRSS_bytes": proc["VmRSS_bytes"], "VmHWM_bytes": proc["VmHWM_bytes"], "fd_count": proc["fd_count"]}
            require(results["content_bytes"] <= 1024 * 1024 * 1024, "retained result bytes exceed locked 1GiB cap")
            self.event("retention_snapshot", **value)
            self.points.append({"completed_jobs": completed, "VmRSS_bytes": proc["VmRSS_bytes"], "VmHWM_bytes": proc["VmHWM_bytes"],
                                "fd_count": proc["fd_count"], "result_bytes": results["content_bytes"], "ledger_bytes": ledger["content_bytes"],
                                "eviction_marker_bytes": evicted["content_bytes"], "orphan_cgroups": len(groups)})
            return value

        def cleanup(self) -> list[str]:
            errors = []
            if self.instance is not None:
                try:
                    self.jobs.update(self.inventory())
                    for job in sorted(self.jobs):
                        record = self.record(job)
                        row = self.rows.get(record["request_id"])
                        if row is not None and row["job_id"] is None:
                            row["job_id"] = job
                            self.event("lost_submit_reconciled", sample_index=row["sample_index"], job_id=job, record=record)
                except Exception as error:
                    errors.append(f"owned ledger reconciliation: {error}")
            errors.extend(super().cleanup())
            return errors
    return SeedHarness


def wave(h: Any, stage: str, rows: list[dict[str, Any]], journal: Journal) -> None:
    live: dict[str, dict[str, Any]] = {}
    for row in rows:
        row.update(status="INCOMPLETE", submit_ns=time.monotonic_ns())
        row["submission"] = {"v": 1, "op": "submit", "request_id": row["request_id"], "profile_id": "example", "stage_id": stage,
                             "argv": [row["workload"]], "wall_ms": 10000}
        journal.save("attempts.jsonl", dict(row))
        try:
            response = h.rpc("submit", request_id=row["request_id"], profile_id="example", stage_id=stage,
                             argv=[row["workload"]], wall_ms=10_000)
        except Refusal as error:
            row.update(status="FAIL", reason=str(error), refusal=error.response, finish_ns=time.monotonic_ns())
            journal.record_sample(row)
            raise
        job = response.get("job_id")
        require(isinstance(job, str) and re.fullmatch(r"[a-f0-9]{32}", job), "submit lacks actual job identity")
        row["job_id"] = job
        row["submit_ack"] = response
        row["submit_rpc_id"] = h.rpc_count
        h.jobs.add(job)
        h.bound_record(row, h.record(job))
    deadline = min(h.deadline, time.monotonic() + 10)
    while len(live) < len(rows):
        require(time.monotonic() < deadline, "fixed short fixture live observation expired")
        h.pump_server()
        for row in rows:
            if row["job_id"] not in live:
                value = h.observe_live(row)
                if value is not None:
                    live[row["job_id"]] = value
        time.sleep(.001)
    groups = []
    try:
        for row in rows:
            groups.append((row, h.open_group(row["job_id"])))
        require(len(groups) == 4, "B-06 requires full four-job waves")

        def observe_wave(phase):
            observations = []
            for row, group in groups:
                job = row["job_id"]
                record = h.record(job)
                populated = b"populated 1\n" in h.control_read(group, "cgroup.events")
                inode = os.fstat(group).st_ino
                item = {"job_id": job, "cgroup_inode": inode, "monotonic_ns": time.monotonic_ns(),
                        "populated": int(populated), "state": record["state"]}
                if record["state"] != "RUNNING" or not populated or inode != live[job]["cgroup_inode"]:
                    h.event("wave_live_failure", wave=row["wave"], phase=phase, observation=item)
                    raise ValueError("wave was not four simultaneously live owned jobs")
                observations.append(item)
            return observations

        before = observe_wave("before")
        common = time.monotonic_ns()
        after = observe_wave("after")
        h.event("wave_concurrent_ready", wave=rows[0]["wave"], observations=after,
                observations_before=before, overlap_monotonic_ns=common)
    finally:
        for _, group in groups:
            os.close(group)
    for row in rows:
        h.verify_output(row, live[row["job_id"]])
        try:
            journal.record_sample(row)
        except BaseException as error:
            row.update(status="FAIL", reason=f"verified native output but sample commit failed: {type(error).__name__}: {error}"[:2048])
            raise


def storage(root: Path, journal: Journal) -> None:
    capacity = os.statvfs(root)
    total = entries = 0
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            info = (Path(parent) / name).lstat()
            require(not stat.S_ISLNK(info.st_mode), "unexpected evidence symlink")
            total += max(info.st_size, info.st_blocks * 512)
            entries += 1
            require(entries <= 100_000, "campaign inode accounting bound exceeded")
    journal.save("events.jsonl", {"type": "storage", "monotonic_ns": time.monotonic_ns(), "accounted_bytes": total,
                                  "entries": entries, "available_bytes": capacity.f_bavail * capacity.f_frsize,
                                  "available_inodes": capacity.f_favail})
    require(total <= 1_000_000_000 and capacity.f_files > 0 and capacity.f_favail >= 16_384
            and capacity.f_bavail * capacity.f_frsize >= 256 * 1024 * 1024, "campaign bounded byte/inode reserve exhausted")


def provenance(args: Any, native: Any, capture: Any) -> dict[str, Any]:
    public = native.absolute(args.public_root)
    digest = lambda path: hashlib.sha256(native.read_file(path, 64 * 1024 * 1024)).hexdigest()
    build = parse(native.read_file(native.absolute(args.build_record), 64 * 1024))
    binaries = {name: digest(native.absolute(args.bin_dir) / name) for name in ("hearthrun", "hearthrun-supervisor", "hearthrun-launcher")}
    fixture = build.get("retention")
    require(build.get("source_sha256") == capture.source_digest(public) and build.get("profile") == "release"
            and build.get("rustc_verbose", "").startswith("rustc 1.99.1 ") and build.get("optimization_flags")
            and isinstance(build.get("build_command"), list) and build["build_command"]
            and re.fullmatch(r"[a-f0-9]{64}", build.get("capture_manifest_sha256", ""))
            and build.get("binary_sha256") == binaries, "native captured release build differs")
    require(isinstance(fixture, dict) and fixture.get("fixture_sha256") == digest(native.absolute(args.fixture))
            and fixture.get("source_sha256") == digest(native.absolute(args.fixture_source)) and fixture.get("build_command")
            and re.fullmatch(r"[a-f0-9]{64}", fixture.get("capture_manifest_sha256", "")), "captured approved retention fixture differs")
    host = parse(native.read_file(native.absolute(args.host_record), 32 * 1024))
    require(all(key in host for key in ("power_policy", "background_load_control", "filesystem_mount_options", "landlock_abi", "seccomp_mode")), "host record incomplete")
    value = {"benchmark": "B-06", "runtime": "actual local Linux native supervisor/launcher", "build": build, "host_record": host,
             "driver_sha256": digest(Path(__file__).resolve(strict=True)),
             "kernel": platform.release(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
             "background_load_start": os.getloadavg(), "doctor_sha256": digest(native.absolute(args.doctor)),
             "oracle": [{"variant": variant, "bytes": oracle(variant)[0], "sha256": oracle(variant)[1]} for variant in range(5)],
             "scope": "one supervisor/store per seed; retention and retry ledger accounted separately; no production scale claim"}
    for field, path, bound in (("cpuinfo", "/proc/cpuinfo", 1024 * 1024), ("meminfo", "/proc/meminfo", 65536),
                               ("boot_id", "/proc/sys/kernel/random/boot_id", 128),
                               ("cgroup_controllers", str(native.absolute(args.cgroup_root) / "cgroup.controllers"), 4096)):
        raw = native.read_file(Path(path), bound, virtual=True).decode("utf-8")
        value[field] = "\n".join(sorted({line for line in raw.splitlines() if line.startswith(("model name", "cpu cores", "siblings"))})) if field == "cpuinfo" else raw
    value["environment_id"] = hashlib.sha256(encode(value)).hexdigest()
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("public-root", "bin-dir", "doctor", "fixture", "fixture-source", "cgroup-root", "build-record", "host-record", "work"):
        parser.add_argument(f"--{flag}", required=True)
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--seed", type=int, default=60621)
    args = parser.parse_args()
    public = Path(args.public_root)
    require(public.is_absolute() and public.resolve(strict=True) == public, "public root must be absolute without symlinks")
    native = load("b06_native", public / "tests/e2e/native.py")
    capture = load("b06_capture", public / "scripts/capture.py")
    Harness = make_harness(native)
    seeds, rows = schedule(args.mode, args.seed, os.urandom(16).hex())
    root = native.absolute(args.work)
    journal: Journal | None = None
    active = None
    seed_reports = []
    code, reason = 1, None
    deadline = time.monotonic() + MAX_CAMPAIGN_SECONDS
    def terminate(_signum: int, _frame: Any) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        raise RuntimeError("termination requested; preserving owned seed state and all attempts")
    signal.signal(signal.SIGTERM, terminate)
    try:
        initial = native.Harness(args)
        active = initial
        initial.preflight()
        require(not initial.cleanup(), "initial mandatory preflight teardown failed")
        active = None
        plan_raw = encode({"benchmark": "B-06", "mode": args.mode, "run_id": rows[0]["run_id"],
                               "master_seed": args.seed, "seeds": seeds, "planned": len(rows), "jobs_each": 1000 if args.mode == "full" else 16,
                               "one_live_supervisor_each_seed": True, "concurrency": 4, "rows": rows})
        native.write_synthetic(root / "schedule.json", plan_raw)
        journal = Journal(root, rows, hashlib.sha256(plan_raw).hexdigest())
        environment = provenance(args, native, capture)
        native.write_synthetic(root / "environment.json", encode(environment))
        for seed_index, seed in enumerate(seeds):
            require(time.monotonic() < deadline, "campaign deadline expired")
            storage(root, journal)
            selected = [row for row in rows if row["seed_index"] == seed_index]
            seed_args = argparse.Namespace(**{**vars(args), "work": str(root / f"seed-{seed_index:02d}")})
            active = Harness(seed_args, journal, seed_index, environment["build"]["retention"]["fixture_sha256"])
            active.rows = {row["request_id"]: row for row in selected}
            seed_error = None
            try:
                stage = active.prepare()
                active.snapshot(0)
                for offset in range(0, len(selected), 4):
                    require(time.monotonic() < deadline, "campaign deadline expired")
                    wave(active, stage, selected[offset:offset + 4], journal)
                    active.snapshot(offset + 4)
                    if offset % 40 == 0:
                        storage(root, journal)
            except Refusal as error:
                seed_error = str(error)
                journal.save("events.jsonl", {"type": "seed_refusal", "seed_index": seed_index, "response": error.response,
                                              "supervisor_restarted": False, "monotonic_ns": time.monotonic_ns()})
                if error.response["error"]["code"] != "STORAGE_FULL":
                    raise
                try:
                    active.snapshot(sum(row["status"] == "PASS" for row in selected))
                except Exception as observation_error:
                    active.event("refused_seed_final_snapshot_error", reason=f"{type(observation_error).__name__}: {observation_error}")
                # A real ledger/storage refusal is a seed FAIL. Preserve the
                # response and stop this seed; never clear or restart its store.
            except BaseException as error:
                seed_error = f"{type(error).__name__}: {error}"
                raise
            finally:
                try:
                    errors = active.cleanup()
                except Exception as cleanup_error:
                    errors = [f"cleanup raised: {type(cleanup_error).__name__}: {cleanup_error}"]
                completed = sum(row["status"] == "PASS" for row in selected)
                report = {"seed_index": seed_index, "seed": seed, "status": "PASS" if not seed_error and not errors and completed == len(selected) else "FAIL",
                          "reason": seed_error, "teardown_errors": errors, "supervisor_starts": 1 if active.spawn_identity else 0,
                          "spawn_identity": active.spawn_identity, "completed_jobs": completed,
                          "rpc_count": active.rpc_count, "cli_commands": active.commands,
                          "owned_children_reaped": all(child.proc.poll() is not None for child in active.children),
                          "owned_cgroups_remaining": 0 if not errors else None,
                          "observed_supervisor_peak_rss_bytes": max((point["VmHWM_bytes"] for point in active.points), default=None),
                          "late_slopes": {field: slope(active.points, field) for field in
                                          ("VmRSS_bytes", "VmHWM_bytes", "fd_count", "result_bytes", "ledger_bytes", "eviction_marker_bytes")}}
                seed_reports.append(report)
                journal.save("events.jsonl", {"type": "seed_teardown", **report})
                for row in selected:
                    if row["status"] == "INCOMPLETE":
                        row.update(status="FAIL", reason="wave interrupted; native state retained for review")
                    if row["status"] == "NOT RUN":
                        row["reason"] = "seed stopped before attempt; no replacement store"
                active = None
                require(not errors, f"owned seed cleanup failed: {errors}")
        code = 0 if all(row["status"] == "PASS" for row in rows) else 1
        if code != 0:
            reason = "one or more planned seed populations did not pass; see actual refusal and teardown evidence"
    except BaseException as error:
        reason = f"{type(error).__name__}: {error}"[:2048]
        code = 78 if isinstance(error, native.Blocked) else 1
    finally:
        if active is not None:
            try:
                errors = active.cleanup()
            except BaseException as cleanup_error:
                errors = [f"cleanup raised: {type(cleanup_error).__name__}: {cleanup_error}"]
            if errors:
                code, reason = 1, f"{reason}; cleanup: {errors}"[:4096]
        if journal is not None:
            for row in rows:
                if row["status"] == "INCOMPLETE":
                    row.update(status="FAIL", reason=reason or "campaign interrupted")
                elif row["status"] == "NOT RUN" and row["reason"] is None:
                    row["reason"] = "campaign stopped before attempt"
            summary = {"benchmark": "B-06", "mode": args.mode, "planned": len(rows), "counts": dict(Counter(row["status"] for row in rows)),
                       "status": "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL", "reason": reason, "seeds": seed_reports,
                       "peak_scope": "actual /proc VmHWM bytes for one anchored supervisor per seed; no getrusage child substitution",
                       "slope_scope": "late completed-job500..1000 OLS per seed; incomplete populations stay NOT YET MEASURED",
                       "limitations": "finite synthetic local workload; ledger and eviction marker growth disclosed separately from retained bundles; allocator and cgroup delayed reclamation can affect RSS"}
            try:
                if not journal.finish(rows, summary):
                    code = 1
                    reason = f"{reason or ''}; evidence finalization failed or contains unrecoverable/rolled-back writes"[:4096]
            except BaseException as finalization_error:
                code, reason = 1, f"{reason or ''}; evidence finalization: {type(finalization_error).__name__}: {finalization_error}"[:4096]
            finally:
                try:
                    journal.close()
                except BaseException as close_error:
                    code, reason = 1, f"{reason or ''}; evidence close: {type(close_error).__name__}: {close_error}"[:4096]
        print(json.dumps({"benchmark": "B-06", "mode": args.mode, "exit_code": code, "reason": reason,
                          "counts": dict(Counter(row["status"] for row in rows))}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
