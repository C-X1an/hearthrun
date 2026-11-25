#!/usr/bin/env python3
"""B-04 finite native campaign; no builds, provisioning or host-policy changes.

Draft: --public-root points to an existing public product tree. Supply absolute
--bin-dir, --doctor, --resource-fixture (resources.c), --scheduler-fixture
(task.c), --cgroup-root, --build-record, --host-record and NEW --work on the
already delegated, OS-bounded noswap tmpfs. Capture with scripts/capture.py.
Full: 30 repetitions EACH of memory, pids, >=10-second CPU and 4+16/21st
refusal. Smoke: one repetition EACH, with exactly the same native assertions.
Only the four existing fixed benign fixture modes are used; never direct-exec
resource controls. Each repetition gets a fresh supervisor/store, so retention
does not substitute for queue capacity. Failed shards and all raw logs remain.

Supervisor RSS/FD values are point-in-time /proc samples for the owned Popen
PID/start_ticks only. They are neither cumulative child usage nor a peak-RSS
claim. Kernel counters are from exact journal-owned cgroup descriptors; missing
counters fail. Phase event clocks remain in the supervisor's clock domain.
This driver does not establish the external project-wide 15GB boundary.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import time
from typing import Any

sys.dont_write_bytecode = True
PROFILES = ("memory", "pids", "cpu", "admission")
COUNTERS = ("memory.events", "pids.events", "cpu.stat")
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 128 * 1024
MAX_RETAINED_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_SECONDS = 3600


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def plan(mode: str, run_id: str) -> list[dict[str, Any]]:
    require(mode in {"full", "smoke"}, "unknown B-04 mode")
    return [{"benchmark": "B-04", "run_id": run_id, "sample_index": index,
             "workload": workload, "repetition": repetition,
             "status": "NOT RUN", "started_ns": None, "finish_ns": None,
             "reason": None, "measurements": None, "teardown": None}
            for index, (workload, repetition) in enumerate(
                (workload, repetition) for workload in PROFILES
                for repetition in range(30 if mode == "full" else 1))]


class Journal:
    """Append-only bounded, fsynced journals; failed writes never become PASS."""
    def __init__(self, root: Path):
        self.fds: dict[str, int] = {}
        self.bytes = 0
        try:
            for name in ("attempts.jsonl", "samples.jsonl", "events.jsonl"):
                self.fds[name] = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except BaseException:
            self.close()
            raise

    def save(self, name: str, row: dict[str, Any]) -> None:
        raw = encode(row)
        require(len(raw) <= MAX_RECORD_BYTES and self.bytes + len(raw) <= MAX_JOURNAL_BYTES,
                "B-04 evidence bound exceeded")
        pending = memoryview(raw)
        while pending:
            written = os.write(self.fds[name], pending)
            require(written > 0, "evidence write made no progress")
            pending = pending[written:]
        os.fsync(self.fds[name])
        self.bytes += len(raw)

    def close(self) -> None:
        for descriptor in self.fds.values():
            os.close(descriptor)
        self.fds.clear()


def load(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    require(specification is not None and specification.loader is not None, "helper unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def parsed_counters(raw: str) -> dict[str, int]:
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in result and fields[1].isdigit(),
                "malformed or duplicate kernel counter")
        result[fields[0]] = int(fields[1])
    return result


class Instrumented:
    """Read-only instrumentation around the unchanged finite integration suites."""
    journal: Journal
    row: dict[str, Any]
    native: Any

    def bind(self, journal: Journal, row: dict[str, Any]) -> None:
        self.journal, self.row = journal, row
        self.current_job: str | None = None
        self.seen_groups: set[str] = set()
        self.group_inodes: dict[str, int] = {}
        self.next_proc_sample = 0.0
        self.proc_samples = 0
        self.rpc_sequence = 0
        self.proc_anchor: dict[str, Any] | None = None
        self.sampling_enabled = True
        self.last_cpu_read: tuple[int, int] | None = None

    def start(self) -> None:
        super().start()
        require(self.server is not None, "owned supervisor spawn missing")
        identity = self.process_identity(self.server.proc.pid)
        require(identity is not None, "owned supervisor spawn identity unavailable")
        if self.proc_anchor is None:
            self.proc_anchor = identity
            self.event("supervisor_spawn", popen_pid=self.server.proc.pid, identity=identity)

    def event(self, kind: str, **value: Any) -> None:
        self.journal.save("events.jsonl", {"type": kind, "sample_index": self.row["sample_index"],
                                          "monotonic_ns": time.monotonic_ns(), **value})

    def supervisor_sample(self, context: str) -> None:
        server = self.server
        require(server is not None and server.proc.poll() is None, "owned supervisor unavailable")
        pid = server.proc.pid
        before = self.process_identity(pid)
        require(before is not None and before["state"] != "Z", "owned supervisor has no live identity")
        # Startup sampling may occur while the inherited start() is waiting for
        # readiness; anchor directly to its owned Popen before the first sample.
        if self.proc_anchor is None:
            self.proc_anchor = before
            self.event("supervisor_spawn", popen_pid=pid, identity=before)
        require((pid, before["start_ticks"]) == (self.proc_anchor["pid"], self.proc_anchor["start_ticks"]),
                "supervisor sample differs from owned spawn anchor")
        root = Path(f"/proc/{pid}")
        require(root.stat().st_uid == os.geteuid(), "owned supervisor UID differs")
        raw = self.native.read_file(root / "status", 64 * 1024, virtual=True).decode("ascii")
        rss = [line.split() for line in raw.splitlines() if line.startswith("VmRSS:")]
        require(len(rss) == 1 and len(rss[0]) == 3 and rss[0][1].isdigit() and rss[0][2] == "kB",
                "supervisor VmRSS missing/malformed")
        descriptor = os.open(root / "fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fds = os.listdir(descriptor)
            require(len(fds) <= 1024 and all(name.isdigit() for name in fds),
                    "supervisor FD inventory exceeds bound or is malformed")
        finally:
            os.close(descriptor)
        after = self.process_identity(pid)
        require(after is not None and before["start_ticks"] == after["start_ticks"]
                and server.proc.poll() is None, "supervisor identity changed during /proc observation")
        self.proc_samples += 1
        require(self.proc_samples <= 500, "supervisor observation count exceeded")
        self.event("supervisor_proc", context=context, identity=before, identity_after=after,
                   vmrss_line=" ".join(rss[0]), rss_bytes=int(rss[0][1]) * 1024,
                   fd_count=len(fds), fd_numbers=sorted(int(name) for name in fds))

    def pump_server(self, excluding: Any = None) -> None:
        super().pump_server(excluding)
        if (hasattr(self, "journal") and self.sampling_enabled and self.server is not excluding and self.server is not None and
                self.server.proc.poll() is None and time.monotonic() >= self.next_proc_sample):
            self.next_proc_sample = time.monotonic() + 0.25
            self.supervisor_sample("periodic")

    def cli(self, *arguments: str, ok: bool = True, error: str | None = None) -> dict[str, Any]:
        self.rpc_sequence += 1
        rpc_id = self.rpc_sequence
        if error == "QUEUE_FULL":
            self.admission_boundary("before_refusal", rpc_id)
        self.event("rpc_intent", rpc_id=rpc_id, operation=arguments[0], arguments=list(arguments[1:]),
                   expected_ok=ok, expected_error=error)
        value = super().cli(*arguments, ok=ok, error=error)
        self.event("rpc_result", rpc_id=rpc_id, operation=arguments[0], value=value, expected_ok=ok)
        if error == "QUEUE_FULL":
            self.admission_boundary("after_refusal", rpc_id)
        return value

    def admission_boundary(self, context: str, rpc_id: int) -> None:
        self.event("admission_boundary", context=context, rpc_id=rpc_id,
                   records=[self.record(job) for job in sorted(self.inventory())], groups=sorted(self.group_names()))

    def control_read(self, group: int, name: str) -> bytes:
        began = time.monotonic_ns()
        raw = super().control_read(group, name)
        ended = time.monotonic_ns()
        if name == "cpu.stat":
            self.last_cpu_read = (began, ended)
        return raw

    def cleanup(self) -> list[str]:
        self.sampling_enabled = False
        return super().cleanup()

    def submit(self, request: str, stage: str, mode: str) -> str:
        job = super().submit(request, stage, mode)
        self.current_job = job
        return job

    def open_group(self, job: str) -> int:
        descriptor = super().open_group(job)
        try:
            self.current_job = job
            self.group_inodes[job] = os.fstat(descriptor).st_ino
            if job not in self.seen_groups:
                controls_raw = {name: super(Instrumented, self).control_read(descriptor, name).decode("ascii")
                                for name in ("memory.max", "memory.swap.max", "memory.oom.group", "pids.max", "cpu.max")}
                self.event("cgroup_controls", job_id=job, cgroup_inode=os.fstat(descriptor).st_ino,
                           group_name=self.group_name(job), raw=controls_raw)
                for filename in COUNTERS:
                    raw = super().control_read(descriptor, filename).decode("ascii")
                    self.event("kernel_raw", job_id=job, filename=filename, context="live_initial",
                               raw=raw, counters=parsed_counters(raw), cgroup_inode=self.group_inodes[job])
                self.seen_groups.add(job)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def live_group(self, job: str) -> tuple[Any, ...]:
        descriptor, members, launchers, controls = super().live_group(job)
        try:
            self.event("live_membership", job_id=job, members=members, launchers=launchers,
                       controls=controls, cgroup_inode=os.fstat(descriptor).st_ino)
            return descriptor, members, launchers, controls
        except BaseException:
            os.close(descriptor)
            raise

    def cleanup_observed(self, job: str, members: list[dict[str, Any]], launchers: list[dict[str, Any]]) -> None:
        super().cleanup_observed(job, members, launchers)
        member_witness = [{"original": item, "current": self.process_identity(item["pid"])} for item in members]
        launcher_witness = [{"original": item, "current": self.process_identity(item["pid"])} for item in launchers]
        # Keep the exact final observations too; an earlier suite assertion alone
        # is not a raw witness for the report consumer.
        require(all(item["current"] is None or item["current"]["start_ticks"] != item["original"]["start_ticks"]
                    or item["current"]["state"] == "Z" for item in member_witness), "original fixture member survived cleanup")
        require(all(item["current"] is None or item["current"]["start_ticks"] != item["original"]["start_ticks"]
                    for item in launcher_witness), "original launcher was not reaped")
        removed = self.group_name(job) not in self.group_names()
        require(removed, "owned group reappeared after cleanup")
        self.event("cleanup_witness", job_id=job, members=member_witness, launchers=launcher_witness,
                   owned_leaf_removed=removed, direct_populated_zero=None,
                   emptiness_scope="verified owned leaf removal; kernel removal invariant, not a sampled populated=0")

    def phases(self) -> list[dict[str, Any]]:
        """Persist all actual events and final records, never infer phase clocks."""
        self.jobs.update(self.inventory())
        records = []
        for job in sorted(self.jobs):
            record = self.record(job)
            records.append(record)
            self.event("job_record", job_id=job, record=record)
            after = 0
            for _ in range(12):
                page = self.cli("events", job, str(after), "100")
                require(page.get("truncated") is False, "native phase ring lost events")
                values = page.get("events")
                require(isinstance(values, list) and len(values) <= 100, "invalid native event page")
                sequences = [value["sequence"] for value in values]
                require(sequences == sorted(set(sequences)) and all(value > after for value in sequences),
                        "phase event sequence duplicated or regressed")
                self.event("native_phase_page", job_id=job, after_seq=after, page=page)
                if len(values) < 100:
                    break
                require(page.get("next_seq") == sequences[-1], "invalid phase continuation")
                after = sequences[-1]
            else:
                raise ValueError("native phase evidence exceeds bounded ring")
        return records


def prepare(harness: Any) -> None:
    harness.preflight()
    code, stdout, _ = harness.command([str(harness.bin_dir / "hearthrun-supervisor"),
                                       "install-profile", str(harness.state), "example", str(harness.fixture)])
    profile = harness.native.strict_json(stdout)
    require(code == 0 and profile.get("profile_id") == "example", "profile install failed")
    harness.start()
    harness.doctor_case()
    source = harness.work / "data.ndjson"
    harness.native.write_synthetic(source, b'{"value":1}\n')
    harness.stage = harness.cli("stage", f"data.ndjson={source}").get("stage_id")
    require(isinstance(harness.stage, str) and harness.native.ID.fullmatch(harness.stage) is not None,
            "stage has no actual identity")
    harness.supervisor_sample("before-profile")


def checkpoint(root: Path, journal: Journal, sample_index: int | None = None, context: str = "before-trial") -> None:
    capacity = os.statvfs(root)
    total, entries = 0, 0
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            info = (Path(parent) / name).lstat()
            require(not stat.S_ISLNK(info.st_mode), "unexpected evidence symlink")
            total += max(info.st_size, info.st_blocks * 512)
            entries += 1
            require(entries <= MAX_ENTRIES, "evidence entry bound exceeded")
    observation = {"type": "storage", "monotonic_ns": time.monotonic_ns(), "sample_index": sample_index, "context": context,
                   "retained_bytes": total, "entries": entries,
                   "available_bytes": capacity.f_bavail * capacity.f_frsize,
                   "available_inodes": capacity.f_favail}
    journal.save("events.jsonl", observation)
    require(total <= MAX_RETAINED_BYTES and observation["available_bytes"] >= 256 * 1024 * 1024
            and capacity.f_files > 0 and capacity.f_favail >= 16_384,
            "insufficient bounded evidence byte/inode headroom")


def host_reserve(root: Path, jobs: Path, journal: Journal, native: Any, sample_index: int | None = None) -> None:
    # These are actual local envelope reads, not an operator assertion or quota
    # provisioning. Finite service memory/pids caps bound a faulty guest cap.
    # The authorized parent CPU setting is unlimited; exact 1-core job controls
    # are asserted by ResourceSuite and the fixed CPU fixture ends at 16s.
    service = jobs.parent
    controls = {name: native.read_file(service / name, 4096, virtual=True).decode("ascii").strip()
                for name in ("memory.max", "memory.swap.max", "memory.current", "pids.max", "pids.current", "cpu.max")}
    memory_cap = int(controls["memory.max"])
    pids_cap = int(controls["pids.max"])
    quota = controls["cpu.max"].split()
    require(0 < memory_cap <= 8_000_000_000 and controls["memory.swap.max"] == "0"
            and 128 <= pids_cap <= 256 and len(quota) == 2 and quota[0] == "max"
            and quota[1] == "100000", "local service envelope is missing or differs from approved bounds")
    controllers = native.read_file(jobs / "cgroup.controllers", 4096, virtual=True).decode("ascii")
    require({"cpu", "memory", "pids"} <= set(controllers.split()), "mandatory delegated controllers unavailable")
    require(memory_cap - int(controls["memory.current"]) >= 768 * 1024 * 1024
            and pids_cap - int(controls["pids.current"]) >= 128,
            "service lacks memory/pid reserve for fixed fixtures")
    raw = native.read_file(Path("/proc/meminfo"), 64 * 1024, virtual=True).decode("ascii")
    available = [line.split() for line in raw.splitlines() if line.startswith("MemAvailable:")]
    require(len(available) == 1 and available[0][1].isdigit() and available[0][2] == "kB"
            and int(available[0][1]) * 1024 >= 1024 * 1024 * 1024, "host RAM reserve unavailable")
    journal.save("events.jsonl", {"type": "host_reserve", "monotonic_ns": time.monotonic_ns(), "sample_index": sample_index,
                                 "service_controls": controls, "delegated_controllers": controllers,
                                 "parent_cpu_scope": "unlimited parent; exact finite one-core job quota and fixed time-bounded fixtures",
                                 "host_mem_available_line": " ".join(available[0])})
    checkpoint(root, journal, sample_index)


def provenance(args: Any, root: Path, benchmark: Any, native: Any) -> dict[str, Any]:
    public = Path(args.public_root)
    build = native.strict_json(native.read_file(native.absolute(args.build_record), 64 * 1024))
    require(build.get("source_sha256") == benchmark.c.source_digest(public), "captured build source differs")
    require(build.get("profile") == "release" and isinstance(build.get("rustc_verbose"), str)
            and build["rustc_verbose"].startswith("rustc 1.99.1 ") and build.get("optimization_flags")
            and isinstance(build.get("target"), str) and build["target"]
            and isinstance(build.get("build_command"), list) and build["build_command"]
            and native.DIGEST.fullmatch(build.get("capture_manifest_sha256", "")), "captured release build provenance missing")
    binaries = {name: benchmark.digest(native.absolute(args.bin_dir) / name)
                for name in ("hearthrun", "hearthrun-supervisor", "hearthrun-launcher")}
    require(build.get("binary_sha256") == binaries, "binary bytes differ from captured build")
    for key, executable, source in (("resources", args.resource_fixture, "resources.c"),
                                    ("task", args.scheduler_fixture, "task.c")):
        entry = build.get(key)
        require(isinstance(entry, dict) and entry.get("fixture_sha256") == benchmark.digest(native.absolute(executable))
                and entry.get("source_sha256") == benchmark.digest(public / "fixtures/native" / source)
                and isinstance(entry.get("build_command"), list) and entry["build_command"]
                and native.DIGEST.fullmatch(entry.get("capture_manifest_sha256", "")), f"captured {key} fixture build missing/different")
    host = native.strict_json(native.read_file(native.absolute(args.host_record), 32 * 1024))
    require(isinstance(host, dict) and all(key in host for key in
            ("power_policy", "background_load_control", "filesystem_mount_options", "landlock_abi", "seccomp_mode")),
            "host record lacks required observations")
    filesystem, options = native.mount_for(root)
    environment = {"benchmark": "B-04", "runtime": "actual local Linux native supervisor/launcher",
                   "kernel": platform.release(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                   "background_load_start": os.getloadavg(), "build": build, "host_record": host,
                   "doctor_sha256": benchmark.digest(native.absolute(args.doctor)),
                   "mount": {"filesystem": filesystem, "options": sorted(options)},
                   "observed_binary_sha256": binaries,
                   "observed_fixture_sha256": {"resources": benchmark.digest(native.absolute(args.resource_fixture)),
                                               "task": benchmark.digest(native.absolute(args.scheduler_fixture))},
                   "observed_fixture_source_sha256": {key: benchmark.digest(public / "fixtures/native" / source)
                                                       for key, source in (("resources", "resources.c"), ("task", "task.c"))},
                   "observed_source_sha256": benchmark.c.source_digest(public),
                   "build_record_sha256": benchmark.digest(native.absolute(args.build_record)),
                   "host_record_sha256": benchmark.digest(native.absolute(args.host_record))}
    for field, path, maximum in (("cpuinfo", "/proc/cpuinfo", 1024 * 1024),
                                 ("meminfo", "/proc/meminfo", 64 * 1024),
                                 ("boot_id", "/proc/sys/kernel/random/boot_id", 128),
                                 ("cgroup_controllers", str(native.absolute(args.cgroup_root) / "cgroup.controllers"), 4096)):
        raw = native.read_file(Path(path), maximum, virtual=True).decode("utf-8")
        if field == "cpuinfo":
            raw = "\n".join(sorted({line for line in raw.splitlines() if line.startswith(("model name", "cpu cores", "siblings"))}))
        environment[field] = raw
    environment["environment_id"] = hashlib.sha256(encode(environment)).hexdigest()
    return environment


def validate_measurement(workload: str, cases: dict[str, Any]) -> None:
    """Sanity checks for report consumers; the native suites remain the oracle."""
    if workload in {"memory", "pids"}:
        case = cases[workload]
        filename, key = ("memory.events", "oom_kill") if workload == "memory" else ("pids.events", "max")
        require(case["status"] == "PASS" and case["counter_file"] == filename
                and case["baseline"][key] == 0 and case["event_before_teardown"][key] > 0,
                "missing independent kernel increment")
    elif workload == "cpu":
        case = cases["cpu"]
        elapsed = case["steady_wall_seconds"]
        before, after = case["before"], case["after"]
        ratio = (after["usage_usec"] - before["usage_usec"]) / (elapsed * 1_000_000)
        require(case["status"] == "PASS" and elapsed >= 10 and 0.85 <= ratio <= 1.15
                and after["nr_throttled"] > before["nr_throttled"]
                and after["throttled_usec"] > before["throttled_usec"]
                and ratio == case["used_cores"], "missing >=10s one-core/throttling measurement")
    else:
        require(workload == "admission", "unknown measurement profile")
        case = cases["capacity_fifo"]
        require(len(case["holders"]) == 4 and len(case["waiting_admission_order"]) == 16
                and case["rejection"]["code"] == "QUEUE_FULL"
                and all(case[key]["active"] == 4 and case[key]["queued"] == 16
                        for key in ("full_metrics", "after_rejection_metrics")),
                "missing exact native admission/refusal boundary")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("public-root", "bin-dir", "doctor", "resource-fixture", "scheduler-fixture", "cgroup-root",
                 "build-record", "host-record", "work"):
        parser.add_argument(f"--{flag}", required=True)
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    args = parser.parse_args()
    public = Path(args.public_root)
    require(public.is_absolute() and public.resolve(strict=True) == public, "public source path must be absolute without symlinks")
    resources = load("b04_resource_suite", public / "tests/integration/resources.py")
    scheduler = load("b04_scheduler_suite", public / "tests/integration/scheduler.py")
    benchmark = load("b04_storage_helper", public / "benchmarks/campaign.py")
    native = resources.native

    class Resources(Instrumented, resources.ResourceSuite):
        pass

    class Scheduler(Instrumented, scheduler.SchedulerSuite):
        pass

    def terminate(_signum: int, _frame: Any) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        raise RuntimeError("termination requested; reconciling only owned test resources")

    signal.signal(signal.SIGTERM, terminate)
    rows = plan(args.mode, os.urandom(16).hex())
    root = native.absolute(args.work)
    journal: Journal | None = None
    active: Any = None
    code, reason = 1, None
    deadline = time.monotonic() + MAX_SECONDS
    counter_parser = resources.counters

    def capture_counter(raw: bytes) -> dict[str, int]:
        values = counter_parser(raw)
        require(active is not None and active.current_job is not None, "counter lacks exact active job scope")
        filename = "cpu.stat" if active.row["workload"] == "cpu" else f"{active.row['workload']}.events"
        active.event("kernel_raw", job_id=active.current_job, filename=filename,
                     context="retained_counter_read", raw=raw.decode("ascii"), counters=values,
                     cgroup_inode=active.group_inodes[active.current_job],
                     read_started_ns=active.last_cpu_read[0] if filename == "cpu.stat" else None,
                     read_finished_ns=active.last_cpu_read[1] if filename == "cpu.stat" else None)
        return values

    resources.counters = capture_counter
    try:
        # Native preflight creates the root only after mandatory bounded mount,
        # executable ownership and cgroup2 checks. No guest starts here.
        initial_args = argparse.Namespace(**vars(args), fixture=args.resource_fixture)
        active = Resources(initial_args)
        active.preflight()
        journal = Journal(root)
        active.bind(journal, {"sample_index": -1})
        require(not active.cleanup(), "initial preflight cleanup failed")
        active = None
        native.write_synthetic(root / "schedule.json", encode({"benchmark": "B-04", "mode": args.mode,
                               "run_id": rows[0]["run_id"], "rows": rows, "warmups": 0,
                               "required_full_repetitions_each": 30, "profiles": list(PROFILES)}))
        native.write_synthetic(root / "environment.json", encode(provenance(args, root, benchmark, native)))
        for destination, supplied in (("build-record.json", args.build_record), ("host-record.json", args.host_record)):
            native.write_synthetic(root / destination, native.read_file(native.absolute(supplied), 64 * 1024))
        for row in rows:
            require(time.monotonic() < deadline, "B-04 campaign deadline exceeded")
            host_reserve(root, native.absolute(args.cgroup_root), journal, native, row["sample_index"])
            row["status"], row["started_ns"] = "INCOMPLETE", time.monotonic_ns()
            journal.save("attempts.jsonl", dict(row))
            fixture = args.scheduler_fixture if row["workload"] == "admission" else args.resource_fixture
            shard_args = argparse.Namespace(**{**vars(args), "fixture": fixture,
                                               "work": str(root / f"shard-{row['sample_index']:03d}")})
            active = Scheduler(shard_args) if row["workload"] == "admission" else Resources(shard_args)
            active.native = scheduler.native if row["workload"] == "admission" else native
            active.bind(journal, row)
            prepare(active)
            if row["workload"] == "memory":
                active.kernel_limit("memory", "memory.events", "oom_kill")
            elif row["workload"] == "pids":
                active.kernel_limit("pids", "pids.events", "max")
            elif row["workload"] == "cpu":
                active.cpu()
            else:
                active.capacity_fifo()
            row["measurements"] = active.observations["cases"]
            validate_measurement(row["workload"], row["measurements"])
            active.supervisor_sample("after-profile")
            records = active.phases()
            for record in records:
                require(record["state"] in active.native.TERMINAL and record.get("cleanup_confirmed") is True,
                        "profile left a nonterminal/unconfirmed job")
                active.verify_result(record["job_id"], record["state"])
            require(not active.group_names(), "profile retained cgroups")
            require(len(records) == (21 if row["workload"] == "admission" else 1), "unexpected native attempt/job count")
            stopped = active
            errors = active.cleanup()
            require(not errors and all(child.proc.poll() is not None for child in active.children),
                    f"native shard teardown failed: {errors}")
            active = None
            row["teardown"] = {"status": "PASS", "owned_children_reaped": True, "owned_cgroups_remaining": 0}
            journal.save("events.jsonl", {"type": "shard_teardown", "sample_index": row["sample_index"],
                                         "jobs": len(records), **row["teardown"]})
            benchmark.compact_shard(stopped)
            journal.save("events.jsonl", {"type": "compaction", "sample_index": row["sample_index"],
                                         "monotonic_ns": time.monotonic_ns(), "shard": stopped.work.name,
                                         "archive_sha256": benchmark.digest(stopped.work / "transients.tar.gz"),
                                         "index_sha256": benchmark.digest(stopped.work / "transients-index.json"),
                                         "compaction_sha256": benchmark.digest(stopped.work / "compaction.json")})
            checkpoint(root, journal, row["sample_index"], "after-compaction")
            row["status"], row["finish_ns"] = "PASS", time.monotonic_ns()
            journal.save("samples.jsonl", row)
        code = 0
    except BaseException as error:
        reason = f"{type(error).__name__}: {error}"[:2048]
        code = 78 if isinstance(error, (native.Blocked, scheduler.native.Blocked)) else 1
        for unfinished in rows:
            if unfinished["status"] == "INCOMPLETE":
                unfinished.update(status="FAIL", reason=reason, finish_ns=time.monotonic_ns())
        if active is not None and hasattr(active, "row") and active.row.get("sample_index", -1) >= 0:
            active.row.update(status="FAIL", reason=reason, finish_ns=time.monotonic_ns(),
                              measurements=active.observations["cases"])
    finally:
        resources.counters = counter_parser
        if active is not None:
            errors = []
            try:
                if active.instance is not None:
                    active.jobs.update(active.inventory())
                    if active.server is not None and active.server.proc.poll() is None:
                        active.phases()
            except Exception as error:
                errors.append(f"identity/phase reconciliation: {type(error).__name__}: {error}")
            try:
                errors.extend(active.cleanup())
            except Exception as error:
                errors.append(f"cleanup: {type(error).__name__}: {error}")
            teardown = {"status": "FAIL" if errors else "PASS", "errors": errors,
                        "owned_children_reaped": all(child.proc.poll() is not None for child in active.children),
                        "owned_cgroups_remaining": None if errors else 0}
            if hasattr(active, "row") and active.row.get("sample_index", -1) >= 0:
                active.row["teardown"] = teardown
            if journal is not None:
                journal.save("events.jsonl", {"type": "aborted_teardown", "sample_index": active.row["sample_index"], **teardown})
            if errors:
                code = 1
                reason = f"{reason}; teardown: {errors}"[:4096]
        if journal is not None:
            for row in rows:
                if row["status"] != "PASS":
                    if row["status"] == "NOT RUN":
                        row["reason"] = "campaign stopped before attempt; see summary"
                    journal.save("samples.jsonl", row)
            summary = {"benchmark": "B-04", "mode": args.mode, "run_id": rows[0]["run_id"],
                       "status": "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL",
                       "reason": reason, "planned": len(rows), "counts": dict(Counter(row["status"] for row in rows)),
                       "groups": [{"workload": profile, "planned": sum(row["workload"] == profile for row in rows),
                                   "counts": dict(Counter(row["status"] for row in rows if row["workload"] == profile))}
                                  for profile in PROFILES],
                       "supervisor_scope": "owned Popen PID/start_ticks /proc VmRSS and fd-directory samples; no peak claim",
                       "scope": "synthetic fixed native B-04 only; smoke never establishes full matrix; mutants/review separate"}
            native.write_synthetic(root / "summary.json", encode(summary))
            journal.close()
        print(json.dumps({"benchmark": "B-04", "mode": args.mode, "exit_code": code, "reason": reason,
                          "counts": dict(Counter(row["status"] for row in rows))}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
