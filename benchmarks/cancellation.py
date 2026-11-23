#!/usr/bin/env python3
"""Bounded real-native B-03 cancellation campaign; never builds or provisions.

Capture a static build of fixtures/native/cancellation.c, then run through capture.py:
  python3 -B benchmarks/cancellation.py --mode smoke --bin-dir ABS_RELEASE_BIN \
    --doctor ABS_DOCTOR --fixture ABS_STATIC_CANCELLATION --cgroup-root ABS_JOBS \
    --build-record ABS_BUILD_JSON --host-record ABS_HOST_JSON --work ABS_NEW_WORK
Use --mode full for 5 seeds x 100 cancels x 3 fixtures x concurrency 1/4.
The build-record JSON additionally requires a cancellation object with actual
source_sha256, fixture_sha256, build_command and capture_manifest_sha256.
No warmups are prescribed for B-03. Smoke is eight jobs/type/concurrency with
one seed, never full evidence. All failed attempts remain in the denominator.

Client request and acknowledgement clocks are real observations. The current
protocol exposes neither server receipt nor exact kill issuance: those fields
stay null. Cleanup timing is an observation upper bound including host polling;
it is not an exact kernel transition time. cgroup removal proves emptiness but
is never described as a directly sampled populated=0 value.

Requires the already established project-wide 15GB enforced storage boundary.
The inherited native preflight independently checks bounded noswap tmpfs and
ownership. The campaign checks headroom, keeps <=100 jobs/shard and losslessly
compacts successful stopped shards using the public benchmark helper. It never
removes failed-shard evidence. Parent capture must use bounded storage too.
"""
from __future__ import annotations

import argparse
import collections
import errno
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import signal
import stat
import sys
import time
from typing import Any

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("b03_campaign_helper", ROOT / "benchmarks/campaign.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("public benchmark helper cannot be loaded")
b = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = b
SPEC.loader.exec_module(b)
n = b.n
MODES = ("spin", "detached", "output")
SHARD_JOBS = 100
OUTPUT_SHARD_JOBS = 48
STREAM_LIMIT = 1024 * 1024
OUTPUT_BLOCK = b"B" * 4095 + b"\n"
OUTPUT_READY_BYTES = 32 * len(OUTPUT_BLOCK)
MAX_ROWS = 3000
MAX_RECORD_BYTES = 64 * 1024
MAX_RAW_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 8 * 3600
PROVENANCE = {
    "clock": "time.monotonic_ns on harness host; polling observations are upper bounds",
    "cancel_request_ns": "client immediately before owner-only RPC, including connect/send; not server receipt",
    "cancel_ack_ns": "client after complete framed acknowledgement validation",
    "cancel_receipt_ns": "unavailable: current protocol has no server receipt timestamp",
    "kill_request_ns": "unavailable: current protocol/journal exposes no exact cgroup.kill issue timestamp",
    "launcher_reap_ns": "first /proc PID/start_ticks absence/reuse; zombie is not reaped",
    "empty_observed_ns": "first retained cgroup.events populated=0; null if removal won race",
    "empty_confirmed_ns": "first populated=0 or verified owned leaf removal; removal kernel invariant implies empty",
    "cleanup_ns": "first poll satisfying no live observed members, launcher reap and confirmed empty",
    "start_ns": "actual guest marker-FD plus cmdline and kernel membership observation, not exact exec time",
}


class Evidence:
    def __init__(self, root: Path):
        self.root = root
        self.bytes = 0
        self.sample_indices: set[int] = set()
        self.fds: dict[str, int] = {}
        self.unrecoverable: set[str] = set()
        try:
            for name in ("attempts.jsonl", "samples.jsonl", "events.jsonl"):
                self.fds[name] = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        except BaseException:
            self.close()
            raise

    def save(self, name: str, row: dict[str, Any]) -> None:
        raw = b.encode(row)
        n.require(len(raw) <= MAX_RECORD_BYTES, "B-03 raw record exceeds bound")
        n.require(self.bytes + len(raw) <= MAX_RAW_BYTES, "B-03 raw journal exceeds bound")
        n.require(name not in self.unrecoverable, "cannot append after a failed evidence rollback")
        if name == "samples.jsonl":
            n.require(row["sample_index"] not in self.sample_indices, "duplicate B-03 sample identity")
        fd = self.fds[name]
        start = os.lseek(fd, 0, os.SEEK_END)
        pending = memoryview(raw)
        try:
            while pending:
                written = os.write(fd, pending)
                if written == 0:
                    raise OSError(errno.EIO, "B-03 journal write made no progress")
                pending = pending[written:]
            os.fsync(fd)
        except BaseException:
            try:
                os.ftruncate(fd, start)
                os.fsync(fd)
            except OSError:
                self.unrecoverable.add(name)
                raise
            raise
        self.bytes += len(raw)
        if name == "samples.jsonl":
            self.sample_indices.add(row["sample_index"])

    def close(self) -> None:
        for fd in self.fds.values():
            os.close(fd)


class Shard(b.Shard):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.deadline = time.monotonic() + 900

    def ready(self, row: dict[str, Any]) -> dict[str, Any] | None:
        job, mode = row["job_id"], row["workload"]
        record = self.record(job)
        n.require(record.get("state") not in n.TERMINAL, "fixture terminated before cancellation readiness")
        if record.get("state") != "RUNNING" or record.get("launch_stage") != "EXEC_RELEASED":
            return None
        try:
            group = self.open_group(job)
        except FileNotFoundError:
            return None
        try:
            raw = self.control_read(group, "cgroup.procs").splitlines()
            n.require(len(raw) <= 32 and all(line.isdigit() for line in raw), "malformed bounded cgroup inventory")
            members = [entry for line in raw if (entry := self.process_identity(int(line))) is not None]
            n.require(self.server is not None, "supervisor missing")
            launchers = [entry for entry in members if entry["ppid"] == self.server.proc.pid]
            if len(launchers) != 1:
                return None
            marker_members = []
            for member in members:
                pid = member["pid"]
                try:
                    command = n.read_file(Path(f"/proc/{pid}/cmdline"), 4096, virtual=True)
                    if command != b"/bin/task\0" + mode.encode() + b"\0":
                        continue
                    # readlink observes only the kernel FD target; it never opens
                    # a guest-supplied target or follows an output pathname.
                    fd_root = Path(f"/proc/{pid}/fd")
                    fds = list(fd_root.iterdir())
                    n.require(len(fds) <= 32, "fixture FD inventory exceeds bound")
                    found = False
                    for fd in fds:
                        try:
                            found |= os.readlink(fd) == f"/out/b03-ready-{mode}"
                        except FileNotFoundError:
                            continue
                    current = self.process_identity(pid)
                    if found and current is not None and current["start_ticks"] == member["start_ticks"] and current["state"] != "Z":
                        marker_members.append(current)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except PermissionError:
                    # A matching process can still be transitioning through
                    # exec. Only a later positive retained-FD witness is ready.
                    row["readiness_access_denied"] += 1
                    continue
            if len(marker_members) != 1 or len(members) < (4 if mode == "detached" else 3):
                return None
            if mode == "detached":
                inits = [entry for entry in members if entry["ppid"] == launchers[0]["pid"]]
                leaders = [entry for entry in members if entry["pid"] != marker_members[0]["pid"] and
                           any(entry["ppid"] == init["pid"] for init in inits)]
                if len(inits) != 1 or len(leaders) != 1:
                    return None
                n.require(marker_members[0]["session"] != leaders[0]["session"], "actual ready descendant is not detached")
            n.require(b"populated 1\n" in self.control_read(group, "cgroup.events"), "ready group is not actually populated")
            row.update({"start_ns": time.monotonic_ns(), "members": members, "launchers": launchers,
                        "ready_marker_members": marker_members})
            return {"group": group, "members": members, "launchers": launchers}
        finally:
            # Ownership transfers only when ready evidence was recorded.
            if row["start_ns"] is None:
                os.close(group)

    def population(self, group: int, job: str) -> str:
        try:
            raw = self.control_read(group, "cgroup.events")
            values = [line for line in raw.splitlines() if line.startswith(b"populated ")]
            n.require(values in ([b"populated 0"], [b"populated 1"]), "ambiguous populated counter")
            return "empty" if values == [b"populated 0"] else "populated"
        except OSError as error:
            if error.errno not in {errno.ENOENT, errno.ENODEV}:
                raise
            n.require(self.group_name(job) not in self.group_names(), "owned control disappeared while leaf remains")
            return "removed"

    def observe(self, row: dict[str, Any], owned: dict[str, Any]) -> bool:
        job = row["job_id"]
        population = self.population(owned["group"], job)
        observed = time.monotonic_ns()
        if population == "empty" and row["empty_observed_ns"] is None:
            row["empty_observed_ns"] = observed
        if population in {"empty", "removed"} and row["empty_confirmed_ns"] is None:
            row.update({"empty_confirmed_ns": observed, "empty_confirmation": population})
        live = []
        unreaped = []
        for member in owned["members"]:
            current = self.process_identity(member["pid"])
            if current is not None and current["start_ticks"] == member["start_ticks"]:
                if current["state"] != "Z":
                    live.append(current["pid"])
                if member in owned["launchers"]:
                    unreaped.append(current["pid"])
        if not unreaped and row["launcher_reap_ns"] is None:
            row["launcher_reap_ns"] = time.monotonic_ns()
            row["launcher_reap_witness"] = [{"original": launcher, "current": self.process_identity(launcher["pid"])}
                                            for launcher in owned["launchers"]]
        record = self.record(job)
        row["state"] = record.get("state")
        row["cleanup_pending_observations"] += record.get("state") == "CLEANUP_PENDING"
        after = self.population(owned["group"], job)
        row["last_observation"] = {"monotonic_ns": time.monotonic_ns(), "population_before": population,
                                   "population_after": after, "journal_state": record.get("state"),
                                   "observed_live_pids": live, "unreaped_launcher_pids": unreaped}
        if population == after == "populated":
            n.require(record.get("state") not in n.TERMINAL and record.get("state") != "EXPORTING", "terminal/export observed while group populated")
        if record.get("state") in n.TERMINAL or record.get("state") == "EXPORTING":
            # Recheck after the journal read: reap may race the earlier poll.
            for launcher in owned["launchers"]:
                current = self.process_identity(launcher["pid"])
                n.require(current is None or current["start_ticks"] != launcher["start_ticks"], "completion observed before launcher reap")
        if not live and not unreaped and row["empty_confirmed_ns"] is not None and row["cleanup_ns"] is None:
            row["cleanup_ns"] = time.monotonic_ns()
        return row["cleanup_ns"] is not None and record.get("state") in n.TERMINAL


def fresh_row(run_id: str, index: int, seed: int, repetition: int, mode: str, concurrency: int) -> dict[str, Any]:
    return {"run_id": run_id, "benchmark": "B-03", "sample_index": index, "seed": seed,
            "repetition": repetition, "workload": mode, "concurrency": concurrency, "bytes": 0,
            "planned_cancel_delay_ms": random.Random(seed ^ index).randint(5, 50),
            "request_id": hashlib.sha256(f"B-03 {run_id} {index}".encode()).hexdigest()[:32],
            "job_id": None, "status": "NOT RUN", "state": None, "submit_ns": None,
            "start_ns": None, "finish_ns": None, "cancel_ns": None, "cancel_request_ns": None,
            "cancel_ack_ns": None, "cancel_receipt_ns": None, "kill_request_ns": None,
            "empty_observed_ns": None, "empty_confirmed_ns": None, "launcher_reap_ns": None,
            "cleanup_ns": None, "exit_code": None, "max_rss_bytes": None, "cpu_usec": None,
            "output_digest": None, "cleanup_pending_observations": 0, "readiness_access_denied": 0, "reason": None}


def wave(h: Shard, stage: str, rows: list[dict[str, Any]], evidence: Evidence) -> None:
    owned: dict[int, dict[str, Any]] = {}
    try:
        for row in rows:
            row["status"] = "INCOMPLETE"
            row["submit_ns"] = time.monotonic_ns()
            evidence.save("attempts.jsonl", dict(row))
            response = h.rpc("submit", request_id=row["request_id"], profile_id="example", stage_id=stage,
                             argv=[row["workload"]], wall_ms=12000)
            job = response.get("job_id")
            n.require(isinstance(job, str) and n.ID.fullmatch(job) is not None, "submit lacks job identity")
            row["job_id"] = job
            h.jobs.add(job)
        until = min(h.deadline, time.monotonic() + 4)
        while len(owned) < len(rows):
            h.pump_server()
            if time.monotonic() >= until:
                denied = sum(row["readiness_access_denied"] for row in rows)
                raise n.Failure(f"wave actual fixture readiness expired after {denied} denied process observations")
            for row in rows:
                if row["sample_index"] not in owned:
                    value = h.ready(row)
                    if value is not None:
                        owned[row["sample_index"]] = value
            time.sleep(0.001)
        # Bracket simultaneous readiness so c4 cannot accidentally measure four
        # sequential jobs. Marker-ready processes all remain in populated groups.
        for row in rows:
            n.require(h.record(row["job_id"])["state"] == "RUNNING" and
                      b"populated 1\n" in h.control_read(owned[row["sample_index"]]["group"], "cgroup.events"),
                      "concurrent wave was not simultaneously running before cancel")
        random.Random(rows[0]["seed"] ^ rows[0]["sample_index"]).shuffle(rows)
        wave_ready_ns = time.monotonic_ns()
        for row in rows:
            due_ns = wave_ready_ns + row["planned_cancel_delay_ms"] * 1000000
            while time.monotonic_ns() < due_ns:
                h.pump_server()
                remaining_ns = max(0, due_ns - time.monotonic_ns())
                time.sleep(min(.001, remaining_ns / 1000000000))
            row["cancel_request_ns"] = row["cancel_ns"] = time.monotonic_ns()
            # Persist intention before sending, outside the measured interval.
            evidence.save("events.jsonl", {"type": "cancel_intent", "sample_index": row["sample_index"],
                                          "client_before_intent_fsync_ns": row["cancel_request_ns"]})
            row["cancel_request_ns"] = row["cancel_ns"] = time.monotonic_ns()
            ack = h.rpc("cancel", job_id=row["job_id"])
            row["cancel_ack_ns"] = time.monotonic_ns()
            row["cancel_ack"] = ack
            n.require(ack.get("cancel_requested") is True, "cancel was not acknowledged as requested")
        until = min(h.deadline, time.monotonic() + 15)
        remaining = {row["sample_index"] for row in rows}
        while remaining:
            h.pump_server()
            n.require(time.monotonic() < until, "cancelled wave cleanup deadline expired")
            for row in rows:
                if row["sample_index"] in remaining and h.observe(row, owned[row["sample_index"]]):
                    remaining.remove(row["sample_index"])
            time.sleep(0.001)
        for row in rows:
            n.require(row["state"] == "CANCELLED", f"unexpected cancellation terminal state: {row['state']}")
            h.terminal(row["job_id"], "CANCELLED")
            metadata, stdout, stderr = h.verify_result(row["job_id"], "CANCELLED")
            n.require(metadata["artifacts"] == [], "cancelled fixture exported artifacts")
            if row["workload"] == "output":
                expected = OUTPUT_BLOCK * (STREAM_LIMIT // len(OUTPUT_BLOCK))
                n.require(metadata["stdout_truncated"] is False and metadata["stderr_truncated"] is False
                          and all(OUTPUT_READY_BYTES < len(stream) <= STREAM_LIMIT
                                  and stream == expected[:len(stream)] for stream in (stdout, stderr)),
                          "output did not continue past readiness with exact bounded prefixes")
                row.update({"stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                            "output_ready_bytes_per_stream": OUTPUT_READY_BYTES})
            else:
                n.require(stdout == stderr == b"" and metadata["stdout_truncated"] is False
                          and metadata["stderr_truncated"] is False, "silent cancellation fixture emitted output")
            row.update({"finish_ns": time.monotonic_ns(), "exit_code": metadata["exit_code"],
                        "output_digest": h.record(row["job_id"])["result_digest"], "status": "PASS"})
        n.require(not h.group_names(), "completed cancellation wave retained cgroups")
    except BaseException as error:
        for row in rows:
            if row["status"] != "NOT RUN":
                row["status"] = "FAIL"
                row["reason"] = f"{type(error).__name__}: {error}"[:1024]
        raise
    finally:
        for value in owned.values():
            os.close(value["group"])
        for row in rows:
            evidence.save("samples.jsonl", row)


def quantiles(values: list[int]) -> dict[str, int | None]:
    values = sorted(values)
    return {**{name: values[max(0, math.ceil(len(values) * fraction) - 1)] if values else None
               for name, fraction in (("p50_ns", .5), ("p95_ns", .95), ("p99_ns", .99))},
            "min_ns": min(values) if values else None, "max_ns": max(values) if values else None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("bin-dir", "doctor", "fixture", "cgroup-root", "build-record", "host-record", "work"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--seed", type=int, default=21083)
    args = parser.parse_args()
    def terminate(_signum: int, _frame: Any) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        raise n.Failure("termination requested; preserving rows and reconciling owned resources")
    signal.signal(signal.SIGTERM, terminate)
    run_id = n.secrets.token_hex(16)
    seeds = random.Random(args.seed).sample(range(1 << 32), 5 if args.mode == "full" else 1)
    rows = []
    for seed in seeds:
        for mode in MODES:
            for concurrency in (1, 4):
                for repetition in range(100 if args.mode == "full" else 8):
                    rows.append(fresh_row(run_id, len(rows), seed, repetition, mode, concurrency))
    n.require(len(rows) <= MAX_ROWS, "B-03 schedule exceeds fixed bound")
    root = n.absolute(args.work)
    active: Shard | None = None
    evidence: Evidence | None = None
    code = 1
    error_text = None
    deadline = time.monotonic() + MAX_SECONDS
    try:
        active = Shard(args)
        active.preflight()
        evidence = Evidence(root)
        b.json_file(root / "schedule.json", {"benchmark": "B-03", "run_id": run_id, "mode": args.mode,
            "master_seed": args.seed, "seeds": seeds, "planned_jobs": len(rows), "shard_job_bound": SHARD_JOBS,
            "output_shard_job_bound": OUTPUT_SHARD_JOBS,
            "timing_provenance": PROVENANCE, "warmups": 0, "rows": rows})
        # Reuse only the storage/accounting object; its B-01/B-02 preflight
        # would mislabel this fixture's source, so bind B-03 provenance here.
        n.require(not active.cleanup(), "initial preflight teardown failed")
        active = None
        provenance_args = argparse.Namespace(**vars(args))
        provenance_args.work = str(root)
        provenance_args.workload = "B-01"
        provenance_args.aggregate_fixture = None
        provenance = b.Campaign(provenance_args)
        try:
            provenance.storage_checkpoint("B-03-start")
            n.new_private(root / ".finalization-reserve")
            reserve_info = (root / ".finalization-reserve").lstat()
            provenance.reserve_directory = (reserve_info.st_dev, reserve_info.st_ino)
            for index in range(b.RESERVE_FILES):
                name = f"{index:03d}"
                n.write_synthetic(root / ".finalization-reserve" / name, b"\0" * b.RESERVE_FILE_BYTES)
                info = (root / ".finalization-reserve" / name).lstat()
                provenance.reserve.append((name, info.st_dev, info.st_ino))
            fixture_source = ROOT / "fixtures/native/cancellation.c"
            n.require(fixture_source.resolve(strict=True) == fixture_source, "fixture source contains symlinks")
            build = n.strict_json(n.read_file(n.absolute(args.build_record), 64 * 1024))
            n.require(build.get("source_sha256") == b.c.source_digest(ROOT), "build record differs from current public source")
            n.require(isinstance(build.get("rustc_verbose"), str) and build["rustc_verbose"].startswith("rustc 1.99.1 ") and
                      build.get("profile") == "release" and isinstance(build.get("optimization_flags"), list) and
                      build["optimization_flags"] and isinstance(build.get("target"), str) and build["target"], "missing pinned release compiler provenance")
            n.require(isinstance(build.get("build_command"), list) and build["build_command"] and
                      n.DIGEST.fullmatch(build.get("capture_manifest_sha256", "")), "missing captured build provenance")
            binaries = {name: b.digest(n.absolute(args.bin_dir) / name) for name in
                        ("hearthrun", "hearthrun-supervisor", "hearthrun-launcher")}
            n.require(build.get("binary_sha256") == binaries, "native executable differs from captured build")
            fixture_build = build.get("cancellation")
            n.require(isinstance(fixture_build, dict) and fixture_build.get("fixture_sha256") == b.digest(n.absolute(args.fixture)) and
                      fixture_build.get("source_sha256") == b.digest(fixture_source) and
                      isinstance(fixture_build.get("build_command"), list) and fixture_build["build_command"] and
                      n.DIGEST.fullmatch(fixture_build.get("capture_manifest_sha256", "")), "missing matching captured cancellation fixture build")
            host = n.strict_json(n.read_file(n.absolute(args.host_record), 32 * 1024))
            n.require(isinstance(host, dict) and all(key in host for key in
                      ("power_policy", "background_load_control", "filesystem_mount_options", "landlock_abi", "seccomp_mode")), "host record lacks required observations")
            filesystem, options = n.mount_for(root)
            environment = {"benchmark": "B-03", "runtime": "actual local Linux native supervisor/launcher",
                "kernel": platform.release(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                "background_load_start": os.getloadavg(), "build": build, "host_record": host,
                "mount": {"filesystem": filesystem, "options": sorted(options)},
                "clock": time.get_clock_info("monotonic").implementation,
                "fixture_sha256": b.digest(n.absolute(args.fixture)), "fixture_source_sha256": b.digest(fixture_source),
                "doctor_sha256": b.digest(n.absolute(args.doctor)), "source_sha256": b.c.source_digest(ROOT),
                "fixture_provenance": "operator-supplied approved static executable; retain external captured build manifest",
                "timing_provenance": PROVENANCE}
            for field, path, bound in (("cpuinfo", "/proc/cpuinfo", 1024 * 1024),
                                       ("meminfo", "/proc/meminfo", 64 * 1024),
                                       ("boot_id", "/proc/sys/kernel/random/boot_id", 128),
                                       ("cgroup_controllers", str(n.absolute(args.cgroup_root) / "cgroup.controllers"), 4096)):
                raw = n.read_file(Path(path), bound, virtual=True).decode("utf-8")
                if field == "cpuinfo":
                    raw = "\n".join(sorted({line for line in raw.splitlines() if line.startswith(("model name", "cpu cores", "siblings"))}))
                environment[field] = raw
            environment["environment_id"] = hashlib.sha256(b.encode(environment)).hexdigest()
            b.json_file(root / "environment.json", environment)
        except BaseException:
            provenance.release_reserve()
            raise
        def checkpoint(context: str) -> None:
            nonlocal evidence
            capacity = b.capacity(root)
            total = entries = 0
            for parent, directories, files in os.walk(root, followlinks=False):
                for name in directories + files:
                    info = (Path(parent) / name).lstat()
                    n.require(not stat.S_ISLNK(info.st_mode), "unexpected symlink in campaign storage")
                    total += max(info.st_size, info.st_blocks * 512)
                    entries += 1
                    n.require(entries <= 100000, "B-03 storage inode bound exceeded")
            evidence.save("events.jsonl", {"type": "storage", "context": context, "monotonic_ns": time.monotonic_ns(),
                                           "accounted_bytes": total, "entries": entries, **capacity})
            n.require(total <= b.MAX_EVIDENCE_BYTES and capacity["available_bytes"] >= b.SHARD_HEADROOM_BYTES and
                      capacity["available_inodes"] >= b.SHARD_HEADROOM_INODES, "B-03 storage/headroom bound exceeded")
        shard_index = 0
        # Homogeneous shards preserve 100 cancels per seed/type/concurrency;
        # smoke uses one short shard per combination. No shard exceeds 100 jobs.
        groups: dict[tuple[int, str, int], list[dict[str, Any]]] = collections.defaultdict(list)
        for row in rows:
            groups[(row["seed"], row["workload"], row["concurrency"])].append(row)
        for (_, mode, concurrency), group_rows in groups.items():
            shard_bound = OUTPUT_SHARD_JOBS if mode == "output" else SHARD_JOBS
            for start in range(0, len(group_rows), shard_bound):
                shard_rows = group_rows[start:start + shard_bound]
                shard_index += 1
                checkpoint("before-shard")
                n.require(time.monotonic() < deadline, "campaign deadline expired")
                shard_args = argparse.Namespace(**vars(args))
                shard_args.work = str(root / f"shard-{shard_index:04d}")
                active = Shard(shard_args)
                stage = active.prepare(b'{"value":1}\n')
                for offset in range(0, len(shard_rows), concurrency):
                    n.require(time.monotonic() < deadline, "campaign deadline expired")
                    wave(active, stage, shard_rows[offset:offset + concurrency], evidence)
                n.require(len(active.inventory()) == len(shard_rows) <= shard_bound, "shard inventory differs from schedule")
                errors = active.cleanup()
                n.require(not errors and all(child.proc.poll() is not None for child in active.children), f"shard cleanup failed: {errors}")
                stopped = active
                active = None
                b.compact_shard(stopped)
                teardown = {"type": "shard_teardown", "shard": shard_index, "status": "PASS", "jobs": len(shard_rows),
                            "owned_children_reaped": True, "owned_cgroups_remaining": 0}
                b.json_file(stopped.work / "teardown.json", teardown)
                evidence.save("events.jsonl", teardown)
                checkpoint("after-shard")
        code = 0
    except n.Blocked as error:
        code, error_text = 78, str(error)[:1024]
    except BaseException as error:
        error_text = f"{type(error).__name__}: {error}"[:1024]
    finally:
        if "provenance" in locals():
            try:
                provenance.release_reserve()
            except Exception as error:
                code = 1
                error_text = f"{error_text or ''}; reserve release: {type(error).__name__}: {error}"[:2048]
        if active is not None:
            # Catalog reconciliation includes submissions whose response was
            # lost. Retain the request/job mapping before owned cleanup.
            try:
                if active.created_work and (active.state / "records/catalog.json").exists():
                    for job in active.inventory():
                        record = active.record(job)
                        matching = [row for row in rows if row["request_id"] == record["request_id"]]
                        if matching and matching[0]["job_id"] is None:
                            matching[0]["job_id"] = job
                            if evidence is not None:
                                evidence.save("events.jsonl", {"type": "lost_submit_reconciled", "job_id": job,
                                    "request_id": record["request_id"], "sample_index": matching[0]["sample_index"]})
            except Exception as error:
                code = 1
                error_text = f"{error_text or ''}; reconciliation: {type(error).__name__}: {error}"[:2048]
            try:
                errors = active.cleanup()
            except Exception as error:
                errors = [f"{type(error).__name__}: {error}"]
            if errors:
                code = 1
                error_text = f"{error_text or ''}; teardown: {errors}"[:2048]
        if evidence is not None:
            for row in rows:
                if row["sample_index"] not in evidence.sample_indices:
                    if row["status"] == "NOT RUN":
                        row["reason"] = "campaign stopped before attempt; see summary"
                    evidence.save("samples.jsonl", row)
            summaries = []
            for mode in MODES:
                for concurrency in (1, 4):
                    population = [row for row in rows if row["workload"] == mode and row["concurrency"] == concurrency]
                    passed = [row for row in population if row["status"] == "PASS"]
                    times = [row["cleanup_ns"] - row["cancel_request_ns"] for row in passed]
                    batches = []
                    for seed in seeds:
                        values = [row["cleanup_ns"] - row["cancel_request_ns"] for row in passed if row["seed"] == seed]
                        batches.append({"seed": seed, "success_count": len(values), **quantiles(values)})
                    summaries.append({"workload": mode, "concurrency": concurrency, "planned": len(population),
                        "counts": dict(collections.Counter(row["status"] for row in population)),
                        "latency_population": "successful validated cancellations only; failures retained in raw denominator",
                        "cancel_request_to_cleanup": quantiles(times), "batches": batches,
                        "cancel_receipt_to_kill_request": None,
                        "cleanup_pending_jobs": sum(row["cleanup_pending_observations"] > 0 for row in population),
                        "p95_target_ns": 250000000, "p95_target_met": None if not times else quantiles(times)["p95_ns"] <= 250000000})
            b.json_file(root / "summary.json", {"benchmark": "B-03", "run_id": run_id, "mode": args.mode,
                "status": "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL", "error": error_text,
                "planned": len(rows), "counts": dict(collections.Counter(row["status"] for row in rows)),
                "quantile_method": "nearest rank", "timing_provenance": PROVENANCE, "groups": summaries,
                "scope": "synthetic local cancellation only; native mutants and independent review remain separate gates"})
            evidence.close()
        n.emit("B-03", "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL", reason=error_text,
               planned=len(rows), counts=dict(collections.Counter(row["status"] for row in rows)))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
