#!/usr/bin/env python3
"""Pure synthetic B-04 validator tests. These never execute native fixtures."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


driver = load("synthetic_capacity_driver", "capacity.py")
analyzer = load("synthetic_capacity_analyzer", "analyze_capacity.py")


def raw_counter(job, filename, values, context="retained_counter_read"):
    return {"type": "kernel_raw", "job_id": job, "filename": filename, "context": context,
            "cgroup_inode": 2000,
            "raw": "".join(f"{key} {value}\n" for key, value in values.items()), "counters": values}


def fixture(workload):
    """Construct explicitly fictional observations for validation branches only."""
    row = next(row for row in driver.plan("smoke", "synthetic-only") if row["workload"] == workload)
    row.update(status="PASS", started_ns=100, finish_ns=30_000_000_000,
               teardown={"status": "PASS", "owned_children_reaped": True, "owned_cgroups_remaining": 0})
    pid = {"pid": 321, "start_ticks": 456, "state": "S"}
    events = [{"type": "supervisor_proc", "context": context, "identity": dict(pid), "identity_after": dict(pid),
               "monotonic_ns": stamp,
               "vmrss_line": "VmRSS: 123 kB", "rss_bytes": 123 * 1024, "fd_numbers": [0, 1, 2], "fd_count": 3}
              for context, stamp in (("before-profile", 120), ("after-profile", 20_000_000_000))]
    events.append({"type": "supervisor_spawn", "popen_pid": pid["pid"], "identity": dict(pid), "monotonic_ns": 110})
    events.extend([{"type": "host_reserve", "monotonic_ns": 50,
                    "service_controls": {"memory.max": "8000000000", "memory.swap.max": "0", "memory.current": "2000000000",
                                         "pids.max": "256", "pids.current": "12", "cpu.max": "max 100000"},
                    "delegated_controllers": "cpu memory pids", "host_mem_available_line": "MemAvailable: 2000000 kB"},
                   *[{"type": "storage", "context": context, "monotonic_ns": stamp, "retained_bytes": 1000, "entries": 30,
                      "available_bytes": 1_000_000_000, "available_inodes": 20_000}
                     for context, stamp in (("before-trial", 60), ("after-compaction", 25_000_000_000))]])
    jobs = [f"{index + 1:032x}" for index in range(21 if workload == "admission" else 1)]
    records = {}
    for index, job in enumerate(jobs):
        record = {"job_id": job, "instance_id": "b" * 32, "request_id": f"{1000 + index:032x}",
                  "state": "CANCELLED" if workload == "admission" and index < 4 else "SUCCEEDED",
                  "executable_digest": "e" * 64, "launch_stage": "CLEANED", "started_monotonic_ns": 1000 + index,
                  "cleanup_confirmed": True, "result_digest": "a" * 64}
        if workload == "admission" and index == 20:
            record["request_id"] = "f" * 32
        if workload in {"memory", "pids"}:
            record.update(state="FAILED", cancel_reason="RESOURCE_LIMIT")
        records[job] = record
        events.extend([{"type": "job_record", "job_id": job, "record": {"job_id": job, "state": "SUCCEEDED",
                       "cleanup_confirmed": True, "result_digest": "a" * 64}},
                       {"type": "native_phase_page", "job_id": job, "after_seq": 0,
                        "page": {"truncated": False, "events": [{"event": "RUNNING", "sequence": 1}], "next_seq": 1}}])
        events[-2]["record"] = record
    events.append({"type": "shard_teardown", "status": "PASS", "jobs": len(jobs),
                   "owned_children_reaped": True, "owned_cgroups_remaining": 0})
    def membership(job, index):
        launcher = {"pid": 1000 + 4 * index, "ppid": pid["pid"], "start_ticks": 5000 + index, "state": "S"}
        members = [launcher, *[{"pid": launcher["pid"] + step, "ppid": launcher["pid"], "start_ticks": 6000 + step + index,
                               "state": "S"} for step in (1, 2, 3)]]
        events.extend([{"type": "cgroup_controls", "job_id": job, "cgroup_inode": 2000 + index,
                        "group_name": f"hr-{'b' * 32}-{job}", "raw": {key: value + "\n" for key, value in analyzer.EXPECTED_CONTROLS.items()}},
                       {"type": "live_membership", "job_id": job, "members": members, "launchers": [launcher],
                        "cgroup_inode": 2000 + index, "controls": dict(analyzer.EXPECTED_CONTROLS)},
                       {"type": "cleanup_witness", "job_id": job, "owned_leaf_removed": True, "direct_populated_zero": None,
                        "members": [{"original": member, "current": None} for member in members],
                        "launchers": [{"original": launcher, "current": None}]}])
        return members, [launcher]

    def rpc(operation, arguments, value, stamp, ok=True, error=None):
        key = 1 + sum(event["type"] == "rpc_intent" for event in events)
        events.extend([{"type": "rpc_intent", "rpc_id": key, "operation": operation, "arguments": arguments,
                        "expected_ok": ok, "expected_error": error, "monotonic_ns": stamp},
                       {"type": "rpc_result", "rpc_id": key, "operation": operation, "value": deepcopy(value),
                        "expected_ok": ok, "monotonic_ns": stamp + 1}])
        return key

    if workload == "admission":
        case = {"holders": [],
                "waiting_admission_order": [{"job_id": job, "request_id": records[job]["request_id"]} for job in jobs[4:20]],
                "rejection": {"code": "QUEUE_FULL"}, "rejected_request_id": "f" * 32,
                "explicit_post_capacity_retry_job_id": jobs[-1],
                "full_metrics": {"active": 4, "queued": 16, "retained_requests": 20},
                "after_rejection_metrics": {"active": 4, "queued": 16, "retained_requests": 20}}
        row["measurements"] = {"capacity_fifo": case}
        for index, job in enumerate(jobs[:4]):
            members, launchers = membership(job, index)
            case["holders"].append({"job_id": job, "request_id": records[job]["request_id"], "members": members, "launchers": launchers})
        for index, job in enumerate(jobs[:20]):
            rpc("submit", [records[job]["request_id"], "example", "c" * 32, "60000", "--", "hold" if index < 4 else "empty"],
                {"job_id": job}, 200 + index * 3)
        rpc("metrics", [], case["full_metrics"], 1000)
        refused = rpc("submit", ["f" * 32, "example", "c" * 32, "60000", "--", "empty"], case["rejection"], 1200, False, "QUEUE_FULL")
        boundary = []
        for index, job in enumerate(jobs[:20]):
            boundary.append({**deepcopy(records[job]), "state": "RUNNING" if index < 4 else "QUEUED",
                             "launch_stage": "EXEC_RELEASED" if index < 4 else "INTENT",
                             "started_monotonic_ns": 1000 if index < 4 else None})
        groups = [f"hr-{'b' * 32}-{job}" for job in jobs[:4]]
        events.extend({"type": "admission_boundary", "rpc_id": refused, "context": context,
                       "records": deepcopy(boundary), "groups": groups, "monotonic_ns": stamp}
                      for context, stamp in (("before_refusal", 1100), ("after_refusal", 1300)))
        rpc("metrics", [], case["after_rejection_metrics"], 1400)
        rpc("submit", ["f" * 32, "example", "c" * 32, "60000", "--", "empty"], {"job_id": jobs[-1]}, 2000)
    else:
        job = jobs[0]
        case = {"status": "PASS", "job_id": job, "controls": dict(analyzer.EXPECTED_CONTROLS)}
        row["measurements"] = {workload: case}
        for filename, values in (("memory.events", {"oom_kill": 0}), ("pids.events", {"max": 0}),
                                  ("cpu.stat", {"usage_usec": 0, "nr_throttled": 0, "throttled_usec": 0})):
            events.append(raw_counter(job, filename, values, "live_initial"))
        membership(job, 0)
        if workload == "cpu":
            before = {"usage_usec": 10, "nr_throttled": 0, "throttled_usec": 0}
            after = {"usage_usec": 10_000_010, "nr_throttled": 1, "throttled_usec": 200}
            case.update(before=before, after=after, steady_wall_seconds=10.0, used_cores=1.0)
            filename, expected = "cpu.stat", [before, after]
        else:
            filename, key = ("memory.events", "oom_kill") if workload == "memory" else ("pids.events", "max")
            baseline, final = {key: 0}, {key: 1}
            case.update(counter_file=filename, baseline=baseline, event_before_teardown=final)
            expected = [baseline, final]
        for index, value in enumerate(expected):
            event = raw_counter(job, filename, value)
            if workload == "cpu":
                end = 2000 + index * 10_000_000_001
                event.update(read_started_ns=end - 1, read_finished_ns=end, monotonic_ns=end + 1)
            events.append(event)
    for event in events:
        event["sample_index"] = row["sample_index"]
        event.setdefault("monotonic_ns", 20_000_000_001)
    return row, events


def archive_fixture(row, events):
    """Tiny in-memory gzip/tar fixtures, never a native archive claim."""
    entries, total = [], 0
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name in ("state", "state/records", "logs", "tmp"):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o700
            archive.addfile(item)
            entries.append({"path": name, "type": "directory", "mode": item.mode, "size": 0})
        contents = {f"state/records/{event['job_id']}.json": driver.encode(event["record"])
                    for event in events if event["type"] == "job_record"}
        contents["data.ndjson"] = b'{"value":1}\n'
        for name, raw in contents.items():
            item = tarfile.TarInfo(name)
            item.mode, item.size = 0o600, len(raw)
            archive.addfile(item, io.BytesIO(raw))
            total += len(raw)
            entries.append({"path": name, "type": "file", "mode": item.mode, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    compressed = output.getvalue()
    index = driver.encode({"format": "hearthrun-shard-tar-gzip-v1", "status": "PASS", "entries": entries,
                           "content_bytes": total, "archive_sha256": hashlib.sha256(compressed).hexdigest()})
    compact = driver.encode({"status": "PASS", "entries": len(entries), "content_bytes": total,
                             "originals_removed": True, "index_sha256": hashlib.sha256(index).hexdigest()})
    shard = f"shard-{row['sample_index']:03d}"
    report = {"type": "compaction", "shard": shard, "sample_index": row["sample_index"], "monotonic_ns": 24_000_000_000,
              "archive_sha256": hashlib.sha256(compressed).hexdigest(), "index_sha256": hashlib.sha256(index).hexdigest(),
              "compaction_sha256": hashlib.sha256(compact).hexdigest()}
    return {f"{shard}/transients.tar.gz": compressed, f"{shard}/transients-index.json": index,
            f"{shard}/compaction.json": compact}, report


def population(mode="smoke", statuses="NOT RUN"):
    planned = driver.plan(mode, "synthetic-only")
    rows, events = [], []
    for row in planned:
        if statuses == "PASS":
            measured, values = fixture(row["workload"])
            measured.update(sample_index=row["sample_index"], repetition=row["repetition"])
            for value in values:
                value["sample_index"] = row["sample_index"]
            rows.append(measured)
            events.extend(values)
        else:
            rows.append(deepcopy(row))
    attempts = [{**deepcopy(row), "status": "INCOMPLETE", "finish_ns": None, "measurements": None, "teardown": None}
                for row in rows if row["status"] != "NOT RUN"]
    build = {"profile": "release", "rustc_verbose": "rustc 1.99.1 SYNTHETIC", "optimization_flags": ["SYNTHETIC"],
             "target": "SYNTHETIC", "build_command": ["SYNTHETIC"], "capture_manifest_sha256": "a" * 64,
             "source_sha256": "b" * 64, "binary_sha256": {name: "c" * 64 for name in ("hearthrun", "hearthrun-supervisor", "hearthrun-launcher")},
             **{key: {"fixture_sha256": "e" * 64, "source_sha256": "d" * 64, "capture_manifest_sha256": "a" * 64,
                      "build_command": ["SYNTHETIC"]} for key in ("resources", "task")}}
    host = {key: "SYNTHETIC" for key in ("power_policy", "background_load_control", "filesystem_mount_options", "landlock_abi", "seccomp_mode")}
    environment = {"benchmark": "B-04", "runtime": "actual local Linux native supervisor/launcher", "build": build, "host_record": host,
                   "build_record_sha256": hashlib.sha256(driver.encode(build)).hexdigest(),
                   "host_record_sha256": hashlib.sha256(driver.encode(host)).hexdigest(),
                   "observed_binary_sha256": build["binary_sha256"], "observed_source_sha256": build["source_sha256"],
                   "observed_fixture_sha256": {key: "e" * 64 for key in ("resources", "task")},
                   "observed_fixture_source_sha256": {key: "d" * 64 for key in ("resources", "task")},
                   "doctor_sha256": "d" * 64, "mount": {"filesystem": "tmpfs", "options": ["noswap"]},
                   **{key: "SYNTHETIC" for key in ("kernel", "machine", "cpu_count", "cpuinfo", "meminfo", "boot_id", "cgroup_controllers")}}
    environment["environment_id"] = hashlib.sha256(driver.encode(environment)).hexdigest()
    summary = {"benchmark": "B-04", "mode": mode, "run_id": "synthetic-only", "planned": len(rows),
               "status": "PASS" if statuses == "PASS" else "FAIL", "counts": {statuses: len(rows)},
               "groups": [{"workload": workload, "planned": sum(row["workload"] == workload for row in rows),
                           "counts": {statuses: sum(row["workload"] == workload for row in rows)}} for workload in driver.PROFILES]}
    files = {"schedule.json": driver.encode({"benchmark": "B-04", "mode": mode, "run_id": "synthetic-only", "rows": planned}),
             "summary.json": driver.encode(summary), "environment.json": driver.encode(environment),
             "samples.jsonl": b"".join(driver.encode(row) for row in rows),
             "attempts.jsonl": b"".join(driver.encode(row) for row in attempts),
             "events.jsonl": b"".join(driver.encode(row) for row in events),
             "build-record.json": driver.encode(build), "host-record.json": driver.encode(host)}
    for row in rows:
        if row["status"] == "PASS":
            scoped = [event for event in events if event["sample_index"] == row["sample_index"]]
            payloads, report = archive_fixture(row, scoped)
            files.update(payloads)
            events.append(report)
    files["events.jsonl"] = b"".join(driver.encode(row) for row in events)
    return files


def compare(files):
    with patch.object(analyzer, "read", side_effect=lambda path: files[str(path.relative_to(Path("synthetic-only-never-opened"))).replace("\\", "/")]):
        return analyzer.compare_population(Path("synthetic-only-never-opened"))


class CapacitySyntheticTests(unittest.TestCase):
    def test_equal_cpu_raw_read_clocks_cannot_claim_ten_seconds(self):
        row, events = fixture("cpu")
        for value in events:
            if value["type"] == "kernel_raw" and value["context"] == "retained_counter_read":
                value.update(read_started_ns=2000, read_finished_ns=2001, monotonic_ns=2002)
        with self.assertRaisesRegex(ValueError, "ten-second"):
            analyzer.checked_measurement(row, events)

    def test_equal_cpu_event_timestamps_rejected(self):
        row, events = fixture("cpu")
        for value in events:
            if value["type"] == "kernel_raw" and value["context"] == "retained_counter_read":
                value["monotonic_ns"] = 20_000_000_000
        with self.assertRaisesRegex(ValueError, "clock bounds"):
            analyzer.checked_measurement(row, events)

    def test_counter_from_different_cgroup_inode_rejected(self):
        row, events = fixture("memory")
        next(value for value in events if value["type"] == "kernel_raw")["cgroup_inode"] += 1
        with self.assertRaisesRegex(ValueError, "different cgroup"):
            analyzer.checked_measurement(row, events)

    def test_contradictory_live_membership_controls_rejected(self):
        row, events = fixture("memory")
        next(value for value in events if value["type"] == "live_membership")["controls"]["memory.max"] = "max"
        with self.assertRaisesRegex(ValueError, "live membership"):
            analyzer.checked_measurement(row, events)

    def test_contradictory_raw_cgroup_controls_rejected(self):
        row, events = fixture("pids")
        next(value for value in events if value["type"] == "cgroup_controls")["raw"]["pids.max"] = "max\n"
        with self.assertRaisesRegex(ValueError, "live cgroup"):
            analyzer.checked_measurement(row, events)

    def test_zero_raw_admission_metrics_rejected(self):
        row, events = fixture("admission")
        for value in events:
            if value["type"] == "rpc_result" and value["operation"] == "metrics":
                value["value"] = {"active": 0, "queued": 0, "retained_requests": 0}
        with self.assertRaisesRegex(ValueError, "metrics"):
            analyzer.checked_measurement(row, events)

    def test_duplicated_unrelated_waiting_ids_rejected(self):
        row, events = fixture("admission")
        waiting = row["measurements"]["capacity_fifo"]["waiting_admission_order"]
        waiting[1]["job_id"] = waiting[0]["job_id"]
        with self.assertRaisesRegex(ValueError, "job sets"):
            analyzer.checked_measurement(row, events)

    def test_admission_unreaped_original_launcher_rejected(self):
        row, events = fixture("admission")
        cleanup = next(value for value in events if value["type"] == "cleanup_witness")
        cleanup["launchers"][0]["current"] = deepcopy(cleanup["launchers"][0]["original"])
        with self.assertRaisesRegex(ValueError, "launcher was not reaped"):
            analyzer.checked_measurement(row, events)

    def test_consistent_alias_supervisor_pid_rejected(self):
        row, events = fixture("cpu")
        for value in events:
            if value["type"] == "supervisor_proc":
                value["identity"]["pid"] = value["identity_after"]["pid"] = 9876
        with self.assertRaisesRegex(ValueError, "supervisor"):
            analyzer.checked_measurement(row, events)

    def test_mismatched_rpc_operation_id_rejected(self):
        row, events = fixture("admission")
        next(value for value in events if value["type"] == "rpc_result")["rpc_id"] = 999
        with self.assertRaisesRegex(ValueError, "unpaired"):
            analyzer.checked_measurement(row, events)

    def test_missing_host_reserve_rejected(self):
        row, events = fixture("memory")
        with self.assertRaisesRegex(ValueError, "host reserve"):
            analyzer.checked_measurement(row, [value for value in events if value["type"] != "host_reserve"])

    def test_missing_storage_checks_rejected(self):
        row, events = fixture("memory")
        with self.assertRaisesRegex(ValueError, "storage"):
            analyzer.checked_measurement(row, [value for value in events if value["type"] != "storage"])

    def test_missing_build_provenance_rejected(self):
        files = population("smoke", "PASS")
        environment = json.loads(files["environment.json"])
        del environment["build"]
        del environment["environment_id"]
        environment["environment_id"] = hashlib.sha256(driver.encode(environment)).hexdigest()
        files["environment.json"] = driver.encode(environment)
        with self.assertRaises((ValueError, KeyError)):
            compare(files)

    def test_missing_archive_rejected(self):
        files = population("smoke", "PASS")
        del files["shard-000/transients.tar.gz"]
        with self.assertRaises((ValueError, KeyError)):
            compare(files)

    def test_valid_archive_of_different_final_record_rejected(self):
        files = population("smoke", "PASS")
        row = json.loads(files["samples.jsonl"].splitlines()[0])
        events = [json.loads(line) for line in files["events.jsonl"].splitlines()]
        scoped = deepcopy([value for value in events if value["sample_index"] == 0])
        next(value for value in scoped if value["type"] == "job_record")["record"]["cleanup_confirmed"] = False
        payloads, report = archive_fixture(row, scoped)
        files.update(payloads)
        events = [report if value["type"] == "compaction" and value["sample_index"] == 0 else value for value in events]
        files["events.jsonl"] = b"".join(driver.encode(value) for value in events)
        with self.assertRaisesRegex(ValueError, "archived final job records"):
            compare(files)

    def test_sampling_skips_excluded_supervisor_and_teardown(self):
        class Base:
            def pump_server(self, excluding=None):
                pass
            def cleanup(self):
                self.pump_server()
                return []
        class Subject(driver.Instrumented, Base):
            pass
        subject = Subject()
        subject.bind(SimpleNamespace(save=lambda *_args: None), {"sample_index": 0})
        subject.server = SimpleNamespace(proc=SimpleNamespace(poll=lambda: None))
        calls = []
        subject.supervisor_sample = calls.append
        subject.pump_server(excluding=subject.server)
        self.assertEqual(calls, [])
        subject.pump_server()
        self.assertEqual(calls, ["periodic"])
        subject.next_proc_sample = 0
        self.assertEqual(subject.cleanup(), [])
        self.assertEqual(calls, ["periodic"])

    def test_approved_existing_service_envelope(self):
        records = []
        controls = {"memory.max": b"8000000000\n", "memory.swap.max": b"0\n", "memory.current": b"2000000000\n",
                    "pids.max": b"256\n", "pids.current": b"12\n", "cpu.max": b"max 100000\n",
                    "cgroup.controllers": b"cpu memory pids\n", "meminfo": b"MemAvailable: 2000000 kB\n"}
        native = SimpleNamespace(read_file=lambda path, *_args, **_kwargs: controls[path.name])
        journal = SimpleNamespace(save=lambda _name, row: records.append(row))
        with patch.object(driver, "checkpoint"):
            driver.host_reserve(Path("synthetic"), Path("/synthetic-service/jobs"), journal, native)
        self.assertEqual(records[0]["service_controls"]["cpu.max"], "max 100000")
        self.assertIn("unlimited parent", records[0]["parent_cpu_scope"])

    def test_missing_delegated_cpu_controller_rejected(self):
        controls = {"memory.max": b"8000000000\n", "memory.swap.max": b"0\n", "memory.current": b"2000000000\n",
                    "pids.max": b"256\n", "pids.current": b"12\n", "cpu.max": b"max 100000\n",
                    "cgroup.controllers": b"memory pids\n"}
        native = SimpleNamespace(read_file=lambda path, *_args, **_kwargs: controls[path.name])
        with self.assertRaises(ValueError), patch.object(driver, "checkpoint"):
            driver.host_reserve(Path("synthetic"), Path("/synthetic-service/jobs"), None, native)

    def test_unbounded_service_memory_rejected(self):
        controls = {"memory.max": b"max\n", "memory.swap.max": b"0\n", "memory.current": b"2000000000\n",
                    "pids.max": b"256\n", "pids.current": b"12\n", "cpu.max": b"max 100000\n"}
        native = SimpleNamespace(read_file=lambda path, *_args, **_kwargs: controls[path.name])
        with self.assertRaises(ValueError), patch.object(driver, "checkpoint"):
            driver.host_reserve(Path("synthetic"), Path("/synthetic-service/jobs"), None, native)

    def test_full_plan_has_thirty_each(self):
        rows = driver.plan("full", "test")
        self.assertEqual(len(rows), 120)
        self.assertEqual([row["sample_index"] for row in rows], list(range(120)))
        for workload in driver.PROFILES:
            self.assertEqual([row["repetition"] for row in rows if row["workload"] == workload], list(range(30)))

    def test_smoke_retains_each_native_profile(self):
        self.assertEqual([row["workload"] for row in driver.plan("smoke", "test")], list(driver.PROFILES))

    def test_duplicate_counters_rejected(self):
        for parse in (driver.parsed_counters, analyzer.counters):
            with self.assertRaises(ValueError):
                parse("max 0\nmax 1\n")

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(ValueError):
            analyzer.parse(b'{"x":1,"x":2}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(ValueError):
            analyzer.parse(b'{"x":NaN}')

    def test_all_four_synthetic_measurement_branches(self):
        for workload in driver.PROFILES:
            with self.subTest(workload=workload):
                row, events = fixture(workload)
                driver.validate_measurement(workload, row["measurements"])
                self.assertEqual(analyzer.checked_measurement(row, events)["supervisor_sample_count"], 2)

    def test_cpu_short_trial_rejected(self):
        row, events = fixture("cpu")
        row["measurements"]["cpu"]["steady_wall_seconds"] = 9.99
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_kernel_increment_missing_rejected(self):
        row, events = fixture("memory")
        row["measurements"]["memory"]["event_before_teardown"]["oom_kill"] = 0
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_raw_counter_mismatch_rejected(self):
        row, events = fixture("pids")
        next(value for value in events if value["type"] == "kernel_raw")["raw"] = "oom_kill 999\n"
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_borrowed_supervisor_pid_rejected(self):
        row, events = fixture("cpu")
        events[0]["identity_after"]["start_ticks"] += 1
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_child_usage_cannot_replace_proc_rss(self):
        row, events = fixture("cpu")
        events[0]["rss_bytes"] = 123
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_launcher_zombie_is_not_reaped(self):
        row, events = fixture("memory")
        witness = next(value for value in events if value["type"] == "cleanup_witness")["launchers"][0]
        witness["current"] = {**witness["original"], "state": "Z"}
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_expected_refusal_is_not_actual_refusal(self):
        row, events = fixture("admission")
        events[:] = [value for value in events if value["type"] != "rpc_result"]
        with self.assertRaises(ValueError):
            analyzer.checked_measurement(row, events)

    def test_full_synthetic_population_counting(self):
        report = compare(population("full", "PASS"))
        self.assertEqual(report["counts"], {"PASS": 120})
        self.assertEqual(len(report["measurements"]), 120)

    def test_explicit_unrun_population_is_failure(self):
        report = compare(population())
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["counts"], {"NOT RUN": 4})

    def test_missing_attempt_rejected(self):
        files = population("smoke", "PASS")
        files["attempts.jsonl"] = b"\n".join(files["attempts.jsonl"].splitlines()[1:]) + b"\n"
        with self.assertRaises(ValueError):
            compare(files)

    def test_duplicate_plan_rejected(self):
        files = population()
        schedule = json.loads(files["schedule.json"])
        schedule["rows"][1] = schedule["rows"][0]
        files["schedule.json"] = driver.encode(schedule)
        with self.assertRaises(ValueError):
            compare(files)

    def test_smoke_cannot_claim_full(self):
        files = population("smoke", "PASS")
        schedule = json.loads(files["schedule.json"])
        schedule["mode"] = "full"
        files["schedule.json"] = driver.encode(schedule)
        with self.assertRaises(ValueError):
            compare(files)

    def test_false_summary_pass_rejected(self):
        files = population()
        summary = json.loads(files["summary.json"])
        summary["status"] = "PASS"
        files["summary.json"] = driver.encode(summary)
        with self.assertRaises(ValueError):
            compare(files)


if __name__ == "__main__":
    print("Pure synthetic validation only; native B-04 remains NOT RUN.")
    unittest.main(verbosity=2)
