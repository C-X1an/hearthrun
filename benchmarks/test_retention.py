#!/usr/bin/env python3
"""Pure synthetic B-06 checks. No subprocesses, native fixtures or host controls."""
from collections import Counter
from contextlib import contextmanager, ExitStack, redirect_stderr
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("retention_draft", Path(__file__).with_name("retention.py"))
draft = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(draft)


class MemoryFile:
    """Pure byte-buffer I/O faults, never a filesystem/native evidence stand-in."""
    def __init__(self, raw=b'{"old":1}\n', write_fault=None, fsync_faults=(), truncate_fault=False):
        self.raw = bytearray(raw)
        self.position = len(raw)
        self.write_fault = write_fault
        self.writes = 0
        self.syncs = 0
        self.fsync_faults = set(fsync_faults)
        self.truncate_fault = truncate_fault
    def lseek(self, _fd, offset, whence):
        self.position = len(self.raw) + offset if whence == 2 else offset
        return self.position
    def write(self, _fd, value):
        self.writes += 1
        if self.write_fault == "partial" and self.writes == 2:
            raise OSError("synthetic write failure")
        if self.write_fault == "zero":
            return 0
        count = 3 if self.write_fault == "partial" else len(value)
        self.raw.extend(bytes(value[:count]))
        self.position += count
        return count
    def fsync(self, _fd):
        self.syncs += 1
        if self.syncs in self.fsync_faults:
            raise OSError("synthetic fsync failure")
    def ftruncate(self, _fd, size):
        if self.truncate_fault:
            raise OSError("synthetic rollback failure")
        del self.raw[size:]


class MemoryFS:
    """Owned-file and capacity model for fault logic; no real files are opened."""
    def __init__(self):
        self.files, self.names = {}, {}
        self.fault_channel = None
        self.fault_phase = 0
        self.rollback_fail = False
        self.sync_failures = {}
    def open(self, name, _flags, *_args, **_kwargs):
        name = "__root__" if isinstance(name, Path) else name
        fd = 10 + len(self.files)
        self.files[fd] = {"name": name, "raw": bytearray(), "position": 0}
        self.names[name] = fd
        return fd
    def fstat(self, fd):
        value = self.files[fd]
        return SimpleNamespace(st_dev=1, st_ino=fd, st_uid=1000, st_nlink=1, st_size=len(value["raw"]),
                               st_mode=(stat.S_IFDIR | 0o700) if value["name"] == "__root__" else (stat.S_IFREG | 0o600))
    def write(self, fd, raw):
        value = self.files[fd]
        if value["name"] == self.fault_channel and self.fault_phase == 1:
            self.fault_phase = 2
            raise OSError("synthetic partial write failure")
        count = len(raw)
        if value["name"] == self.fault_channel and self.fault_phase == 0:
            count = min(3, len(raw))
            self.fault_phase = 1
        position = value["position"]
        value["raw"][position:position + count] = raw[:count]
        value["position"] += count
        return count
    def lseek(self, fd, offset, whence):
        value = self.files[fd]
        value["position"] = len(value["raw"]) + offset if whence == 2 else offset
        return value["position"]
    def ftruncate(self, fd, size):
        value = self.files[fd]
        if value["name"] == self.fault_channel and self.rollback_fail:
            raise OSError("synthetic rollback failure")
        del value["raw"][size:]
    def fsync(self, fd):
        name = self.files[fd]["name"]
        if self.sync_failures.get(name, 0):
            self.sync_failures[name] -= 1
            raise OSError("synthetic sync failure")
    def raw(self, name):
        return bytes(self.files[self.names[name]]["raw"])


@contextmanager
def journal_model(rows):
    filesystem = MemoryFS()
    with ExitStack() as patches:
        replacements = {"open": filesystem.open, "fstat": filesystem.fstat, "write": filesystem.write,
                        "lseek": filesystem.lseek, "ftruncate": filesystem.ftruncate, "fsync": filesystem.fsync,
                        "close": lambda _fd: None, "geteuid": lambda: 1000,
                        "stat": lambda name, **_kwargs: filesystem.fstat(filesystem.names[name]),
                        "statvfs": lambda _path: SimpleNamespace(f_bavail=1_000_000, f_frsize=4096, f_favail=100_000),
                        "pread": lambda fd, size, at: bytes(filesystem.files[fd]["raw"][at:at + size])}
        for name, replacement in replacements.items():
            patches.enter_context(patch.object(draft.os, name, replacement, create=True))
        for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"):
            if not hasattr(draft.os, name):
                patches.enter_context(patch.object(draft.os, name, 0, create=True))
        journal = draft.Journal(Path("synthetic-never-opened"), rows, "a" * 64)
        try:
            yield journal, filesystem
        finally:
            journal.close()


def identity_fixture():
    row = draft.schedule("smoke", 1, "synthetic")[1][0]
    row["job_id"] = "1" * 32
    request = {"v": 1, "op": "submit", "request_id": row["request_id"], "profile_id": "example",
               "stage_id": "2" * 32, "argv": [row["workload"]], "wall_ms": 10000}
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
    row.update(submission=request, submit_ack={"job_id": row["job_id"], "state": "QUEUED", "sequence": 1}, submit_rpc_id=1)
    record = {"v": 1, "job_id": row["job_id"], "request_id": row["request_id"], "profile_id": "example",
              "stage_id": request["stage_id"], "stage_manifest_digest": "3" * 64,
              "profile_digest": "4" * 64, "executable_digest": "5" * 64,
              "canonical_request": canonical, "canonical_request_sha256": hashlib.sha256(canonical.encode()).hexdigest()}
    return row, record


class RetentionSyntheticTests(unittest.TestCase):
    def test_sample_room_is_reserved_and_independent_of_protocol_budget(self):
        rows = draft.schedule("smoke", 1, "synthetic")[1]
        with journal_model(rows) as (journal, filesystem):
            self.assertEqual(len(filesystem.raw("finalization.reserve")), len(rows) * draft.MAX_SAMPLE_ROW)
            baseline = draft.parse(filesystem.raw("summary.json"))
            self.assertEqual(baseline["planned"], len(rows))
            self.assertEqual(baseline["status"], "INCOMPLETE")
            journal.bytes = draft.MAX_JOURNAL
            with self.assertRaises(ValueError):
                journal.save("events.jsonl", {"type": "over-budget"})
            journal.record_sample(rows[0])
            self.assertEqual(journal.sample_indices["samples.jsonl"], {0})
            self.assertTrue(journal.finish(rows, {"status": "FAIL"}))
            report = draft.parse(filesystem.raw("summary.json"))
            self.assertEqual(report["counts"], {"NOT RUN": 16})
            self.assertTrue(report["samples_complete"])
            self.assertEqual(len(filesystem.raw("samples.jsonl").splitlines()), 16)
            self.assertEqual(filesystem.raw("finalization.reserve"), b"")

    def test_journal_fsync_rollback_does_not_lose_byte_accounting(self):
        rows = draft.schedule("smoke", 1, "synthetic")[1]
        with journal_model(rows) as (journal, filesystem):
            journal.save("events.jsonl", {"type": "committed"})
            before, size = filesystem.raw("events.jsonl"), journal.bytes
            filesystem.sync_failures["events.jsonl"] = 1
            with self.assertRaises(draft.AppendFailure):
                journal.save("events.jsonl", {"type": "must-rollback"})
            self.assertEqual(filesystem.raw("events.jsonl"), before)
            self.assertEqual(journal.bytes, size)
            self.assertEqual(journal.sizes["events.jsonl"], size)
            self.assertFalse(journal.finish(rows, {"status": "PASS"}))
            self.assertEqual(draft.parse(filesystem.raw("summary.json"))["status"], "FAIL")

    def test_unrecoverable_partial_channel_is_sealed_and_prefix_declared(self):
        rows = draft.schedule("smoke", 1, "synthetic")[1]
        with journal_model(rows) as (journal, filesystem):
            filesystem.fault_channel, filesystem.rollback_fail = "events.jsonl", True
            with self.assertRaises(draft.AppendFailure):
                journal.save("events.jsonl", {"type": "dirty"})
            dirty = filesystem.raw("events.jsonl")
            self.assertEqual(journal.bytes, len(dirty))
            with self.assertRaises(ValueError):
                journal.save("events.jsonl", {"type": "must-not-append"})
            self.assertEqual(filesystem.raw("events.jsonl"), dirty)
            self.assertFalse(journal.finish(rows, {"status": "PASS"}))
            report = draft.parse(filesystem.raw("summary.json"))
            self.assertEqual(report["planned"], 16)
            self.assertEqual(report["recovery"]["committed_prefix_bytes"]["events.jsonl"], 0)
            self.assertTrue(report["samples_complete"])

    def test_dirty_sample_tail_uses_complete_separate_recovery_population(self):
        rows = draft.schedule("smoke", 1, "synthetic")[1]
        with journal_model(rows) as (journal, filesystem):
            journal.record_sample(rows[0])
            filesystem.fault_channel, filesystem.rollback_fail = "samples.jsonl", True
            with self.assertRaises(draft.AppendFailure):
                journal.record_sample(rows[1])
            dirty = filesystem.raw("samples.jsonl")
            self.assertFalse(journal.finish(rows, {"status": "PASS"}))
            report = draft.parse(filesystem.raw("summary.json"))
            recovered = [draft.parse(raw) for raw in filesystem.raw("samples-recovery.jsonl").splitlines()]
            self.assertEqual(report["authoritative_samples_file"], "samples-recovery.jsonl")
            self.assertEqual({row["sample_index"] for row in recovered}, set(range(16)))
            self.assertEqual(len(recovered), 16)
            self.assertEqual(filesystem.raw("samples.jsonl"), dirty)
            self.assertEqual(report["status"], "FAIL")

    def test_summary_sync_failure_restores_incomplete_denominator(self):
        rows = draft.schedule("smoke", 1, "synthetic")[1]
        with journal_model(rows) as (journal, filesystem):
            filesystem.sync_failures["summary.json"] = 1
            output = io.StringIO()
            with redirect_stderr(output):
                self.assertFalse(journal.finish(rows, {"status": "PASS"}))
            report = draft.parse(filesystem.raw("summary.json"))
            self.assertEqual((report["status"], report["planned"]), ("INCOMPLETE", 16))
            diagnostic = json.loads(output.getvalue())
            self.assertEqual((diagnostic["status"], diagnostic["planned"]), ("FAIL", 16))

    def test_summary_failed_rollback_is_explicitly_unrecoverable(self):
        rows = draft.schedule("smoke", 1, "synthetic")[1]
        with journal_model(rows) as (journal, filesystem):
            filesystem.sync_failures["summary.json"] = 2
            with redirect_stderr(io.StringIO()):
                self.assertFalse(journal.finish(rows, {"status": "PASS"}))
            self.assertIn("summary.json", journal.poisoned)

    def test_both_sample_channels_failed_still_report_full_5000_denominator(self):
        rows = draft.schedule("full", 60621, "synthetic")[1]
        journal = draft.Journal.__new__(draft.Journal)
        journal.planned = [None] * 5000
        journal.sample_indices = {"samples.jsonl": set(), "samples-recovery.jsonl": set()}
        journal.poisoned, journal.errors, journal.sizes = {}, [], {name: 0 for name in
                                                               ("attempts.jsonl", "events.jsonl", "samples.jsonl", "samples-recovery.jsonl")}
        journal.schedule_sha256 = "a" * 64
        journal.begin_finalization = lambda: None
        reports = []
        journal.write_summary = reports.append
        def failed_save(*_args):
            raise OSError("synthetic all sample storage unavailable")
        journal.save = failed_save
        self.assertFalse(journal.finish(rows, {"status": "PASS"}))
        self.assertEqual(reports[0]["planned"], 5000)
        self.assertEqual(reports[0]["counts"], {"NOT RUN": 5000})
        self.assertFalse(reports[0]["samples_complete"])
        self.assertFalse(reports[0]["evidence_finalized"])
        self.assertEqual(reports[0]["status"], "FAIL")

    def test_partial_append_is_rolled_back_to_prior_jsonl(self):
        fake = MemoryFile(write_fault="partial")
        before = bytes(fake.raw)
        with self.assertRaises(draft.AppendFailure) as caught:
            draft.transactional_append(10, b'{"new":2}\n', fake)
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(bytes(fake.raw), before)

    def test_fsync_failure_is_rolled_back_not_counted(self):
        fake = MemoryFile(fsync_faults=(1,))
        before = bytes(fake.raw)
        with self.assertRaises(draft.AppendFailure) as caught:
            draft.transactional_append(10, b'{"new":2}\n', fake)
        self.assertTrue(caught.exception.rolled_back)
        self.assertEqual(bytes(fake.raw), before)

    def test_failed_rollback_reports_committed_prefix(self):
        fake = MemoryFile(write_fault="partial", truncate_fault=True)
        before = len(fake.raw)
        with self.assertRaises(draft.AppendFailure) as caught:
            draft.transactional_append(10, b'{"new":2}\n', fake)
        self.assertFalse(caught.exception.rolled_back)
        self.assertEqual(caught.exception.committed_prefix, before)
        self.assertTrue(caught.exception.rollback_error)

    def test_zero_progress_append_is_an_error(self):
        fake = MemoryFile(write_fault="zero")
        with self.assertRaises(draft.AppendFailure):
            draft.transactional_append(10, b'{"new":2}\n', fake)

    def test_installed_profile_must_match_captured_fixture_and_retained_bytes(self):
        image = b"explicit synthetic image, never executable"
        expected = hashlib.sha256(image).hexdigest()
        manifest = draft.encode({"v": 1, "profile_id": "example", "sha256": expected})
        profile = {"profile_id": "example", "executable_digest": expected, "profile_digest": hashlib.sha256(manifest).hexdigest()}
        self.assertEqual(draft.validate_profile(profile, manifest, image, expected), profile["profile_digest"])
        with self.assertRaises(ValueError):
            draft.validate_profile(profile, manifest, image + b"wrong", expected)

    def test_exact_scheduled_request_and_ack_bind_to_durable_record(self):
        row, record = identity_fixture()
        draft.validate_record_identity(row, record, "5" * 64, "4" * 64, "3" * 64)
        for field in ("request_id", "profile_id", "stage_id", "executable_digest", "profile_digest"):
            bad = dict(record)
            bad[field] = "wrong"
            with self.assertRaises(ValueError):
                draft.validate_record_identity(row, bad, "5" * 64, "4" * 64, "3" * 64)

    def test_rehashed_wrong_argv_or_wall_limit_is_not_the_planned_job(self):
        row, record = identity_fixture()
        for field, value in (("argv", ["v4", "extra"]), ("wall_ms", 9999)):
            bad = dict(record)
            altered = {**row["submission"], field: value}
            bad["canonical_request"] = json.dumps(altered, sort_keys=True, separators=(",", ":"))
            bad["canonical_request_sha256"] = hashlib.sha256(bad["canonical_request"].encode()).hexdigest()
            with self.assertRaises(ValueError):
                draft.validate_record_identity(row, bad, "5" * 64, "4" * 64, "3" * 64)

    def test_rehashed_substituted_stage_and_alias_ack_are_rejected(self):
        row, record = identity_fixture()
        row["submission"]["stage_id"] = "9" * 32
        record["stage_id"] = "9" * 32
        record["canonical_request"] = json.dumps(row["submission"], sort_keys=True, separators=(",", ":"))
        record["canonical_request_sha256"] = hashlib.sha256(record["canonical_request"].encode()).hexdigest()
        with self.assertRaises(ValueError):
            draft.validate_record_identity(row, record, "5" * 64, "4" * 64, "3" * 64, stage_id="2" * 32)
        row, record = identity_fixture()
        row["submit_ack"]["job_id"] = "9" * 32
        with self.assertRaises(ValueError):
            draft.validate_record_identity(row, record, "5" * 64, "4" * 64, "3" * 64)

    def test_full_is_five_distinct_seeds_thousand_each(self):
        seeds, rows = draft.schedule("full", 60621, "synthetic")
        self.assertEqual(len(seeds), len(set(seeds)))
        self.assertEqual(len(seeds), 5)
        self.assertEqual(len(rows), 5000)
        self.assertEqual(len({row["request_id"] for row in rows}), 5000)
        for index, seed in enumerate(seeds):
            selected = [row for row in rows if row["seed"] == seed]
            self.assertEqual([row["job_index"] for row in selected], list(range(1000)))
            self.assertEqual(Counter(row["wave"] for row in selected), {wave: 4 for wave in range(250)})
            self.assertEqual(Counter(row["variant"] for row in selected), {variant: 200 for variant in range(5)})
            self.assertTrue(all(row["seed_index"] == index and row["status"] == "NOT RUN" for row in selected))

    def test_smoke_is_separate_small_population(self):
        seeds, rows = draft.schedule("smoke", 1, "synthetic")
        self.assertEqual((len(seeds), len(rows)), (1, 16))
        self.assertEqual({row["concurrency"] for row in rows}, {4})

    def test_fixed_oracle_known_sizes_and_hashes(self):
        expected = (
            (4096, "f1a9116e64d5ce92231de69558afad42a650a9ee7ad481813ef824d649784ded"),
            (16384, "bd059670d899cb536791b52bb581ab858eb25dcfc8afc6fd766c734b80b4545c"),
            (65536, "ac172e7e31799a95638ec34befc5f736001b2cbe63ff3de3cc69cc91a472204d"),
            (262144, "02fd6969e820420b3224e5756a80ab2930dd3fbc68fe3516fd657f9531289907"),
            (1048576, "31d2ac66669deda571bbfee76f2c568382058c76e2366a5ede39324cc6b6d4a5"))
        self.assertEqual(tuple(draft.oracle(index) for index in range(5)), expected)

    def test_unknown_or_caller_sized_mode_rejected(self):
        for variant in (-1, 5, 1048576, "v0"):
            with self.assertRaises(ValueError):
                draft.oracle(variant)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                draft.parse(raw)

    def test_vm_hwm_is_real_kernel_field_with_byte_units(self):
        values = draft.resource_fields("Name:\tsynthetic\nVmRSS:\t100 kB\nVmHWM:\t150 kB\n")
        self.assertEqual(values, {"VmRSS_bytes": 102400, "VmHWM_bytes": 153600})

    def test_child_rusage_or_missing_hwm_cannot_replace_peak(self):
        for raw in ("VmRSS: 100 kB\nru_maxrss: 150\n", "VmRSS: 100 kB\nVmHWM: 150 bytes\n", "VmRSS: 100 kB\nVmHWM: 50 kB\n"):
            with self.assertRaises(ValueError):
                draft.resource_fields(raw)

    def test_late_slope_uses_only_late_complete_seed(self):
        points = [{"completed_jobs": index, "metric": 100 + 2 * index} for index in range(0, 1001, 4)]
        value = draft.slope(points, "metric")
        self.assertEqual(value["per_job"], 2)
        self.assertEqual((value["first_completed"], value["last_completed"]), (500, 1000))

    def test_storage_full_at_256_cannot_claim_late_slope(self):
        value = draft.slope([{"completed_jobs": index, "metric": 12} for index in range(0, 257, 4)], "metric")
        self.assertEqual(value["status"], "NOT YET MEASURED")
        self.assertIsNone(value["per_job"])

    def test_storage_full_response_preserved_no_next_submit(self):
        _, rows = draft.schedule("smoke", 1, "synthetic")
        response = {"v": 1, "ok": False, "error": {"code": "STORAGE_FULL", "message": "retained retry record count is full"}}
        calls, journal_rows, samples = [], [], []
        def rpc(op, **fields):
            calls.append((op, fields))
            raise draft.Refusal(response)
        harness = SimpleNamespace(rpc=rpc)
        journal = SimpleNamespace(save=lambda name, row: journal_rows.append((name, dict(row))), record_sample=lambda row: samples.append(dict(row)))
        with self.assertRaises(draft.Refusal):
            draft.wave(harness, "synthetic-stage", rows[:4], journal)
        self.assertEqual(len(calls), 1)
        self.assertEqual(rows[0]["status"], "FAIL")
        self.assertEqual(rows[0]["refusal"], response)
        self.assertTrue(all(row["status"] == "NOT RUN" for row in rows[1:]))
        self.assertEqual(len(journal_rows), 1)
        self.assertEqual(journal_rows[0][0], "attempts.jsonl")
        self.assertEqual(samples[0]["refusal"], response)

    def test_256_successes_and_refusal_keep_743_unrun_in_same_seed(self):
        _, planned = draft.schedule("full", 60621, "synthetic")
        rows = [row for row in planned if row["seed_index"] == 0]
        for row in rows[:256]:
            row["status"] = "PASS"  # Explicit model input, not native results.
        response = {"v": 1, "ok": False, "error": {"code": "STORAGE_FULL", "message": "synthetic ledger full"}}
        def refuse(*_args, **_kwargs):
            raise draft.Refusal(response)
        with self.assertRaises(draft.Refusal):
            draft.wave(SimpleNamespace(rpc=refuse), "synthetic", rows[256:260], SimpleNamespace(save=lambda *_args: None, record_sample=lambda _row: None))
        self.assertEqual(Counter(row["status"] for row in rows), {"PASS": 256, "FAIL": 1, "NOT RUN": 743})

    def test_per_job_approvals_use_socket_adapter_not_cli(self):
        base_calls, socket_calls = [], []
        class Base:
            def __init__(self, args):
                pass
            def cli(self, *args, **kwargs):
                base_calls.append(args)
                return {"stage_id": "synthetic"}
        native = SimpleNamespace(Harness=Base)
        harness = draft.make_harness(native)(SimpleNamespace(), SimpleNamespace(), 0, "5" * 64)
        harness.rpc = lambda op, **fields: socket_calls.append((op, fields)) or {"approved": True}
        self.assertEqual(harness.cli("result", "synthetic"), {"approved": True})
        self.assertEqual(harness.cli("inspect", "synthetic"), {"approved": True})
        harness.cli("stage", "synthetic-input")
        self.assertEqual(len(base_calls), 1)
        self.assertEqual([op for op, _fields in socket_calls], ["result", "inspect"])
        with self.assertRaises(ValueError):
            harness.cli("submit", "synthetic")

    def test_observer_reads_1000_without_changing_product_256(self):
        instance = "a" * 32
        scheduled = draft.schedule("full", 60621, "synthetic")[1][:1000]
        records = {}
        for index, row in enumerate(scheduled):
            job = f"{index + 1:032x}"
            submission = {"v": 1, "op": "submit", "request_id": row["request_id"], "profile_id": "example", "stage_id": "2" * 32,
                          "argv": [row["workload"]], "wall_ms": 10000}
            row.update(job_id=job, submission=submission)
            canonical = json.dumps(submission, sort_keys=True, separators=(",", ":"))
            records[job] = {"v": 1, "job_id": job, "request_id": row["request_id"], "canonical_request": canonical,
                            "canonical_request_sha256": hashlib.sha256(canonical.encode()).hexdigest(), "profile_id": "example",
                            "stage_id": "2" * 32, "stage_manifest_digest": "3" * 64, "profile_digest": "4" * 64, "executable_digest": "5" * 64}
        entries = [{key: value[key] for key in ("job_id", "request_id", "canonical_request_sha256")} for value in records.values()]
        raw = json.dumps({"v": 1, "instance_id": instance, "entries": entries}).encode()
        class Base:
            def __init__(self, args):
                self.state = Path("synthetic-never-opened")
            def inventory(self):
                raise AssertionError("must not inherit portable helper's 256 observer bound")
        native = SimpleNamespace(Harness=Base, MAX_RECORDS=256, ID=re.compile(r"[a-f0-9]{32}"), read_file=lambda *_args, **_kwargs: raw)
        harness = draft.make_harness(native)(SimpleNamespace(), SimpleNamespace(), 0, "5" * 64)
        harness.profile_digest, harness.stage_id, harness.stage_manifest_digest = "4" * 64, "2" * 32, "3" * 64
        harness.rows = {row["request_id"]: row for row in scheduled}
        harness.read_instance = lambda: instance
        harness.record = lambda job: records[job]
        names = [Path("catalog.json"), *(Path(job + ".json") for job in records)]
        with patch.object(Path, "iterdir", return_value=iter(names)):
            self.assertEqual(harness.inventory(), set(records))
        self.assertEqual(native.MAX_RECORDS, 256)
        self.assertEqual(harness.last_catalog["entries"], 1000)

    def test_clock_domains_and_unavailable_job_metrics_stay_explicit(self):
        _, rows = draft.schedule("smoke", 1, "synthetic")
        self.assertIn("incomparable", rows[0]["start_clock"])
        self.assertIsNone(rows[0]["max_rss_bytes"])
        self.assertIsNone(rows[0]["cpu_usec"])


if __name__ == "__main__":
    print("Pure synthetic B-06 checks only; native retention benchmark remains NOT RUN.")
    unittest.main(verbosity=2)
