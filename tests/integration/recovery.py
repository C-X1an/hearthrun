#!/usr/bin/env python3
"""DRAFT finite AC-012 checkpoints; real components, fixed hold/empty fixtures.

Run only after review/integration on the existing bounded Linux host. A named
checkpoint is one deterministic regression case, not B-05's 100 seeds/cut.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import signal
import stat
import sys
import time
from typing import Any

sys.dont_write_bytecode = True
# This is the final PUBLIC destination's relative path, not this private draft.
SPEC = importlib.util.spec_from_file_location("hearthrun_recovery_native", Path(__file__).resolve().parents[1] / "e2e" / "native.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native recovery helper unavailable")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)

POINTS = (
    "durable-create-intent", "created-before-spawn", "spawned-before-attach",
    "attached-before-prepare", "policy-ready-before-intent", "durable-exec-intent",
    "exec-sent-before-running", "running-hold-ready", "quiescent-export", "bundle-before-receipt",
)
LIMITS = {"memory.max": "268435456", "memory.swap.max": "0", "memory.oom.group": "1",
          "pids.max": "32", "cpu.max": "100000 100000"}
PREFIX = b"HEARTHRUN_CRASH_CHECKPOINT "
CHILD_TEST = "scheduler::recovery_child::checkpoint_daemon_child"
TARGET_REQUEST = "00000000000000000000000000000012"
PRIOR_REQUEST = "00000000000000000000000000000011"


class RecoverySuite(native.Harness):
    def __init__(self, args: argparse.Namespace, checkpoint: str, cancelled: bool):
        super().__init__(args)
        self.test_bin = native.absolute(args.test_bin)
        self.checkpoint = checkpoint
        self.cancelled = cancelled
        self.environment.update({"NO_COLOR": "1", "TERM": "dumb"})

    def preflight(self) -> None:
        native.require(self.test_bin.resolve(strict=True) == self.test_bin, "libtest binary path contains symlinks")
        info = self.test_bin.stat()
        native.require(stat.S_ISREG(info.st_mode) and os.access(self.test_bin, os.X_OK), "libtest binary is not executable regular source")
        super().preflight()

    def start_checkpoint_child(self) -> None:
        native.require(self.server is None, "checkpoint fixture already started")
        self.environment.update({
            "HEARTHRUN_RECOVERY_CHILD": "v1", "HEARTHRUN_RECOVERY_CHECKPOINT": self.checkpoint,
            "HEARTHRUN_RECOVERY_REQUEST": TARGET_REQUEST,
            "HEARTHRUN_RECOVERY_STATE": str(self.state), "HEARTHRUN_RECOVERY_JOBS": str(self.cgroup_root),
            "HEARTHRUN_RECOVERY_LAUNCHER": str(self.bin_dir / "hearthrun-launcher"),
            "HEARTHRUN_RECOVERY_DOCTOR": str(self.doctor),
        })
        self.server = native.Process(self, "server-checkpoint", [str(self.test_bin), "--ignored", "--exact", CHILD_TEST,
                                                               "--nocapture", "--test-threads=1"])
        self.children.append(self.server)
        until = min(self.deadline, time.monotonic() + 30)
        while time.monotonic() < until:
            native.require(self.server.poll() is None, "libtest child died before readiness; inspect bounded capture")
            if b"HEARTHRUN_RECOVERY_CHILD_READY\n" in self.server.buffers["stdout"]:
                report = self.cli("doctor")
                if report.get("compatible") is not True:
                    raise native.Blocked("real operational doctor did not authorize execution")
                self.read_instance()
                return
            time.sleep(0.01)
        raise native.Failure("exec-separated fixture child readiness deadline expired")

    def checkpoint_packet(self, job: str) -> dict[str, Any]:
        native.require(self.server is not None, "checkpoint child missing")
        until = min(self.deadline, time.monotonic() + 5)
        while time.monotonic() < until:
            native.require(self.server.poll() is None, "checkpoint child died before selected cut")
            lines = bytes(self.server.buffers["stdout"]).splitlines()
            packets = [native.strict_json(line[len(PREFIX):]) for line in lines if line.startswith(PREFIX)]
            native.require(len(packets) <= 1, "child reported more than one selected checkpoint")
            if packets:
                packet = packets[0]
                native.require(set(packet) == {"v", "point", "job_id", "request_id", "supervisor_pid", "witness"}
                               and packet["v"] == 1 and packet["point"] == self.checkpoint and packet["job_id"] == job
                               and packet["request_id"] == TARGET_REQUEST and packet["supervisor_pid"] == self.server.proc.pid,
                               "checkpoint witness does not belong to the exact selected owned child/job")
                return packet
            time.sleep(0.005)
        raise native.Failure("selected checkpoint did not produce a completed witness")

    def bundle_bytes(self, job: str, expected: str) -> tuple[bytes, bytes, bytes]:
        directory = self.state / "results" / job
        native.private_directory(directory)
        native.require({path.name for path in directory.iterdir()} == {"result.json", "artifacts", "stdout.bin", "stderr.bin"},
                       "fixed benign result bundle has unexpected entries")
        native.private_directory(directory / "artifacts")
        native.require(not list((directory / "artifacts").iterdir()), "hold/empty unexpectedly published artifacts")
        raw = native.read_file(directory / "result.json", native.MAX_HEADER, owner=True, mode=0o600)
        meta = native.strict_json(raw)
        native.require(meta.get("job_id") == job and meta.get("status") == expected and meta.get("cleanup_confirmed") is True
                       and meta.get("artifacts") == [], "result bytes do not describe the expected fixed benign job")
        streams = tuple(native.read_file(directory / name, 1024 * 1024, owner=True, mode=0o600)
                        for name in ("stdout.bin", "stderr.bin"))
        return raw, streams[0], streams[1]

    def post_recovery_inventory(self, prior: str, job: str) -> dict[str, list[str]]:
        """Observe exact, owner/type-safe siblings independently of Scheduler.

        Enumerate at most expected-count + one entries; never follow or delete
        an unexpected scratch directory, result sibling, or publication temp.
        """
        expected_results = {prior, job}
        native.require(len(expected_results) == 2 and all(native.ID.fullmatch(name) is not None for name in expected_results),
                       "post-recovery inventory requires two exact admitted job identities")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW

        def identity(info: Any, device: int | None = None) -> tuple[int, int, int, int]:
            native.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                           and info.st_uid == os.geteuid(), "recovery inventory directory is not owner/type-safe")
            native.require(device is None or info.st_dev == device, "recovery inventory directory crossed filesystems")
            return info.st_dev, info.st_ino, info.st_mode, info.st_uid

        state_fd = os.open(self.state, flags)
        try:
            state_identity = identity(os.fstat(state_fd))
            inventories: dict[str, list[str]] = {}
            for category, expected in (("scratch", set()), ("results", expected_results)):
                parent_fd = os.open(category, flags, dir_fd=state_fd)
                try:
                    parent_identity = identity(os.fstat(parent_fd), state_identity[0])
                    observed: set[str] = set()
                    with os.scandir(parent_fd) as entries:
                        for entry in entries:
                            native.require(len(observed) < len(expected) and entry.name in expected and entry.name not in observed,
                                           "post-recovery scratch/result inventory contains a remnant or unexpected sibling")
                            named_identity = identity(entry.stat(follow_symlinks=False), parent_identity[0])
                            child_fd = os.open(entry.name, flags, dir_fd=parent_fd)
                            try:
                                native.require(identity(os.fstat(child_fd), parent_identity[0]) == named_identity,
                                               "recovery inventory entry changed while opening")
                                native.require(identity(os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False), parent_identity[0]) == named_identity,
                                               "recovery inventory entry changed after opening")
                            finally:
                                os.close(child_fd)
                            observed.add(entry.name)
                    native.require(observed == expected, "post-recovery scratch/result inventory is incomplete")
                    native.require(identity(os.stat(category, dir_fd=state_fd, follow_symlinks=False), state_identity[0]) == parent_identity,
                                   "recovery inventory parent name changed during observation")
                    inventories[category] = sorted(observed)
                finally:
                    os.close(parent_fd)
            native.require(identity(os.stat(self.state, follow_symlinks=False)) == state_identity,
                           "recovery state name changed during inventory observation")
            return inventories
        finally:
            os.close(state_fd)

    def observe_cut(self, job: str, packet: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        record = self.record(job)
        point = self.checkpoint
        state, stage = ("STARTING", "CGROUP_CREATED")
        if point == "policy-ready-before-intent": stage = "CGROUP_ATTACHED"
        if point in {"durable-exec-intent", "exec-sent-before-running"}: stage = "EXEC_RELEASED"
        if point == "running-hold-ready": state, stage = "RUNNING", "EXEC_RELEASED"
        if point in {"quiescent-export", "bundle-before-receipt"}: state, stage = "EXPORTING", "CLEANED"
        native.require((record["state"], record["launch_stage"]) == (state, stage)
                       and record.get("result_digest") is None, "actual durable state does not match selected checkpoint")
        native.require(record.get("cleanup_confirmed") == (state == "EXPORTING"), "cleanup intent claimed at wrong cut")
        native.require(record.get("cancel_reason") == ("USER_CANCEL" if self.cancelled else None), "precrash reason changed")
        witness = packet["witness"]
        native.require(isinstance(witness, dict), "checkpoint lacks bounded witness object")
        observed_native = witness.get("native")
        members: list[dict[str, Any]] = []
        launchers: list[dict[str, Any]] = []
        absent = point in {"durable-create-intent", "quiescent-export", "bundle-before-receipt"}
        expected_names = set() if absent else {self.group_name(job)}
        native.require(self.group_names() == expected_names, "unexpected direct kernel cgroup inventory at cut")
        if not absent:
            group = self.open_group(job)
            try:
                lines = self.control_read(group, "cgroup.procs").splitlines()
                native.require(len(lines) <= 32 and all(line.isdigit() for line in lines), "malformed bounded cgroup membership")
                members = [entry for line in lines if (entry := self.process_identity(int(line))) is not None]
                # Parse only the independent standard kernel populated key.
                events = dict(line.split() for line in self.control_read(group, "cgroup.events").splitlines())
                native.require(events.get(b"populated") in {b"0", b"1"}, "missing kernel populated observation")
                actual_populated = events[b"populated"] == b"1"
                native.require(actual_populated == (point not in {"created-before-spawn", "spawned-before-attach"}),
                               "kernel population disagrees with actual operation cut")
                if point != "created-before-spawn":
                    actual_limits = {name: self.control_read(group, name).decode("ascii").strip() for name in LIMITS}
                    native.require(actual_limits == LIMITS, "actual pre-exec limits differ from required controls")
            finally:
                os.close(group)
        if observed_native is not None:
            pid = observed_native.get("launcher_pid")
            if point in {"durable-create-intent", "created-before-spawn"}:
                native.require(pid is None, "pre-spawn cut unexpectedly owns launcher")
            elif state != "EXPORTING":
                native.require(isinstance(pid, int) and pid > 1, "actual spawn lacks exact launcher identity")
                identity = self.process_identity(pid)
                native.require(identity is not None and identity["ppid"] == self.server.proc.pid, "launcher is not direct child of owned supervisor")
                launchers = [identity]
                in_group = any(entry["pid"] == pid and entry["start_ticks"] == identity["start_ticks"] for entry in members)
                native.require(in_group == (point != "spawned-before-attach"), "launcher placement witness disagrees with kernel")
                if not in_group: members.append(identity)
            ready = point in {"policy-ready-before-intent", "durable-exec-intent", "exec-sent-before-running", "running-hold-ready", "quiescent-export", "bundle-before-receipt"}
            released = point in {"exec-sent-before-running", "running-hold-ready", "quiescent-export", "bundle-before-receipt"}
            native.require(observed_native.get("ready") == ready and observed_native.get("released") == released,
                           "actual authenticated READY/EXEC witnesses differ from journal intent")
            if point in {"policy-ready-before-intent", "durable-exec-intent"}:
                native.require(observed_native.get("output_retained") is True and observed_native.get("control_retained") is True,
                               "authenticated policy readiness lacks retained output/control descriptors")
        native.require(observed_native is not None or point == "durable-create-intent", "checkpoint omitted native witness")
        if point == "running-hold-ready":
            native.require(observed_native.get("stdout_hold_ready") is True and len(members) >= 4
                           and any(entry["session"] == entry["pgrp"] and entry["ppid"] != self.server.proc.pid for entry in members),
                           "RUNNING lacks real fixed hold readiness/detached descendant witness")
        if state == "EXPORTING":
            native.require(observed_native.get("launcher_reaped") is True and observed_native.get("group_removed") is True,
                           "export began before actual quiescence and cgroup removal")
            if not self.cancelled:
                native.require(record.get("observed_exit") == {"exit_code": 0, "signal": None}, "empty exit observation absent before export")
        if point == "bundle-before-receipt":
            bundle = self.bundle_bytes(job, "CANCELLED" if self.cancelled else "SUCCEEDED")
            meta = native.strict_json(bundle[0])
            native.require(meta.get("exit_code") == (record.get("observed_exit") or {}).get("exit_code")
                           and meta.get("signal") == (record.get("observed_exit") or {}).get("signal"),
                           "persisted bundle lost observed exit")
        else:
            native.require(not (self.state / "results" / job).exists(), "result became visible before the selected publication cut")
        native.emit("crash_checkpoint_observed", "PASS", checkpoint=point, cancelled=self.cancelled,
                    journal_state=state, launch_stage=stage, members=members, completed_witness=witness)
        return record, members, launchers

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile", str(self.state),
                                       "example", str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout)["profile_id"] == "example", "approved fixture installation failed")
        self.start_checkpoint_child()
        source = self.work / "data.ndjson"
        native.write_synthetic(source, b'{"value":1}\n')
        stage = self.cli("stage", f"data.ndjson={source}")["stage_id"]
        prior = self.submit(PRIOR_REQUEST, stage, "empty")
        self.terminal(prior, "SUCCEEDED")
        prior_verified = self.verify_result(prior, "SUCCEEDED")
        prior_bytes = self.bundle_bytes(prior, "SUCCEEDED")
        prior_record = self.record(prior)
        native.require(prior_verified[1:] == (b"", b""), "fixed prior empty result has unexpected streams")
        # Hold keeps membership observable even just after EXEC; the empty
        # fixture could otherwise finish between the send witness and procfs.
        mode = "empty" if self.checkpoint in {"quiescent-export", "bundle-before-receipt"} and not self.cancelled else "hold"
        job = self.submit(TARGET_REQUEST, stage, mode)
        if self.cancelled:
            self.detached_ready(job)
            native.require(self.cli("cancel", job).get("cancel_requested") is True, "owned precrash cancel refused")
        packet = self.checkpoint_packet(job)
        before, members, launchers = self.observe_cut(job, packet)
        native.require(self.server is not None and self.server.poll() is None, "exact checkpoint child no longer alive")
        crashed = time.monotonic_ns()
        # Only signal authority used for fault injection: retained direct Popen.
        self.server.proc.kill()
        native.require(self.server.wait(5) == -signal.SIGKILL, "exact owned checkpoint child was not SIGKILLed/reaped")
        for key in list(self.environment):
            if key.startswith("HEARTHRUN_RECOVERY_"): del self.environment[key]
        # Recovery uses the production supervisor, whose binary has no seam.
        self.start()
        self.terminal(job, "INTERRUPTED")
        self.cleanup_observed(job, members, launchers)
        confirmed_inventory = self.post_recovery_inventory(prior, job)
        recovery_ns = time.monotonic_ns() - crashed
        result = self.verify_result(job, "INTERRUPTED")
        after = self.record(job)
        native.require(after.get("cancel_reason") == (before.get("cancel_reason") or "SUPERVISOR_RESTART")
                       and after.get("observed_exit") == before.get("observed_exit"), "recovery overwrote immutable reason/exit observations")
        native.require(result[0]["artifacts"] == [] and result[1:] == (b"", b""), "uncertain result retained successful payload/streams")
        native.require(result[0].get("exit_code") == (before.get("observed_exit") or {}).get("exit_code")
                       and result[0].get("signal") == (before.get("observed_exit") or {}).get("signal"), "interrupted metadata lost actual prior exit")
        inventory = self.inventory()
        native.require(inventory == {prior, job}, "recovery created/replayed additional identity")
        retry = self.cli("submit", TARGET_REQUEST, "example", stage, "60000", "--", mode)
        native.require(retry.get("job_id") == job and retry.get("state") == "INTERRUPTED", "exact retry changed/replayed interrupted identity")
        alternate = "empty" if mode == "hold" else "hold"
        self.cli("submit", TARGET_REQUEST, "example", stage, "60000", "--", alternate, ok=False, error="CONFLICT")
        self.cli("submit", TARGET_REQUEST, "example", stage, "59000", "--", mode, ok=False, error="CONFLICT")
        until = min(self.deadline, time.monotonic() + 0.5)
        observations = 0
        while time.monotonic() < until:
            metrics = self.cli("metrics")
            native.require(metrics.get("active") == 0 and metrics.get("queued") == 0 and not self.group_names(), "recovery automatically requeued uncertain work")
            native.require(self.post_recovery_inventory(prior, job) == confirmed_inventory,
                           "post-recovery filesystem inventory changed during the no-replay window")
            observations += 1
            time.sleep(0.025)
        native.require(observations >= 2 and self.inventory() == inventory and self.record(job) == after,
                       "retry/conflict modified journal or no-replay observation was too short")
        native.require(self.record(prior) == prior_record and self.verify_result(prior, "SUCCEEDED") == prior_verified
                       and self.bundle_bytes(prior, "SUCCEEDED") == prior_bytes, "crash/retry changed exact prior result bytes")
        native.require(self.post_recovery_inventory(prior, job) == confirmed_inventory,
                       "post-recovery filesystem inventory changed after retry/result verification")
        native.emit("deterministic_recovery", "PASS", checkpoint=self.checkpoint, cancelled=self.cancelled,
                    recovery_ns=recovery_ns, prior_result_bytes_unchanged=True, retry_identity_preserved=True,
                    scratch_entries=confirmed_inventory["scratch"], result_siblings=confirmed_inventory["results"],
                    conflict_cases=2, replay_observation_ms=500, replay_observations=observations,
                    scope="one deterministic cut; SIGKILL does not certify power-loss durability or B-05 completion")

    def cleanup(self) -> list[str]:
        errors = []
        if self.created_work and (self.state / "records" / "catalog.json").exists():
            try: self.jobs.update(self.inventory())
            except Exception as error: errors.append(f"owned catalog reconciliation failed: {error}")
        return errors + super().cleanup()


def run_case(args: argparse.Namespace, point: str, cancelled: bool) -> int:
    suite = RecoverySuite(args, point, cancelled)
    code = 1
    try:
        suite.preflight()
        suite.exercise()
        code = 0
    except native.Blocked as error:
        native.emit("deterministic_recovery", "BLOCKED", checkpoint=point, reason=str(error)[:1024]); code = 78
    except (Exception, KeyboardInterrupt) as error:
        native.emit("deterministic_recovery", "FAIL", checkpoint=point, reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        errors = suite.cleanup()
        if errors:
            native.emit("teardown", "FAIL", checkpoint=point, errors=errors[:16]); code = 1
        elif suite.created_work:
            native.emit("teardown", "PASS", checkpoint=point, owned_cgroups_remaining=0)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bin-dir", "doctor", "fixture", "cgroup-root", "test-bin", "work"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--checkpoint", choices=("all", *POINTS), required=True)
    parser.add_argument("--cancel-before-export", action="store_true")
    args = parser.parse_args()
    native.require(not args.cancel_before_export or args.checkpoint in {"quiescent-export", "bundle-before-receipt"},
                   "cancel variant is fixed to actual exporter cuts")
    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("recovery parent termination requested; reconcile owned resources")
    signal.signal(signal.SIGTERM, terminate)
    if args.checkpoint != "all": return run_case(args, args.checkpoint, args.cancel_before_export)
    # Disjoint NEW paths under the same OS-bounded parent; no recursive delete.
    cases = [(point, False) for point in POINTS] + [(point, True) for point in ("quiescent-export", "bundle-before-receipt")]
    prefix = args.work
    overall_until = time.monotonic() + 420
    for point, cancelled in cases:
        native.require(time.monotonic() < overall_until, "finite recovery matrix deadline expired")
        args.work = prefix + "-" + point + ("-cancel" if cancelled else "")
        code = run_case(args, point, cancelled)
        if code: return code
    native.emit("deterministic_recovery_matrix", "PASS", deterministic_cases=len(cases),
                scope="AC-012 deterministic regressions only; B-05 seeded campaign and negative control NOT RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
