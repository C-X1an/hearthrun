#!/usr/bin/env python3
"""Native AC-014 schedule campaign; smoke is explicitly not full acceptance.

Compile the approved static synthetic fixture in the bounded toolchain area:
  cc -O2 -std=c11 -Wall -Wextra -Werror -static fixtures/native/late_output.c -o ABS_FIXTURE
Run with all paths absolute and --work NEW on an OS-bounded noswap tmpfs:
  python3 tests/integration/quiescence.py --bin-dir ABS_DEBUG --doctor ABS_DOCTOR \
    --fixture ABS_FIXTURE --cgroup-root ABS_JOBS --work ABS_NEW_WORK --full --seed 14014
Omit --full for eight smoke schedules. Each <=100-job shard is independently
stopped, checked for no children/cgroups, and its owned state removed. Captured
command logs and per-schedule JSONL remain. Missing observations fail closed.
This campaign does not substitute for source review of retained descriptors or
the independently run pass/fail/pass premature-publication negative control.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import signal
import stat
import sys
import time
from typing import Any

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("hearthrun_quiescence_native", Path(__file__).resolve().parents[1] / "e2e" / "native.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native Harness source is unavailable")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)


def save_line(fd: int, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    native.require(len(raw) <= 512 * 1024, "schedule evidence exceeds bound")
    native.require(os.write(fd, raw) == len(raw), "short evidence write")
    os.fsync(fd)


def remove_owned_state(path: Path) -> tuple[int, int]:
    """Descriptor-relative removal, only after verified teardown; never follow links."""
    native.private_directory(path)
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    count = total = 0

    def walk(directory: int, depth: int) -> None:
        nonlocal count, total
        native.require(depth <= 16, "owned state removal depth bound exceeded")
        for name in os.listdir(directory):
            count += 1
            native.require(count <= 20000, "owned state removal entry bound exceeded")
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            native.require(info.st_uid == os.geteuid(), "state removal encountered another UID")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    opened = os.fstat(child)
                    native.require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "state directory changed before removal")
                    walk(child, depth + 1)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory)
            else:
                native.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "state removal encountered nonregular/linked file")
                total += info.st_size
                native.require(total <= 32 * 1024 * 1024, "state removal byte bound exceeded")
                os.unlink(name, dir_fd=directory)
    try:
        walk(root, 0)
        original = os.fstat(root)
        named = path.lstat()
        native.require((original.st_dev, original.st_ino) == (named.st_dev, named.st_ino), "state root changed before removal")
        path.rmdir()
    finally:
        os.close(root)
    native.require(not path.exists() and not path.is_symlink(), "ephemeral shard state remains")
    return count, total


class Shard(native.Harness):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.rpc_count = 0
        self.stage: str | None = None

    def rpc(self, operation: str, *, ok: bool = True, **fields: Any) -> dict[str, Any]:
        self.rpc_count += 1
        native.require(self.rpc_count <= 40000, "shard RPC count exceeds bound")
        native.require(time.monotonic() < self.deadline, "shard deadline expired")
        self.pump_server()
        value = self.raw_request(json.dumps({"v": 1, "op": operation, **fields}, separators=(",", ":")).encode())
        native.require(isinstance(value, dict) and value.get("v") == 1 and value.get("ok") is ok, f"unexpected {operation} envelope: {value}")
        key = "result" if ok else "error"
        native.require(isinstance(value.get(key), dict), "RPC has no typed payload")
        return value[key]

    def prepare(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile", str(self.state), "example", str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout).get("profile_id") == "example", "synthetic profile installation failed")
        self.start()
        self.doctor_case()
        source = self.work / "synthetic.txt"
        native.write_synthetic(source, b"HearthRun synthetic late-output campaign\n")
        self.stage = self.cli("stage", f"synthetic.txt={source}").get("stage_id")
        native.require(isinstance(self.stage, str) and native.ID.fullmatch(self.stage) is not None, "stage identity missing")

    def population(self, group: int, job: str) -> str:
        try:
            raw = self.control_read(group, "cgroup.events")
        except OSError as error:
            if error.errno not in {errno.ENOENT, errno.ENODEV}:
                raise
            # Kernel removal requires an empty cgroup. Do not label an absent
            # control file as an actual populated=0 sample.
            native.require(self.group_name(job) not in self.group_names(), "cgroup control disappeared while owned leaf still exists")
            return "removed"
        lines = raw.splitlines()
        populations = [line for line in lines if line.startswith(b"populated ")]
        native.require(populations in ([b"populated 0"], [b"populated 1"]), "kernel populated counter missing or ambiguous")
        return "populated" if populations == [b"populated 1"] else "empty"

    def live(self, job: str) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
        until = min(self.deadline, time.monotonic() + 4)
        while time.monotonic() < until:
            record = self.record(job)
            native.require(record["state"] not in native.TERMINAL, "fixture ended before live writer observation")
            if record.get("launch_stage") == "EXEC_RELEASED":
                try:
                    group = self.open_group(job)
                except FileNotFoundError:
                    time.sleep(0.001)
                    continue
                try:
                    procs = self.control_read(group, "cgroup.procs").splitlines()
                    native.require(len(procs) <= 32 and all(line.isdigit() for line in procs), "invalid actual process list")
                    members = [entry for line in procs if (entry := self.process_identity(int(line))) is not None]
                    native.require(self.server is not None, "supervisor unavailable")
                    launchers = [entry for entry in members if entry["ppid"] == self.server.proc.pid]
                    if len(members) >= 4 and len(launchers) == 1:
                        native.require(b"populated 1\n" in self.control_read(group, "cgroup.events"), "live writer group is not populated")
                        return group, members, launchers
                except BaseException:
                    os.close(group)
                    raise
                os.close(group)
            time.sleep(0.001)
        raise native.Failure("actual launcher/init/leader/writer observation deadline expired")

    def schedule(self, plan: dict[str, Any], observation: dict[str, Any]) -> None:
        request = hashlib.sha256(f"HearthRun AC-014 {plan['index']} {plan['seed']}".encode()).hexdigest()[:32]
        submitted = self.rpc("submit", request_id=request, profile_id="example", stage_id=self.stage,
                             argv=[str(plan["token"]), str(plan["first_ms"]), str(plan["tail_ms"])], wall_ms=5000)
        job = submitted.get("job_id")
        native.require(isinstance(job, str) and native.ID.fullmatch(job) is not None, "submit omitted job identity")
        self.jobs.add(job)
        observation["job_id"] = job
        group, members, launchers = self.live(job)
        inits = [entry for entry in members if entry["ppid"] == launchers[0]["pid"]]
        leaders = [entry for entry in members if any(entry["ppid"] == init["pid"] for init in inits)]
        writers = [entry for entry in members if any(entry["ppid"] == leader["pid"] for leader in leaders)]
        if len(inits) != 1 or len(leaders) != 1 or len(writers) != 1:
            os.close(group)
            raise native.Failure("actual launcher/init/leader/writer process tree was not established")
        leader, writer = leaders[0], writers[0]
        observation.update({"members": members, "launchers": launchers, "leader": leader, "writer": writer,
                            "live_samples": 0, "empty_samples": 0, "orphan_writer_samples": 0, "samples": []})
        begun = time.monotonic()
        cancel_at = None if plan["cancel_ms"] is None else begun + plan["cancel_ms"] / 1000
        cancelled = False
        try:
            until = min(self.deadline, begun + 8)
            while time.monotonic() < until:
                if cancel_at is not None and not cancelled and time.monotonic() >= cancel_at:
                    acknowledgement = self.rpc("cancel", job_id=job)
                    native.require(type(acknowledgement.get("cancel_requested")) is bool, "cancellation acknowledgement malformed")
                    observation["cancel_ack"] = acknowledgement
                    observation["cancel_actual_us"] = round((time.monotonic() - begun) * 1_000_000)
                    cancelled = True
                # Bracket the API observations with the same retained kernel
                # cgroup FD. Only 1->1 proves the writer remained live across
                # an observation; 1->0 is an explicitly ambiguous transition.
                before = self.population(group, job)
                launcher = launchers[0]
                launcher_before = self.process_identity(launcher["pid"])
                inspected = self.rpc("inspect", job_id=job)
                after_inspect = self.population(group, job)
                response = self.raw_request(json.dumps({"v": 1, "op": "result", "job_id": job}).encode())
                self.rpc_count += 1
                published = (self.state / "results" / job).exists()
                current_leader = self.process_identity(leader["pid"])
                current_writer = self.process_identity(writer["pid"])
                launcher_after = self.process_identity(launcher["pid"])
                reaped_before = launcher_before is None or launcher_before["start_ticks"] != launcher["start_ticks"]
                reaped_after = launcher_after is None or launcher_after["start_ticks"] != launcher["start_ticks"]
                leader_gone = current_leader is None or current_leader["start_ticks"] != leader["start_ticks"]
                orphan_alive = (leader_gone and current_writer is not None and current_writer["start_ticks"] == writer["start_ticks"]
                                and current_writer["state"] != "Z")
                after = self.population(group, job)
                live_inspect = before == after_inspect == "populated"
                live_result = after_inspect == after == "populated"
                sample = {"us": round((time.monotonic() - begun) * 1_000_000), "state": inspected.get("state"),
                          "population_before": before, "population_after_inspect": after_inspect,
                          "population_after": after, "result_ok": response.get("ok"), "published_directory": published,
                          "orphan_writer_alive": orphan_alive, "launcher_reaped_before": reaped_before,
                          "launcher_reaped_after": reaped_after}
                native.require(len(observation["samples"]) < 1200, "per-schedule sample bound exceeded")
                observation["samples"].append(sample)
                if live_inspect:
                    native.require(inspected.get("state") not in native.TERMINAL and inspected.get("state") != "EXPORTING",
                                   "terminal/export state observed while actual cgroup remained populated")
                if live_result:
                    observation["live_samples"] += 1
                    native.require(response.get("v") == 1 and response.get("ok") is False and response.get("error", {}).get("code") == "NOT_READY",
                                   "approved result exposed while actual writer cgroup remained populated")
                    native.require(not published, "result directory committed while actual writer cgroup remained populated")
                if inspected.get("state") in native.TERMINAL or inspected.get("state") == "EXPORTING" or response.get("ok") is True or published:
                    native.require(reaped_after, "completion or publication was observed before launcher reaping")
                if after == "empty":
                    observation["empty_samples"] += 1
                if orphan_alive and live_result:
                    observation["orphan_writer_samples"] += 1
                if inspected.get("state") in native.TERMINAL and (cancel_at is None or cancelled):
                    break
                time.sleep(0.003)
            else:
                raise native.Failure("schedule did not reach terminal within eight seconds")
            state = inspected.get("state")
            native.require(state in {"SUCCEEDED", "CANCELLED"}, f"unexpected fixture outcome: {state}")
            native.require(observation["live_samples"] > 0, "no bracketed live result observation was obtained")
            if plan["cancel_ms"] is None:
                native.require(observation["orphan_writer_samples"] > 0, "natural completion did not observe a live writer after leader reap")
            self.terminal(job, state)
            self.cleanup_observed(job, members, launchers)
            metadata, stdout, stderr = self.verify_result(job, state)
            native.require(stdout == b"" and stderr == b"", "late-output fixture emitted unexpected streams")
            native.require(metadata.get("stdout_truncated") is False and metadata.get("stderr_truncated") is False,
                           "tiny fixture unexpectedly truncated streams")
            if state == "SUCCEEDED":
                expected = f"HearthRun synthetic late output v1 {plan['token']} replacement\n".encode()
                artifact = self.state / "results" / job / "artifacts" / "final.bin"
                actual = native.read_file(artifact, 160, owner=True, mode=0o600)
                native.require(actual == expected and metadata["artifacts"] == [{"path": "final.bin", "size_bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()}],
                               "approved artifact differs from independently specified final replacement bytes")
            else:
                native.require(metadata["artifacts"] == [], "cancelled writer published artifacts")
            # Verify again after a settling window to catch post-approval writes.
            digest = self.record(job).get("result_digest")
            time.sleep(0.01)
            native.require(self.verify_result(job, state)[0] == metadata and self.record(job).get("result_digest") == digest,
                           "approved result identity changed after quiescence")
            native.require(not self.group_names(), "completed schedule retained a cgroup")
            observation.update({"state": state, "result_digest": digest, "cleanup_confirmed": True,
                                "cgroup_removed": True, "launcher_reaped": True, "status": "PASS"})
        finally:
            os.close(group)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("bin-dir", "doctor", "fixture", "cgroup-root", "work"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--full", action="store_true", help="run all 1000 seeded schedules; default is eight smoke schedules")
    parser.add_argument("--seed", type=int, default=14014)
    args = parser.parse_args()
    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("campaign termination requested; reconciling owned resources")
    signal.signal(signal.SIGTERM, terminate)
    rng = random.Random(args.seed)
    count = 1000 if args.full else 8
    root = native.absolute(args.work)
    suite: Shard | None = None
    evidence: int | None = None
    passed = successes = cancellations = shards = 0
    code = 1
    try:
        # The first Harness preflight proves the bounded storage and host setup
        # before the campaign directory or any evidence is created.
        suite = Shard(args)
        suite.preflight()
        evidence = os.open(root / "schedules.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        save_line(evidence, {"type": "campaign", "mode": "full" if args.full else "smoke", "master_seed": args.seed,
                             "planned_schedules": count, "shard_job_bound": 100})
        for offset in range(0, count, 100):
            if offset:
                shard_args = argparse.Namespace(**vars(args))
                shard_args.work = str(root / f"shard-{offset // 100:02d}")
                suite = Shard(shard_args)
                suite.preflight()
            suite.prepare()
            for index in range(offset, min(offset + 100, count)):
                seed = rng.getrandbits(64)
                schedule_rng = random.Random(seed)
                first, tail = schedule_rng.randint(160, 220), schedule_rng.randint(80, 120)
                category = index % 4
                cancellation = [None, schedule_rng.randint(10, 90), first + schedule_rng.randint(-15, 15), first + tail + schedule_rng.randint(20, 60)][category]
                plan = {"index": index, "seed": seed, "token": schedule_rng.randrange(2147483648),
                        "first_ms": first, "tail_ms": tail, "cancel_ms": cancellation, "category": category}
                save_line(evidence, {"type": "plan", **plan})
                observation: dict[str, Any] = {"type": "observation", "index": index, "seed": seed, "status": "INCOMPLETE"}
                try:
                    suite.schedule(plan, observation)
                except BaseException as error:
                    observation.update({"status": "FAIL", "reason": f"{type(error).__name__}: {error}"[:1024]})
                    raise
                finally:
                    save_line(evidence, observation)
                passed += 1
                successes += observation.get("state") == "SUCCEEDED"
                cancellations += observation.get("state") == "CANCELLED"
                native.emit("schedule", "PASS", index=index, seed=seed, state=observation["state"])
            native.require(len(suite.inventory()) == min(100, count - offset), "shard journal count differs from exercised schedules")
            errors = suite.cleanup()
            native.require(not errors, f"shard teardown failed: {errors}")
            native.require(all(child.proc.poll() is not None for child in suite.children), "shard retained direct children")
            removed_entries, removed_bytes = remove_owned_state(suite.state)
            shards += 1
            save_line(evidence, {"type": "shard_teardown", "index": offset // 100, "status": "PASS", "jobs": min(100, count - offset),
                                 "removed_state_entries": removed_entries, "removed_state_bytes": removed_bytes,
                                 "owned_children_reaped": True, "owned_cgroups_remaining": 0})
            suite = None
        native.require(passed == count and successes > 0 and cancellations > 0, "campaign lacks full schedule/outcome coverage")
        code = 0
    except native.Blocked as error:
        native.emit("quiescence_campaign", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except BaseException as error:
        native.emit("quiescence_campaign", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        if suite is not None:
            errors = suite.cleanup()
            if errors:
                native.emit("teardown", "FAIL", errors=errors[:16])
                code = 1
        summary = {"type": "summary", "status": "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL",
                   "mode": "full" if args.full else "smoke", "master_seed": args.seed, "planned_schedules": count,
                   "passed_schedules": passed, "successful_jobs": successes, "cancelled_jobs": cancellations, "clean_shards": shards,
                   "scope": "native schedule observations and immutable-byte oracle; independent source review and negative control remain separate gates"}
        if evidence is not None:
            save_line(evidence, summary)
            os.close(evidence)
        native.emit("quiescence_campaign", summary.pop("status"), **summary)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
