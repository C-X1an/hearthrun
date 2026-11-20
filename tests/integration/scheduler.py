#!/usr/bin/env python3
"""Finite real scheduler capacity/FIFO/wall-expiry integration checks.

Invocation (all paths absolute, --work NEW on bounded noswap tmpfs):
  python3 tests/integration/scheduler.py --bin-dir ABS_DEBUG --doctor ABS_DOCTOR \
    --fixture ABS_STATIC_TASK --cgroup-root ABS_JOBS --work ABS_NEW_WORK

Reuses the native end-to-end harness for actual child processes, authenticated
CLI requests, protected result verification, and exact journal-owned cleanup.
This script does not install tools, provision delegation, change host policy,
or use replacement guests. It tests 4 live hold jobs, 16 queued empty jobs, one
rejected distinct request, then releases one slot to observe FIFO. It separately
tests whole-group wall expiry, without sending that job a cancellation request.

Raw command logs and scheduler-observations.json remain in --work. A fresh run
must be machine-captured before any native evidence claim. This is a finite
functional suite, not the full mutation/fault/performance acceptance campaign.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import signal
import sys
import time
from typing import Any


# Loading the reusable source helper must not create caches beside audited
# product source, even when the caller omitted Python's -B option.
sys.dont_write_bytecode = True
HELPER = Path(__file__).resolve().parents[1] / "e2e" / "native.py"
SPEC = importlib.util.spec_from_file_location("hearthrun_native_e2e", HELPER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native end-to-end helper could not be loaded")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)


class SchedulerSuite(native.Harness):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.stage: str | None = None
        self.observations: dict[str, Any] = {"schema_version": 1, "suite": "finite_native_scheduler", "cases": {}}
        self.retry_identity: tuple[str, str] | None = None

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile",
                                      str(self.state), "example", str(self.fixture)])
        native.require(code == 0, "approved synthetic profile installation failed")
        profile = native.strict_json(stdout)
        native.require(profile.get("profile_id") == "example", "unexpected approved profile identity")
        self.start()
        self.case("doctor_and_socket", self.doctor_case)
        source = self.work / "data.ndjson"
        native.write_synthetic(source, b'{"value":1}\n')
        staged = self.cli("stage", f"data.ndjson={source}")
        stage = staged.get("stage_id")
        native.require(isinstance(stage, str) and native.ID.fullmatch(stage) is not None, "actual staged input ID is invalid")
        self.stage = stage
        self.case("four_running_sixteen_waiting_fifo", self.capacity_fifo)
        self.case("whole_group_wall_expiry", self.wall_expiry)
        self.case("retained_identity_after_restart", self.restart_identity)

    def checked_stage(self) -> str:
        native.require(self.stage is not None, "scheduler input stage is unavailable")
        return self.stage

    def metrics(self) -> dict[str, Any]:
        value = self.cli("metrics")
        native.require(type(value.get("active")) is int and 0 <= value["active"] <= 4, "observed running capacity exceeded four")
        native.require(type(value.get("queued")) is int and 0 <= value["queued"] <= 16, "observed waiting capacity exceeded sixteen")
        native.require(value.get("admission_open") is True, "scheduler closed admission unexpectedly")
        return value

    def capacity_fifo(self) -> dict[str, Any]:
        stage = self.checked_stage()
        begun = time.monotonic()
        holders: list[dict[str, Any]] = []
        waiting: list[dict[str, Any]] = []
        observed: dict[str, Any] = {"holders": holders, "waiting_admission_order": waiting}
        self.observations["cases"]["capacity_fifo"] = observed
        # Four actual fixtures sleep with detached descendants for eight seconds.
        # Establish each live group before putting sixteen fast jobs behind them.
        for _ in range(4):
            request = secrets.token_hex(16)
            job = self.submit(request, stage, "hold")
            members, launchers = self.detached_ready(job)
            holders.append({"request_id": request, "job_id": job, "members": members, "launchers": launchers})
        ready = self.metrics()
        native.require(ready["active"] == 4 and ready["queued"] == 0, "four live hold jobs did not occupy exactly four running slots")
        for index in range(16):
            request = secrets.token_hex(16)
            job = self.submit(request, stage, "empty")
            record = self.record(job)
            native.require(record.get("state") == "QUEUED" and record.get("launch_stage") == "INTENT"
                           and record.get("started_monotonic_ns") is None,
                           "a waiting empty job executed before a running slot was released")
            waiting.append({"position": index, "request_id": request, "job_id": job})
        # The fixture window is finite. A slow setup must fail rather than let
        # naturally expired holds turn this into a smaller-capacity substitute.
        native.require(time.monotonic() - begun < 6, "could not fill the required queue within the live hold fixture window")
        full = self.metrics()
        native.require(full["active"] == 4 and full["queued"] == 16 and full.get("retained_requests") == 20,
                       "did not observe the complete four-running/sixteen-waiting boundary")
        expected_groups = {self.group_name(holder["job_id"]) for holder in holders}
        native.require(self.group_names() == expected_groups, "queued jobs created cgroups or a running fixture disappeared")
        for holder in holders:
            native.require(self.record(holder["job_id"])["state"] == "RUNNING", "holder stopped before full-queue rejection")
        for item in waiting:
            native.require(self.record(item["job_id"])["state"] == "QUEUED", "queued job started while all four running slots remained held")
        before = self.inventory()
        rejection_request = secrets.token_hex(16)
        rejection = self.cli("submit", rejection_request, "example", stage, "60000", "--", "empty",
                             ok=False, error="QUEUE_FULL")
        after = self.metrics()
        native.require(after["active"] == 4 and after["queued"] == 16 and self.inventory() == before
                       and self.group_names() == expected_groups, "21st rejected admission had a durable or execution side effect")
        native.require(all(self.record(job)["request_id"] != rejection_request for job in before),
                       "QUEUE_FULL persisted the rejected request identity")
        # Existing identities retain their meaning even while new admission is
        # full. This is an explicit test retry, never a client automatic retry.
        duplicate = self.cli("submit", holders[0]["request_id"], "example", stage, "60000", "--", "hold")
        native.require(duplicate.get("job_id") == holders[0]["job_id"], "full-queue retry replaced a durable job identity")
        self.cli("submit", holders[0]["request_id"], "example", stage, "59999", "--", "hold",
                 ok=False, error="CONFLICT")
        observed["full_metrics"] = full
        observed["after_rejection_metrics"] = after
        observed["rejected_request_id"] = rejection_request
        observed["rejection"] = rejection

        first = holders[0]
        cancellation = self.cli("cancel", first["job_id"])
        native.require(cancellation.get("cancel_requested") is True, "controlled slot release was not acknowledged")
        self.terminal(first["job_id"], "CANCELLED")
        self.cleanup_observed(first["job_id"], first["members"], first["launchers"])
        # Leave the other three holders live: exactly one slot must process all
        # sixteen waiting jobs, making execution-release order observable FIFO.
        while True:
            metrics = self.metrics()
            for holder in holders[1:]:
                native.require(self.record(holder["job_id"])["state"] == "RUNNING",
                               "a second slot became free before the one-slot FIFO observation completed")
            records = [self.record(item["job_id"]) for item in waiting]
            for record in records:
                native.require(record["state"] not in native.TERMINAL or record["state"] == "SUCCEEDED",
                               "an approved queued empty fixture failed")
            if all(record["state"] == "SUCCEEDED" for record in records):
                break
            native.require(time.monotonic() - begun < 6.5, "single-slot FIFO drain exceeded the live holder window")
            time.sleep(0.01)
        starts = [record.get("started_monotonic_ns") for record in records]
        native.require(all(type(start) is int and start > 0 for start in starts), "FIFO execution-start observations are missing")
        native.require(all(left < right for left, right in zip(starts, starts[1:])),
                       "actual single-slot execution release did not preserve waiting admission order")
        running_events = []
        for item, start in zip(waiting, starts):
            item["started_monotonic_ns"] = start
            page = self.cli("events", item["job_id"], "0", "100")
            native.require(page.get("truncated") is False, "fresh FIFO event evidence was lost")
            events = [event for event in page.get("events", []) if event.get("event") == "RUNNING"]
            native.require(len(events) == 1 and type(events[0].get("monotonic_ns")) is int,
                           "queued job lacks one actual RUNNING event")
            running_events.append(events[0]["monotonic_ns"])
        native.require(all(left < right for left, right in zip(running_events, running_events[1:])),
                       "RUNNING event order differs from FIFO admission order")
        observed["running_event_monotonic_ns"] = running_events
        observed["single_slot_drain_elapsed_ms"] = round((time.monotonic() - begun) * 1000)
        for holder in holders[1:]:
            cancelled = self.cli("cancel", holder["job_id"])
            native.require(cancelled.get("cancel_requested") is True, "remaining live holder was not cancelled")
            self.terminal(holder["job_id"], "CANCELLED")
            self.cleanup_observed(holder["job_id"], holder["members"], holder["launchers"])
        idle = self.metrics()
        native.require(idle["active"] == idle["queued"] == 0 and not self.group_names(), "capacity test did not clean all actual job groups")
        # The previously refused ID was never admitted; an explicit later retry
        # may now acquire one new identity rather than conflict with a phantom.
        retried = self.submit(rejection_request, stage, "empty")
        self.terminal(retried, "SUCCEEDED")
        self.verify_result(retried, "SUCCEEDED")
        native.require(len(self.inventory()) == 21, "rejected-then-admitted request count differs")
        self.retry_identity = (waiting[0]["request_id"], waiting[0]["job_id"])
        observed["explicit_post_capacity_retry_job_id"] = retried
        return {"running": 4, "waiting": 16, "rejection": "QUEUE_FULL", "fifo_jobs": len(waiting),
                "fifo_observation": "one released slot; durable start observations and RUNNING events"}

    def wall_expiry(self) -> dict[str, Any]:
        stage = self.checked_stage()
        request = secrets.token_hex(16)
        submitted = time.monotonic()
        admitted = self.cli("submit", request, "example", stage, "3000", "--", "hold")
        job = admitted.get("job_id")
        native.require(isinstance(job, str) and native.ID.fullmatch(job) is not None, "wall-expiry submit lacks actual job ID")
        self.jobs.add(job)
        members, launchers = self.detached_ready(job)
        observed = {"request_id": request, "job_id": job, "wall_ms": 3000,
                    "members_before_expiry": members, "launcher_before_expiry": launchers}
        self.observations["cases"]["wall_expiry"] = observed
        self.cli("result", job, ok=False, error="NOT_READY")
        native.require(not (self.state / "results" / job).exists(), "wall-limited result appeared while descendants were live")
        # The fixture naturally holds for eight seconds. This six-second total
        # observation bound prevents a leader-only timeout from passing by just
        # waiting for its detached descendant to finish naturally.
        remaining = 6.0 - (time.monotonic() - submitted)
        native.require(remaining > 0, "wall-expiry fixture readiness consumed the observation window")
        terminal = self.terminal(job, "TIMED_OUT", timeout=remaining)
        self.cleanup_observed(job, members, launchers)
        elapsed = time.monotonic() - submitted
        native.require(elapsed < 6, "whole-group wall cleanup was not observed before the fixture's natural completion window")
        record = self.record(job)
        native.require(record.get("cancel_reason") == "WALL_LIMIT" and record.get("state") == "TIMED_OUT",
                       "wall expiry was replaced by manual cancellation or a different terminal cause")
        metadata, stdout, _ = self.verify_result(job, "FAILED")
        native.require(metadata["artifacts"] == [] and b"detached-ready\n" in stdout,
                       "wall result lacks real detached readiness or discarded-artifact policy")
        idle = self.metrics()
        native.require(idle["active"] == idle["queued"] == 0 and not self.group_names(), "wall-expired whole group retained scheduler capacity")
        observed.update({"terminal": terminal, "elapsed_ms": round(elapsed * 1000), "cgroup_removed": True,
                         "launcher_reaped": True, "manual_cancel_sent": False})
        return {"job_id": job, "wall_ms": 3000, "state": "TIMED_OUT", "reason": "WALL_LIMIT",
                "observed_cgroup_processes": len(members), "cleanup_elapsed_ms": round(elapsed * 1000),
                "manual_cancel_sent": False}

    def restart_identity(self) -> dict[str, Any]:
        native.require(self.retry_identity is not None, "capacity identity evidence is unavailable")
        request, job = self.retry_identity
        records = self.inventory()
        previous = self.record(job)
        native.require(self.server is not None and self.server.poll() is None, "no owned supervisor available to restart")
        self.server.proc.terminate()
        native.require(self.server.wait(20) == 0, "scheduler did not shut down cleanly before identity restart")
        self.start()
        duplicate = self.cli("submit", request, "example", self.checked_stage(), "60000", "--", "empty")
        native.require(duplicate.get("job_id") == job and duplicate.get("state") == "SUCCEEDED",
                       "restart forgot a completed capacity request identity")
        self.cli("submit", request, "example", self.checked_stage(), "59999", "--", "empty", ok=False, error="CONFLICT")
        metrics = self.metrics()
        native.require(self.inventory() == records and self.record(job) == previous and metrics["active"] == metrics["queued"] == 0
                       and metrics.get("retained_requests") == len(records) and not self.group_names(),
                       "restart duplicate/conflict replayed or changed a retained capacity identity")
        self.verify_result(job, "SUCCEEDED")
        self.observations["cases"]["restart_identity"] = {"request_id": request, "job_id": job,
            "retained_requests": len(records), "metrics": metrics, "sequence_preserved": previous["sequence"]}
        return {"job_id": job, "retained_requests": len(records), "replayed": False}

    def save_observations(self) -> None:
        if self.created_work:
            data = json.dumps(self.observations, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            native.require(len(data) <= native.MAX_HEADER, "scheduler observation file exceeds evidence bound")
            native.write_synthetic(self.work / "scheduler-observations.json", data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("bin-dir", "doctor", "fixture", "cgroup-root", "work"):
        parser.add_argument(f"--{flag}", required=True)
    args = parser.parse_args()

    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("scheduler harness termination requested; reconciling only owned test resources")

    signal.signal(signal.SIGTERM, terminate)
    harness: SchedulerSuite | None = None
    code = 1
    try:
        harness = SchedulerSuite(args)
        harness.preflight()
        harness.exercise()
        code = 0
    except native.Blocked as error:
        native.emit("scheduler_integration", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except KeyboardInterrupt:
        native.emit("scheduler_integration", "FAIL", reason="scheduler harness interrupted")
    except Exception as error:
        native.emit("scheduler_integration", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        if harness is not None:
            errors = []
            try:
                harness.save_observations()
            except Exception as error:
                errors.append(f"bounded observation persistence failed: {error}")
            try:
                if harness.instance is not None:
                    # Unexpected acceptance must still get exact journal-owned
                    # cleanup, even if the negative assertion failed before its
                    # job ID could be registered in a successful CLI response.
                    harness.jobs.update(harness.inventory())
            except Exception as error:
                errors.append(f"bounded identity reconciliation failed: {error}")
            errors.extend(harness.cleanup())
            if errors:
                native.emit("scheduler_teardown", "FAIL", errors=errors[:16])
                code = 1
            elif harness.created_work:
                native.emit("scheduler_teardown", "PASS", owned_children_reaped=True, owned_cgroups_remaining=0)
            if code == 0:
                native.emit("scheduler_integration", "PASS", passed_cases=harness.passes, commands=harness.commands,
                            captured_bytes=harness.captured, scope="finite capacity/FIFO/wall-expiry/restart suite")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
