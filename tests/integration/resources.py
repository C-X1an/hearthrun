#!/usr/bin/env python3
"""Finite real resource/stream checks, using the native e2e harness.

Prepare the approved static fixture in the existing bounded toolchain area:
  cc -O2 -std=c11 -Wall -Wextra -Werror -static fixtures/native/resources.c -o ABS_STATIC_RESOURCES
Then machine-capture (all supplied paths absolute; --work NEW on bounded noswap tmpfs):
  python3 tests/integration/resources.py --bin-dir ABS_DEBUG --doctor ABS_DOCTOR \
    --fixture ABS_STATIC_RESOURCES --cgroup-root ABS_JOBS --work ABS_NEW_WORK

This provisions nothing and never modifies the operator's cgroup controls. It
reads only exact journal-owned job leaves. A missed kernel counter is a failed
observation, never inferred from an exit code or relabelled as a pass. This is
finite functional evidence, not full acceptance or a mutation campaign.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import time
from typing import Any

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("hearthrun_native_resources_helper", Path(__file__).resolve().parents[1] / "e2e" / "native.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native e2e helper is unavailable")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)

LIMITS = {"memory.max": "268435456", "memory.swap.max": "0", "memory.oom.group": "1",
          "pids.max": "32", "cpu.max": "100000 100000"}
STREAM_LIMIT = 1024 * 1024


def counters(raw: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in raw.decode("ascii").splitlines():
        fields = line.split()
        native.require(len(fields) == 2 and fields[0] not in result and fields[1].isdigit(), "malformed or duplicate kernel counter")
        result[fields[0]] = int(fields[1])
    return result


class ResourceSuite(native.Harness):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.environment.update({"NO_COLOR": "1", "TERM": "dumb"})
        self.stage: str | None = None
        self.observations: dict[str, Any] = {"schema_version": 1, "suite": "finite_native_resources", "cases": {}}

    def command(self, argv: list[str], timeout: float = 25) -> tuple[int, bytes, bytes]:
        result = super().command(argv, timeout)
        native.require(b"\x1b" not in result[1] + result[2], "NO_COLOR/TERM=dumb command emitted terminal escape bytes")
        return result

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile", str(self.state), "example", str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout).get("profile_id") == "example", "approved synthetic resource profile installation failed")
        self.start()
        self.case("doctor_and_socket", self.doctor_case)
        source = self.work / "data.ndjson"
        native.write_synthetic(source, b'{"value":1}\n')
        self.stage = self.cli("stage", f"data.ndjson={source}").get("stage_id")
        native.require(isinstance(self.stage, str) and native.ID.fullmatch(self.stage) is not None, "stage lacks an actual identity")
        self.case("standard_release_without_color", self.standard)
        self.case("cpu_exact_controls_and_ten_second_quota", self.cpu)
        self.case("pids_kernel_limit", lambda: self.kernel_limit("pids", "pids.events", "max"))
        self.case("memory_kernel_limit", lambda: self.kernel_limit("memory", "memory.events", "oom_kill"))
        self.case("bounded_stream_release", self.streams)

    def submit_mode(self, mode: str) -> str:
        native.require(self.stage is not None, "staged input unavailable")
        return self.submit(secrets.token_hex(16), self.stage, mode)

    def responsive(self) -> dict[str, Any]:
        begun = time.monotonic()
        metrics = self.cli("metrics")
        elapsed = time.monotonic() - begun
        native.require(metrics.get("admission_open") is True and metrics.get("queued") == 0 and metrics.get("active") in {0, 1}, "resource run corrupted scheduler capacity/admission")
        native.require(elapsed < 2.0, "supervisor metrics exceeded two-second responsiveness bound")
        return {"response_ms": round(elapsed * 1000), "active": metrics["active"]}

    def live_group(self, job: str) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
        deadline = min(self.deadline, time.monotonic() + 4)
        while time.monotonic() < deadline:
            self.pump_server()
            record = self.record(job)
            native.require(record["state"] not in native.TERMINAL, "resource fixture ended before independent live cgroup observation")
            if record.get("launch_stage") != "EXEC_RELEASED":
                time.sleep(0.01)
                continue
            group = self.open_group(job)
            try:
                limits = {name: self.control_read(group, name).decode("ascii").strip() for name in LIMITS}
                native.require(limits == LIMITS, f"live exact resource controls differ: {limits}")
                lines = self.control_read(group, "cgroup.procs").splitlines()
                native.require(len(lines) <= 32 and all(line.isdigit() for line in lines), "unbounded/malformed job process inventory")
                members = [entry for line in lines if (entry := self.process_identity(int(line))) is not None]
                native.require(self.server is not None, "owned supervisor unavailable")
                launchers = [entry for entry in members if entry["ppid"] == self.server.proc.pid]
                native.require(len(launchers) == 1 and len(members) >= 3, "live launcher/init/guest membership was not established")
                return group, members, launchers, limits
            except BaseException:
                os.close(group)
                raise
        raise native.Failure("resource fixture did not reach actual exec release within four seconds")

    def completed(self, job: str, state: str, members: list[dict[str, Any]], launchers: list[dict[str, Any]], timeout: float = 15) -> tuple[dict[str, Any], bytes, bytes]:
        self.terminal(job, state, timeout=timeout)
        self.cleanup_observed(job, members, launchers)
        result = self.verify_result(job, state)
        native.require(result[0]["artifacts"] == [], "resource fixture unexpectedly published artifacts")
        self.responsive()
        native.require(not self.group_names(), "completed resource job retained a cgroup")
        return result

    def standard(self) -> dict[str, Any]:
        help_code, help_text, _ = self.command([str(self.bin_dir / "hearthrun"), "--help"])
        native.require(help_code == 0 and b"Usage:" in help_text and b"result JOB_ID" in help_text, "plain-text keyboard CLI help is missing")
        job = self.submit_mode("standard")
        self.terminal(job, "SUCCEEDED")
        metadata, stdout, stderr = self.verify_result(job, "SUCCEEDED")
        native.require(stdout == b"synthetic resource fixture: standard success\n" and stderr == b"synthetic resource fixture: diagnostic\n", "standard native release changed exact synthetic stream bytes")
        native.require(metadata["stdout_truncated"] is False and metadata["stderr_truncated"] is False and metadata["exit_code"] == 0 and metadata["signal"] is None and metadata["artifacts"] == [], "standard release metadata differs")
        native.require(native.DIGEST.fullmatch(metadata.get("policy_sha256", "")) is not None and isinstance(metadata.get("environment_id"), str) and bool(metadata["environment_id"]), "release lacks policy/environment identity")
        native.require(not self.group_names(), "standard terminal release retained a cgroup")
        value = {"job_id": job, "state": "SUCCEEDED", "NO_COLOR": "1", "TERM": "dumb", "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
        self.observations["cases"]["standard"] = value
        return value

    def cpu(self) -> dict[str, Any]:
        job = self.submit_mode("cpu")
        observed: dict[str, Any] = {"job_id": job, "status": "INCOMPLETE"}
        self.observations["cases"]["cpu"] = observed
        group, members, launchers, limits = self.live_group(job)
        observed["controls"] = limits
        try:
            # Fixture starts after one second. Settle for two seconds before the
            # >=10 s measurement; two busy workers demand more than one core.
            settle = time.monotonic() + 2.0
            while time.monotonic() < settle:
                self.pump_server()
                time.sleep(0.02)
            before = counters(self.control_read(group, "cpu.stat"))
            started = time.monotonic()
            responses = []
            next_response = started
            while time.monotonic() - started < 10.25:
                self.pump_server()
                if time.monotonic() >= next_response:
                    responses.append(self.responsive())
                    next_response = time.monotonic() + 1.0
                native.require(self.record(job)["state"] == "RUNNING", "CPU fixture ended during steady quota window")
                time.sleep(0.02)
            after = counters(self.control_read(group, "cpu.stat"))
            elapsed = time.monotonic() - started
            observed.update({"before": before, "after": after, "steady_wall_seconds": elapsed, "responsiveness": responses})
            native.require(all(key in before and key in after for key in ("usage_usec", "nr_throttled", "throttled_usec")), "CPU kernel counters needed for quota evidence are unavailable")
            ratio = (after["usage_usec"] - before["usage_usec"]) / (elapsed * 1_000_000)
            observed["used_cores"] = ratio
            native.require(elapsed >= 10, "CPU measurement was shorter than ten seconds")
            native.require(after["nr_throttled"] > before["nr_throttled"] and after["throttled_usec"] > before["throttled_usec"], "two-worker demand did not independently observe CPU throttling")
            native.require(0.85 <= ratio <= 1.15, f"CPU one-core quota outside locked +/-15% window: {ratio:.6f}; host contention is not a pass")
        finally:
            os.close(group)
        self.completed(job, "SUCCEEDED", members, launchers, timeout=8)
        observed["status"] = "PASS"
        return {"job_id": job, "steady_wall_seconds": elapsed, "used_cores": ratio, "throttling_observed": True}

    def kernel_limit(self, mode: str, filename: str, key: str) -> dict[str, Any]:
        job = self.submit_mode(mode)
        observed: dict[str, Any] = {"job_id": job, "status": "INCOMPLETE", "counter_file": filename, "samples": []}
        self.observations["cases"][mode] = observed
        group, members, launchers, limits = self.live_group(job)
        observed["controls"] = limits
        descriptor: int | None = None
        try:
            # Retain the actual control file, never reopen by a recycled name.
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=group)
            def read_counter() -> dict[str, int]:
                os.lseek(descriptor, 0, os.SEEK_SET)
                return counters(native.read_fd(descriptor, 4096))
            baseline = read_counter()
            observed["baseline"] = baseline
            native.require(key in baseline and baseline[key] == 0, "fresh job event counter missing or already changed before baseline")
            begun = time.monotonic()
            next_response = begun
            found = False
            last: dict[str, int] | None = None
            while time.monotonic() - begun < 10:
                self.pump_server()
                try:
                    current = read_counter()
                except OSError as error:
                    observed["observation_error"] = f"kernel counter unavailable before sample: {error}"
                    raise native.Failure(observed["observation_error"]) from error
                native.require(key in current, "required kernel event disappeared")
                if current != last:
                    native.require(len(observed["samples"]) < 128, "kernel counter change evidence exceeds bounded sample count")
                    observed["samples"].append({"elapsed_ms": round((time.monotonic() - begun) * 1000), "counters": current})
                    last = current
                if current[key] > baseline[key]:
                    # Sample while the named leaf still exists; a terminal code
                    # cannot stand in for independent kernel observations.
                    native.require(self.group_name(job) in self.group_names(), "kernel event only became observable after cgroup teardown")
                    observed["event_before_teardown"] = current
                    found = True
                    break
                if time.monotonic() >= next_response:
                    self.responsive()
                    next_response = time.monotonic() + 0.5
                if self.record(job)["state"] in native.TERMINAL:
                    break
                time.sleep(0.005)
            native.require(found, f"{filename} {key} increment not independently observed before teardown; fixture outcome alone is insufficient")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(group)
        metadata, _, _ = self.completed(job, "FAILED", members, launchers)
        native.require(self.record(job).get("cancel_reason") == "RESOURCE_LIMIT", f"{mode} job did not report RESOURCE_LIMIT")
        native.require(metadata["stdout_truncated"] is False and metadata["stderr_truncated"] is False, "resource failure was substituted by a stream failure")
        observed["status"] = "PASS"
        return {"job_id": job, "kernel_counter": f"{filename}:{key}", "event_before_teardown": observed["event_before_teardown"][key], "state": "FAILED", "reason": "RESOURCE_LIMIT"}

    def streams(self) -> dict[str, Any]:
        job = self.submit_mode("streams")
        group, members, launchers, limits = self.live_group(job)
        os.close(group)
        metadata, stdout, stderr = self.completed(job, "FAILED", members, launchers)
        native.require(self.record(job).get("cancel_reason") == "STREAM_LIMIT", "bounded stream flood did not terminate with STREAM_LIMIT")
        native.require(len(stdout) <= STREAM_LIMIT and len(stderr) <= STREAM_LIMIT and len(stdout) + len(stderr) <= 2 * STREAM_LIMIT, "retained stream cap exceeded")
        native.require(metadata["stdout_truncated"] is True or metadata["stderr_truncated"] is True, "actual stream truncation was not explicit")
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            native.require(b"synthetic <script>fixture</script> & " in data, f"{name} did not retain actual synthetic hostile stream prefix")
            if metadata[f"{name}_truncated"]:
                native.require(len(data) == STREAM_LIMIT, f"{name} truncation does not correspond to its exact retained cap")
        page = self.cli("events", job, "0", "100")
        native.require(isinstance(page.get("events"), list) and len(page["events"]) <= 100 and type(page.get("truncated")) is bool, "event page lacks bounded explicit truncation semantics")
        # This finite fixture does not generate 1025 events: bounded paging is
        # measured here; the full 1024-entry ring rollover gate remains separate.
        observed = {"job_id": job, "controls": limits, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "stdout_truncated": metadata["stdout_truncated"], "stderr_truncated": metadata["stderr_truncated"], "reason": "STREAM_LIMIT", "event_page_count": len(page["events"]), "ring_rollover": "NOT MEASURED by this finite fixture", "rendering": "CLI JSON escapes guest bytes; HTML report not exercised by this suite"}
        self.observations["cases"]["streams"] = observed
        return observed

    def save_observations(self) -> None:
        if self.created_work:
            data = json.dumps(self.observations, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            native.require(len(data) <= native.MAX_HEADER, "resource observation file exceeds bounded evidence size")
            native.write_synthetic(self.work / "resource-observations.json", data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("bin-dir", "doctor", "fixture", "cgroup-root", "work"):
        parser.add_argument(f"--{flag}", required=True)
    args = parser.parse_args()
    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("resource harness termination requested; reconciling only owned jobs")
    signal.signal(signal.SIGTERM, terminate)
    harness: ResourceSuite | None = None
    code = 1
    try:
        harness = ResourceSuite(args)
        harness.preflight()
        harness.exercise()
        code = 0
    except native.Blocked as error:
        native.emit("resource_integration", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except KeyboardInterrupt:
        native.emit("resource_integration", "FAIL", reason="resource harness interrupted")
    except Exception as error:
        if harness is not None:
            harness.observations["failure"] = f"{type(error).__name__}: {error}"[:1024]
        native.emit("resource_integration", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        if harness is not None:
            errors = []
            try:
                harness.save_observations()
            except Exception as error:
                errors.append(f"bounded observation persistence failed: {error}")
            try:
                if harness.instance is not None:
                    harness.jobs.update(harness.inventory())
            except Exception as error:
                errors.append(f"bounded identity reconciliation failed: {error}")
            errors.extend(harness.cleanup())
            if errors:
                native.emit("resource_teardown", "FAIL", errors=errors[:16])
                code = 1
            elif harness.created_work:
                native.emit("resource_teardown", "PASS", owned_children_reaped=True, owned_cgroups_remaining=0)
            if code == 0:
                native.emit("resource_integration", "PASS", passed_cases=harness.passes, commands=harness.commands, captured_bytes=harness.captured, scope="finite resource, stream and plain CLI checks; full acceptance remains separate")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
