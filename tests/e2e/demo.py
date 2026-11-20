#!/usr/bin/env python3
"""Run a real local demo and render a bounded static report from actual evidence.

  python3 -B tests/e2e/demo.py --bin-dir ABS_DEBUG --doctor ABS_DOCTOR \
    --fixture ABS_STATIC_TASK --cgroup-root ABS_JOBS --work ABS_NEW_WORK

Uses unchanged native.py helpers, scripts/capture.py and scripts/report.py.
The outer work directory and its run/ child must be new, on already OS-bounded
noswap tmpfs, outside product source. No setup, build, browser, screenshot,
publication, remote endpoint, or weakened host fallback is supplied here.
The wrapper returns nonzero for a failed/blocked run, even if it can render the
observations. Reports/raw logs remain local and require an audit before sharing.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import sys
import time
from typing import Any


sys.dont_write_bytecode = True
PUBLIC = Path(__file__).resolve().parents[2]
MAX_REPORT = 256 * 1024
RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}-[0-9a-f]{12}\Z")


def load(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("required local source module cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


native = load("hearthrun_demo_native", Path(__file__).with_name("native.py"))


def start_gated_service(command: list[str]) -> int:
    if len(command) != 5 or not all(Path(path).is_absolute() for path in command):
        return 1
    if os.read(0, 1) != b"R":
        return 1
    with open(os.devnull, "rb") as empty:
        os.dup2(empty.fileno(), 0)
    binary, *parameters = command
    os.execv(binary, [binary, "serve", *parameters])
    return 1


class Demo(native.Harness):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.origin = time.monotonic()
        self.timeline: list[dict[str, Any]] = []
        self.facts: dict[str, Any] = {}
        self.stage: str | None = None
        self.source: Path | None = None

    def start(self) -> None:
        # The service cannot initialize state until its recovery identity is
        # durable. If this worker dies first, closing the gate aborts startup.
        native.require(self.server is None, "demo starts exactly one owned supervisor")
        binary = self.bin_dir / "hearthrun-supervisor"
        image = binary.stat()
        guard_image = Path(sys.executable).stat()
        argv = [sys.executable, "-B", str(Path(__file__).resolve()), "--gated-service", str(binary),
                str(self.state), str(self.cgroup_root), str(self.bin_dir / "hearthrun-launcher"), str(self.doctor)]
        self.server = native.Process(self, "server-01", argv, gated=True)
        self.children.append(self.server)
        gate = self.server.proc.stdin
        native.require(gate is not None, "demo launch gate pipe is missing")
        with gate:
            identity = self.process_identity(self.server.proc.pid)
            native.require(identity is not None, "demo supervisor exited before identity recording")
            control = {"v": 1, "pid": self.server.proc.pid, "start_ticks": identity["start_ticks"],
                       "uid": os.geteuid(), "executable_device": image.st_dev, "executable_inode": image.st_ino,
                       "guard_device": guard_image.st_dev, "guard_inode": guard_image.st_ino}
            native.write_synthetic(self.work / "supervisor-identity.json", json.dumps(control, sort_keys=True).encode() + b"\n")
            directory = os.open(self.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            gate.write(b"R")
        deadline = min(self.deadline, time.monotonic() + 30)
        while time.monotonic() < deadline:
            native.require(self.server.poll() is None, "demo supervisor exited before readiness; inspect captured logs")
            if (self.state / "control.sock").exists():
                code, stdout, stderr = self.command([str(self.bin_dir / "hearthrun"), "--state", str(self.state), "doctor"])
                value = native.strict_json(stdout if stdout.strip() else stderr)
                if value.get("ok") is True:
                    report = value.get("result", {})
                    if code == 78 or report.get("compatible") is not True:
                        native.emit("doctor", "BLOCKED", report=report)
                        raise native.Blocked("operational doctor did not authorize demo execution")
                    native.require(code == 0, "compatible demo doctor returned unsuccessful exit")
                    self.read_instance()
                    return
                native.require(value.get("error", {}).get("code") == "IO_UNCERTAIN", "unexpected demo startup refusal")
            time.sleep(0.02)
        raise native.Failure("demo supervisor readiness deadline expired")

    def case(self, name: str, callback: Any) -> None:
        started = time.monotonic()
        row = {"case": name, "started_ms": round((started - self.origin) * 1000)}
        self.timeline.append(row)
        try:
            details = callback() or {}
        except BaseException:
            row.update(status="FAIL", elapsed_ms=round((time.monotonic() - started) * 1000))
            raise
        row.update(status="PASS", elapsed_ms=round((time.monotonic() - started) * 1000), details=details)
        native.emit(name, "PASS", elapsed_ms=row["elapsed_ms"], **details)
        self.passes += 1

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile",
                                      str(self.state), "example", str(self.fixture)])
        native.require(code == 0, "approved synthetic profile installation failed")
        approved = native.strict_json(stdout)
        native.require(approved.get("profile_id") == "example", "unexpected approved profile identity")
        self.start()
        self.case("doctor_and_socket", self.doctor_case)
        doctor = self.cli("doctor")
        self.facts["host"] = {"compatible": doctor.get("compatible"), "landlock_abi": doctor.get("landlock_abi")}
        self.source = self.work / "data.ndjson"
        native.write_synthetic(self.source, b'{"value":7}\n{"value":-2}\n{"value":0}\n{"value":11}\n')
        staged = self.cli("stage", f"data.ndjson={self.source}")
        stage = staged.get("stage_id")
        native.require(isinstance(stage, str) and native.ID.fullmatch(stage) is not None,
                       "native demo input stage is invalid")
        self.stage = stage
        self.facts["input"] = {"logical_path": "data.ndjson", "synthetic": True,
            "size_bytes": self.source.stat().st_size, "sha256": hashlib.sha256(native.read_file(self.source, 4096)).hexdigest(),
            "stage_manifest_digest": staged.get("manifest_digest")}
        self.case("approved_transformation", self.transformation)
        self.case("typed_admission_refusal", self.admission_refusal)
        self.case("guest_canary_and_input_denial", self.guest_denial)
        self.case("detached_cancellation", self.detached_cancellation)

    def stage_id(self) -> str:
        native.require(self.stage is not None, "native demo stage is unavailable")
        return self.stage

    def job_facts(self, job: str) -> dict[str, Any]:
        record = self.record(job)
        approved = self.cli("result", job)
        return {"job_id": job, "state": record.get("state"), "cleanup_confirmed": record.get("cleanup_confirmed"),
            "result_digest": approved.get("result_digest"), "policy_sha256": record.get("policy_digest"),
            "executable_sha256": record.get("executable_digest"), "profile_digest": record.get("profile_digest"),
            "observed_exit": record.get("observed_exit"), "metadata": approved.get("metadata")}

    def transformation(self) -> dict[str, Any]:
        # The unchanged helper independently checks actual summary bytes, hashes,
        # durable result metadata, and retry identity through the real CLI.
        result = self.summary_case(self.stage_id())
        facts = self.job_facts(result["job_id"])
        summary = native.strict_json(native.read_file(self.state / "results" / result["job_id"] /
            "artifacts" / "summary.json", 1024, owner=True, mode=0o600))
        facts["summary"] = summary
        facts["cgroup_removed"] = self.group_name(result["job_id"]) not in self.group_names()
        native.require(facts["cgroup_removed"], "transformation retained its owned cgroup")
        self.facts["transformation"] = facts
        return {"job_id": result["job_id"], "count": summary["count"], "sum": summary["sum"],
                "cleanup_confirmed": facts["cleanup_confirmed"], "result_digest": facts["result_digest"]}

    def admission_refusal(self) -> dict[str, Any]:
        canary = self.work / "synthetic-host-canary.txt"
        native.write_synthetic(canary, b"Synthetic HearthRun demo canary; no credentials.\n")
        before = native.read_file(canary, 4096, owner=True, mode=0o600)
        records = self.inventory()
        groups = self.group_names()
        refused = self.cli("submit", secrets.token_hex(16), "unapproved", self.stage_id(), "10000", "--", "empty",
                           ok=False, error="PROFILE_NOT_FOUND")
        after = native.read_file(canary, 4096, owner=True, mode=0o600)
        metrics = self.cli("metrics")
        native.require(before == after and self.inventory() == records and self.group_names() == groups
                       and metrics.get("active") == metrics.get("queued") == 0,
                       "typed refusal changed the synthetic host canary or admitted execution")
        self.facts["admission_refusal"] = {"code": refused["code"], "admitted": False,
            "host_canary_sha256_before": hashlib.sha256(before).hexdigest(),
            "host_canary_sha256_after": hashlib.sha256(after).hexdigest(),
            "record_count_unchanged": True, "cgroup_inventory_unchanged": True,
            "boundary": "operator profile admission; this rejection did not execute a guest"}
        return {"code": refused["code"], "admitted": False, "host_canary_unchanged": True}

    def guest_denial(self) -> dict[str, Any]:
        canary = self.work / "synthetic-host-canary.txt"
        canary_before = native.read_file(canary, 4096, owner=True, mode=0o600)
        staged_input = self.state / "stages" / self.stage_id() / "tree" / "data.ndjson"
        input_before = native.read_file(staged_input, 4096, owner=True, mode=0o600)
        admitted = self.cli("submit", secrets.token_hex(16), "example", self.stage_id(), "60000", "--", "check", str(canary))
        job = admitted.get("job_id")
        native.require(isinstance(job, str) and native.ID.fullmatch(job) is not None, "approved check fixture lacks a job identity")
        self.jobs.add(job)
        self.terminal(job, "SUCCEEDED")
        metadata, stdout, _ = self.verify_result(job, "SUCCEEDED")
        witness = b"synthetic canary inaccessible, input read-only, environment and descriptors checked\n"
        native.require(witness in stdout and metadata.get("artifacts") == [], "actual guest check did not confirm the expected bounded denials")
        canary_after = native.read_file(canary, 4096, owner=True, mode=0o600)
        input_after = native.read_file(staged_input, 4096, owner=True, mode=0o600)
        native.require(canary_before == canary_after and input_before == input_after,
                       "host observer found changed canary or staged input bytes")
        facts = self.job_facts(job)
        facts.update({"guest_check_exit_zero": True, "host_canary_unchanged": True, "staged_input_unchanged": True,
            "host_canary_sha256": hashlib.sha256(canary_after).hexdigest(),
            "staged_input_sha256": hashlib.sha256(input_after).hexdigest(),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "scope": "one synthetic host canary and the staged input; approved check fixture also checked its fixed environment and descriptors"})
        self.facts["guest_denial"] = facts
        return {"job_id": job, "host_canary_unchanged": True, "staged_input_unchanged": True,
                "cleanup_confirmed": facts["cleanup_confirmed"]}

    def detached_cancellation(self) -> dict[str, Any]:
        # The helper requires actual >=4 cgroup members and detached session,
        # checks NOT_READY while live, then verifies launcher reap/group removal
        # and reads the committed readiness witness only after terminal cleanup.
        observed = self.cancel_case(self.stage_id())
        facts = self.job_facts(observed["job_id"])
        facts.update(observed)
        self.facts["cancellation"] = facts
        return observed


def worker(args: argparse.Namespace) -> int:
    harness: Demo | None = None
    code = 1
    reason: str | None = None
    cleanup: dict[str, Any] = {"status": "NOT RUN"}
    try:
        harness = Demo(args)
        harness.preflight()
        harness.exercise()
        code = 0
    except native.Blocked as error:
        reason = str(error)[:1024]
        native.emit("native_demo", "BLOCKED", reason=reason)
        code = 78
    except KeyboardInterrupt:
        code = 1
        reason = "demo interrupted; reconciling only owned test resources"
        native.emit("native_demo", "FAIL", reason=reason)
    except Exception as error:
        reason = f"{type(error).__name__}: {error}"[:1024]
        native.emit("native_demo", "FAIL", reason=reason)
    finally:
        if harness is not None:
            errors: list[str] = []
            try:
                if harness.instance is not None:
                    harness.jobs.update(harness.inventory())
            except Exception as error:
                errors.append(f"exact journal ownership reconciliation failed: {error}")
            errors.extend(harness.cleanup())
            if errors:
                cleanup = {"status": "FAIL", "errors": errors[:16]}
                native.emit("demo_teardown", "FAIL", errors=errors[:16])
                code = 1
            elif harness.created_work:
                cleanup = {"status": "PASS", "owned_children_reaped": True, "owned_cgroups_remaining": 0}
                native.emit("demo_teardown", "PASS", owned_children_reaped=True, owned_cgroups_remaining=0)
            if harness.created_work:
                observation = {"schema_version": 1, "status": "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL",
                    "reason": reason, "timeline": harness.timeline, "facts": harness.facts, "teardown": cleanup,
                    "commands": harness.commands, "captured_bytes": harness.captured}
                encoded = json.dumps(observation, sort_keys=True, indent=2).encode("utf-8") + b"\n"
                native.require(len(encoded) <= native.MAX_HEADER, "demo observation file exceeds bound")
                native.write_synthetic(harness.work / "demo-observations.json", encoded)
            if code == 0:
                native.emit("native_demo", "PASS", cases=harness.passes, commands=harness.commands,
                            scope="approved transformation, explicit denials, detached cancellation; finite demo only")
    return code


def escaped(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_report(renderer: Any, data: dict[str, Any]) -> str:
    """Use report.py's escaped record/CSP and add static keyboard navigation."""
    document = renderer.render(data, illustrative=False)
    run_id = data["evidence_run_id"]
    native.require(RUN_ID.fullmatch(run_id) is not None, "actual capture run ID is invalid")
    facts = data.get("observations", {}).get("facts", {})
    transformation = facts.get("transformation", {})
    refusal = facts.get("admission_refusal", {})
    denial = facts.get("guest_denial", {})
    cancellation = facts.get("cancellation", {})
    rows = []
    for label, fact in [("Approved transformation", transformation), ("Guest denial checks", denial), ("Detached cancellation", cancellation)]:
        rows.append("<tr>" + "".join(f"<td>{escaped(value)}</td>" for value in [label, fact.get("state", "NOT RUN"),
            fact.get("policy_sha256", "unavailable"), fact.get("cleanup_confirmed", "unavailable"),
            fact.get("result_digest", "unavailable")]) + "</tr>")
    timeline = "".join(f'<li>{escaped(row.get("case"))}: {escaped(row.get("status"))}; observed elapsed '
                       f'{escaped(row.get("elapsed_ms"))} ms</li>' for row in data.get("observations", {}).get("timeline", []))
    navigation = ('<nav aria-label="Demo sections"><p><a href="#demo-summary">Summary</a> · '
                  '<a href="#policy">Policy and results</a> · <a href="#cleanup">Cleanup</a> · '
                  '<a href="#evidence">Evidence</a> · <a href="#record">Sanitized record</a></p></nav>')
    sections = navigation + (
        '<section aria-labelledby="demo-summary"><h2 id="demo-summary" tabindex="-1">Recorded local demo</h2>'
        f'<p>Actual captured run: <strong>{escaped(data["status"])}</strong></p>'
        f'<p>Observed summary bytes: <code>{escaped(json.dumps(transformation.get("summary"), sort_keys=True))}</code>.</p>'
        f'<p>Typed profile admission refusal: <code>{escaped(refusal.get("code", "NOT RUN"))}</code>; '
        f'admitted: {escaped(refusal.get("admitted", "unavailable"))}. This refusal did not execute a guest.</p>'
        f'<p>Approved guest check: synthetic host canary unchanged: {escaped(denial.get("host_canary_unchanged", "NOT RUN"))}; '
        f'staged input unchanged: {escaped(denial.get("staged_input_unchanged", "NOT RUN"))}.</p>'
        f'<ol>{timeline}</ol></section>'
        '<section aria-labelledby="policy"><h2 id="policy" tabindex="-1">Policy, cleanup and result are separate</h2>'
        '<p>Admission authorizes a bounded request. A successful fixture exit does not replace cleanup proof. '
        'The committed result digest binds the retained bytes only after publication.</p>'
        '<div class="table-scroll" tabindex="0" role="region" aria-label="Scrollable policy and result table"><table><caption>Actual journal and committed-result observations</caption>'
        '<thead><tr><th scope="col">Case</th><th scope="col">Journal state</th><th scope="col">Policy SHA-256</th>'
        '<th scope="col">Cleanup confirmed</th><th scope="col">Result digest</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div></section>'
        '<section aria-labelledby="cleanup"><h2 id="cleanup" tabindex="-1">Observed cleanup</h2>'
        f'<p>Cancellation observed cgroup members: {escaped(cancellation.get("observed_cgroup_processes", "NOT RUN"))}; '
        f'launcher reaped: {escaped(cancellation.get("launcher_reaped", "NOT RUN"))}; '
        f'owned cgroup removed: {escaped(cancellation.get("cgroup_removed", "NOT RUN"))}.</p>'
        f'<p>Final harness teardown: {escaped(data.get("observations", {}).get("teardown", {}).get("status", "unavailable"))}.</p>'
        f'<p>Outer ownership check: {escaped(data.get("outer_teardown", {}).get("status", "unavailable"))}; '
        f'cleanup diagnostics: {escaped(data.get("outer_teardown", {}).get("error_count", "unavailable"))}.</p>'
        '<p>Cgroup removal is recorded as removal; the report does not invent a populated=0 sample after removal.</p></section>'
        '<section aria-labelledby="evidence"><h2 id="evidence" tabindex="-1">Local evidence and scope</h2>'
        f'<ul><li><a href="evidence/{run_id}.json">Machine-captured command record</a></li>'
        f'<li><a href="evidence/raw/{run_id}.stdout">Captured case observations</a></li>'
        f'<li><a href="evidence/raw/{run_id}.stderr">Captured diagnostics</a></li>'
        '<li><a href="run/demo-observations.json">Detailed demo observations</a></li>'
        '<li><a href="wrapper-cleanup.json">Private wrapper cleanup observations</a></li>'
        '<li><a href="run/data.ndjson">Actual synthetic input</a></li></ul>'
        '<p>Use Tab/Shift+Tab for links and Enter to follow them. No script, external font, analytics, browser capture, or screenshot is required.</p>'
        '<p>This finite demo does not establish full containment acceptance. It does not run a network-denial case, '
        'mutation campaign, benchmarks, clean-host reproduction, or independent review. Raw local records may contain '
        'operator paths and remain private until audited for sharing.</p></section>')
    marker = '<p>This report is data, not a claim that containment acceptance passed.</p>'
    native.require(document.count(marker) == 1 and document.count('<h2>Record</h2>') == 1,
                   "report renderer contract changed; refusing an unverified HTML adaptation")
    document = document.replace(marker, marker + sections, 1)
    document = document.replace('<h2>Record</h2>', '<h2 id="record" tabindex="-1">Sanitized machine record</h2>', 1)
    document = document.replace('<title>HearthRun inspection</title>', '<title>HearthRun recorded local demo</title>', 1)
    document = document.replace('<h1>HearthRun inspection</h1>', '<h1>HearthRun recorded local demo</h1>', 1)
    document = document.replace('</style>',
        ':root{color-scheme:light dark}body{background:Canvas;color:CanvasText}:focus-visible{outline:3px solid;outline-offset:3px}'
        'nav a{display:inline-block;padding:.3rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid;padding:.5rem;'
        'text-align:left;overflow-wrap:anywhere;max-width:24rem}.table-scroll{overflow-x:auto}section{scroll-margin-top:1rem}</style>', 1)
    native.require(len(document.encode("utf-8")) <= MAX_REPORT, "static report exceeds bounded output size")
    return document


def stop_interrupted_service(prepared: Any) -> list[str]:
    """Never signal a saved numeric PID: pin and revalidate the recorded service."""
    control_path = prepared.work / "run" / "supervisor-identity.json"
    if not control_path.exists():
        if (prepared.work / "run" / "state" / "control.sock").exists():
            return ["worker endpoint remains without a service identity; refused ambiguous signaling"]
        return []
    identity = native.strict_json(native.read_file(control_path, 4096, owner=True, mode=0o600))
    fields = {"v", "pid", "start_ticks", "uid", "executable_device", "executable_inode", "guard_device", "guard_inode"}
    native.require(set(identity) == fields and identity["v"] == 1 and identity["uid"] == os.geteuid()
                   and all(type(identity[key]) is int and 0 <= identity[key] < 2**64 for key in fields),
                   "invalid private demo service identity")
    pid = identity["pid"]
    native.require(0 < pid < 2**31 and identity["start_ticks"] > 0, "invalid recorded service PID/start identity")
    current = prepared.process_identity(pid)
    if current is None or current["start_ticks"] != identity["start_ticks"]:
        return []  # Original process is gone; a reused PID is never signaled.
    native.require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                   "pidfd service cleanup is unavailable; refusing numeric PID fallback")
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return []
    try:
        current = prepared.process_identity(pid)
        if current is None or current["start_ticks"] != identity["start_ticks"]:
            return []
        try:
            process_owner = os.stat(f"/proc/{pid}").st_uid
            image = os.stat(f"/proc/{pid}/exe")
        except FileNotFoundError:
            if select.select([descriptor], [], [], 0)[0]:
                return []
            raise
        permitted = {(identity["executable_device"], identity["executable_inode"]),
                     (identity["guard_device"], identity["guard_inode"])}
        native.require(process_owner == identity["uid"] and (image.st_dev, image.st_ino) in permitted,
                       "recorded service or launch guard UID/image changed; refused signaling")
        issues = ["worker left its recorded service alive; required outer recovery"]
        signal.pidfd_send_signal(descriptor, signal.SIGTERM, None, 0)
        deadline = time.monotonic() + 22
        while not select.select([descriptor], [], [], 0.05)[0]:
            if time.monotonic() >= deadline:
                issues.append("recorded service failed graceful shutdown; required pidfd SIGKILL")
                signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                if not select.select([descriptor], [], [], 5)[0]:
                    issues.append("recorded service exit remains unresolved")
                break
        return issues
    finally:
        os.close(descriptor)


def outer(args: argparse.Namespace) -> int:
    prepared: Any = None
    renderer: Any = None
    captured: dict[str, Any] | None = None
    observations: dict[str, Any] = {}
    teardown_errors: list[str] = []
    code = 1
    try:
        prepared = native.Harness(args)
        native.require(PUBLIC not in prepared.work.parents and prepared.work != PUBLIC,
                       "demo work/evidence must stay outside the audited product source tree")
        prepared.preflight()
        capture = load("hearthrun_demo_capture", PUBLIC / "scripts" / "capture.py")
        renderer = load("hearthrun_demo_report", PUBLIC / "scripts" / "report.py")
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--bin-dir", str(prepared.bin_dir),
            "--doctor", str(prepared.doctor), "--fixture", str(prepared.fixture), "--cgroup-root", str(prepared.cgroup_root),
            "--work", str(prepared.work / "run")]
        captured = capture.capture(command, PUBLIC, prepared.work / "evidence", "native-demo",
                                   ["UX-001", "FR-004", "SEC-003", "REL-001", "REL-002"], timeout=210)
        code = 0 if captured["exit_code"] == 0 else 78 if captured["exit_code"] == 78 else 1
        path = prepared.work / "run" / "demo-observations.json"
        observations = native.strict_json(native.read_file(path, native.MAX_HEADER, owner=True, mode=0o600)) if path.exists() else {
            "status": captured["status"], "reason": "worker produced no completed observation file",
            "facts": {}, "timeline": [], "teardown": {"status": "UNKNOWN"}}
        if code == 0:
            native.require(observations.get("status") == "PASS" and observations.get("teardown", {}).get("status") == "PASS",
                           "successful capture lacks observed demo completion/cleanup")
            observed_cases = {row["case"] for row in observations["timeline"] if row["status"] == "PASS"}
            expected_cases = {"doctor_and_socket", "approved_transformation", "typed_admission_refusal",
                              "guest_canary_and_input_denial", "detached_cancellation"}
            native.require(observed_cases == expected_cases and len(observations["timeline"]) == len(expected_cases),
                           "successful capture lacks the full set of expected observations")
    except native.Blocked as error:
        native.emit("demo_report", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except KeyboardInterrupt:
        native.emit("demo_report", "FAIL", reason="demo wrapper interrupted")
        code = 1
    except Exception as error:
        native.emit("demo_report", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
        code = 1
    finally:
        if prepared is not None:
            if prepared.created_work:
                # A rejected pre-existing --work grants no authority to inspect
                # its service identity or signal any resource recorded there.
                try:
                    teardown_errors.extend(stop_interrupted_service(prepared))
                except Exception as error:
                    teardown_errors.append(f"exact worker service cleanup refused: {error}")
                try:
                    child_state = prepared.work / "run" / "state"
                    if (child_state / "instance.json").exists():
                        prepared.state = child_state
                        prepared.read_instance()
                        prepared.jobs.update(prepared.inventory())
                except Exception as error:
                    teardown_errors.append(f"worker journal ownership reconciliation refused: {error}")
            teardown_errors.extend(prepared.cleanup())
            if teardown_errors:
                native.emit("demo_wrapper_teardown", "FAIL", errors=teardown_errors[:16])
                code = 1
            if prepared.created_work:
                try:
                    cleanup_record = {"status": "FAIL" if teardown_errors else "PASS", "error_count": len(teardown_errors),
                                      "errors": [message[:512] for message in teardown_errors[:16]]}
                    encoded_cleanup = json.dumps(cleanup_record, indent=2, sort_keys=True).encode("utf-8") + b"\n"
                    native.require(len(encoded_cleanup) <= native.MAX_HEADER, "wrapper cleanup observation exceeds evidence bound")
                    native.write_synthetic(prepared.work / "wrapper-cleanup.json", encoded_cleanup)
                except Exception as error:
                    native.emit("demo_wrapper_teardown", "FAIL", reason=f"cleanup observation persistence failed: {error}"[:1024])
                    code = 1
    # Rendering follows both worker and outer cleanup, so no report can announce
    # PASS before the wrapper has checked its own retained resource ownership.
    if captured is not None and prepared is not None and renderer is not None:
        try:
            status = "PASS" if code == 0 else "BLOCKED" if code == 78 else "FAIL"
            sanitized = json.loads(json.dumps(observations))
            if sanitized.get("reason") is not None:
                sanitized["reason"] = "worker recorded a failure/blocker; inspect private captured diagnostics"
            worker_teardown = sanitized.get("teardown", {})
            if worker_teardown.get("errors"):
                worker_teardown["error_count"] = len(worker_teardown.pop("errors"))
                worker_teardown["diagnostics"] = "private captured diagnostics contain the original cleanup errors"
            selected = {"schema_version": 1, "evidence_run_id": captured["run_id"], "status": status,
                "captured_command_status": captured["status"], "captured_exit_code": captured["exit_code"],
                "observed_start_utc": captured.get("start_utc"), "observed_end_utc": captured.get("end_utc"),
                "source_commit": captured.get("git_commit"), "source_dirty": captured.get("git_dirty"),
                "source_sha256_before": captured.get("source_sha256_before"), "source_sha256_after": captured.get("source_sha256_after"),
                "source_changed_during_run": captured.get("source_sha256_before") != captured.get("source_sha256_after"),
                "environment": captured.get("environment"), "actual_duration_seconds": captured.get("duration_seconds"),
                "observations": sanitized, "outer_teardown": {"status": "FAIL" if teardown_errors else "PASS",
                    "error_count": len(teardown_errors), "diagnostics": "inspect private captured diagnostics if errors occurred"},
                "scope": "finite local native demo; not full acceptance or a publication approval"}
            encoded = json.dumps(selected, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            native.require(len(encoded) <= native.MAX_HEADER, "sanitized report input exceeds byte bound")
            native.write_synthetic(prepared.work / "report-input.json", encoded)
            native.write_synthetic(prepared.work / "report.html", render_report(renderer, selected).encode("utf-8"))
            native.emit("demo_report", status, evidence_run_id=captured["run_id"], report="report.html",
                        observations="run/demo-observations.json", browser_visual_check="NOT RUN")
        except Exception as error:
            native.emit("demo_report", "FAIL", reason=f"rendering failed: {error}"[:1024])
            code = 1
    return code


def main() -> int:
    if sys.argv[1:2] == ["--gated-service"]:
        return start_gated_service(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("bin-dir", "doctor", "fixture", "cgroup-root", "work"):
        parser.add_argument(f"--{flag}", required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("demo termination requested; reconciling only owned resources")
    signal.signal(signal.SIGTERM, terminate)
    return worker(args) if args.worker else outer(args)


if __name__ == "__main__":
    raise SystemExit(main())
