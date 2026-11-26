#!/usr/bin/env python3
"""DRAFT AC-018: protected approved bytes survive owned source replacement.

Integrate as tests/security/profiles.py before native execution. Only a copy in
a NEW harness work directory is replaced, always with non-executable harmless
text. Neither the operator fixture nor the installed protected image is edited.
This finite concurrency observation does not instrument a hash-to-exec cut.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import threading
import time
from typing import Any

sys.dont_write_bytecode = True
# Deliberately resolve the final PUBLIC path, never a private fallback.
SPEC = importlib.util.spec_from_file_location(
    "hearthrun_profiles_native", Path(__file__).resolve().parents[1] / "e2e" / "native.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native profile helper unavailable")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)

IMAGE_LIMIT = 8 * 1024 * 1024
MAX_REPLACEMENTS = 256
MARKERS = (b"HearthRun owned inert source replacement A\n",
           b"HearthRun owned inert source replacement B\n")
INPUT = b'{"value":7}\n{"value":-2}\n{"value":0}\n{"value":11}\n'
SUMMARY = b'{"count":4,"sum":16}\n'


class ProfileSuite(native.Harness):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)
        self.approved_digest = args.fixture_sha256
        self.approved_bytes = b""
        self.approval: dict[str, Any] = {}
        self.installed_identity: tuple[int, int] | None = None
        self.manifest_bytes: bytes | None = None
        self.source = self.work / "source" / "operator-source"

    def prepare_profile(self) -> None:
        native.require(native.DIGEST.fullmatch(self.approved_digest) is not None,
                       "operator must pin the approved fixture SHA-256")
        self.approved_bytes = native.read_file(self.fixture, IMAGE_LIMIT, owner=True)
        native.require(hashlib.sha256(self.approved_bytes).hexdigest() == self.approved_digest,
                       "operator fixture differs from independently pinned approved bytes")
        native.new_private(self.source.parent)
        # Source need only be readable by install-profile, never executable here.
        native.write_synthetic(self.source, self.approved_bytes)
        code, output, _ = self.command([
            str(self.bin_dir / "hearthrun-supervisor"), "install-profile",
            str(self.state), "example", str(self.source),
        ])
        native.require(code == 0, "production operator profile installation failed")
        self.approval = native.strict_json(output)
        native.require(set(self.approval) == {"profile_id", "profile_digest", "executable_digest"}
                       and self.approval["profile_id"] == "example"
                       and self.approval["executable_digest"] == self.approved_digest,
                       "install-profile did not report the pinned approved image")
        self.check_profile()

    def check_profile(self) -> None:
        native.private_directory(self.source.parent)
        directory = self.state / "profiles" / "example"
        native.private_directory(directory)
        native.require({entry.name for entry in directory.iterdir()} == {"task", "manifest.json"},
                       "installed approval contains unexpected entries")
        image = directory / "task"
        actual = native.read_file(image, IMAGE_LIMIT, owner=True, mode=0o400)
        info = image.lstat()
        identity = (info.st_dev, info.st_ino)
        if self.installed_identity is None:
            self.installed_identity = identity
        native.require(identity == self.installed_identity and actual == self.approved_bytes
                       and hashlib.sha256(actual).hexdigest() == self.approved_digest,
                       "installed protected image identity or exact approved bytes changed")
        manifest = native.read_file(directory / "manifest.json", 4096, owner=True, mode=0o600)
        native.require(native.strict_json(manifest) == {
            "v": 1, "profile_id": "example", "sha256": self.approved_digest,
        }, "protected manifest does not approve the pinned image")
        if self.manifest_bytes is None:
            self.manifest_bytes = manifest
        native.require(manifest == self.manifest_bytes
                       and hashlib.sha256(manifest).hexdigest() == self.approval["profile_digest"],
                       "protected manifest bytes differ from operator approval identity")

    def refused_snapshot(self) -> dict[str, Any]:
        return {
            "metrics": self.cli("metrics"), "jobs": self.inventory(), "groups": self.group_names(),
            "catalog": native.read_file(self.state / "records" / "catalog.json",
                                        native.MAX_CATALOG, owner=True, mode=0o600),
            "results": {entry.name for entry in (self.state / "results").iterdir()},
            "scratch": {entry.name for entry in (self.state / "scratch").iterdir()},
        }

    def refusal_case(self, stage: str) -> dict[str, Any]:
        before = self.refused_snapshot()
        native.require(not before["jobs"] and not before["groups"] and not before["results"]
                       and not before["scratch"] and before["metrics"]["active"] == 0
                       and before["metrics"]["queued"] == 0, "refusal baseline must be idle and empty")
        cases = (("unknown_profile", "missing", {}, "PROFILE_NOT_FOUND"),
                 ("client_host_path", "example", {"host_path": str(self.source.parent)}, "UNKNOWN_FIELD"),
                 ("client_mounts", "example", {"mounts": [{"source": str(self.source.parent),
                                                           "target": "/unapproved"}]}, "UNKNOWN_FIELD"))
        for label, profile, extra, expected in cases:
            packet = {"v": 1, "op": "submit", "request_id": secrets.token_hex(16),
                      "profile_id": profile, "stage_id": stage, "argv": ["summary"],
                      "wall_ms": 10000, **extra}
            response = self.raw_request(json.dumps(packet, separators=(",", ":")).encode())
            # Preserve cleanup ownership even if a broken implementation admits it.
            if response.get("ok") is True:
                job = response.get("result", {}).get("job_id")
                if isinstance(job, str) and native.ID.fullmatch(job) is not None:
                    self.jobs.add(job)
            native.require(type(response.get("v")) is int and response["v"] == 1
                           and response.get("ok") is False
                           and response.get("error", {}).get("code") == expected
                           and response["error"].get("retryable") is False,
                           f"{label} did not produce the exact typed refusal")
            native.require(self.refused_snapshot() == before,
                           f"{label} changed job, catalog, result, scratch, cgroup or scheduler state")
            self.check_profile()
            native.emit(label, "PASS", error_code=expected, admitted_jobs=0,
                        unchanged_catalog=True, results=0, scratch=0, cgroups=0)
        return {"typed_refusals": len(cases), "no_execution_or_publication_side_effects": True}

    def summary_result(self, stage: str) -> dict[str, Any]:
        request = secrets.token_hex(16)
        job = self.submit(request, stage, "summary")
        inspected = self.terminal(job, "SUCCEEDED")
        metadata, stdout, stderr = self.verify_result(job, "SUCCEEDED")
        record = self.record(job)
        artifact = self.state / "results" / job / "artifacts" / "summary.json"
        raw = native.read_file(artifact, 1024, owner=True, mode=0o600)
        native.require(raw == SUMMARY and stdout == b"" and stderr == b""
                       and metadata.get("exit_code") == 0 and metadata.get("signal") is None
                       and metadata.get("stdout_truncated") is False
                       and metadata.get("stderr_truncated") is False,
                       "approved summary did not preserve exact checked artifact, streams and exit")
        native.require(metadata["artifacts"] == [{"path": "summary.json", "size_bytes": len(SUMMARY),
                                                  "sha256": hashlib.sha256(SUMMARY).hexdigest()}],
                       "summary result manifest is not the exact expected checked artifact")
        native.require(record.get("request_id") == request and record.get("profile_id") == "example"
                       and record.get("executable_digest") == self.approved_digest
                       and record.get("profile_digest") == self.approval["profile_digest"]
                       and inspected.get("executable_digest") == self.approved_digest,
                       "executed job identity differs from the pinned installed profile")
        native.require(not self.group_names() and self.cli("metrics")["active"] == 0,
                       "checked summary retained live execution state")
        self.check_profile()
        return {"job_id": job, "request_id": request, "result_digest": record["result_digest"],
                "executable_digest": record["executable_digest"], "profile_digest": record["profile_digest"],
                "summary_sha256": hashlib.sha256(raw).hexdigest()}

    def replacement_case(self, stage: str) -> dict[str, Any]:
        events: list[dict[str, Any]] = []
        errors: list[BaseException] = []
        ready, proceed, stop = threading.Event(), threading.Event(), threading.Event()

        def replace_once(generation: int) -> None:
            replacement = self.source.parent / f"replacement-{generation:03d}"
            marker = MARKERS[generation % len(MARKERS)]
            native.write_synthetic(replacement, marker)
            started = time.monotonic_ns()
            os.replace(replacement, self.source)
            finished = time.monotonic_ns()
            native.require(native.read_file(self.source, 256, owner=True, mode=0o600) == marker,
                           "owned source replacement did not preserve exact inert text")
            events.append({"generation": generation, "replace_started_ns": started,
                           "replace_finished_ns": finished, "sha256": hashlib.sha256(marker).hexdigest()})

        def worker() -> None:
            try:
                # Deterministically remove original source bytes before submission.
                replace_once(0)
                ready.set()
                native.require(proceed.wait(5), "source replacement start handshake expired")
                for generation in range(1, MAX_REPLACEMENTS):
                    if stop.is_set():
                        break
                    replace_once(generation)
                    if stop.wait(0.002):
                        break
            except BaseException as error:
                errors.append(error)
                ready.set()

        thread = threading.Thread(target=worker, name="owned-inert-source", daemon=False)
        thread.start()
        try:
            native.require(ready.wait(5) and not errors, "initial owned source replacement failed")
            self.check_profile()
            window_start = time.monotonic_ns()
            proceed.set()
            result = self.summary_result(stage)
            window_end = time.monotonic_ns()
        finally:
            stop.set()
            proceed.set()
            thread.join(timeout=5)
            native.require(not thread.is_alive(), "owned source worker did not stop")
            # Preserve observations on success or failure; no claimed native result here.
            native.write_synthetic(self.logs / "source-replacements.json", json.dumps({
                "v": 1, "maximum": MAX_REPLACEMENTS, "events": events,
                "worker_errors": [f"{type(error).__name__}: {error}" for error in errors],
            }, sort_keys=True).encode())
        native.require(not errors, "owned source replacement worker failed")
        overlap = [entry for entry in events if window_start <= entry["replace_started_ns"]
                   <= entry["replace_finished_ns"] <= window_end]
        native.require(bool(overlap), "no atomic source replacement observed within submission/result window")
        self.check_profile()
        native.require(native.read_file(self.fixture, IMAGE_LIMIT, owner=True) == self.approved_bytes,
                       "original operator fixture changed")
        result.update({"source_replacements": len(events), "replacements_in_observed_window": len(overlap),
                       "window_start_ns": window_start, "window_end_ns": window_end,
                       "race_scope": "submission through checked result; no internal hash/exec ordering claim"})
        return result

    def exercise(self) -> None:
        self.prepare_profile()
        self.start()
        self.doctor_case()
        data = self.work / "data.ndjson"
        native.write_synthetic(data, INPUT)
        staged = self.cli("stage", f"data.ndjson={data}")
        stage = staged.get("stage_id")
        native.require(isinstance(stage, str) and native.ID.fullmatch(stage) is not None,
                       "staging did not return a valid immutable input identity")
        self.case("profile_authority_refusals", lambda: self.refusal_case(stage))
        self.case("approved_profile_reference_result", lambda: self.summary_result(stage))
        self.case("protected_profile_source_replacement", lambda: self.replacement_case(stage))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("bin-dir", "doctor", "fixture", "fixture-sha256", "cgroup-root", "work"):
        parser.add_argument(f"--{flag}", required=True)
    suite = ProfileSuite(parser.parse_args())

    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("profile verification interrupted; reconciling owned resources")

    signal.signal(signal.SIGTERM, terminate)
    code = 1
    try:
        suite.preflight()
        suite.exercise()
        code = 0
    except native.Blocked as error:
        native.emit("profiles", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except (Exception, KeyboardInterrupt) as error:
        native.emit("profiles", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        errors = suite.cleanup()
        if errors:
            native.emit("teardown", "FAIL", errors=errors[:16])
            code = 1
        elif suite.created_work:
            native.emit("teardown", "PASS", owned_children_reaped=True, owned_cgroups_remaining=0)
        if code == 0:
            native.emit("profiles", "PASS", cases=suite.passes, scope="finite AC-018 functional check; mutation gate separate")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
