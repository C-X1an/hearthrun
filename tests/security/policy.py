#!/usr/bin/env python3
"""Finite native policy checks through the real CLI/supervisor/launcher.

Compile only within the existing bounded toolchain area:
  musl-gcc -std=c11 -static -O2 -Wall -Wextra -Werror fixtures/native/policy_probe.c -o ABS_STATIC_POLICY
Machine-capture on the prepared Linux host (all paths absolute):
  python3 tests/security/policy.py --bin-dir ABS_DEBUG --doctor ABS_DOCTOR \
    --fixture ABS_STATIC_POLICY --cgroup-root ABS_JOBS --work ABS_NEW_WORK

Reuses the e2e harness's OS-bounded noswap storage, process deadlines, owner-only
IPC, result hashing and cleanup. Provisions no host capabilities. This finite
suite does not satisfy the locked listener/DNS network campaign, injected
inherited-FD negative control, architecture-mismatch control or pass/fail/pass
policy mutant. Those acceptance gates remain separate and unclaimed.
"""
from __future__ import annotations

import argparse
import errno
import importlib.util
from pathlib import Path
import re
import secrets
import signal
import sys
from typing import Any

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("hearthrun_native_policy_helper", Path(__file__).resolve().parents[1] / "e2e" / "native.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native e2e helper is unavailable")
native = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = native
SPEC.loader.exec_module(native)


class PolicySuite(native.Harness):
    def exercise(self) -> None:
        # This synthetic secret reaches the owned supervisor, never the caller's
        # real environment. The guest must still observe exactly three entries.
        self.secret = secrets.token_hex(24).encode("ascii")
        self.environment["SECRET_CANARY"] = self.secret.decode("ascii")
        code, stdout, _ = self.command([str(self.bin_dir / "hearthrun-supervisor"), "install-profile", str(self.state), "example", str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout).get("profile_id") == "example", "approved policy profile installation failed")
        self.start()
        self.case("doctor_and_socket", self.doctor_case)
        self.canary = self.work / "host-canary.txt"
        self.canary_bytes = b"synthetic-host-canary:" + secrets.token_hex(24).encode("ascii") + b"\n"
        native.write_synthetic(self.canary, self.canary_bytes)
        self.canary_identity = (self.canary.stat().st_dev, self.canary.stat().st_ino)
        self.input_bytes = b"synthetic-staged-policy-input:" + secrets.token_hex(16).encode("ascii") + b"\n"
        source = self.work / "probe.txt"
        native.write_synthetic(source, self.input_bytes)
        self.stage = self.cli("stage", f"probe.txt={source}").get("stage_id")
        native.require(isinstance(self.stage, str) and native.ID.fullmatch(self.stage) is not None, "stage lacks actual identity")
        self.case("filesystem_environment_descriptors_and_approved_io", self.isolation)
        self.case("socket_creation_default_deny", lambda: self.denials("sockets", ["unix", "ipv4", "ipv6"]))
        self.case("invalid_operation_default_deny", lambda: self.denials("operations", ["connect", "ptrace", "bpf", "mount", "keyctl", "io_uring_setup", "setns"]))
        self.case("x32_benign_identity_query_terminated", self.x32)

    def run_mode(self, mode: str, *arguments: str, expected: str = "SUCCEEDED") -> tuple[str, dict[str, Any], bytes]:
        value = self.cli("submit", secrets.token_hex(16), "example", self.stage, "10000", "--", mode, *arguments)
        job = value.get("job_id")
        native.require(isinstance(job, str) and native.ID.fullmatch(job) is not None, "policy submit lacks actual job identity")
        self.jobs.add(job)
        self.record(job)
        self.terminal(job, expected)
        metadata, stdout, stderr = self.verify_result(job, expected)
        native.require(not self.group_names(), "policy job cgroup remains after terminal publication")
        native.require(metadata["stdout_truncated"] is False and metadata["stderr_truncated"] is False and stderr == b"", "policy probe has truncated streams or unexpected diagnostics")
        native.require(self.canary_bytes not in stdout + stderr and self.secret not in stdout + stderr, "synthetic secret/canary leaked into streams")
        info = self.canary.lstat()
        native.require((info.st_dev, info.st_ino) == self.canary_identity and native.read_file(self.canary, 256, owner=True, mode=0o600) == self.canary_bytes, "owned host canary identity/content changed")
        if expected == "SUCCEEDED":
            native.require(metadata["exit_code"] == 0 and metadata["signal"] is None, "successful policy probe lacks normal exit")
        return job, metadata, stdout

    def isolation(self) -> dict[str, Any]:
        job, metadata, stdout = self.run_mode("isolation", str(self.canary))
        match = re.fullmatch(rb"isolation-ok fd_ceiling=([0-9]+)\n", stdout)
        native.require(match is not None and 3 <= int(match[1]) <= 1048576, "guest did not complete bounded FD/environment/filesystem checks")
        native.require(len(metadata["artifacts"]) == 1 and metadata["artifacts"][0]["path"] == "approved.txt", "approved input/output produced wrong artifact inventory")
        output = native.read_file(self.state / "results" / job / "artifacts" / "approved.txt", 128, owner=True, mode=0o600)
        native.require(output == self.input_bytes and self.canary_bytes not in output and self.secret not in output, "approved output differs from actual staged bytes or leaked authority")
        return {"job_id": job, "fd_ceiling": int(match[1]), "synthetic_canary_unchanged": True, "approved_io_bytes": len(output)}

    def denials(self, mode: str, names: list[str]) -> dict[str, Any]:
        job, metadata, stdout = self.run_mode(mode)
        expected = b"".join(f"{name} result=-1 errno={errno.EPERM}\n".encode("ascii") for name in names)
        native.require(stdout == expected and metadata["artifacts"] == [], "forbidden operation did not report exact EPERM observations")
        return {"job_id": job, "operations": names, "errno": errno.EPERM}

    def x32(self) -> dict[str, Any]:
        job, metadata, stdout = self.run_mode("x32", expected="FAILED")
        native.require(stdout == b"before-x32-getpid\n" and metadata["exit_code"] is None and metadata["signal"] == signal.SIGSYS and metadata["artifacts"] == [], "x32 identity query lacks exact controlled SIGSYS termination")
        return {"job_id": job, "signal": signal.SIGSYS, "syscall": "x32 getpid"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("bin-dir", "doctor", "fixture", "cgroup-root", "work"):
        parser.add_argument(f"--{flag}", required=True)
    args = parser.parse_args()
    def terminate(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure("policy harness termination requested; reconciling only owned jobs")
    signal.signal(signal.SIGTERM, terminate)
    harness: PolicySuite | None = None
    code = 1
    try:
        harness = PolicySuite(args)
        harness.preflight()
        harness.exercise()
        code = 0
    except native.Blocked as error:
        native.emit("policy_security", "BLOCKED", reason=str(error)[:1024])
        code = 78
    except KeyboardInterrupt:
        native.emit("policy_security", "FAIL", reason="policy harness interrupted")
    except Exception as error:
        native.emit("policy_security", "FAIL", reason=f"{type(error).__name__}: {error}"[:1024])
    finally:
        if harness is not None:
            errors = harness.cleanup()
            if errors:
                native.emit("teardown", "FAIL", errors=errors[:16])
                code = 1
            elif harness.created_work:
                native.emit("teardown", "PASS", owned_children_reaped=True, owned_cgroups_remaining=0)
            if code == 0:
                native.emit("policy_security", "PASS", passed_cases=harness.passes, commands=harness.commands, captured_bytes=harness.captured,
                            scope="finite policy checks; full locked acceptance and mutation controls remain separate")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
