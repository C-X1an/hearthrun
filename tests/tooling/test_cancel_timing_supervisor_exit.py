"""Pure regression of the real shard-finalization statements, using owned-child doubles.

No subprocess, signal, cgroup, native fixture or mount is exercised.
"""
import ast
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "benchmarks"))


class Child:
    def __init__(self, pid, code, *, shutdown_code=0):
        self.name = f"synthetic-{pid}"
        self.proc = self
        self.pid, self.code, self.shutdown_code = pid, code, shutdown_code
        self.terminated = False

    def poll(self):
        return self.code

    def terminate(self):
        self.terminated = True
        self.code = self.shutdown_code

    def wait(self, *args, **kwargs):
        return self.code

    def pump(self):
        pass

    def save(self):
        pass


class OwnedSupervisorExit(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / "tests/test-tmp"
        scratch.mkdir(exist_ok=True)
        self.context = tempfile.TemporaryDirectory(prefix="owned-exit-", dir=scratch)
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)
        script = ROOT / "benchmarks/cancellation.py"
        spec = importlib.util.spec_from_file_location("owned_exit_campaign", script)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        # Execute the actual campaign's immediate post-wave finalization block.
        tree = ast.parse(script.read_text())
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if not isinstance(body, list):
                continue
            for index, statement in enumerate(body):
                if isinstance(statement, ast.Assign) and ast.unparse(statement) == "errors = active.cleanup()":
                    end = next(i for i in range(index, len(body))
                               if ast.unparse(body[i]) == "checkpoint('after-shard')")
                    self.block = compile(ast.Module(body=body[index:end + 1], type_ignores=[]), str(script), "exec")
                    break
            if hasattr(self, "block"):
                break
        self.assertTrue(hasattr(self, "block"))

    def finalize(self, code, *, exact=True, shutdown_code=0, owned=True):
        owner = Child(4101, code, shutdown_code=shutdown_code)
        shard = object.__new__(self.module.Shard)
        shard.args = SimpleNamespace(exact_timing=exact)
        shard.created_work = False
        shard.cgroup_fd = None
        shard.jobs = set()
        shard.server = owner
        shard.children = [Child(4102, 0)] + ([owner] if owned else [])
        shard.work = self.root / "shard-0001"
        shard.work.mkdir()
        clock = {"clock": "CLOCK_MONOTONIC", "boot_id": "synthetic-boot", "time_namespace": "time:[7]"}
        run = "1" * 32
        rows = [{"run_id": run, "status": "PASS", "sample_index": 0, "job_id": "2" * 32,
                 "cancel_request_ns": 100, "cancel_ack_ns": 150, "cleanup_ns": 170, "finish_ns": 180}]
        trace = [{"kind": "header", "version": 1, "run_id": run, "shard": "shard-0001", "pid": 4101, **clock},
                 {"kind": "owner_write", "ordinal": 1, "job_id": "2" * 32, "receipt_ns": 110,
                  "begin_ns": 120, "end_ns": 130, "ok": True},
                 {"kind": "footer", "complete": True, "lost": 0, "received": 1, "events": 1}]
        (shard.work / "cancel-timing.jsonl").write_text("".join(json.dumps(row) + "\n" for row in trace))
        effects = []
        namespace = {**vars(self.module), "active": shard, "args": shard.args, "shard_rows": rows,
                     "run_id": run, "shard_args": SimpleNamespace(exact_shard="shard-0001"),
                     "environment": {"exact_timing": {"clock_identity": clock}}, "shard_index": 1,
                     "evidence": SimpleNamespace(save=lambda *value: effects.append(("event", value))),
                     "checkpoint": lambda value: effects.append(("checkpoint", value))}
        with patch.object(self.module.b, "compact_shard", lambda value: effects.append(("compact", value))), \
             patch.object(self.module.b, "json_file", lambda path, value: effects.append((path.name, value))):
            try:
                exec(self.block, namespace)
            finally:
                self.effects, self.namespace, self.owner = effects, namespace, owner
        return effects

    def test_complete_trace_rejects_already_exited_owned_supervisor_collector_error(self):
        # Removing the exact owned exit-zero condition must make this fail.
        with self.assertRaisesRegex(self.module.n.Failure, "owned supervisor"):
            self.finalize(1)
        self.assertEqual(self.effects, [])
        self.assertIsNotNone(self.namespace["active"])

    def test_other_successful_child_cannot_replace_failed_owned_supervisor(self):
        with self.assertRaisesRegex(self.module.n.Failure, "owned supervisor"):
            self.finalize(-9)
        self.assertEqual(self.effects, [])

    def test_unowned_successful_process_cannot_supply_supervisor_evidence(self):
        with self.assertRaisesRegex(self.module.n.Failure, "owned supervisor"):
            self.finalize(0, owned=False)
        self.assertEqual(self.effects, [])

    def test_exact_zero_exit_records_owner_before_passing_teardown(self):
        effects = self.finalize(0)
        exact = next(value for name, value in effects if name == "exact-timing.json")
        teardown = next(value for name, value in effects if name == "teardown.json")
        self.assertEqual(exact["supervisor_exit"], {"pid": 4101, "exit_code": 0})
        self.assertEqual(teardown["exact_timing_supervisor_exit"], exact["supervisor_exit"])
        self.assertIsNone(self.namespace["active"])

    def test_running_owner_is_gracefully_reaped_before_exact_acceptance(self):
        self.finalize(None)
        self.assertTrue(self.owner.terminated)
        self.assertEqual(self.owner.poll(), 0)

    def test_immediate_shutdown_failure_prevents_trace_and_passing_teardown(self):
        with self.assertRaises(self.module.n.Failure):
            self.finalize(None, shutdown_code=1)
        self.assertEqual(self.effects, [])

    def test_client_only_preserves_historical_already_exited_cleanup_behavior(self):
        effects = self.finalize(1, exact=False)
        self.assertFalse(any(name == "exact-timing.json" for name, _ in effects))
        teardown = next(value for name, value in effects if name == "teardown.json")
        self.assertNotIn("exact_timing_supervisor_exit", teardown)


if __name__ == "__main__":
    unittest.main()
