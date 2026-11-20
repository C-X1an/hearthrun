"""Portable controls for reporter behavior after a worker capture."""
import argparse
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('hearthrun_demo', ROOT / 'tests/e2e/demo.py')
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


class DemoWrapperTests(unittest.TestCase):
    def test_zero_worker_exit_without_observations_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            prepared = SimpleNamespace(work=work, bin_dir=work, cgroup_root=work, doctor=work,
                                       fixture=work, created_work=False,
                                       preflight=lambda: None, cleanup=lambda: [])
            captured = {'status': 'PASS', 'exit_code': 0, 'run_id': '20261118T000000-0123456789ab'}
            capture = SimpleNamespace(capture=lambda *args, **kwargs: captured)
            with (patch.object(demo.native, 'Harness', return_value=prepared),
                  patch.object(demo, 'load', side_effect=[capture, object()]),
                  patch.object(demo.native, 'emit'),
                  patch.object(demo.native, 'write_synthetic'),
                  patch.object(demo, 'render_report', return_value='fixture') as render):
                self.assertEqual(demo.outer(argparse.Namespace()), 1)
                self.assertEqual(render.call_args.args[1]['status'], 'FAIL')

    def test_gate_eof_prevents_service_exec(self):
        # This private control exercises the wrapper only. No service is started.
        with (patch.object(demo.os, 'read', return_value=b'') as read,
              patch.object(demo.os, 'execv') as execute):
            self.assertEqual(demo.start_gated_service([str(ROOT / 'synthetic')] * 5), 1)
            read.assert_called_once_with(0, 1)
            execute.assert_not_called()
