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
                  patch.object(demo, 'worker_command', return_value=[]),
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

    def test_default_cancellation_preserves_original_report_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            subject = SimpleNamespace(
                state=state, submit=lambda *args: "fixed-job", detached_ready=lambda job: ([{"pid": 4}], [{"pid": 4}]),
                cli=lambda *args, **kwargs: {"cancel_requested": True}, terminal=lambda *args, **kwargs: None,
                cleanup_observed=lambda *args: None,
                record=lambda job: {"cancel_reason": "USER_CANCEL", "result_digest": "fixed-digest"},
                verify_result=lambda *args: ({"artifacts": [], "status": "CANCELLED"}, b"detached-ready\n", b""),
            )
            default = demo.native.Harness.cancel_case(subject, "stage")
            scoped = demo.native.Harness.cancel_case(subject, "stage", cleanup_timeout=6.0)
            self.assertEqual(default, {"job_id": "fixed-job", "observed_cgroup_processes": 1,
                                       "launcher_reaped": True, "cgroup_removed": True})
            self.assertEqual(set(scoped) - set(default), {
                "members_before_cancel", "launchers_before_cancel", "cancel_reason",
                "result_status", "result_digest", "cleanup_elapsed_ms",
            })


class DemoReportStructureTests(unittest.TestCase):
    NOTE = '<em>HearthRun inert guest note</em> & "quoted"'

    def fixture(self):
        # Synthetic portable renderer input, never a native execution claim.
        return {"evidence_run_id": "20261118T000000-0123456789ab", "status": "PORTABLE_FIXTURE_NOT_RUN",
                "observations": {"facts": {"transformation": {"state": self.NOTE}},
                                 "timeline": [{"case": self.NOTE, "status": "NOT_RUN", "elapsed_ms": 0}]},
                "outer_teardown": {"status": "NOT_RUN", "error_count": 0}}

    def rendered(self):
        renderer = demo.load("hearthrun_portable_demo_report", ROOT / "scripts/report.py")
        data = self.fixture()
        return data, demo.render_report(renderer, data)

    def test_inert_guest_markup_remains_literal_text(self):
        data, document = self.rendered()
        structure = demo.ReportStructure()
        structure.feed(document)
        structure.close()
        self.assertNotIn("em", structure.tags)
        parsed = demo.check_report_document(data, document)
        self.assertEqual(parsed.rows[0][1], self.NOTE)
        self.assertIn(self.NOTE, " ".join(parsed.text))
        self.assertIn("PORTABLE_FIXTURE_NOT_RUN", " ".join(parsed.text))

    def test_missing_cleanup_evidence_link_is_refused(self):
        data, document = self.rendered()
        document = document.replace('href="wrapper-cleanup.json"', 'href="missing-cleanup.json"', 1)
        with self.assertRaisesRegex(demo.native.Failure, "report links"):
            demo.check_report_document(data, document)

    def test_recorded_fractional_duration_remains_in_embedded_record(self):
        data = dict(self.fixture(), actual_duration_seconds=1.125)
        renderer = demo.load("hearthrun_portable_demo_duration", ROOT / "scripts/report.py")
        document = demo.render_report(renderer, data)
        demo.check_report_document(data, document)

    def test_visible_outer_cleanup_cannot_disagree_with_record(self):
        data, document = self.rendered()
        original = "Outer ownership check: NOT_RUN"
        self.assertIn(original, document)
        document = document.replace(original, "Outer ownership check: PASS", 1)
        with self.assertRaisesRegex(demo.native.Failure, "displayed demo observation"):
            demo.check_report_document(data, document)

    def test_unexpected_inert_markup_in_existing_table_text_is_refused(self):
        data, document = self.rendered()
        document = document.replace("<td>Approved transformation</td>", "<td><em>Approved transformation</em></td>", 1)
        with self.assertRaisesRegex(demo.native.Failure, "unexpected element"):
            demo.check_report_document(data, document)

    def test_conflicting_link_attributes_are_refused(self):
        data, document = self.rendered()
        document = document.replace('href="wrapper-cleanup.json"',
                                    'href="missing-cleanup.json" href="wrapper-cleanup.json"', 1)
        with self.assertRaisesRegex(demo.native.Failure, "duplicate attributes"):
            demo.check_report_document(data, document)

    def test_capture_parser_rejects_ambiguous_and_nonfinite_data(self):
        for payload, error in ((b'{"duration":1.1,"duration":1.2}', "duplicate"),
                               (b'{"duration":1e999}', "nonfinite")):
            with self.subTest(payload=payload), self.assertRaisesRegex(demo.native.Failure, error):
                demo.evidence_json(payload)

    def test_empty_worker_stdout_cannot_prove_completed_observations(self):
        with self.assertRaisesRegex(demo.native.Failure, "exact completed observations"):
            demo.check_worker_stdout(b"", {})
